//
// Copyright (c) 2018, Přemysl Janouch <p@janouch.name>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

// Package ell implements a simple scripting language.
package ell

import (
	"errors"
	"fmt"
	"io"

	// standard library
	"bytes"
	"os"
	"os/exec"
)

// --- Values ------------------------------------------------------------------

// VType denotes the type of a value.
type VType int

const (
	// VTypeString denotes a string value.
	VTypeString VType = iota
	// VTypeList denotes a list value.
	VTypeList
)

// V is a value in the ell language.
type V struct {
	Type   VType  // the type of this value
	List   []V    // the contents of a VTypeList
	String string // the immutable contents of a VTypeString
}

// Clone clones a value including its sublists.
func (v *V) Clone() *V {
	if v == nil {
		return nil
	}
	return &V{
		Type:   v.Type,
		List:   CloneSeq(v.List),
		String: v.String,
	}
}

// CloneSeq clones a value including the rest of its chain.
func CloneSeq(v []V) (result []V) {
	for _, v := range v {
		result = append(result, *v.Clone())
	}
	return
}

// NewString creates a new value containing a string.
func NewString(string string) *V {
	return &V{
		Type:   VTypeString,
		String: string,
	}
}

// NewList creates a new list value containing the given sequence.
func NewList(list []V) *V {
	return &V{
		Type: VTypeList,
		List: list,
	}
}

// --- Lexer -------------------------------------------------------------------

type token int

const (
	tAbort token = iota
	tLParen
	tRParen
	tLBracket
	tRBracket
	tLBrace
	tRBrace
	tString
	tNewline
	tAt
)

func (t token) String() string {
	switch t {
	case tAbort:
		return "end of input"
	case tLParen:
		return "left parenthesis"
	case tRParen:
		return "right parenthesis"
	case tLBracket:
		return "left bracket"
	case tRBracket:
		return "right bracket"
	case tLBrace:
		return "left brace"
	case tRBrace:
		return "right brace"
	case tString:
		return "string"
	case tNewline:
		return "newline"
	case tAt:
		return "at symbol"
	}
	panic("unknown token")
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

type lexer struct {
	p            []byte // unread input
	line, column int    // current line and column
	buf          []byte // parsed string value
}

func newLexer(p []byte) *lexer {
	return &lexer{p: p}
}

func (lex *lexer) advance() byte {
	ch := lex.p[0]
	lex.p = lex.p[1:]

	if ch == '\n' {
		lex.column = 0
		lex.line++
	} else {
		lex.column++
	}
	return ch
}

var lexerHexAlphabet = "0123456789abcdef"

// fromHex converts a nibble from hexadecimal. Avoiding dependencies.
func lexerFromHex(ch byte) int {
	if ch >= 'A' && ch <= 'Z' {
		ch += 32
	}
	for i := 0; i < len(lexerHexAlphabet); i++ {
		if lexerHexAlphabet[i] == ch {
			return i
		}
	}
	return -1
}

func (lex *lexer) hexaEscape() bool {
	if len(lex.p) < 2 {
		return false
	}
	h := lexerFromHex(lex.advance())
	if h < 0 {
		return false
	}
	l := lexerFromHex(lex.advance())
	if l < 0 {
		return false
	}
	lex.buf = append(lex.buf, byte(h<<4|l))
	return true

}

const (
	lexerStringQuote = '\''
	lexerEscape      = '\\'
	lexerComment     = '#'
)

func lexerIsWhitespace(ch byte) bool {
	return ch == 0 || ch == ' ' || ch == '\t' || ch == '\r'
}

var lexerEscapes = map[byte]byte{
	lexerStringQuote: lexerStringQuote,
	lexerEscape:      lexerEscape,
	'a':              '\a',
	'b':              '\b',
	'n':              '\n',
	'r':              '\r',
	't':              '\t',
}

func (lex *lexer) escapeSequence() error {
	if len(lex.p) == 0 {
		return errors.New("premature end of escape sequence")
	}
	ch := lex.advance()
	if ch == 'x' {
		if lex.hexaEscape() {
			return nil
		}
		return errors.New("invalid hexadecimal escape")
	}
	ch, ok := lexerEscapes[ch]
	if !ok {
		return errors.New("unknown escape sequence")
	}
	lex.buf = append(lex.buf, ch)
	return nil
}

func (lex *lexer) string() error {
	for len(lex.p) > 0 {
		ch := lex.advance()
		if ch == lexerStringQuote {
			return nil
		}
		if ch != lexerEscape {
			lex.buf = append(lex.buf, ch)
		} else if err := lex.escapeSequence(); err != nil {
			return err
		}
	}
	return errors.New("premature end of string")
}

var lexerTokens = map[byte]token{
	'(':              tLParen,
	')':              tRParen,
	'[':              tLBracket,
	']':              tRBracket,
	'{':              tLBrace,
	'}':              tRBrace,
	';':              tNewline,
	'\n':             tNewline,
	'@':              tAt,
	lexerStringQuote: tString,
}

func (lex *lexer) next() (token, error) {
	for len(lex.p) > 0 && lexerIsWhitespace(lex.p[0]) {
		lex.advance()
	}
	if len(lex.p) == 0 {
		return tAbort, nil
	}

	lex.buf = nil

	ch := lex.advance()
	if ch == lexerComment {
		for len(lex.p) > 0 {
			if ch := lex.advance(); ch == '\n' {
				return tNewline, nil
			}
		}
		return tAbort, nil
	}

	token, ok := lexerTokens[ch]
	if !ok {
		lex.buf = append(lex.buf, ch)
		for len(lex.p) > 0 && !lexerIsWhitespace(lex.p[0]) &&
			lexerTokens[lex.p[0]] == 0 /* ugly but short */ {
			lex.buf = append(lex.buf, lex.advance())
		}
		return tString, nil
	}

	if token == tString {
		if err := lex.string(); err != nil {
			return tAbort, err
		}
	}
	return token, nil
}

func (lex *lexer) errorf(format string, a ...interface{}) error {
	return fmt.Errorf("at or before line %d, column %d: %s",
		lex.line+1, lex.column+1, fmt.Sprintf(format, a...))
}

// --- Printing ----------------------------------------------------------------

func printStringNeedsQuoting(s *V) bool {
	for i := 0; i < len(s.String); i++ {
		ch := s.String[i]
		if lexerIsWhitespace(ch) || lexerTokens[ch] != 0 ||
			ch == lexerEscape || ch < 32 {
			return true
		}
	}
	return len(s.String) == 0
}

func printString(w io.Writer, s *V) bool {
	if s.Type != VTypeString {
		return false
	}
	if !printStringNeedsQuoting(s) {
		_, _ = w.Write([]byte(s.String))
		return true
	}

	_, _ = w.Write([]byte{lexerStringQuote})
	for i := 0; i < len(s.String); i++ {
		ch := s.String[i]
		if ch < 32 {
			_, _ = fmt.Fprintf(w, "\\x%02x", ch)
		} else if ch == lexerEscape || ch == lexerStringQuote {
			_, _ = fmt.Fprintf(w, "\\%c", ch)
		} else {
			_, _ = w.Write([]byte{ch})
		}
	}
	_, _ = w.Write([]byte{lexerStringQuote})
	return true
}

func printBlock(w io.Writer, list *V) bool {
	if len(list.List) < 1 || list.List[0].String != "block" {
		return false
	}

	sublist := list.List[1:]
	for _, subsub := range sublist {
		if subsub.Type != VTypeList {
			return false
		}
	}

	_, _ = w.Write([]byte{'{'})
	if len(sublist) > 0 {
		_, _ = w.Write([]byte{' '})
		PrintSeq(w, sublist[0].List)
		for _, subsub := range sublist[1:] {
			_, _ = w.Write([]byte("; "))
			PrintSeq(w, subsub.List)
		}
		_, _ = w.Write([]byte{' '})
	}
	_, _ = w.Write([]byte{'}'})
	return true
}

func printSet(w io.Writer, list *V) bool {
	if len(list.List) != 2 || list.List[0].String != "set" {
		return false
	}

	_, _ = w.Write([]byte{'@'})
	PrintSeq(w, list.List[1:])
	return true
}

func printList(w io.Writer, list *V) bool {
	if len(list.List) < 1 || list.List[0].String != "list" {
		return false
	}
	_, _ = w.Write([]byte{'['})
	PrintSeq(w, list.List[1:])
	_, _ = w.Write([]byte{']'})
	return true
}

// PrintV serializes a value to the given writer, ignoring I/O errors.
func PrintV(w io.Writer, v *V) {
	if printString(w, v) ||
		printBlock(w, v) ||
		printSet(w, v) ||
		printList(w, v) {
		return
	}

	_, _ = w.Write([]byte{'('})
	PrintSeq(w, v.List)
	_, _ = w.Write([]byte{')'})
}

// PrintSeq serializes a sequence of values to the given writer.
func PrintSeq(w io.Writer, seq []V) {
	if len(seq) > 0 {
		PrintV(w, &seq[0])
		for _, v := range seq[1:] {
			_, _ = w.Write([]byte{' '})
			PrintV(w, &v)
		}
	}
}

// --- Parsing -----------------------------------------------------------------

// Parser is a context for parsing.
type Parser struct {
	lexer        *lexer // tokenizer
	token        token  // current token in the lexer
	replaceToken bool   // replace the token
}

// NewParser returns a new parser for the give byte slice.
func NewParser(script []byte) *Parser {
	// As reading in tokens may cause exceptions, we wait for the first peek
	// to replace the initial ELLT_ABORT.
	return &Parser{
		lexer:        newLexer(script),
		replaceToken: true,
	}
}

func (p *Parser) peek() token {
	if p.replaceToken {
		token, err := p.lexer.next()
		if err != nil {
			panic(p.lexer.errorf("%s", err))
		}
		p.token = token
		p.replaceToken = false
	}
	return p.token
}

func (p *Parser) accept(token token) bool {
	p.replaceToken = p.peek() == token
	return p.replaceToken
}

func (p *Parser) expect(token token) {
	if !p.accept(token) {
		panic(p.lexer.errorf("unexpected `%s', expected `%s'", p.token, token))
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

func (p *Parser) skipNL() {
	for p.accept(tNewline) {
	}
}

func parsePrefixList(seq []V, name string) *V {
	return NewList(append([]V{*NewString(name)}, seq...))
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

func (p *Parser) parseV() *V {
	p.skipNL()

	var seq []V
	switch {
	case p.accept(tString):
		return NewString(string(p.lexer.buf))
	case p.accept(tAt):
		seq = []V{*p.parseV()}
		return parsePrefixList(seq, "set")
	case p.accept(tLParen):
		for !p.accept(tRParen) {
			seq = append(seq, *p.parseV())
			p.skipNL()
		}
		return NewList(seq)
	case p.accept(tLBracket):
		for !p.accept(tRBracket) {
			seq = append(seq, *p.parseV())
			p.skipNL()
		}
		return parsePrefixList(seq, "list")
	case p.accept(tLBrace):
		for {
			result := p.parseLine()
			if result == nil {
				break
			}
			seq = append(seq, *result)
		}
		p.expect(tRBrace)
		return parsePrefixList(seq, "block")
	}
	panic(p.lexer.errorf("unexpected `%s', expected a value", p.token))
}

func (p *Parser) parseLine() *V {
	var seq []V
	for p.peek() != tRBrace && p.peek() != tAbort {
		if !p.accept(tNewline) {
			seq = append(seq, *p.parseV())
		} else if len(seq) > 0 {
			return NewList(seq)
		}
	}
	if len(seq) > 0 {
		return NewList(seq)
	}
	return nil
}

// Run runs the parser and returns a value to be interpreted or an error.
func (p *Parser) Run() (seq []V, err error) {
	// "The convention in the Go libraries is that even when a package
	// uses panic internally, its external API still presents explicit
	// error return values." We're good.
	defer func() {
		if r := recover(); r != nil {
			seq, err = nil, r.(error)
		}
	}()

	for {
		result := p.parseLine()
		if result == nil {
			break
		}
		seq = append(seq, *result)
	}
	p.expect(tAbort)
	return seq, nil
}

// --- Runtime -----------------------------------------------------------------

// Handler is a Go handler for an Ell function.
type Handler func(ell *Ell, args []V) (result []V, ok bool)

// Ell is an interpreter context.
type Ell struct {
	Globals map[string]V       // list of global variables
	scopes  []map[string]V     // dynamic scopes from the oldest
	Native  map[string]Handler // maps strings to Go functions

	Error string // error information
}

// New returns a new interpreter context ready for program execution.
func New() *Ell {
	return &Ell{
		Globals: make(map[string]V),
		Native:  make(map[string]Handler),
	}
}

func scopeFind(scope []*V, name string) int {
	for i, scope := range scope {
		if scope.List[0].String == name {
			return i
		}
	}
	return -1
}

// Get retrieves a value by name from the scope or from global variables.
func (ell *Ell) Get(name string) *V {
	for i := len(ell.scopes) - 1; i >= 0; i-- {
		if v, ok := ell.scopes[i][name]; ok {
			return &v
		}
	}
	if v, ok := ell.Globals[name]; ok {
		return &v
	}
	return nil
}

// Set sets a value by name in the scope or in global variables.
func (ell *Ell) Set(name string, v *V) {
	for i := len(ell.scopes) - 1; i >= 0; i-- {
		if _, ok := ell.scopes[i][name]; ok {
			ell.scopes[i][name] = *v
			return
		}
	}

	// Variables only get deleted by "arg" or from the global scope.
	ell.Globals[name] = *v
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Errorf sets an error message in the interpreter context and returns an empty
// sequence and false.
func (ell *Ell) Errorf(format string, args ...interface{}) ([]V, bool) {
	ell.Error = fmt.Sprintf(format, args...)
	return nil, false
}

func (ell *Ell) canModifyError() bool {
	// Errors starting with an underscore are exceptions and would not work
	// with stack traces generated this way.
	return ell.Error == "" || ell.Error[0] != '_'
}

func (ell *Ell) evalArgs(args []V) (result []V, ok bool) {
	for i, arg := range args {
		evaluated, ok := ell.evalStatement(&arg)
		if !ok {
			// Once the code flows like this, at least make some use of it.
			if ell.canModifyError() {
				ell.Errorf("(argument %d) -> %s", i, ell.Error)
			}
			return nil, false
		}
		// Arguments should not evaporate, default to a nil value.
		if len(evaluated) < 1 {
			evaluated = []V{*NewList(nil)}
		}
		result = append(result, evaluated[0])
	}
	return result, true
}

func (ell *Ell) evalNative(name string, args []V) (result []V, ok bool) {
	fn := ell.Native[name]
	if fn == nil {
		return ell.Errorf("unknown function")
	}
	if arguments, ok := ell.evalArgs(args); ok {
		return fn(ell, arguments)
	}
	return nil, false
}

func (ell *Ell) evalResolved(body *V, args []V) (result []V, ok bool) {
	// Resolving names recursively could be pretty fatal, let's not do that.
	if body.Type == VTypeString {
		return []V{*body}, true
	}
	if arguments, ok := ell.evalArgs(args); ok {
		return ell.EvalBlock(body.List, arguments)
	}
	return nil, false
}

func (ell *Ell) evalValue(body []V) (result []V, ok bool) {
	args := body[1:]
	if body[0].Type == VTypeString {
		name := body[0].String
		if name == "block" {
			if len(args) > 0 {
				result = []V{*NewList(CloneSeq(args))}
			}
			return result, true
		}
		if body := ell.Get(name); body != nil {
			return ell.evalResolved(body, args)
		}
		return ell.evalNative(name, args)
	}

	// When someone tries to call a block directly, we must evaluate it;
	// e.g. something like `{ choose [@f1 @f2 @f3] } arg1 arg2 arg3`.
	if evaluated, ok := ell.evalStatement(&body[0]); !ok {
		return nil, false
	} else if len(evaluated) > 0 {
		return ell.evalResolved(&evaluated[0], args)
	}

	// It might a bit confusing that this doesn't evaluate arguments
	// but neither does "block" and there's nothing to do here.
	return nil, true
}

func (ell *Ell) evalStatement(statement *V) (result []V, ok bool) {
	if statement.Type == VTypeString {
		return []V{*statement}, true
	}

	// Executing a nil value results in no value. It's not very different from
	// calling a block that returns no value--it's for our callers to resolve.
	if len(statement.List) < 1 {
		return nil, true
	}
	if result, ok = ell.evalValue(statement.List); ok {
		return
	}

	name := "(block)"
	if statement.List[0].Type == VTypeString {
		name = statement.List[0].String
	}

	if ell.canModifyError() {
		ell.Errorf("%s -> %s", name, ell.Error)
	}
	return nil, false
}

func argsToScope(args []V) map[string]V {
	scope := map[string]V{"args": *NewList(args)}
	for i, arg := range args {
		scope[fmt.Sprintf("%d", i+1)] = *arg.Clone()
	}
	return scope
}

// EvalBlock executes a block and returns whatever the last statement returned,
// eats args.
func (ell *Ell) EvalBlock(body []V, args []V) (result []V, ok bool) {
	ell.scopes = append(ell.scopes, argsToScope(args))

	ok = true
	for _, stmt := range body {
		if result, ok = ell.evalStatement(&stmt); !ok {
			break
		}
	}
	ell.scopes = ell.scopes[:len(ell.scopes)-1]
	return result, ok
}

// --- Standard library --------------------------------------------------------

// EvalAny evaluates any value and appends to the result.
func EvalAny(ell *Ell, body *V, arg *V) (result []V, ok bool) {
	if body.Type == VTypeString {
		return []V{*body}, true
	}
	var args []V
	if arg != nil {
		args = append(args, *arg.Clone())
	}
	if res, ok := ell.EvalBlock(body.List, args); ok {
		return res, true
	}
	return nil, false
}

// NewNumber creates a new string value containing a number.
func NewNumber(n float64) *V {
	s := fmt.Sprintf("%f", n)
	i := len(s)
	for i > 0 && s[i-1] == '0' {
		i--
	}
	if s[i-1] == '.' {
		i--
	}
	return NewString(s[:i])
}

// Truthy decides whether any value is logically true.
func Truthy(v *V) bool {
	return v != nil && (len(v.List) > 0 || len(v.String) > 0)
}

// NewBoolean creates a new string value copying the boolean's truthiness.
func NewBoolean(b bool) *V {
	if b {
		return NewString("1")
	}
	return NewString("")
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

func fnLocal(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) == 0 || args[0].Type != VTypeList {
		return ell.Errorf("first argument must be a list")
	}

	// Duplicates or non-strings don't really matter to us, user's problem.
	scope := ell.scopes[len(ell.scopes)-1]

	values := args[1:]
	for _, name := range args[0].List {
		if len(values) > 0 {
			scope[name.String] = *values[0].Clone()
			values = values[1:]
		}
	}
	return nil, true
}

func fnSet(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) == 0 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	if len(args) > 1 {
		result = []V{*args[1].Clone()}
		ell.Set(args[0].String, &result[0])
		return result, true
	}

	// We return an empty list for a nil value.
	if v := ell.Get(args[0].String); v != nil {
		result = []V{*v.Clone()}
	} else {
		result = []V{*NewList(nil)}
	}
	return result, true
}

func fnList(ell *Ell, args []V) (result []V, ok bool) {
	return []V{*NewList(args)}, true
}

func fnValues(ell *Ell, args []V) (result []V, ok bool) {
	return args, true
}

func fnIf(ell *Ell, args []V) (result []V, ok bool) {
	var cond, body, keyword int
	for cond = 0; ; cond = keyword + 1 {
		if cond >= len(args) {
			return ell.Errorf("missing condition")
		}
		if body = cond + 1; body >= len(args) {
			return ell.Errorf("missing body")
		}

		var res []V
		if res, ok = EvalAny(ell, &args[cond], nil); !ok {
			return nil, false
		}
		if len(res) > 0 && Truthy(&res[0]) {
			return EvalAny(ell, &args[body], nil)
		}

		if keyword = body + 1; keyword >= len(args) {
			break
		}
		if args[keyword].Type != VTypeString {
			return ell.Errorf("expected keyword, got list")
		}

		switch kw := args[keyword].String; kw {
		case "else":
			if body = keyword + 1; body >= len(args) {
				return ell.Errorf("missing body")
			}
			return EvalAny(ell, &args[body], nil)
		case "elif":
		default:
			return ell.Errorf("invalid keyword: %s", kw)
		}
	}
	return nil, true
}

func fnMap(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 {
		return ell.Errorf("first argument must be a function")
	}
	if len(args) < 2 || args[0].Type != VTypeList {
		return ell.Errorf("second argument must be a list")
	}

	body, values := &args[0], &args[1]
	for _, v := range values.List {
		res, ok := EvalAny(ell, body, &v)
		if !ok {
			return nil, false
		}
		result = append(result, res...)
	}
	return []V{*NewList(result)}, true
}

func fnPrint(ell *Ell, args []V) (result []V, ok bool) {
	for _, arg := range args {
		if arg.Type != VTypeString {
			PrintV(os.Stdout, &arg)
		} else if _, err := os.Stdout.WriteString(arg.String); err != nil {
			return ell.Errorf("write failed: %s", err)
		}
	}
	return nil, true
}

func fnCat(ell *Ell, args []V) (result []V, ok bool) {
	buf := bytes.NewBuffer(nil)
	for _, arg := range args {
		if arg.Type != VTypeString {
			PrintV(buf, &arg)
		} else {
			buf.WriteString(arg.String)
		}
	}
	return []V{*NewString(buf.String())}, true
}

func fnSystem(ell *Ell, args []V) (result []V, ok bool) {
	var argv []string
	for _, arg := range args {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		argv = append(argv, arg.String)
	}
	if len(argv) == 0 {
		return ell.Errorf("command name required")
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Approximation of system(3) return value to match C ell at least a bit.
	if err := cmd.Run(); err == nil {
		return []V{*NewNumber(0)}, true
	} else if _, ok := err.(*exec.Error); ok {
		return ell.Errorf("%s", err)
	} else {
		return []V{*NewNumber(1)}, true
	}
}

func fnParse(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	res, err := NewParser([]byte(args[0].String)).Run()
	if err != nil {
		return ell.Errorf("%s", err)
	}
	return []V{*NewList(res)}, true
}

func fnTry(ell *Ell, args []V) (result []V, ok bool) {
	var body, handler *V
	if len(args) < 1 {
		return ell.Errorf("first argument must be a function")
	}
	if len(args) < 2 {
		return ell.Errorf("second argument must be a function")
	}
	body, handler = &args[0], &args[1]
	if result, ok = EvalAny(ell, body, nil); ok {
		return
	}

	msg := NewString(ell.Error)
	ell.Error = ""
	return EvalAny(ell, handler, msg)
}

func fnThrow(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	return ell.Errorf("%s", args[0].String)
}

func fnPlus(ell *Ell, args []V) (result []V, ok bool) {
	res := 0.
	for _, arg := range args {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var value float64
		if n, _ := fmt.Sscan(arg.String, &value); n < 1 {
			return ell.Errorf("invalid number: %s", arg.String)
		}
		res += value
	}
	return []V{*NewNumber(res)}, true
}

func fnMinus(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	var res float64
	if n, _ := fmt.Sscan(args[0].String, &res); n < 1 {
		return ell.Errorf("invalid number: %f", args[0].String)
	}
	if len(args) == 1 {
		res = -res
	}

	for _, arg := range args[1:] {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var value float64
		if n, _ := fmt.Sscan(arg.String, &value); n < 1 {
			return ell.Errorf("invalid number: %f", arg.String)
		}
		res -= value
	}
	return []V{*NewNumber(res)}, true
}

func fnMultiply(ell *Ell, args []V) (result []V, ok bool) {
	res := 1.
	for _, arg := range args {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var value float64
		if n, _ := fmt.Sscan(arg.String, &value); n < 1 {
			return ell.Errorf("invalid number: %s", arg.String)
		}
		res *= value
	}
	return []V{*NewNumber(res)}, true
}

func fnDivide(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	var res float64
	if n, _ := fmt.Sscan(args[0].String, &res); n < 1 {
		return ell.Errorf("invalid number: %f", args[0].String)
	}
	for _, arg := range args[1:] {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var value float64
		if n, _ := fmt.Sscan(arg.String, &value); n < 1 {
			return ell.Errorf("invalid number: %f", arg.String)
		}
		res /= value
	}
	return []V{*NewNumber(res)}, true
}

func fnNot(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 {
		return ell.Errorf("missing argument")
	}
	return []V{*NewBoolean(!Truthy(&args[0]))}, true
}

func fnAnd(ell *Ell, args []V) (result []V, ok bool) {
	if args == nil {
		return []V{*NewBoolean(true)}, true
	}
	for _, arg := range args {
		result, ok = EvalAny(ell, &arg, nil)
		if !ok {
			return nil, false
		}
		if len(result) < 1 || !Truthy(&result[0]) {
			return []V{*NewBoolean(false)}, true
		}
	}
	return result, true
}

func fnOr(ell *Ell, args []V) (result []V, ok bool) {
	for _, arg := range args {
		result, ok = EvalAny(ell, &arg, nil)
		if !ok {
			return nil, false
		}
		if len(result) > 0 && Truthy(&result[0]) {
			return result, true
		}
	}
	return []V{*NewBoolean(false)}, true
}

func fnEq(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	etalon, res := args[0].String, true
	for _, arg := range args[1:] {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if res = etalon == arg.String; !res {
			break
		}
	}
	return []V{*NewBoolean(res)}, true
}

func fnLt(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	etalon, res := args[0].String, true
	for _, arg := range args[1:] {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if res = etalon < arg.String; !res {
			break
		}
		etalon = arg.String
	}
	return []V{*NewBoolean(res)}, true
}

func fnEquals(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	var first, second float64
	if n, _ := fmt.Sscan(args[0].String, &first); n < 1 {
		return ell.Errorf("invalid number: %f", args[0].String)
	}
	res := true
	for _, arg := range args[1:] {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if n, _ := fmt.Sscan(arg.String, &second); n < 1 {
			return ell.Errorf("invalid number: %f", arg.String)
		}
		if res = first == second; !res {
			break
		}
		first = second
	}
	return []V{*NewBoolean(res)}, true
}

func fnLess(ell *Ell, args []V) (result []V, ok bool) {
	if len(args) < 1 || args[0].Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	var first, second float64
	if n, _ := fmt.Sscan(args[0].String, &first); n < 1 {
		return ell.Errorf("invalid number: %f", args[0].String)
	}
	res := true
	for _, arg := range args[1:] {
		if arg.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if n, _ := fmt.Sscan(arg.String, &second); n < 1 {
			return ell.Errorf("invalid number: %f", arg.String)
		}
		if res = first < second; !res {
			break
		}
		first = second
	}
	return []V{*NewBoolean(res)}, true
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

var stdNative = map[string]Handler{
	"local":  fnLocal,
	"set":    fnSet,
	"list":   fnList,
	"values": fnValues,
	"if":     fnIf,
	"map":    fnMap,
	"print":  fnPrint,
	"..":     fnCat,
	"system": fnSystem,
	"parse":  fnParse,
	"try":    fnTry,
	"throw":  fnThrow,
	"+":      fnPlus,
	"-":      fnMinus,
	"*":      fnMultiply,
	"/":      fnDivide,
	"not":    fnNot,
	"and":    fnAnd,
	"or":     fnOr,
	"eq?":    fnEq,
	"lt?":    fnLt,
	"=":      fnEquals,
	"<":      fnLess,
}

var stdComposed = `
set unless { if (not (@1)) @2 }
set filter { local [_body _list] @1 @2;
 map { if (@_body @1) { @1 } } @_list }
set for { local [_list _body] @1 @2;
 try { map { @_body @1 } @_list } { if (ne? @1 _break) { throw @1 } } }

set break { throw _break }

# TODO: we should be able to apply them to all arguments
set ne? { not (eq? @1 @2) }; set le? { ge? @2 @1 }
set ge? { not (lt? @1 @2) }; set gt? { lt? @2 @1 }
set <>  { not (= @1 @2)   }; set <=  { >= @2 @1  }
set >=  { not (< @1 @2)   }; set >   { <  @2 @1  }`

// StdInitialize initializes the ell standard library.
func StdInitialize(ell *Ell) bool {
	for name, handler := range stdNative {
		ell.Native[name] = handler
	}

	p := NewParser([]byte(stdComposed))
	program, err := p.Run()
	if err != nil {
		return false
	}

	_, ok := ell.EvalBlock(program, nil)
	return ok
}
