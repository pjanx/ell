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
	Next   *V     // next value in sequence
	Head   *V     // the head of a VTypeList
	String string // the immutable contents of a VTypeString
}

// Clone clones a value without following the rest of its chain.
func (v *V) Clone() *V {
	if v == nil {
		return nil
	}
	return &V{
		Type:   v.Type,
		Next:   nil,
		Head:   v.Head.CloneSeq(),
		String: v.String,
	}
}

// CloneSeq clones a value including the rest of its chain.
func (v *V) CloneSeq() *V {
	var head *V
	for out := &head; v != nil; v = v.Next {
		*out = v.Clone()
		out = &(*out).Next
	}
	return head
}

// NewString creates a new value containing a string.
func NewString(string string) *V {
	return &V{
		Type:   VTypeString,
		String: string,
	}
}

// NewList creates a new list value containing the given sequence.
func NewList(head *V) *V {
	return &V{
		Type: VTypeList,
		Head: head,
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
	if list.Head == nil || string(list.Head.String) != "block" {
		return false
	}

	list = list.Head.Next
	for line := list; line != nil; line = line.Next {
		if line.Type != VTypeList {
			return false
		}
	}

	_, _ = w.Write([]byte{'{'})
	for line := list; line != nil; line = line.Next {
		_, _ = w.Write([]byte{' '})
		PrintSeq(w, line.Head)

		if line.Next != nil {
			_, _ = w.Write([]byte{';'})
		} else {
			_, _ = w.Write([]byte{' '})
		}
	}
	_, _ = w.Write([]byte{'}'})
	return true
}

func printSet(w io.Writer, list *V) bool {
	if list.Head == nil || string(list.Head.String) != "set" ||
		list.Head.Next == nil || list.Head.Next.Next != nil {
		return false
	}

	_, _ = w.Write([]byte{'@'})
	PrintSeq(w, list.Head.Next)
	return true
}

func printList(w io.Writer, list *V) bool {
	if list.Head == nil || string(list.Head.String) != "list" {
		return false
	}
	_, _ = w.Write([]byte{'['})
	PrintSeq(w, list.Head.Next)
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
	PrintSeq(w, v.Head)
	_, _ = w.Write([]byte{')'})
}

// PrintSeq serializes a sequence of values to the given writer.
func PrintSeq(w io.Writer, v *V) {
	for ; v != nil; v = v.Next {
		PrintV(w, v)
		if v.Next != nil {
			_, _ = w.Write([]byte{' '})
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

func parsePrefixList(seq *V, name string) *V {
	prefix := NewString(name)
	prefix.Next = seq
	return NewList(prefix)
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

func (p *Parser) parseV() *V {
	var result *V
	tail := &result

	p.skipNL()
	switch {
	case p.accept(tString):
		return NewString(string(p.lexer.buf))
	case p.accept(tAt):
		result = p.parseV()
		return parsePrefixList(result, "set")
	case p.accept(tLParen):
		for !p.accept(tRParen) {
			*tail = p.parseV()
			tail = &(*tail).Next
			p.skipNL()
		}
		return NewList(result)
	case p.accept(tLBracket):
		for !p.accept(tRBracket) {
			*tail = p.parseV()
			tail = &(*tail).Next
			p.skipNL()
		}
		return parsePrefixList(result, "list")
	case p.accept(tLBrace):
		for {
			*tail = p.parseLine()
			if *tail == nil {
				break
			}
			tail = &(*tail).Next
		}
		p.expect(tRBrace)
		return parsePrefixList(result, "block")
	}
	panic(p.lexer.errorf("unexpected `%s', expected a value", p.token))
}

func (p *Parser) parseLine() *V {
	var result *V
	tail := &result

	for p.peek() != tRBrace && p.peek() != tAbort {
		if !p.accept(tNewline) {
			*tail = p.parseV()
			tail = &(*tail).Next
		} else if result != nil {
			return NewList(result)
		}
	}
	if result != nil {
		return NewList(result)
	}
	return nil
}

// Run runs the parser and returns a value to be interpreted or an error.
func (p *Parser) Run() (result *V, err error) {
	// "The convention in the Go libraries is that even when a package
	// uses panic internally, its external API still presents explicit
	// error return values." We're good.
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, r.(error)
		}
	}()

	tail := &result
	for {
		*tail = p.parseLine()
		if *tail == nil {
			break
		}
		tail = &(*tail).Next
	}
	p.expect(tAbort)
	return result, nil
}

// --- Runtime -----------------------------------------------------------------

// Handler is a Go handler for an Ell function.
type Handler func(*Ell, *V, **V) bool

// Ell is an interpreter context.
type Ell struct {
	Globals *V                 // list of global variables
	scopes  *V                 // dynamic scopes from the newest
	Native  map[string]Handler // maps strings to Go functions

	Error string // error information
}

// New returns a new interpreter context ready for program execution.
func New() *Ell {
	return &Ell{
		Native: make(map[string]Handler),
	}
}

func scopeFind(scope **V, name string) **V {
	for ; *scope != nil; scope = &(*scope).Next {
		if string((*scope).Head.String) == name {
			return scope
		}
	}
	return nil
}

func scopePrepend(scope **V, name string, v *V) {
	key := NewString(name)
	pair := NewList(key)

	key.Next = v
	pair.Next = *scope
	*scope = pair
}

// Get retrieves a value by name from the scope or from global variables.
func (ell *Ell) Get(name string) *V {
	var place **V
	for scope := ell.scopes; scope != nil; scope = scope.Next {
		if place = scopeFind(&scope.Head, name); place != nil {
			return (*place).Head.Next
		}
	}
	if place = scopeFind(&ell.Globals, name); place != nil {
		return (*place).Head.Next
	}
	return nil
}

// Set sets a value by name in the scope or in global variables.
func (ell *Ell) Set(name string, v *V) {
	var place **V
	for scope := ell.scopes; scope != nil; scope = scope.Next {
		if place = scopeFind(&scope.Head, name); place != nil {
			(*place).Head.Next = v
			return
		}
	}

	// Variables only get deleted by "arg" or from the global scope.
	if place = scopeFind(&ell.Globals, name); place != nil {
		*place = (*place).Next
	}
	scopePrepend(&ell.Globals, name, v)
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Errorf sets an error message in the interpreter context and returns false.
func (ell *Ell) Errorf(format string, args ...interface{}) bool {
	ell.Error = fmt.Sprintf(format, args...)
	return false
}

func (ell *Ell) canModifyError() bool {
	// Errors starting with an underscore are exceptions and would not work
	// with stack traces generated this way.
	return ell.Error == "" || ell.Error[0] != '_'
}

func (ell *Ell) evalArgs(args *V, result **V) bool {
	var res *V
	out := &res

	i := 0
	for ; args != nil; args = args.Next {
		var evaluated *V
		// Arguments should not evaporate, default to a nil value.
		if !ell.evalStatement(args, &evaluated) {
			goto error
		}
		if evaluated == nil {
			evaluated = NewList(nil)
		}
		evaluated.Next = nil
		*out = evaluated
		out = &(*out).Next
		i++
	}
	*result = res
	return true

error:
	// Once the code flows like this, at least make some use of it.
	if ell.canModifyError() {
		ell.Errorf("(argument %d) -> %s", i, ell.Error)
	}
	return false
}

func (ell *Ell) evalNative(name string, args *V, result **V) bool {
	fn := ell.Native[name]
	if fn == nil {
		return ell.Errorf("unknown function")
	}

	var arguments *V
	if !ell.evalArgs(args, &arguments) {
		return false
	}
	return fn(ell, arguments, result)
}

func (ell *Ell) evalResolved(body *V, args *V, result **V) bool {
	// Resolving names recursively could be pretty fatal, let's not do that.
	if body.Type == VTypeString {
		*result = body.Clone()
		return true
	}
	var arguments *V
	return ell.evalArgs(args, &arguments) &&
		ell.EvalBlock(body.Head, arguments, result)
}

func (ell *Ell) evalValue(body *V, result **V) bool {
	args := body.Next
	if body.Type == VTypeString {
		name := string(body.String)
		if name == "block" {
			if args != nil {
				*result = NewList(args.CloneSeq())
			}
			return true
		}
		if body := ell.Get(name); body != nil {
			return ell.evalResolved(body, args, result)
		}
		return ell.evalNative(name, args, result)
	}

	// When someone tries to call a block directly, we must evaluate it;
	// e.g. something like `{ choose [@f1 @f2 @f3] } arg1 arg2 arg3`.
	var evaluated *V
	if !ell.evalStatement(body, &evaluated) {
		return false
	}

	// It might a bit confusing that this doesn't evaluate arguments
	// but neither does "block" and there's nothing to do here.
	if evaluated == nil {
		return true
	}
	return ell.evalResolved(evaluated, args, result)
}

func (ell *Ell) evalStatement(statement *V, result **V) bool {
	if statement.Type == VTypeString {
		*result = statement.Clone()
		return true
	}

	// Executing a nil value results in no value. It's not very different from
	// calling a block that returns no value--it's for our callers to resolve.
	if statement.Head == nil || ell.evalValue(statement.Head, result) {
		return true
	}

	*result = nil

	name := "(block)"
	if statement.Head.Type == VTypeString {
		name = string(statement.Head.String)
	}

	if ell.canModifyError() {
		ell.Errorf("%s -> %s", name, ell.Error)
	}
	return false
}

func argsToScope(args *V, scope **V) {
	args = NewList(args)
	scopePrepend(scope, "args", args)

	i := 0
	for args = args.Head; args != nil; args = args.Next {
		i++
		scopePrepend(scope, fmt.Sprintf("%d", i), args.Clone())
	}
	*scope = NewList(*scope)
}

// EvalBlock executes a block and returns whatever the last statement returned,
// eats args.
func (ell *Ell) EvalBlock(body *V, args *V, result **V) bool {
	var scope *V
	argsToScope(args, &scope)

	scope.Next = ell.scopes
	ell.scopes = scope

	ok := true
	for ; body != nil; body = body.Next {
		*result = nil
		if ok = ell.evalStatement(body, result); !ok {
			break
		}
	}
	ell.scopes = scope.Next
	return ok
}

// --- Standard library --------------------------------------------------------

// EvalAny evaluates any value.
func EvalAny(ell *Ell, body *V, arg *V, result **V) bool {
	if body.Type == VTypeString {
		*result = body.Clone()
		return true
	}
	return ell.EvalBlock(body.Head, arg.Clone(), result)
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
	return v != nil && (v.Head != nil || len(v.String) > 0)
}

// NewBoolean creates a new string value copying the boolean's truthiness.
func NewBoolean(b bool) *V {
	if b {
		return NewString("1")
	}
	return NewString("")
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

func fnLocal(ell *Ell, args *V, result **V) bool {
	names := args
	if names == nil || names.Type != VTypeList {
		return ell.Errorf("first argument must be a list")
	}

	// Duplicates or non-strings don't really matter to us, user's problem.
	scope := &ell.scopes.Head

	values := names.Next
	for names = names.Head; names != nil; names = names.Next {
		scopePrepend(scope, string(names.String), values.Clone())
		if values != nil {
			values = values.Next
		}
	}
	return true
}

func fnSet(ell *Ell, args *V, result **V) bool {
	name := args
	if name == nil || name.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	v := name.Next
	if v != nil {
		*result = v.Clone()
		ell.Set(string(name.String), v)
		return true
	}

	// We return an empty list for a nil value.
	if v = ell.Get(string(name.String)); v != nil {
		*result = v.Clone()
	} else {
		*result = NewList(nil)
	}
	return true
}

func fnList(ell *Ell, args *V, result **V) bool {
	*result = NewList(args.CloneSeq())
	return true
}

func fnValues(ell *Ell, args *V, result **V) bool {
	*result = args.CloneSeq()
	return true
}

func fnIf(ell *Ell, args *V, result **V) bool {
	var cond, body, keyword *V
	for cond = args; ; cond = keyword.Next {
		if cond == nil {
			return ell.Errorf("missing condition")
		}
		if body = cond.Next; body == nil {
			return ell.Errorf("missing body")
		}

		var res *V
		if !EvalAny(ell, cond, nil, &res) {
			return false
		}
		if Truthy(res) {
			return EvalAny(ell, body, nil, result)
		}

		if keyword = body.Next; keyword == nil {
			break
		}
		if keyword.Type != VTypeString {
			return ell.Errorf("expected keyword, got list")
		}

		switch kw := string(keyword.String); kw {
		case "else":
			if body = keyword.Next; body == nil {
				return ell.Errorf("missing body")
			}
			return EvalAny(ell, body, nil, result)
		case "elif":
		default:
			return ell.Errorf("invalid keyword: %s", kw)
		}
	}
	return true
}

func fnMap(ell *Ell, args *V, result **V) bool {
	var body, values *V
	if body = args; body == nil {
		return ell.Errorf("first argument must be a function")
	}
	if values = body.Next; values == nil || values.Type != VTypeList {
		return ell.Errorf("second argument must be a list")
	}

	var res *V
	out := &res

	for v := values.Head; v != nil; v = v.Next {
		if !EvalAny(ell, body, v, out) {
			return false
		}
		for *out != nil {
			out = &(*out).Next
		}
	}
	*result = NewList(res)
	return true
}

func fnPrint(ell *Ell, args *V, result **V) bool {
	for ; args != nil; args = args.Next {
		if args.Type != VTypeString {
			PrintV(os.Stdout, args)
		} else if _, err := os.Stdout.WriteString(args.String); err != nil {
			return ell.Errorf("write failed: %s", err)
		}
	}
	return true
}

func fnCat(ell *Ell, args *V, result **V) bool {
	buf := bytes.NewBuffer(nil)
	for ; args != nil; args = args.Next {
		if args.Type != VTypeString {
			PrintV(buf, args)
		} else {
			buf.WriteString(args.String)
		}
	}
	*result = NewString(buf.String())
	return true
}

func fnSystem(ell *Ell, args *V, result **V) bool {
	var argv []string
	for ; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		argv = append(argv, string(args.String))
	}
	if len(argv) == 0 {
		return ell.Errorf("command name required")
	}

	cmd := exec.Command(argv[0], argv[1:]...)

	// Approximation of system(3) return value to match C ell at least a bit.
	if err := cmd.Run(); err == nil {
		*result = NewNumber(0)
	} else if _, ok := err.(*exec.Error); ok {
		return ell.Errorf("%s", err)
	} else {
		*result = NewNumber(1)
	}
	return true
}

func fnParse(ell *Ell, args *V, result **V) bool {
	body := args
	if body == nil || body.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	res, err := NewParser([]byte(body.String)).Run()
	if err != nil {
		return ell.Errorf("%s", err)
	}
	*result = NewList(res)
	return true
}

func fnTry(ell *Ell, args *V, result **V) bool {
	var body, handler *V
	if body = args; body == nil {
		return ell.Errorf("first argument must be a function")
	}
	if handler = body.Next; handler == nil {
		return ell.Errorf("second argument must be a function")
	}
	if EvalAny(ell, body, nil, result) {
		return true
	}

	msg := NewString(ell.Error)
	ell.Error = ""
	*result = nil

	return EvalAny(ell, handler, msg, result)
}

func fnThrow(ell *Ell, args *V, result **V) bool {
	message := args
	if message == nil || message.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	return ell.Errorf("%s", message.String)
}

func fnPlus(ell *Ell, args *V, result **V) bool {
	res := 0.
	for ; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var arg float64
		if n, _ := fmt.Sscan(string(args.String), &arg); n < 1 {
			return ell.Errorf("invalid number: %s", args.String)
		}
		res += arg
	}
	*result = NewNumber(res)
	return true
}

func fnMinus(ell *Ell, args *V, result **V) bool {
	if args == nil || args.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	var res float64
	if n, _ := fmt.Sscan(string(args.String), &res); n < 1 {
		return ell.Errorf("invalid number: %f", args.String)
	}
	if args = args.Next; args == nil {
		res = -res
	}

	for ; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var arg float64
		if n, _ := fmt.Sscan(string(args.String), &arg); n < 1 {
			return ell.Errorf("invalid number: %f", args.String)
		}
		res -= arg
	}
	*result = NewNumber(res)
	return true
}

func fnMultiply(ell *Ell, args *V, result **V) bool {
	res := 1.
	for ; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var arg float64
		if n, _ := fmt.Sscan(string(args.String), &arg); n < 1 {
			return ell.Errorf("invalid number: %s", args.String)
		}
		res *= arg
	}
	*result = NewNumber(res)
	return true
}

func fnDivide(ell *Ell, args *V, result **V) bool {
	if args == nil || args.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}

	var res float64
	if n, _ := fmt.Sscan(string(args.String), &res); n < 1 {
		return ell.Errorf("invalid number: %f", args.String)
	}
	for args = args.Next; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		var arg float64
		if n, _ := fmt.Sscan(string(args.String), &arg); n < 1 {
			return ell.Errorf("invalid number: %f", args.String)
		}
		res /= arg
	}
	*result = NewNumber(res)
	return true
}

func fnNot(ell *Ell, args *V, result **V) bool {
	if args == nil {
		return ell.Errorf("missing argument")
	}
	*result = NewBoolean(!Truthy(args))
	return true
}

func fnAnd(ell *Ell, args *V, result **V) bool {
	if args == nil {
		*result = NewBoolean(true)
		return true
	}
	for ; args != nil; args = args.Next {
		*result = nil
		if !EvalAny(ell, args, nil, result) {
			return false
		}
		if !Truthy(*result) {
			*result = NewBoolean(false)
			return true
		}
	}
	return true
}

func fnOr(ell *Ell, args *V, result **V) bool {
	for ; args != nil; args = args.Next {
		if !EvalAny(ell, args, nil, result) {
			return false
		}
		if Truthy(*result) {
			return true
		}
		*result = nil
	}
	*result = NewBoolean(false)
	return true
}

func fnEq(ell *Ell, args *V, result **V) bool {
	etalon := args
	if etalon == nil || etalon.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	res := true
	for args = etalon.Next; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if res = string(etalon.String) == string(args.String); !res {
			break
		}
	}
	*result = NewBoolean(res)
	return true
}

func fnLt(ell *Ell, args *V, result **V) bool {
	etalon := args
	if etalon == nil || etalon.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	res := true
	for args = etalon.Next; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if res = string(etalon.String) < string(args.String); !res {
			break
		}
		etalon = args
	}
	*result = NewBoolean(res)
	return true
}

func fnEquals(ell *Ell, args *V, result **V) bool {
	etalon := args
	if etalon == nil || etalon.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	var first, second float64
	if n, _ := fmt.Sscan(string(etalon.String), &first); n < 1 {
		return ell.Errorf("invalid number: %f", etalon.String)
	}
	res := true
	for args = etalon.Next; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if n, _ := fmt.Sscan(string(args.String), &second); n < 1 {
			return ell.Errorf("invalid number: %f", args.String)
		}
		if res = first == second; !res {
			break
		}
		first = second
	}
	*result = NewBoolean(res)
	return true
}

func fnLess(ell *Ell, args *V, result **V) bool {
	etalon := args
	if etalon == nil || etalon.Type != VTypeString {
		return ell.Errorf("first argument must be string")
	}
	var first, second float64
	if n, _ := fmt.Sscan(string(etalon.String), &first); n < 1 {
		return ell.Errorf("invalid number: %f", etalon.String)
	}
	res := true
	for args = etalon.Next; args != nil; args = args.Next {
		if args.Type != VTypeString {
			return ell.Errorf("arguments must be strings")
		}
		if n, _ := fmt.Sscan(string(args.String), &second); n < 1 {
			return ell.Errorf("invalid number: %f", args.String)
		}
		if res = first < second; !res {
			break
		}
		first = second
	}
	*result = NewBoolean(res)
	return true
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

	var result *V
	return ell.EvalBlock(program, nil, &result)
}
