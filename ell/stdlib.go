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

package ell

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

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
