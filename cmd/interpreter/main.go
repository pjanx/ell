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

// Program interpreter is a basic ell interpreter.
package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"janouch.name/ell/ell"
)

func main() {
	var script []byte
	var err error

	if len(os.Args) < 2 {
		script, err = ioutil.ReadAll(os.Stdin)
	} else {
		script, err = ioutil.ReadFile(os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	L := ell.New()
	if !ell.StdInitialize(L) {
		fmt.Printf("runtime library initialization failed: %s\n", L.Error)
	}

	program, err := ell.NewParser(script).Run()
	if err != nil {
		fmt.Printf("%s: %s\n", "parse error", err)
		os.Exit(1)
	}

	var args *ell.V
	tail := &args
	for i := 2; i < len(os.Args); i++ {
		*tail = ell.NewString([]byte(os.Args[i]))
		tail = &(*tail).Next
	}

	var result *ell.V
	if !L.EvalBlock(program, args, &result) {
		fmt.Printf("%s: %s\n", "runtime error", L.Error)
	}
}
