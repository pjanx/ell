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

// Program repl is an interactive ell interpreter.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	// This library is rather simplistic but it's going to serve us fine.
	"github.com/peterh/liner"

	"janouch.name/ell/ell"
)

func run(L *ell.Ell, program *ell.V) {
	var result *ell.V
	if !L.EvalBlock(program, nil, &result) {
		fmt.Printf("\x1b[31m%s: %s\x1b[0m\n", "runtime error", L.Error)
		L.Error = ""
	} else {
		ell.PrintSeq(os.Stdout, result)
		os.Stdout.WriteString("\n")
	}
}

func complete(L *ell.Ell, line string) (res []string) {
	// This never actually completes anything, just shows the options,
	// we'd have to figure out the longest common prefix.
	res = append(res, line)

	line = strings.ToLower(line)
	for v := L.Globals; v != nil; v = v.Next {
		name := v.Head.String
		if strings.HasPrefix(strings.ToLower(name), line) {
			res = append(res, name)
		}
	}
	for name := range L.Native {
		if strings.HasPrefix(strings.ToLower(name), line) {
			res = append(res, name)
		}
	}
	return
}

func main() {
	L := ell.New()
	if !ell.StdInitialize(L) {
		fmt.Printf("runtime library initialization failed: %s\n", L.Error)
	}

	line := liner.NewLiner()
	line.SetCompleter(func(line string) []string { return complete(L, line) })
	line.SetMultiLineMode(true)
	line.SetTabCompletionStyle(liner.TabPrints)

	for {
		script, err := line.Prompt("> ")
		if err == nil {
			line.AppendHistory(script)

			p := ell.NewParser([]byte(script))
			if program, err := p.Run(); err != nil {
				fmt.Printf("\x1b[31m%s: %s\x1b[0m\n", "parse error", err)
			} else {
				run(L, program)
			}
		} else if err == liner.ErrPromptAborted || err == io.EOF {
			break
		} else {
			fmt.Printf("\x1b[31m%s: %s\x1b[0m\n", "error", err)
		}
	}
	os.Stdout.WriteString("\n")
}
