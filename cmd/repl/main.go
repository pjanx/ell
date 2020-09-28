//
// Copyright (c) 2018, Přemysl Eric Janouch <p@janouch.name>
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

func run(L *ell.Ell, program []ell.V) {
	if result, ok := L.EvalBlock(program, nil); !ok {
		fmt.Printf("\x1b[31m%s: %s\x1b[0m\n", "runtime error", L.Error)
		L.Error = ""
	} else {
		ell.PrintSeq(os.Stdout, result)
		os.Stdout.WriteString("\n")
	}
}

func complete(L *ell.Ell, line string, pos int) (
	head string, completions []string, tail string) {
	tail = string([]rune(line)[pos:])

	lastSpace := strings.LastIndexAny(string([]rune(line)[:pos]), " ()[]{};\n")
	if lastSpace > -1 {
		head, line = line[:lastSpace+1], line[lastSpace+1:]
	}

	for name := range L.Globals {
		if strings.HasPrefix(strings.ToLower(name), line) {
			completions = append(completions, name)
		}
	}
	for name := range L.Native {
		if strings.HasPrefix(strings.ToLower(name), line) {
			completions = append(completions, name)
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
	line.SetWordCompleter(func(line string, pos int) (
		string, []string, string) {
		return complete(L, line, pos)
	})
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
