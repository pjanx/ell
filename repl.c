/*
 * repl.c: test REPL
 *
 * Copyright (c) 2017, Přemysl Janouch <p.janouch@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include "ell.c"
#include <readline/readline.h>
#include <readline/history.h>

int
main (int argc, char *argv[]) {
	(void) argc;

	struct context ctx;
	context_init (&ctx);
	if (!init_runtime_library (&ctx))
		printf ("%s\n", "runtime library initialization failed");

	using_history ();
	const char *slash = strrchr (argv[0], '/');
	rl_readline_name = slash ? ++slash : argv[0];

	char *line;
	while ((line = readline ("> "))) {
		struct parser parser;
		parser_init (&parser, line, strlen (line));
		add_history (line);

		const char *e = NULL;
		struct item *program = parser_run (&parser, &e);
		free (line);
		if (e) {
			printf ("\x1b[31m%s: %s\x1b[0m\n", "parse error", e);
			parser_free (&parser);
			continue;
		}
		parser_free (&parser);

		struct item *result = NULL;
		(void) execute (&ctx, program, &result);
		item_free_list (program);

		const char *failure = ctx.error;
		if (ctx.memory_failure)
			failure = "memory allocation failure";
		if (failure) {
			printf ("\x1b[31m%s: %s\x1b[0m\n", "runtime error", failure);
			free (ctx.error);
			ctx.error = NULL;
			ctx.memory_failure = false;
		} else {
			print_tree (result, 0);
			putchar ('\n');
			item_free_list (result);
		}
	}
	context_free (&ctx);
	return 0;
}
