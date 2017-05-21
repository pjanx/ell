/*
 * interpreter.c: test interpreter
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

int
main (int argc, char *argv[]) {
	FILE *fp = stdin;
	if (argc > 1 && !(fp = fopen (argv[1], "rb"))) {
		fprintf (stderr, "%s: %s\n", argv[1], strerror (errno));
		return 1;
	}

	int c;
	struct buffer buf = BUFFER_INITIALIZER;
	while ((c = fgetc (fp)) != EOF)
		buffer_append_c (&buf, c);
	buffer_append_c (&buf, 0);
	fclose (fp);

	struct parser parser;
	parser_init (&parser, buf.s, buf.len - 1);
	const char *e = NULL;
	struct item *program = parser_run (&parser, &e);
#ifndef NDEBUG
	printf ("\x1b[1m%s\x1b[0m\n", buf.s);
	print_tree (program, 0);
	printf ("\n\n");
#endif
	free (buf.s);
	if (e) {
		printf ("%s: %s\n", "parse error", e);
		return 1;
	}
	parser_free (&parser);

	struct context ctx;
	context_init (&ctx);
	if (!init_runtime_library (&ctx))
		printf ("%s\n", "runtime library initialization failed");

	struct item *result = NULL;
	(void) execute (&ctx, program, &result);
	item_free_list (result);
	item_free_list (program);

	const char *failure = ctx.error;
	if (ctx.memory_failure)
		failure = "memory allocation failure";
	if (failure)
		printf ("%s: %s\n", "runtime error", failure);
	context_free (&ctx);
	return 0;
}
