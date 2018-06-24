/*
 * interpreter.c: test interpreter
 *
 * Copyright (c) 2017, Přemysl Janouch <p@janouch.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
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
	struct ell_buffer buf = ell_buffer_make ();
	while ((c = fgetc (fp)) != EOF)
		ell_buffer_append_c (&buf, c);
	ell_buffer_append_c (&buf, 0);
	fclose (fp);

	struct ell_parser p = ell_parser_make (buf.s, buf.len - 1);
	const char *e = NULL;
	struct ell_v *program = ell_parser_run (&p, &e);
	free (buf.s);
	if (e) {
		printf ("%s: %s\n", "parse error", e);
		return 1;
	}
	ell_parser_free (&p);

	struct ell ell = ell_make ();
	if (!ell_std_initialize (&ell))
		printf ("%s\n", "runtime library initialization failed");

	// In this one place we optimistically expect allocation to succeed
	struct ell_v *args = NULL, **tail = &args;
	for (int i = 2; i < argc; i++)
		tail = &(*tail = ell_string (argv[i], strlen (argv[i])))->next;

	struct ell_v *result = NULL;
	(void) ell_eval_block (&ell, program, args, &result);
	ell_free_seq (result);
	ell_free_seq (program);

	const char *failure = ell.error;
	if (ell.memory_failure)
		failure = "memory allocation failure";
	if (failure)
		printf ("%s: %s\n", "runtime error", failure);
	ell_free (&ell);
	return 0;
}

