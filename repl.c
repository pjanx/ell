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

static void
run (struct ell *ell, struct ell_v *program) {
	struct ell_v *result = NULL;
	(void) ell_eval_block (ell, program, NULL, &result);
	ell_free_seq (program);

	const char *failure = ell->error;
	if (ell->memory_failure)
		failure = "memory allocation failure";
	if (failure) {
		printf ("\x1b[31m%s: %s\x1b[0m\n", "runtime error", failure);
		free (ell->error);
		ell->error = NULL;
		ell->memory_failure = false;
	} else {
		ell_print_seq (&ell_stdout_printer, result);
		putchar ('\n');
		ell_free_seq (result);
	}
}

static int
init_readline (void) {
	rl_variable_bind ("blink-matching-paren", "on");
	rl_bind_key (TAB, rl_named_function ("possible-completions"));
	return 0;
}

static struct ell ell;

static char **
complete (const char *text, int start, int end) {
	(void) start;
	(void) end;

	// Don't iterate over filenames and stuff
	rl_attempted_completion_over = true;

	static char *buf[128];
	size_t n = 1, len = strlen (text);
	for (struct ell_v *v = ell.globals; v; v = v->next)
		if (n < 127 && !strncmp (v->head->string, text, len))
			buf[n++] = ell_format ("%s", v->head->string);
	for (struct ell_native_fn *iter = ell.native; iter; iter = iter->next)
		if (n < 127 && !strncmp (iter->name, text, len))
			buf[n++] = ell_format ("%s", iter->name);
	if (n < 2)
		return NULL;

	// This never actually completes anything, just shows the options,
	// we'd have to figure out the longest common prefix
	buf[0] = ell_format ("%s", text);

	buf[n++] = NULL;
	char **copy = malloc (sizeof *buf * n);
	memcpy (copy, buf, sizeof *buf * n);
	return copy;
}

int
main (int argc, char *argv[]) {
	(void) argc;

	ell_init (&ell);
	if (!ell_std_initialize (&ell))
		printf ("%s\n", "runtime library initialization failed");

	using_history ();
	const char *slash = strrchr (argv[0], '/');
	rl_readline_name = slash ? ++slash : argv[0];
	rl_startup_hook = init_readline;
	rl_attempted_completion_function = complete;

	char *line;
	while ((line = readline ("> "))) {
		struct ell_parser p;
		ell_parser_init (&p, line, strlen (line));
		add_history (line);

		const char *e = NULL;
		struct ell_v *program = ell_parser_run (&p, &e);
		free (line);
		if (e)
			printf ("\x1b[31m%s: %s\x1b[0m\n", "parse error", e);
		else
			run (&ell, program);
		ell_parser_free (&p);
	}

	putchar ('\n');
	ell_free (&ell);
	return 0;
}
