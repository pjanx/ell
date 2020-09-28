/*
 * ell.c: an experimental little language
 *
 * Copyright (c) 2017, Přemysl Eric Janouch <p@janouch.name>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <setjmp.h>

#if defined __GNUC__
#define ELL_ATTRIBUTE_PRINTF(x, y) __attribute__ ((format (printf, x, y)))
#else // ! __GNUC__
#define ELL_ATTRIBUTE_PRINTF(x, y)
#endif // ! __GNUC__

#define ELL_N_ELEMENTS(a) (sizeof (a) / sizeof ((a)[0]))

// --- Utilities ---------------------------------------------------------------

static char *ell_format (const char *format, ...) ELL_ATTRIBUTE_PRINTF (1, 2);

static char *
ell_vformat (const char *format, va_list ap) {
	va_list aq;
	va_copy (aq, ap);
	int size = vsnprintf (NULL, 0, format, aq);
	va_end (aq);
	if (size < 0)
		return NULL;

	char *buf = malloc (size + 1);
	if (buf && vsnprintf (buf, size + 1, format, ap) < 0) {
		free (buf);
		return NULL;
	}
	return buf;
}

static char *
ell_format (const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	char *result = ell_vformat (format, ap);
	va_end (ap);
	return result;
}

// --- Generic buffer ----------------------------------------------------------

struct ell_buffer {
	char *s;                            ///< Buffer data
	size_t alloc, len;                  ///< Number of bytes allocated and used
	bool memory_failure;                ///< Memory allocation failed
};

static struct ell_buffer
ell_buffer_make (void) {
	return (struct ell_buffer) { NULL, 0, 0, false };
}

static bool
ell_buffer_append (struct ell_buffer *self, const void *s, size_t n) {
	if (self->memory_failure)
		return false;

	if (!self->s)
		self->s = malloc (self->alloc = 8);
	while (self->len + n > self->alloc)
		self->s = realloc (self->s, self->alloc <<= 1);

	if (!self->s) {
		self->memory_failure = true;
		return false;
	}

	memcpy (self->s + self->len, s, n);
	self->len += n;
	return true;
}

inline static bool
ell_buffer_append_c (struct ell_buffer *self, char c) {
	return ell_buffer_append (self, &c, 1);
}

// --- Values ------------------------------------------------------------------

enum ell_v_type { ELL_STRING, ELL_LIST };

struct ell_v {
	enum ell_v_type type;               ///< The type of this value
	struct ell_v *next;                 ///< Next value in sequence

	struct ell_v *head;                 ///< The head of the list
	size_t len;                         ///< Length of "string" (sans '\0')
	char string[];                      ///< The null-terminated string value
};

static void ell_free_seq (struct ell_v *);
static struct ell_v *ell_clone_seq (const struct ell_v *);

static void
ell_free_v (struct ell_v *v) {
	ell_free_seq (v->head);
	free (v);
}

static void
ell_free_seq (struct ell_v *v) {
	while (v) {
		struct ell_v *link = v;
		v = v->next;
		ell_free_v (link);
	}
}

static struct ell_v *
ell_clone (const struct ell_v *v) {
	size_t size = sizeof *v + v->len + 1;
	struct ell_v *clone = malloc (size);
	if (!clone)
		return NULL;

	memcpy (clone, v, size);
	if (clone->head && !(clone->head = ell_clone_seq (clone->head))) {
		free (clone);
		return NULL;
	}
	clone->next = NULL;
	return clone;
}

static struct ell_v *
ell_clone_seq (const struct ell_v *v) {
	struct ell_v *head = NULL;
	for (struct ell_v **out = &head; v; v = v->next) {
		if (!(*out = ell_clone (v))) {
			ell_free_seq (head);
			return NULL;
		}
		out = &(*out)->next;
	}
	return head;
}

static struct ell_v *
ell_string (const char *s, size_t len) {
	struct ell_v *v = calloc (1, sizeof *v + len + 1);
	if (!v)
		return NULL;

	v->type = ELL_STRING;
	v->len = len;
	memcpy (v->string, s, len);
	return v;
}

static struct ell_v *
ell_list (struct ell_v *head) {
	struct ell_v *v = calloc (1, sizeof *v + 1);
	if (!v) {
		ell_free_seq (head);
		return NULL;
	}

	v->type = ELL_LIST;
	v->head = head;
	return v;
}

// --- Lexer -------------------------------------------------------------------

enum ell_token { ELLT_ABORT,  ELLT_LPAREN, ELLT_RPAREN,
	ELLT_LBRACKET, ELLT_RBRACKET, ELLT_LBRACE, ELLT_RBRACE,
	ELLT_STRING, ELLT_NEWLINE, ELLT_AT };

static const char *ell_token_names[] = {
	[ELLT_ABORT]    = "end of input",
	[ELLT_LPAREN]   = "left parenthesis",
	[ELLT_RPAREN]   = "right parenthesis",
	[ELLT_LBRACKET] = "left bracket",
	[ELLT_RBRACKET] = "right bracket",
	[ELLT_LBRACE]   = "left brace",
	[ELLT_RBRACE]   = "right brace",
	[ELLT_STRING]   = "string",
	[ELLT_NEWLINE]  = "newline",
	[ELLT_AT]       = "at symbol",
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct ell_lexer {
	const unsigned char *p;             ///< Current position in input
	size_t len;                         ///< How many bytes of input are left
	unsigned line, column;              ///< Current line and column
	struct ell_buffer string;           ///< Parsed string value
};

static struct ell_lexer
ell_lexer_make (const char *p, size_t len) {
	return (struct ell_lexer) { .p = (const unsigned char *) p, .len = len };
}

static void
ell_lexer_free (struct ell_lexer *self) {
	free (self->string.s);
}

static int
ell_lexer_advance (struct ell_lexer *self) {
	int c = *self->p++;
	if (c == '\n') {
		self->column = 0;
		self->line++;
	} else
		self->column++;

	self->len--;
	return c;
}

static bool
ell_lexer_hexa_escape (struct ell_lexer *self, struct ell_buffer *output) {
	const char *abc = "0123456789abcdef", *h, *l;
	if (!self->len || !(h = strchr (abc, tolower (ell_lexer_advance (self))))
	 || !self->len || !(l = strchr (abc, tolower (ell_lexer_advance (self)))))
		return false;

	ell_buffer_append_c (output, (h - abc) << 4 | (l - abc));
	return true;
}

enum {
	ELL_LEXER_STRING_QUOTE = '\'',
	ELL_LEXER_ESCAPE = '\\',
	ELL_LEXER_COMMENT = '#'
};

static bool ell_lexer_is_whitespace (int c) {
	return !c || c == ' ' || c == '\t' || c == '\r';
}

static unsigned char ell_lexer_escapes[256] = {
	[ELL_LEXER_STRING_QUOTE] = ELL_LEXER_STRING_QUOTE,
	[ELL_LEXER_ESCAPE] = ELL_LEXER_ESCAPE,
	['a'] = '\a', ['b'] = '\b', ['n'] = '\n', ['r'] = '\r', ['t'] = '\t',
};

static const char *
ell_lexer_escape_sequence (struct ell_lexer *self, struct ell_buffer *output) {
	if (!self->len)
		return "premature end of escape sequence";

	int c = ell_lexer_advance (self);
	if (c == 'x') {
		if (ell_lexer_hexa_escape (self, output))
			return NULL;
		return "invalid hexadecimal escape";
	}
	if (!(c = ell_lexer_escapes[c]))
		return "unknown escape sequence";

	ell_buffer_append_c (output, c);
	return NULL;
}

static const char *
ell_lexer_string (struct ell_lexer *self, struct ell_buffer *output) {
	int c;
	const char *e = NULL;
	while (self->len) {
		if ((c = ell_lexer_advance (self)) == ELL_LEXER_STRING_QUOTE)
			return NULL;
		if (c != ELL_LEXER_ESCAPE)
			ell_buffer_append_c (output, c);
		else if ((e = ell_lexer_escape_sequence (self, output)))
			return e;
	}
	return "premature end of string";
}

static enum ell_token ell_lexer_tokens[256] = {
	['('] = ELLT_LPAREN,   [')'] = ELLT_RPAREN,
	['['] = ELLT_LBRACKET, [']'] = ELLT_RBRACKET,
	['{'] = ELLT_LBRACE,   ['}'] = ELLT_RBRACE,
	[';'] = ELLT_NEWLINE, ['\n'] = ELLT_NEWLINE,
	['@'] = ELLT_AT, [ELL_LEXER_STRING_QUOTE] = ELLT_STRING,
};

static enum ell_token
ell_lexer_next (struct ell_lexer *self, const char **e) {
	while (self->len && ell_lexer_is_whitespace (*self->p))
		ell_lexer_advance (self);
	if (!self->len)
		return ELLT_ABORT;

	free (self->string.s);
	self->string = ell_buffer_make ();

	int c = ell_lexer_advance (self);
	if (c == ELL_LEXER_COMMENT) {
		while (self->len)
			if (ell_lexer_advance (self) == '\n')
				return ELLT_NEWLINE;
		return ELLT_ABORT;
	}

	enum ell_token token = ell_lexer_tokens[c];
	if (!token) {
		ell_buffer_append_c (&self->string, c);
		while (self->len && !ell_lexer_is_whitespace (*self->p)
			&& !ell_lexer_tokens[*self->p])
			ell_buffer_append_c (&self->string, ell_lexer_advance (self));
		return ELLT_STRING;
	}
	if (token == ELLT_STRING
	 && (*e = ell_lexer_string (self, &self->string)))
		return ELLT_ABORT;
	return token;
}

static char *ell_lexer_errorf (struct ell_lexer *self, const char *fmt, ...)
	ELL_ATTRIBUTE_PRINTF (2, 3);

static char *
ell_lexer_errorf (struct ell_lexer *self, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *description = ell_vformat (fmt, ap);
	va_end (ap);

	if (!description)
		return NULL;

	char *e = ell_format ("at or before line %u, column %u: %s",
		self->line + 1, self->column + 1, description);
	free (description);
	return e;
}

// --- Printing ----------------------------------------------------------------

// This can be wrapped inside a larger structure, and errors simply accumulated
struct ell_printer {
	void (*putchar) (struct ell_printer *self, unsigned char c);
};

static void ell_print_seq (struct ell_printer *printer, struct ell_v *v);

static bool
ell_print_string_needs_quoting (struct ell_v *s) {
	for (size_t i = 0; i < s->len; i++) {
		unsigned char c = s->string[i];
		if (ell_lexer_is_whitespace (c) || ell_lexer_tokens[c]
		 || c == ELL_LEXER_ESCAPE || c < 32)
			return true;
	}
	return s->len == 0;
}

static bool
ell_print_string (struct ell_printer *printer, struct ell_v *s) {
	if (s->type != ELL_STRING)
		return false;
	if (!ell_print_string_needs_quoting (s)) {
		for (size_t i = 0; i < s->len; i++)
			printer->putchar (printer, s->string[i]);
		return true;
	}

	printer->putchar (printer, ELL_LEXER_STRING_QUOTE);
	for (size_t i = 0; i < s->len; i++) {
		unsigned char c = s->string[i];
		if (c < 32) {
			printer->putchar (printer, '\\');
			printer->putchar (printer, 'x');
			printer->putchar (printer, "0123456789abcdef"[c >> 4]);
			printer->putchar (printer, "0123456789abcdef"[c & 15]);
		} else if (c == ELL_LEXER_ESCAPE || c == ELL_LEXER_STRING_QUOTE) {
			printer->putchar (printer, '\\');
			printer->putchar (printer, c);
		} else
			printer->putchar (printer, c);
	}
	printer->putchar (printer, ELL_LEXER_STRING_QUOTE);
	return true;
}

static bool
ell_print_block (struct ell_printer *printer, struct ell_v *list) {
	if (!list->head || strcmp (list->head->string, "block"))
		return false;

	list = list->head->next;
	for (struct ell_v *line = list; line; line = line->next)
		if (line->type != ELL_LIST)
			return false;

	printer->putchar (printer, '{');
	for (struct ell_v *line = list; line; line = line->next) {
		printer->putchar (printer, ' ');
		ell_print_seq (printer, line->head);
		printer->putchar (printer, line->next ? ';' : ' ');
	}
	printer->putchar (printer, '}');
	return true;
}

static bool
ell_print_set (struct ell_printer *printer, struct ell_v *list) {
	if (!list->head || strcmp (list->head->string, "set")
	 || !list->head->next || list->head->next->next)
		return false;

	printer->putchar (printer, '@');
	ell_print_seq (printer, list->head->next);
	return true;
}

static bool
ell_print_list (struct ell_printer *printer, struct ell_v *list) {
	if (!list->head || strcmp (list->head->string, "list"))
		return false;

	printer->putchar (printer, '[');
	ell_print_seq (printer, list->head->next);
	printer->putchar (printer, ']');
	return true;
}

static void
ell_print_v (struct ell_printer *printer, struct ell_v *v) {
	if (ell_print_string (printer, v)
	 || ell_print_block (printer, v)
	 || ell_print_set (printer, v)
	 || ell_print_list (printer, v))
		return;

	printer->putchar (printer, '(');
	ell_print_seq (printer, v->head);
	printer->putchar (printer, ')');
}

static void
ell_print_seq (struct ell_printer *printer, struct ell_v *v) {
	for (; v; v = v->next) {
		ell_print_v (printer, v);
		if (v->next)
			printer->putchar (printer, ' ');
	}
}

// --- Parsing -----------------------------------------------------------------

struct ell_parser {
	struct ell_lexer lexer;             ///< Tokenizer
	char *error;                        ///< Tokenizer error
	enum ell_token token;               ///< Current token in the lexer
	bool replace_token;                 ///< Replace the token
	bool memory_failure;                ///< Memory allocation failed
};

static struct ell_parser
ell_parser_make (const char *script, size_t len) {
	// As reading in tokens may cause exceptions, we wait for the first peek()
	// to replace the initial ELLT_ABORT.
	return (struct ell_parser) {
		.lexer = ell_lexer_make (script, len),
		.replace_token = true,
	};
}

static void
ell_parser_free (struct ell_parser *p) {
	ell_lexer_free (&p->lexer);
	if (p->error)
		free (p->error);
}

static enum ell_token
ell_parser_peek (struct ell_parser *p, jmp_buf out) {
	if (p->replace_token) {
		const char *e = NULL;
		p->token = ell_lexer_next (&p->lexer, &e);
		if (e) {
			p->memory_failure =
				!(p->error = ell_lexer_errorf (&p->lexer, "%s", e));
			longjmp (out, 1);
		}
		if (p->token == ELLT_STRING && p->lexer.string.memory_failure)
			longjmp (out, 1);
		p->replace_token = false;
	}
	return p->token;
}

static bool
ell_parser_accept (struct ell_parser *p, enum ell_token token, jmp_buf out) {
	return p->replace_token = (ell_parser_peek (p, out) == token);
}

static void
ell_parser_expect (struct ell_parser *p, enum ell_token token, jmp_buf out) {
	if (ell_parser_accept (p, token, out))
		return;

	p->memory_failure = !(p->error = ell_lexer_errorf (&p->lexer,
		"unexpected `%s', expected `%s'",
		ell_token_names[p->token], ell_token_names[token]));
	longjmp (out, 1);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// We don't need no generator, but a few macros will come in handy.
// From time to time C just doesn't have the right features.

#define PEEK()         ell_parser_peek   (p, err)
#define ACCEPT(token)  ell_parser_accept (p, token, err)
#define EXPECT(token)  ell_parser_expect (p, token, err)
#define SKIP_NL()      do {} while (ACCEPT (ELLT_NEWLINE))

static struct ell_v *
ell_parser_check (struct ell_parser *p, struct ell_v *v, jmp_buf out) {
	if (!v) {
		p->memory_failure = true;
		longjmp (out, 1);
	}
	return v;
}

// Beware that this jumps to the "out" buffer directly
#define CHECK(v)       ell_parser_check (p, (v), out)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct ell_v *
ell_parse_prefix_list (struct ell_v *seq, const char *name) {
	struct ell_v *prefix;
	if (!(prefix = ell_string (name, strlen (name)))) {
		ell_free_seq (seq);
		return NULL;
	}
	prefix->next = seq;
	return ell_list (prefix);
}

static struct ell_v * ell_parse_line (struct ell_parser *p, jmp_buf out);

static struct ell_v *
ell_parse_v (struct ell_parser *p, jmp_buf out) {
	jmp_buf err;
	struct ell_v *volatile result = NULL, *volatile *tail = &result;
	if (setjmp (err)) {
		ell_free_seq (result);
		longjmp (out, 1);
	}

	SKIP_NL ();
	if (ACCEPT (ELLT_STRING))
		return CHECK (ell_string
			(p->lexer.string.s, p->lexer.string.len));
	if (ACCEPT (ELLT_AT)) {
		result = ell_parse_v (p, out);
		return CHECK (ell_parse_prefix_list (result, "set"));
	}
	if (ACCEPT (ELLT_LPAREN)) {
		while (!ACCEPT (ELLT_RPAREN)) {
			tail = &(*tail = ell_parse_v (p, err))->next;
			SKIP_NL ();
		}
		return CHECK (ell_list (result));
	}
	if (ACCEPT (ELLT_LBRACKET)) {
		while (!ACCEPT (ELLT_RBRACKET)) {
			tail = &(*tail = ell_parse_v (p, err))->next;
			SKIP_NL ();
		}
		return CHECK (ell_parse_prefix_list (result, "list"));
	}
	if (ACCEPT (ELLT_LBRACE)) {
		while ((*tail = ell_parse_line (p, err)))
			tail = &(*tail)->next;
		EXPECT (ELLT_RBRACE);
		return CHECK (ell_parse_prefix_list (result, "block"));
	}

	p->memory_failure = !(p->error = ell_lexer_errorf (&p->lexer,
		"unexpected `%s', expected a value", ell_token_names[p->token]));
	longjmp (out, 1);
}

static struct ell_v *
ell_parse_line (struct ell_parser *p, jmp_buf out) {
	jmp_buf err;
	struct ell_v *volatile result = NULL, *volatile *tail = &result;
	if (setjmp (err)) {
		ell_free_seq (result);
		longjmp (out, 1);
	}

	while (PEEK () != ELLT_RBRACE && PEEK () != ELLT_ABORT) {
		if (!ACCEPT (ELLT_NEWLINE)) {
			tail = &(*tail = ell_parse_v (p, err))->next;
		} else if (result) {
			return CHECK (ell_list (result));
		}
	}
	if (result)
		return CHECK (ell_list (result));
	return NULL;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#undef PEEK
#undef ACCEPT
#undef EXPECT
#undef SKIP_NL
#undef CHECK

static struct ell_v *
ell_parser_run (struct ell_parser *p, const char **e) {
	jmp_buf err;
	struct ell_v *volatile result = NULL, *volatile *tail = &result;
	if (setjmp (err)) {
		ell_free_seq (result);
		*e = p->error;
		if (p->memory_failure || p->lexer.string.memory_failure)
			*e = "memory allocation failure";
		return NULL;
	}

	while ((*tail = ell_parse_line (p, err)))
		tail = &(*tail)->next;
	ell_parser_expect (p, ELLT_ABORT, err);
	return result;
}

// --- Runtime -----------------------------------------------------------------

struct ell {
	struct ell_v *globals;              ///< List of global variables
	struct ell_v *scopes;               ///< Dynamic scopes from newest
	struct ell_native_fn *native;       ///< Maps strings to C functions

	char *error;                        ///< Error information
	bool memory_failure;                ///< Memory allocation failure
	void *user_data;                    ///< User data
};

typedef bool (*EllHandler) (struct ell *, struct ell_v *, struct ell_v **);

struct ell_native_fn {
	struct ell_native_fn *next;         ///< The next link in the chain
	EllHandler handler;                 ///< Internal C handler, or NULL
	char name[];                        ///< The name of the function
};

static struct ell ell_make (void) { return (struct ell) {}; }

static void
ell_free (struct ell *ell) {
	struct ell_native_fn *next, *iter;
	for (iter = ell->native; iter; iter = next) {
		next = iter->next;
		free (iter);
	}
	ell_free_seq (ell->globals);
	ell_free_seq (ell->scopes);
	free (ell->error);
}

static bool
ell_check (struct ell *ell, struct ell_v *v) {
	return !(ell->memory_failure |= !v);
}

static struct ell_v **
ell_scope_find (struct ell_v **scope, const char *name) {
	for (; *scope; scope = &(*scope)->next)
		if (!strcmp ((*scope)->head->string, name))
			return scope;
	return NULL;
}

static bool
ell_scope_prepend (struct ell *ell, struct ell_v **scope, const char *name,
	struct ell_v *v) {
	struct ell_v *key, *pair;
	if (!ell_check (ell, (key = ell_string (name, strlen (name))))
	 || !ell_check (ell, (pair = ell_list (key)))) {
		ell_free_seq (v);
		return false;
	}
	key->next = v;
	pair->next = *scope;
	*scope = pair;
	return true;
}

static struct ell_v *
ell_get (struct ell *ell, const char *name) {
	struct ell_v **place;
	for (struct ell_v *scope = ell->scopes; scope; scope = scope->next)
		if ((place = ell_scope_find (&scope->head, name)))
			return (*place)->head->next;
	if (!(place = ell_scope_find (&ell->globals, name)))
		return NULL;
	return (*place)->head->next;
}

static bool
ell_set (struct ell *ell, const char *name, struct ell_v *v) {
	struct ell_v **place;
	for (struct ell_v *scope = ell->scopes; scope; scope = scope->next) {
		if ((place = ell_scope_find (&scope->head, name))) {
			ell_free_seq ((*place)->head->next);
			(*place)->head->next = v;
			return true;
		}
	}

	// Variables only get deleted by "arg" or from the global scope
	if ((place = ell_scope_find (&ell->globals, name))) {
		struct ell_v *tmp = *place;
		*place = (*place)->next;
		ell_free_v (tmp);
	}
	return !v || ell_scope_prepend (ell, &ell->globals, name, v);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct ell_native_fn *
ell_native_find (struct ell *ell, const char *name) {
	for (struct ell_native_fn *fn = ell->native; fn; fn = fn->next)
		if (!strcmp (fn->name, name))
			return fn;
	return NULL;
}

static bool
ell_native_register (struct ell *ell, const char *name, EllHandler handler) {
	struct ell_native_fn *fn = ell_native_find (ell, name);
	if (!fn) {
		if (!(fn = calloc (1, sizeof *fn + strlen (name) + 1)))
			return false;
		strcpy (fn->name, name);
		fn->next = ell->native;
		ell->native = fn;
	}
	fn->handler = handler;
	return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
ell_error (struct ell *ell, const char *ell_format, ...) {
	va_list ap;
	va_start (ap, ell_format);
	free (ell->error);
	if (!(ell->error = ell_vformat (ell_format, ap)))
		ell->memory_failure = true;
	va_end (ap);
	return false;
}

static bool
ell_can_modify_error (struct ell *ell) {
	// In that case, `error' is NULL and there's nothing else to do anyway.
	// Errors starting with an underscore are exceptions and would not work
	// with stack traces generated this way.
	return !ell->memory_failure && ell->error[0] != '_';
}

static bool ell_eval_statement
	(struct ell *, const struct ell_v *, struct ell_v **);
static bool ell_eval_block
	(struct ell *, const struct ell_v *, struct ell_v *, struct ell_v **);

static bool
ell_eval_args (struct ell *ell,
	const struct ell_v *args, struct ell_v **result) {
	size_t i = 0;
	struct ell_v *res = NULL, **out = &res;
	for (; args; args = args->next) {
		struct ell_v *evaluated = NULL;
		// Arguments should not evaporate, default to a nil value
		if (!ell_eval_statement (ell, args, &evaluated)
		 || (!evaluated && !ell_check (ell, (evaluated = ell_list (NULL)))))
			goto error;
		ell_free_seq (evaluated->next);
		evaluated->next = NULL;
		out = &(*out = evaluated)->next;
		i++;
	}
	*result = res;
	return true;

error:
	// Once the code flows like this, at least make some use of it
	if (ell_can_modify_error (ell)) {
		char *tmp = ell->error;
		ell->error = NULL;
		ell_error (ell, "(argument %zu) -> %s", i, tmp);
		free (tmp);
	}
	ell_free_seq (res);
	return false;
}

static bool
ell_eval_native (struct ell *ell, const char *name, const struct ell_v *args,
	struct ell_v **result) {
	struct ell_native_fn *fn = ell_native_find (ell, name);
	if (!fn)
		return ell_error (ell, "unknown function");

	struct ell_v *arguments = NULL;
	if (!ell_eval_args (ell, args, &arguments))
		return false;

	bool ok = fn->handler (ell, arguments, result);
	ell_free_seq (arguments);
	return ok;
}

static bool
ell_eval_resolved (struct ell *ell,
	const struct ell_v *body, const struct ell_v *args, struct ell_v **result) {
	// Resolving names recursively could be pretty fatal, let's not do that
	if (body->type == ELL_STRING)
		return ell_check (ell, (*result = ell_clone (body)));
	struct ell_v *arguments = NULL;
	return ell_eval_args (ell, args, &arguments)
		&& ell_eval_block (ell, body->head, arguments, result);
}

static bool
ell_eval_value (struct ell *ell, const struct ell_v *body,
	struct ell_v **result) {
	const struct ell_v *args = body->next;
	if (body->type == ELL_STRING) {
		const char *name = body->string;
		if (!strcmp (name, "block")) {
			struct ell_v *cloned = NULL;
			return (!args || ell_check (ell, (cloned = ell_clone_seq (args))))
				&& ell_check (ell, (*result = ell_list (cloned)));
		}
		if ((body = ell_get (ell, name)))
			return ell_eval_resolved (ell, body, args, result);
		return ell_eval_native (ell, name, args, result);
	}

	// When someone tries to call a block directly, we must evaluate it;
	// e.g. something like `{ choose [@f1 @f2 @f3] } arg1 arg2 arg3`.
	struct ell_v *evaluated = NULL;
	if (!ell_eval_statement (ell, body, &evaluated))
		return false;

	// It might a bit confusing that this doesn't evaluate arguments
	// but neither does "block" and there's nothing to do here
	if (!evaluated)
		return true;

	bool ok = ell_eval_resolved (ell, evaluated, args, result);
	ell_free_seq (evaluated);
	return ok;
}

static bool
ell_eval_statement
	(struct ell *ell, const struct ell_v *statement, struct ell_v **result) {
	if (statement->type == ELL_STRING)
		return ell_check (ell, (*result = ell_clone (statement)));

	// Executing a nil value results in no value.  It's not very different from
	// calling a block that returns no value--it's for our callers to resolve.
	if (!statement->head
	 || ell_eval_value (ell, statement->head, result))
		return true;

	ell_free_seq (*result);
	*result = NULL;

	const char *name = "(block)";
	if (statement->head->type == ELL_STRING)
		name = statement->head->string;

	if (ell_can_modify_error (ell)) {
		char *tmp = ell->error;
		ell->error = NULL;
		ell_error (ell, "%s -> %s", name, tmp);
		free (tmp);
	}
	return false;
}

static bool
args_to_scope (struct ell *ell, struct ell_v *args, struct ell_v **scope) {
	if (!ell_check (ell, (args = ell_list (args)))
	 || !ell_scope_prepend (ell, scope, "args", args))
		return false;

	size_t i = 0;
	for (args = args->head; args; args = args->next) {
		char buf[16] = "";
		(void) snprintf (buf, sizeof buf, "%zu", ++i);
		struct ell_v *copy = NULL;
		if ((args && !ell_check (ell, (copy = ell_clone (args))))
		 || !ell_scope_prepend (ell, scope, buf, copy))
			return false;
	}
	return ell_check (ell, (*scope = ell_list (*scope)));
}

/// Execute a block and return whatever the last statement returned, eats args
static bool
ell_eval_block (struct ell *ell, const struct ell_v *body, struct ell_v *args,
	struct ell_v **result) {
	struct ell_v *scope = NULL;
	if (!args_to_scope (ell, args, &scope)) {
		ell_free_seq (scope);
		return false;
	}

	scope->next = ell->scopes;
	ell->scopes = scope;

	bool ok = true;
	for (; body; body = body->next) {
		ell_free_seq (*result);
		*result = NULL;

		if (!(ok = ell_eval_statement (ell, body, result)))
			break;
	}
	ell->scopes = scope->next;
	ell_free_v (scope);
	return ok;
}

// --- Standard library --------------------------------------------------------

#define ell_defn(name) static bool name \
	(struct ell *ell, struct ell_v *args, struct ell_v **result)

static bool
ell_eval_any (struct ell *ell,
	const struct ell_v *body, const struct ell_v *arg, struct ell_v **result) {
	if (body->type == ELL_STRING)
		return ell_check (ell, (*result = ell_clone (body)));
	struct ell_v *cloned_arg = NULL;
	if (arg && !ell_check (ell, (cloned_arg = ell_clone (arg))))
		return false;
	return ell_eval_block (ell, body->head, cloned_arg, result);
}

static struct ell_v *
ell_number (double n) {
	char *s;
	if (!(s = ell_format ("%f", n)))
		return NULL;

	char *p = strchr (s, 0);
	while (--p > s && *p == '0')
		*p = 0;
	if (*p == '.')
		*p = 0;

	struct ell_v *v = ell_string (s, strlen (s));
	free (s);
	return v;
}

static bool ell_truthy (struct ell_v *v) { return v && (v->head || v->len); }
static struct ell_v *ell_boolean (bool b) { return ell_string ("1", b); }

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
ell_stdout_printer_putchar (struct ell_printer *self, unsigned char c) {
	(void) self;
	(void) putchar (c);
}

static struct ell_printer ell_stdout_printer = { ell_stdout_printer_putchar };

struct ell_buffer_printer {
	struct ell_printer super;           ///< Superclass
	struct ell_buffer *output;          ///< Where to append the result to
};

static void
ell_buffer_printer_putchar (struct ell_printer *printer, unsigned char c) {
	struct ell_buffer_printer *self = (struct ell_buffer_printer *) printer;
	ell_buffer_append_c (self->output, c);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

ell_defn (ell_fn_local) {
	struct ell_v *names = args;
	if (!names || names->type != ELL_LIST)
		return ell_error (ell, "first argument must be a list");

	// Duplicates or non-strings don't really matter to us, user's problem
	struct ell_v **scope = &ell->scopes->head;
	(void) result;

	struct ell_v *values = names->next;
	for (names = names->head; names; names = names->next) {
		struct ell_v *value = NULL;
		if ((values && !ell_check (ell, (value = ell_clone (values))))
		 || !ell_scope_prepend (ell, scope, names->string, value))
			return false;
		if (values)
			values = values->next;
	}
	return true;
}

ell_defn (ell_fn_set) {
	struct ell_v *name = args;
	if (!name || name->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");

	struct ell_v *v;
	if ((v = name->next))
		return ell_check (ell, (v = ell_clone (v)))
			&& ell_check (ell, (*result = ell_clone (v)))
			&& ell_set (ell, name->string, v);

	// We return an empty list for a nil value
	if (!(v = ell_get (ell, name->string)))
		return ell_check (ell, (*result = ell_list (NULL)));
	return ell_check (ell, (*result = ell_clone (v)));
}

ell_defn (ell_fn_list) {
	struct ell_v *values = NULL;
	if (args && !ell_check (ell, (values = ell_clone_seq (args))))
		return false;
	return ell_check (ell, (*result = ell_list (values)));
}

ell_defn (ell_fn_values) {
	return !args || ell_check (ell, (*result = ell_clone_seq (args)));
}

ell_defn (ell_fn_if) {
	struct ell_v *cond, *body, *keyword;
	for (cond = args; ; cond = keyword->next) {
		if (!cond)
			return ell_error (ell, "missing condition");
		if (!(body = cond->next))
			return ell_error (ell, "missing body");

		struct ell_v *res = NULL;
		if (!ell_eval_any (ell, cond, NULL, &res))
			return false;
		bool match = ell_truthy (res);
		ell_free_seq (res);
		if (match)
			return ell_eval_any (ell, body, NULL, result);

		if (!(keyword = body->next))
			break;
		if (keyword->type != ELL_STRING)
			return ell_error (ell, "expected keyword, got list");

		if (!strcmp (keyword->string, "else")) {
			if (!(body = keyword->next))
				return ell_error (ell, "missing body");
			return ell_eval_any (ell, body, NULL, result);
		}
		if (strcmp (keyword->string, "elif"))
			return ell_error (ell, "invalid keyword: %s", keyword->string);
	}
	return true;
}

ell_defn (ell_fn_map) {
	struct ell_v *body, *values;
	if (!(body = args))
		return ell_error (ell, "first argument must be a function");
	if (!(values = body->next) || values->type != ELL_LIST)
		return ell_error (ell, "second argument must be a list");

	struct ell_v *res = NULL, **out = &res;
	for (struct ell_v *v = values->head; v; v = v->next) {
		if (!ell_eval_any (ell, body, v, out)) {
			ell_free_seq (res);
			return false;
		}
		while (*out)
			out = &(*out)->next;
	}
	return ell_check (ell, (*result = ell_list (res)));
}

ell_defn (ell_fn_print) {
	(void) result;
	for (; args; args = args->next) {
		if (args->type != ELL_STRING)
			ell_print_v (&ell_stdout_printer, args);
		else if (fwrite (args->string, 1, args->len, stdout) != args->len)
			return ell_error (ell, "write failed: %s", strerror (errno));
	}
	return true;
}

ell_defn (ell_fn_cat) {
	struct ell_buffer buf = ell_buffer_make ();
	struct ell_buffer_printer bp = { { ell_buffer_printer_putchar }, &buf };
	for (; args; args = args->next) {
		if (args->type != ELL_STRING)
			ell_print_v (&bp.super, args);
		else
			ell_buffer_append (&buf, args->string, args->len);
	}
	bool ok = !(ell->memory_failure |= buf.memory_failure)
		&& ell_check (ell, (*result = ell_string (buf.s, buf.len)));
	free (buf.s);
	return ok;
}

ell_defn (ell_fn_system) {
	struct ell_v *command = args;
	if (!command || command->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	if (command->next)
		return ell_error (ell, "cannot deal with multiple arguments");
	return ell_check (ell, (*result = ell_number (system (command->string))));
}

ell_defn (ell_fn_parse) {
	struct ell_v *body = args;
	if (!body || body->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");

	struct ell_parser p = ell_parser_make (args->string, args->len);
	const char *e = NULL;
	bool ok = ell_check (ell, (*result = ell_list (ell_parser_run (&p, &e))));
	if (e)
		ok = ell_error (ell, "%s", e);
	ell_parser_free (&p);
	return ok;
}

ell_defn (ell_fn_try) {
	struct ell_v *body, *handler;
	if (!(body = args))
		return ell_error (ell, "first argument must be a function");
	if (!(handler = body->next))
		return ell_error (ell, "second argument must be a function");
	if (ell_eval_any (ell, body, NULL, result))
		return true;

	struct ell_v *msg;
	if (ell->memory_failure
	 || !ell_check (ell, (msg = ell_string (ell->error, strlen (ell->error)))))
		return false;

	free (ell->error); ell->error = NULL;
	ell_free_seq (*result); *result = NULL;

	bool ok = ell_eval_any (ell, handler, msg, result);
	ell_free_v (msg);
	return ok;
}

ell_defn (ell_fn_throw) {
	(void) result;

	struct ell_v *message = args;
	if (!message || message->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	return ell_error (ell, "%s", message->string);
}

ell_defn (ell_fn_plus) {
	double res = 0.0;
	for (; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		res += strtod (args->string, NULL);
	}
	return ell_check (ell, (*result = ell_number (res)));
}

ell_defn (ell_fn_minus) {
	if (!args || args->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	double res = strtod (args->string, NULL);
	if (!(args = args->next))
		res = -res;

	for (; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		res -= strtod (args->string, NULL);
	}
	return ell_check (ell, (*result = ell_number (res)));
}

ell_defn (ell_fn_multiply) {
	double res = 1.0;
	for (; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		res *= strtod (args->string, NULL);
	}
	return ell_check (ell, (*result = ell_number (res)));
}

ell_defn (ell_fn_divide) {
	if (!args || args->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	double res = strtod (args->string, NULL), x;
	for (args = args->next; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		if (!(x = strtod (args->string, NULL)))
			return ell_error (ell, "division by zero");
		res /= x;
	}
	return ell_check (ell, (*result = ell_number (res)));
}

ell_defn (ell_fn_not) {
	if (!args)
		return ell_error (ell, "missing argument");
	return ell_check (ell, (*result = ell_boolean (!ell_truthy (args))));
}

ell_defn (ell_fn_and) {
	if (!args)
		return ell_check (ell, (*result = ell_boolean (true)));
	for (; args; args = args->next) {
		ell_free_seq (*result);
		*result = NULL;

		if (!ell_eval_any (ell, args, NULL, result))
			return false;
		if (!ell_truthy (*result))
			return ell_check (ell, (*result = ell_boolean (false)));
	}
	return true;
}

ell_defn (ell_fn_or) {
	for (; args; args = args->next) {
		if (!ell_eval_any (ell, args, NULL, result))
			return false;
		if (ell_truthy (*result))
			return true;

		ell_free_seq (*result);
		*result = NULL;
	}
	return ell_check (ell, (*result = ell_boolean (false)));
}

ell_defn (ell_fn_eq) {
	struct ell_v *etalon = args;
	if (!etalon || etalon->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		if (!(res &= !strcmp (etalon->string, args->string)))
			break;
	}
	return ell_check (ell, (*result = ell_boolean (res)));
}

ell_defn (ell_fn_lt) {
	struct ell_v *etalon = args;
	if (!etalon || etalon->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		if (!(res &= strcmp (etalon->string, args->string) < 0))
			break;
		etalon = args;
	}
	return ell_check (ell, (*result = ell_boolean (res)));
}

ell_defn (ell_fn_equals) {
	struct ell_v *etalon = args;
	if (!etalon || etalon->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		if (!(res &= strtod (etalon->string, NULL)
			== strtod (args->string, NULL)))
			break;
	}
	return ell_check (ell, (*result = ell_boolean (res)));
}

ell_defn (ell_fn_less) {
	struct ell_v *etalon = args;
	if (!etalon || etalon->type != ELL_STRING)
		return ell_error (ell, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ELL_STRING)
			return ell_error (ell, "arguments must be strings");
		if (!(res &= strtod (etalon->string, NULL)
			< strtod (args->string, NULL)))
			break;
		etalon = args;
	}
	return ell_check (ell, (*result = ell_boolean (res)));
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct ell_handler_pair {
	const char *name;                   ///< Name of function
	EllHandler handler;                 ///< Handler for the function
} ell_std_native[] = {
	{ "local",     ell_fn_local     },
	{ "set",       ell_fn_set       },
	{ "list",      ell_fn_list      },
	{ "values",    ell_fn_values    },
	{ "if",        ell_fn_if        },
	{ "map",       ell_fn_map       },
	{ "print",     ell_fn_print     },
	{ "..",        ell_fn_cat       },
	{ "system",    ell_fn_system    },
	{ "parse",     ell_fn_parse     },
	{ "try",       ell_fn_try       },
	{ "throw",     ell_fn_throw     },
	{ "+",         ell_fn_plus      },
	{ "-",         ell_fn_minus     },
	{ "*",         ell_fn_multiply  },
	{ "/",         ell_fn_divide    },
	{ "not",       ell_fn_not       },
	{ "and",       ell_fn_and       },
	{ "or",        ell_fn_or        },
	{ "eq?",       ell_fn_eq        },
	{ "lt?",       ell_fn_lt        },
	{ "=",         ell_fn_equals    },
	{ "<",         ell_fn_less      },
};

const char ell_std_composed[] =
	"set unless { if (not (@1)) @2 }\n"
	"set filter { local [_body _list] @1 @2;"
	" map { if (@_body @1) { @1 } } @_list }\n"
	"set for { local [_list _body] @1 @2;"
	" try { map { @_body @1 } @_list } { if (ne? @1 _break) { throw @1 } } }\n"
	"set break { throw _break }\n"

	// TODO: we should be able to apply them to all arguments
	"set ne? { not (eq? @1 @2) }; set le? { ge? @2 @1 }\n"
	"set ge? { not (lt? @1 @2) }; set gt? { lt? @2 @1 }\n"
	"set <>  { not (= @1 @2)   }; set <=  { >= @2 @1  }\n"
	"set >=  { not (< @1 @2)   }; set >   { <  @2 @1  }\n";

static bool
ell_std_initialize (struct ell *ell) {
	for (size_t i = 0; i < ELL_N_ELEMENTS (ell_std_native); i++) {
		struct ell_handler_pair *pair = &ell_std_native[i];
		if (!ell_native_register (ell, pair->name, pair->handler))
			return false;
	}

	struct ell_parser p =
		ell_parser_make (ell_std_composed, sizeof ell_std_composed);

	const char *e = NULL;
	struct ell_v *result = NULL;
	struct ell_v *program = ell_parser_run (&p, &e);
	bool ok = !e && ell_eval_block (ell, program, NULL, &result);
	ell_parser_free (&p);
	ell_free_seq (program);
	ell_free_seq (result);
	return ok;
}
