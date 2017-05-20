/*
 * ell.c: an experimental little language
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

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>
#include <strings.h>
#include <math.h>
#include <setjmp.h>

#if defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__ ((format (printf, x, y)))
#else // ! __GNUC__
#define ATTRIBUTE_PRINTF(x, y)
#endif // ! __GNUC__

#define N_ELEMENTS(a) (sizeof (a) / sizeof ((a)[0]))

// --- Utilities ---------------------------------------------------------------

static char *format (const char *format, ...) ATTRIBUTE_PRINTF (1, 2);

static char *
vformat (const char *format, va_list ap) {
	va_list aq;
	va_copy (aq, ap);
	int size = vsnprintf (NULL, 0, format, aq);
	va_end (aq);
	if (size < 0)
		return NULL;

	char buf[size + 1];
	size = vsnprintf (buf, sizeof buf, format, ap);
	if (size < 0)
		return NULL;

	return strdup (buf);
}

static char *
format (const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	char *result = vformat (format, ap);
	va_end (ap);
	return result;
}

// --- Generic buffer ----------------------------------------------------------

struct buffer {
	char *s;                            ///< Buffer data
	size_t alloc;                       ///< Number of bytes allocated
	size_t len;                         ///< Number of bytes used
	bool memory_failure;                ///< Memory allocation failed
};

#define BUFFER_INITIALIZER { NULL, 0, 0, false }

static bool
buffer_append (struct buffer *self, const void *s, size_t n) {
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
buffer_append_c (struct buffer *self, char c) {
	return buffer_append (self, &c, 1);
}

// --- Data types --------------------------------------------------------------

enum item_type { ITEM_STRING, ITEM_LIST };

struct item {
	enum item_type type;                ///< The type of this object
	struct item *next;                  ///< Next item on the list/stack

	struct item *head;                  ///< The head of the list
	size_t len;                         ///< Length of the string (sans '\0')
	char value[];                       ///< The null-terminated string value
};

const char *
item_type_to_str (enum item_type type) {
	switch (type) {
	case ITEM_STRING: return "string";
	case ITEM_LIST:   return "list";
	}
	abort ();
}

// --- Item management ---------------------------------------------------------

static void item_free_list (struct item *);
static struct item *new_clone_list (const struct item *);

static void
item_free (struct item *item) {
	if (item->type == ITEM_LIST)
		item_free_list (item->head);
	free (item);
}

static void
item_free_list (struct item *item) {
	while (item) {
		struct item *link = item;
		item = item->next;
		item_free (link);
	}
}

static struct item *
new_clone (const struct item *item) {
	size_t size = sizeof *item + 1;
	if (item->type == ITEM_STRING)
		size += item->len;

	struct item *clone = malloc (size);
	if (!clone)
		return NULL;

	memcpy (clone, item, size);
	if (item->type == ITEM_LIST && clone->head) {
		if (!(clone->head = new_clone_list (clone->head))) {
			free (clone);
			return NULL;
		}
	}
	clone->next = NULL;
	return clone;
}

static struct item *
new_clone_list (const struct item *item) {
	struct item *head = NULL;
	for (struct item **out = &head; item; item = item->next) {
		if (!(*out = new_clone (item))) {
			item_free_list (head);
			return NULL;
		}
		out = &(*out)->next;
	}
	return head;
}

static struct item *
new_string (const char *s, ssize_t len) {
	if (len < 0)
		len = strlen (s);

	struct item *item = calloc (1, sizeof *item + len + 1);
	if (!item)
		return NULL;

	item->type = ITEM_STRING;
	item->len = len;
	memcpy (item->value, s, len);
	item->value[len] = '\0';
	return item;
}

static struct item *
new_list (struct item *head) {
	struct item *item = calloc (1, sizeof *item + 1);
	if (!item) {
		item_free_list (head);
		return NULL;
	}

	item->type = ITEM_LIST;
	item->head = head;
	return item;
}

// --- Lexer -------------------------------------------------------------------

enum token { T_ABORT,  T_LPAREN, T_RPAREN, T_LBRACKET, T_RBRACKET,
	T_LBRACE, T_RBRACE, T_STRING, T_NEWLINE, T_AT };

static const char *token_names[] = {
	[T_ABORT]    = "end of input",
	[T_LPAREN]   = "left parenthesis",
	[T_RPAREN]   = "right parenthesis",
	[T_LBRACKET] = "left bracket",
	[T_RBRACKET] = "right bracket",
	[T_LBRACE]   = "left brace",
	[T_RBRACE]   = "right brace",
	[T_STRING]   = "string",
	[T_NEWLINE]  = "newline",
	[T_AT]       = "at symbol",
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct lexer {
	const char *p;                      ///< Current position in input
	size_t len;                         ///< How many bytes of input are left
	unsigned line, column;              ///< Current line and column
	struct buffer string;               ///< Parsed string value
};

/// Input has to be null-terminated anyway
static void
lexer_init (struct lexer *self, const char *p, size_t len) {
	memset (self, 0, sizeof *self);
	self->p = p;
	self->len = len;
}

static void
lexer_free (struct lexer *self) {
	free (self->string.s);
}

static bool lexer_is_ignored (int c) { return strchr (" \t", c); }
static bool lexer_is_word_char (int c) {
	return !lexer_is_ignored (c) && !strchr ("()[]{}\n@#'", c);
}

static int
lexer_advance (struct lexer *self) {
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
lexer_hexa_escape (struct lexer *self, struct buffer *output) {
	int i;
	unsigned char code = 0;

	for (i = 0; self->len && i < 2; i++) {
		unsigned char c = tolower (*self->p);
		if (c >= '0' && c <= '9')
			code = (code << 4) | (c - '0');
		else if (c >= 'a' && c <= 'f')
			code = (code << 4) | (c - 'a' + 10);
		else
			break;

		lexer_advance (self);
	}

	if (!i)
		return false;

	buffer_append_c (output, code);
	return true;
}

static const char *
lexer_escape_sequence (struct lexer *self, struct buffer *output) {
	if (!self->len)
		return "premature end of escape sequence";

	unsigned char c = *self->p;
	switch (c) {
	case '"':              break;
	case '\\':             break;
	case 'a':   c = '\a';  break;
	case 'b':   c = '\b';  break;
	case 'f':   c = '\f';  break;
	case 'n':   c = '\n';  break;
	case 'r':   c = '\r';  break;
	case 't':   c = '\t';  break;
	case 'v':   c = '\v';  break;

	case 'x':
	case 'X':
		lexer_advance (self);
		if (lexer_hexa_escape (self, output))
			return NULL;
		return "invalid hexadecimal escape";

	default:
		return "unknown escape sequence";
	}

	buffer_append_c (output, c);
	lexer_advance (self);
	return NULL;
}

static const char *
lexer_string (struct lexer *self, struct buffer *output) {
	unsigned char c;
	const char *e = NULL;
	while (self->len) {
		if ((c = lexer_advance (self)) == '\'')
			return NULL;
		if (c != '\\')
			buffer_append_c (output, c);
		else if ((e = lexer_escape_sequence (self, output)))
			return e;
	}
	return "premature end of string";
}

static enum token
lexer_next (struct lexer *self, const char **e) {
	// Skip over any whitespace between tokens
	while (self->len && lexer_is_ignored (*self->p))
		lexer_advance (self);
	if (!self->len)
		return T_ABORT;

	free (self->string.s);
	self->string = (struct buffer) BUFFER_INITIALIZER;

	switch (*self->p) {
	case '(':   lexer_advance (self);  return T_LPAREN;
	case ')':   lexer_advance (self);  return T_RPAREN;
	case '[':   lexer_advance (self);  return T_LBRACKET;
	case ']':   lexer_advance (self);  return T_RBRACKET;
	case '{':   lexer_advance (self);  return T_LBRACE;
	case '}':   lexer_advance (self);  return T_RBRACE;
	case '\n':  lexer_advance (self);  return T_NEWLINE;
	case '@':   lexer_advance (self);  return T_AT;

	case '#':
		// Comments go until newline
		while (self->len)
			if (lexer_advance (self) == '\n')
				return T_NEWLINE;
		return T_ABORT;

	case '\'':
		lexer_advance (self);
		if ((*e = lexer_string (self, &self->string)))
			return T_ABORT;
		return T_STRING;
	}

	assert (lexer_is_word_char (*self->p));
	do
		buffer_append_c (&self->string, lexer_advance (self));
	while (lexer_is_word_char (*self->p));
	return T_STRING;
}

static char *lexer_errorf (struct lexer *self, const char *fmt, ...)
	ATTRIBUTE_PRINTF (2, 3);

static char *
lexer_errorf (struct lexer *self, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *description = vformat (fmt, ap);
	va_end (ap);

	if (!description)
		return NULL;

	char *e = format ("near line %u, column %u: %s",
		self->line + 1, self->column + 1, description);
	free (description);
	return e;
}

// --- Parsing -----------------------------------------------------------------

static void
print_string (const char *s) {
	putc ('\'', stdout);
	for (; *s; s++)
		if      (*s == '\n') printf ("\\n");
		else if (*s == '\\') putc ('\\', stdout);
		else                 putc (*s, stdout);
	putc ('\'', stdout);
}

static void
print_tree (struct item *tree, int level) {
	// TODO: also re-add syntax sugar
	for (struct item *iter = tree; iter; iter = iter->next) {
		if (iter != tree)
			printf ("%*s", level, "");
		if (iter->type == ITEM_STRING) {
			print_string (iter->value);
		} else if (iter->head->type == ITEM_STRING
			&& !strcmp (iter->head->value, "list")) {
			printf ("[");
			print_tree (iter->head->next, level + 1);
			printf ("]");
		} else {
			printf ("(");
			print_tree (iter->head, level + 1);
			printf (")");
		}
		if (iter->next)
			printf ("\n");
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct parser {
	struct lexer lexer;                 ///< Tokenizer
	char *error;                        ///< Tokenizer error
	enum token token;                   ///< Current token in the lexer
	bool replace_token;                 ///< Replace the token
	bool memory_failure;                ///< Memory allocation failed
};

static void
parser_init (struct parser *self, const char *script, size_t len) {
	memset (self, 0, sizeof *self);
	lexer_init (&self->lexer, script, len);

	// As reading in tokens may cause exceptions, we wait for the first peek()
	// to replace the initial T_ABORT.
	self->replace_token = true;
}

static void
parser_free (struct parser *self) {
	lexer_free (&self->lexer);
	if (self->error)
		free (self->error);
}

static enum token
parser_peek (struct parser *self, jmp_buf out) {
	if (self->replace_token) {
		const char *e = NULL;
		self->token = lexer_next (&self->lexer, &e);
		if (e) {
			self->memory_failure =
				!(self->error = lexer_errorf (&self->lexer, "%s", e));
			longjmp (out, 1);
		}
		if (self->token == T_STRING && self->lexer.string.memory_failure)
			longjmp (out, 1);
		self->replace_token = false;
	}
	return self->token;
}

static bool
parser_accept (struct parser *self, enum token token, jmp_buf out) {
	return self->replace_token = (parser_peek (self, out) == token);
}

static void
parser_expect (struct parser *self, enum token token, jmp_buf out) {
	if (parser_accept (self, token, out))
		return;

	self->memory_failure = !(self->error = lexer_errorf (&self->lexer,
		"unexpected `%s', expected `%s'",
		token_names[self->token], token_names[token]));
	longjmp (out, 1);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// We don't need no generator, but a few macros will come in handy.
// From time to time C just doesn't have the right features.

#define PEEK()         parser_peek   (self, err)
#define ACCEPT(token)  parser_accept (self, token, err)
#define EXPECT(token)  parser_expect (self, token, err)
#define SKIP_NL()      do {} while (ACCEPT (T_NEWLINE))

static struct item *
parser_check (struct parser *self, struct item *item, jmp_buf out) {
	if (!item) {
		self->memory_failure = true;
		longjmp (out, 1);
	}
	return item;
}

// Beware that this jumps to the "out" buffer directly
#define CHECK(item)    parser_check (self, (item), out)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct item *
parse_prefix_list (struct item *list, const char *name) {
	struct item *prefix;
	if (!(prefix = new_string (name, strlen (name)))) {
		item_free_list (list);
		return NULL;
	}
	prefix->next = list;
	return new_list (prefix);
}

static struct item * parse_line (struct parser *self, jmp_buf out);

static struct item *
parse_item (struct parser *self, jmp_buf out) {
	jmp_buf err;
	struct item *volatile result = NULL, *volatile *tail = &result;
	if (setjmp (err)) {
		item_free_list (result);
		longjmp (out, 1);
	}

	SKIP_NL ();
	if (ACCEPT (T_STRING))
		return CHECK (new_string
			(self->lexer.string.s, self->lexer.string.len));
	if (ACCEPT (T_AT)) {
		result = parse_item (self, out);
		return CHECK (parse_prefix_list (result, "set"));
	}
	if (ACCEPT (T_LPAREN)) {
		while (!ACCEPT (T_RPAREN)) {
			tail = &(*tail = parse_item (self, err))->next;
			SKIP_NL ();
		}
		return CHECK (new_list (result));
	}
	if (ACCEPT (T_LBRACKET)) {
		while (!ACCEPT (T_RBRACKET)) {
			tail = &(*tail = parse_item (self, err))->next;
			SKIP_NL ();
		}
		return CHECK (parse_prefix_list (result, "list"));
	}
	if (ACCEPT (T_LBRACE)) {
		while ((*tail = parse_line (self, err)))
			tail = &(*tail)->next;
		EXPECT (T_RBRACE);
		result = CHECK (new_list (result));
		return CHECK (parse_prefix_list (result, "quote"));
	}

	self->memory_failure = !(self->error = lexer_errorf (&self->lexer,
		"unexpected `%s', expected a value", token_names[self->token]));
	longjmp (out, 1);
}

static struct item *
parse_line (struct parser *self, jmp_buf out) {
	jmp_buf err;
	struct item *volatile result = NULL, *volatile *tail = &result;
	if (setjmp (err)) {
		item_free_list (result);
		longjmp (out, 1);
	}

	while (PEEK () != T_RBRACE && PEEK () != T_ABORT) {
		if (!ACCEPT (T_NEWLINE)) {
			tail = &(*tail = parse_item (self, err))->next;
		} else if (result) {
			return CHECK (new_list (result));
		}
	}
	if (result)
		return CHECK (new_list (result));
	return NULL;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#undef PEEK
#undef ACCEPT
#undef EXPECT
#undef SKIP_NL
#undef CHECK

static struct item *
parser_run (struct parser *self, const char **e) {
	jmp_buf err;
	struct item *volatile result = NULL, *volatile *tail = &result;
	if (setjmp (err)) {
		item_free_list (result);
		*e = self->error;
		if (self->memory_failure || self->lexer.string.memory_failure)
			*e = "memory allocation failure";
		return NULL;
	}

	while ((*tail = parse_line (self, err)))
		tail = &(*tail)->next;
	parser_expect (self, T_ABORT, err);
	return result;
}

// --- Runtime -----------------------------------------------------------------

struct context;
typedef bool (*handler_fn) (struct context *, struct item *, struct item **);

struct native_fn {
	struct native_fn *next;             ///< The next link in the chain
	handler_fn handler;                 ///< Internal C handler, or NULL
	char name[];                        ///< The name of the function
};

struct native_fn *g_native;             ///< Maps words to functions

static struct native_fn *
native_find (const char *name) {
	for (struct native_fn *fn = g_native; fn; fn = fn->next)
		if (!strcmp (fn->name, name))
			return fn;
	return NULL;
}

static bool
native_register (const char *name, handler_fn handler) {
	struct native_fn *fn = native_find (name);
	if (!fn) {
		if (!(fn = calloc (1, sizeof *fn + strlen (name) + 1)))
			return false;
		strcpy (fn->name, name);
		fn->next = g_native;
		g_native = fn;
	}

	fn->handler = handler;
	return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct context {
	struct item *variables;             ///< List of variables

	char *error;                        ///< Error information
	bool error_is_fatal;                ///< Whether the error can be catched
	bool memory_failure;                ///< Memory allocation failure

	void *user_data;                    ///< User data
};

static void
context_init (struct context *ctx) {
	memset (ctx, 0, sizeof *ctx);
}

static void
context_free (struct context *ctx) {
	item_free_list (ctx->variables);
	free (ctx->error);
}

static bool
check (struct context *ctx, struct item *item) {
	return !(ctx->memory_failure |= !item);
}

static struct item *
get (struct context *ctx, const char *name) {
	for (struct item *iter = ctx->variables; iter; iter = iter->next)
		if (!strcmp (iter->head->value, name))
			return iter->head->next;
	return NULL;
}

static bool
set (struct context *ctx, const char *name, struct item *value) {
	struct item *iter, *key, *pair;
	for (iter = ctx->variables; iter; iter = iter->next)
		if (!strcmp (iter->head->value, name))
			break;
	if (iter) {
		item_free (iter->head->next);
		return check (ctx, (iter->head->next = new_clone (value)));
	}
	if (!check (ctx, (key = new_string (name, strlen (name))))
	 || !check (ctx, (pair = new_list (key))))
		return false;
	if (!check (ctx, (key->next = new_clone (value)))) {
		item_free (pair);
		return false;
	}
	pair->next = ctx->variables;
	ctx->variables = pair;
	return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
set_error (struct context *ctx, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	free (ctx->error);
	if (!(ctx->error = vformat (format, ap)))
		ctx->memory_failure = true;
	va_end (ap);
	return false;
}

static bool
rename_arguments (struct context *ctx, struct item *names) {
	size_t i = 0;
	for (; names; names = names->next) {
		char buf[64];
		(void) snprintf (buf, sizeof buf, "%zu", i++);
		struct item *value = get (ctx, buf);

		// TODO: set to some sort of nil value?
		if (!value)
			return true;

		if (names->type != ITEM_STRING)
			return set_error (ctx, "argument names must be strings");
		if (!set (ctx, names->value, value))
			return false;
	}
	return true;
}

static bool execute_statement (struct context *, struct item *, struct item **);
static bool execute (struct context *ctx, struct item *body, struct item **);

static bool
execute_args (struct context *ctx, struct item *args, struct item **res) {
	for (; args; args = args->next) {
		struct item *evaluated = NULL;
		if (!execute_statement (ctx, args, &evaluated))
			return false;
		if (evaluated) {
			item_free_list (evaluated->next);
			evaluated->next = NULL;
			res = &(*res = evaluated)->next;
		}
	}
	return true;
}

// TODO: we should probably maintain arguments in a separate list,
//   either that or at least remember the count so that we can reset them
static bool
execute_args_and_set (struct context *ctx, struct item *following) {
	struct item *args = NULL;
	if (!execute_args (ctx, following, &args)) {
		item_free_list (args);
		return false;
	}

	size_t i = 0;
	for (struct item *arg = args; arg; arg = arg->next) {
		char buf[64];
		(void) snprintf (buf, sizeof buf, "%zu", i++);
		if (!set (ctx, buf, arg))
			return false;
	}
	item_free_list (args);
	return true;
}

static bool
execute_native (struct context *ctx,
	struct native_fn *fn, struct item *next, struct item **res) {
	struct item *args = NULL;
	bool ok = execute_args (ctx, next, &args)
		&& fn->handler (ctx, args, res);
	item_free_list (args);
	return ok;
}

static bool
execute_statement
	(struct context *ctx, struct item *statement, struct item **result) {
	if (statement->type == ITEM_STRING)
		return check (ctx, (*result = new_clone (statement)));

	// XXX: should this ever happen and what are the consequences?
	//   Shouldn't we rather clone the empty list?
	struct item *body;
	if (!(body = statement->head))
		return true;

	struct item *following = body->next;
	const char *name = "(anonymous)";
	if (body->type == ITEM_STRING) {
		name = body->value;
		// TODO: these could be just regular handlers, only top priority
		// TODO: these should also get a stack trace the normal way
		if (!strcmp (name, "quote"))
			return !following
				|| check (ctx, (*result = new_clone_list (following)));
		if (!strcmp (name, "arg"))
			return rename_arguments (ctx, following);
		body = get (ctx, name);
	}

	if (!body) {
		struct native_fn *fn = native_find (name);
		if (!fn)
			return set_error (ctx, "unknown function: %s", name);
		if (execute_native (ctx, fn, following, result))
			return true;
	} else if (body->type == ITEM_STRING) {
		// Recursion could be pretty fatal, let's not do that
		if (check (ctx, (*result = new_clone (body))))
			return true;
	} else {
		if (execute_args_and_set (ctx, following)
		 && execute (ctx, body->head, result))
			return true;
	}

	// In that case, `error' is NULL and there's nothing else to do anyway
	if (!ctx->memory_failure) {
		// This creates some form of a stack trace
		char *tmp = ctx->error;
		set_error (ctx, "%s -> %s", name, tmp);
		free (tmp);
	}
	return false;
}

// Execute a block and return whatever the last statement returned
static bool
execute (struct context *ctx, struct item *body, struct item **result) {
	for (; body; body = body->next) {
		item_free_list (*result);
		*result = NULL;
		if (!execute_statement (ctx, body, result))
			return false;
	}
	return true;
}

// --- Runtime library ---------------------------------------------------------

#define defn(name) static bool name \
	(struct context *ctx, struct item *args, struct item **result)

static bool
init_runtime_library_scripts (struct context *ctx) {
	bool ok = true;

	struct {
		const char *name;               ///< Name of the function
		const char *definition;         ///< The defining script
	} functions[] = {
		// TODO: try to think of something useful
	};

	for (size_t i = 0; i < N_ELEMENTS (functions); i++) {
		struct parser parser;
		parser_init (&parser,
			functions[i].definition, strlen (functions[i].definition));
		const char *e = NULL;
		struct item *body = parser_run (&parser, &e);
		if (e) {
			printf ("error parsing internal function `%s': %s\n",
				functions[i].name, e);
			ok = false;
		} else
			ok &= set (ctx, functions[i].name, body);
		parser_free (&parser);
	}
	return ok;
}

defn (fn_set) {
	struct item *name = args;
	if (!name || name->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");

	struct item *value;
	if ((value = name->next))
		return set (ctx, name->value, value);

	// We return an empty list for a nil value
	if (!(value = get (ctx, name->value)))
		return check (ctx, (*result = new_list (NULL)));
	return check (ctx, (*result = new_clone (value)));
}

defn (fn_list) {
	struct item *values = NULL;
	if (args && !check (ctx, (values = new_clone_list (args))))
		return false;
	return check (ctx, (*result = new_list (values)));
}

defn (fn_print) {
	(void) result;
	for (; args; args = args->next) {
		if (args->type != ITEM_STRING)
			// TODO: print lists as their parsable representation
			return set_error (ctx, "cannot print lists");
		if (fwrite (args->value, 1, args->len, stdout) != args->len)
			return set_error (ctx, "write failed: %s", strerror (errno));
	}
	return true;
}

defn (fn_concatenate) {
	struct buffer buf = BUFFER_INITIALIZER;
	for (; args; args = args->next) {
		if (args->type != ITEM_STRING) {
			free (buf.s);
			return set_error (ctx, "cannot concatenate lists");
		}
		buffer_append (&buf, args->value, args->len);
	}
	buffer_append_c (&buf, '\0');

	bool ok = !(ctx->memory_failure = buf.memory_failure)
		&& check (ctx, (*result = new_string (buf.s, buf.len)));
	free (buf.s);
	return ok;
}

static bool
init_runtime_library (void)
{
	return native_register ("set",    fn_set)
		&& native_register ("list",   fn_list)
		&& native_register ("print",  fn_print)
		&& native_register ("..",     fn_concatenate);
}

static void
free_runtime_library (void) {
	struct native_fn *next, *iter;
	for (iter = g_native; iter; iter = next) {
		next = iter->next;
		free (iter);
	}
}

// --- Main --------------------------------------------------------------------

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
	free (buf.s);
	if (e) {
		printf ("%s: %s\n", "parse error", e);
		return 1;
	}

#ifndef NDEBUG
	printf ("\x1b[1m%s\x1b[0m\n", buf.s);
	print_tree (program, 0);
	printf ("\n\n");
#endif
	parser_free (&parser);

	struct context ctx;
	context_init (&ctx);
	if (!init_runtime_library ()
	 || !init_runtime_library_scripts (&ctx))
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

	free_runtime_library ();
	return 0;
}

