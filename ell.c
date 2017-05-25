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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
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

	char *buf = malloc (size + 1);
	if (buf && vsnprintf (buf, size + 1, format, ap) < 0) {
		free (buf);
		return NULL;
	}
	return buf;
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
	size_t alloc, len;                  ///< Number of bytes allocated and used
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

// --- Data items --------------------------------------------------------------

enum item_type { ITEM_STRING, ITEM_LIST };

struct item {
	enum item_type type;                ///< The type of this object
	struct item *next;                  ///< Next item on the list/stack

	struct item *head;                  ///< The head of the list
	size_t len;                         ///< Length of "value" (sans '\0')
	char value[];                       ///< The null-terminated string value
};

static void item_free_list (struct item *);
static struct item *new_clone_list (const struct item *);

static void
item_free (struct item *item) {
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
	size_t size = sizeof *item + item->len + 1;
	struct item *clone = malloc (size);
	if (!clone)
		return NULL;

	memcpy (clone, item, size);
	if (clone->head && !(clone->head = new_clone_list (clone->head))) {
		free (clone);
		return NULL;
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
new_string (const char *s, size_t len) {
	struct item *item = calloc (1, sizeof *item + len + 1);
	if (!item)
		return NULL;

	item->type = ITEM_STRING;
	item->len = len;
	memcpy (item->value, s, len);
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
	const unsigned char *p;             ///< Current position in input
	size_t len;                         ///< How many bytes of input are left
	unsigned line, column;              ///< Current line and column
	struct buffer string;               ///< Parsed string value
};

static void
lexer_init (struct lexer *self, const char *p, size_t len) {
	*self = (struct lexer) { .p = (const unsigned char *) p, .len = len };
}

static void
lexer_free (struct lexer *self) {
	free (self->string.s);
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
	const char *alphabet = "0123456789abcdef", *h, *l;
	if (!self->len || !(h = strchr (alphabet, tolower (lexer_advance (self))))
	 || !self->len || !(l = strchr (alphabet, tolower (lexer_advance (self)))))
		return false;

	buffer_append_c (output, (h - alphabet) << 4 | (l - alphabet));
	return true;
}

enum { LEXER_STRING_QUOTE = '\'', LEXER_ESCAPE = '\\', LEXER_COMMENT = '#' };
static bool lexer_is_whitespace (int c) { return !c || c == ' ' || c == '\t'; }

static unsigned char lexer_escapes[256] = {
	[LEXER_STRING_QUOTE] = LEXER_STRING_QUOTE, [LEXER_ESCAPE] = LEXER_ESCAPE,
	['a'] = '\a', ['b'] = '\b', ['n'] = '\n', ['r'] = '\r', ['t'] = '\t',
};

static const char *
lexer_escape_sequence (struct lexer *self, struct buffer *output) {
	if (!self->len)
		return "premature end of escape sequence";

	int c = lexer_advance (self);
	if (c == 'x') {
		if (lexer_hexa_escape (self, output))
			return NULL;
		return "invalid hexadecimal escape";
	}
	if (!(c = lexer_escapes[c]))
		return "unknown escape sequence";

	buffer_append_c (output, c);
	return NULL;
}

static const char *
lexer_string (struct lexer *self, struct buffer *output) {
	int c;
	const char *e = NULL;
	while (self->len) {
		if ((c = lexer_advance (self)) == LEXER_STRING_QUOTE)
			return NULL;
		if (c != LEXER_ESCAPE)
			buffer_append_c (output, c);
		else if ((e = lexer_escape_sequence (self, output)))
			return e;
	}
	return "premature end of string";
}

static enum token lexer_tokens[256] = {
	['('] = T_LPAREN, [')'] = T_RPAREN, ['['] = T_LBRACKET, [']'] = T_RBRACKET,
	['{'] = T_LBRACE, ['}'] = T_RBRACE, [';'] = T_NEWLINE, ['\n'] = T_NEWLINE,
	['@'] = T_AT, [LEXER_STRING_QUOTE] = T_STRING,
};

static enum token
lexer_next (struct lexer *self, const char **e) {
	while (self->len && lexer_is_whitespace (*self->p))
		lexer_advance (self);
	if (!self->len)
		return T_ABORT;

	free (self->string.s);
	self->string = (struct buffer) BUFFER_INITIALIZER;

	int c = lexer_advance (self);
	if (c == LEXER_COMMENT) {
		while (self->len)
			if (lexer_advance (self) == '\n')
				return T_NEWLINE;
		return T_ABORT;
	}

	enum token token = lexer_tokens[c];
	if (!token) {
		buffer_append_c (&self->string, c);
		while (self->len && !lexer_is_whitespace (*self->p)
			&& !lexer_tokens[*self->p])
			buffer_append_c (&self->string, lexer_advance (self));
		return T_STRING;
	}
	if (token == T_STRING
	 && (*e = lexer_string (self, &self->string)))
		return T_ABORT;
	return token;
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

	char *e = format ("at or before line %u, column %u: %s",
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
		} else if (iter->head
			&& iter->head->type == ITEM_STRING
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

struct context {
	struct item *variables;             ///< List of variables
	struct native_fn *native;           ///< Maps strings to C functions
	struct item *arguments;             ///< Arguments to last executed block

	char *error;                        ///< Error information
	bool memory_failure;                ///< Memory allocation failure
	void *user_data;                    ///< User data
};

typedef bool (*handler_fn) (struct context *, struct item *, struct item **);

struct native_fn {
	struct native_fn *next;             ///< The next link in the chain
	handler_fn handler;                 ///< Internal C handler, or NULL
	char name[];                        ///< The name of the function
};

static void
context_init (struct context *ctx) {
	memset (ctx, 0, sizeof *ctx);
}

static void
context_free (struct context *ctx) {
	struct native_fn *next, *iter;
	for (iter = ctx->native; iter; iter = next) {
		next = iter->next;
		free (iter);
	}
	item_free_list (ctx->variables);
	item_free_list (ctx->arguments);
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
	struct item **p;
	for (p = &ctx->variables; *p; p = &(*p)->next)
		if (!strcmp ((*p)->head->value, name)) {
			struct item *tmp = *p;
			*p = (*p)->next;
			item_free (tmp);
			break;
		}
	if (!value)
		return true;

	struct item *key, *pair;
	if (!check (ctx, (key = new_string (name, strlen (name))))
	 || !check (ctx, (pair = new_list (key)))) {
		item_free_list (value);
		return false;
	}
	key->next = value;
	pair->next = ctx->variables;
	ctx->variables = pair;
	return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct native_fn *
native_find (struct context *ctx, const char *name) {
	for (struct native_fn *fn = ctx->native; fn; fn = fn->next)
		if (!strcmp (fn->name, name))
			return fn;
	return NULL;
}

static bool
native_register (struct context *ctx, const char *name, handler_fn handler) {
	struct native_fn *fn = native_find (ctx, name);
	if (!fn) {
		if (!(fn = calloc (1, sizeof *fn + strlen (name) + 1)))
			return false;
		strcpy (fn->name, name);
		fn->next = ctx->native;
		ctx->native = fn;
	}
	fn->handler = handler;
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
can_modify_error (struct context *ctx) {
	// In that case, `error' is NULL and there's nothing else to do anyway.
	// Errors starting with an underscore are exceptions and would not work
	// with stack traces generated this way.
	return !ctx->memory_failure && ctx->error[0] != '_';
}

static bool
assign_arguments (struct context *ctx, struct item *names) {
	struct item *arg = ctx->arguments;
	for (; names; names = names->next) {
		if (names->type != ITEM_STRING)
			return set_error (ctx, "argument names must be strings");

		struct item *value = NULL;
		if (arg && !check (ctx, (value = new_clone (arg))))
			return false;
		if (!set (ctx, names->value, value))
			return false;
		if (arg)
			arg = arg->next;
	}
	return true;
}

static bool execute_statement (struct context *, struct item *, struct item **);
static bool execute (struct context *ctx, struct item *body, struct item **);

static bool
execute_args (struct context *ctx, struct item *args) {
	size_t i = 0;
	struct item *res = NULL, **out = &res;
	for (; args; args = args->next) {
		struct item *evaluated = NULL;
		// Arguments should not evaporate, default to a nil value
		if (!execute_statement (ctx, args, &evaluated)
		 || (!evaluated && !check (ctx, (evaluated = new_list (NULL)))))
			goto error;
		item_free_list (evaluated->next);
		evaluated->next = NULL;
		out = &(*out = evaluated)->next;
		i++;
	}
	item_free_list (ctx->arguments);
	ctx->arguments = res;
	return true;

error:
	// Once the code flows like this, at least make some use of it
	if (can_modify_error (ctx)) {
		char *tmp = ctx->error;
		ctx->error = NULL;
		set_error (ctx, "(argument %zu) -> %s", i, tmp);
		free (tmp);
	}
	item_free_list (res);
	return false;
}

static bool
execute_native (struct context *ctx, const char *name, struct item *args,
	struct item **result) {
	struct native_fn *fn = native_find (ctx, name);
	if (!fn)
		return set_error (ctx, "unknown function");
	if (!execute_args (ctx, args))
		return false;

	// "ctx->arguments" is for assign_arguments() only
	args = ctx->arguments;
	ctx->arguments = NULL;
	bool ok = fn->handler (ctx, args, result);
	item_free_list (args);
	return ok;
}

static bool
execute_resolved (struct context *ctx, struct item *body, struct item *args,
	struct item **result) {
	// Resolving names ecursively could be pretty fatal, let's not do that
	if (body->type == ITEM_STRING)
		return check (ctx, (*result = new_clone (body)));
	return execute_args (ctx, args)
		&& execute (ctx, body->head, result);
}

static bool
execute_item (struct context *ctx, struct item *body, struct item **result) {
	struct item *args = body->next;
	if (body->type == ITEM_STRING) {
		const char *name = body->value;
		// TODO: these could be just regular handlers, only top priority
		if (!strcmp (name, "quote"))
			return !args || check (ctx, (*result = new_clone_list (args)));
		if (!strcmp (name, "arg"))
			return assign_arguments (ctx, args);
		if ((body = get (ctx, name)))
			return execute_resolved (ctx, body, args, result);
		return execute_native (ctx, name, args, result);
	}

	// When someone tries to call a block directly, we must evaluate it;
	// e.g. something like `{ choose [@f1 @f2 @f3] } arg1 arg2 arg3`.
	struct item *evaluated = NULL;
	if (!execute_statement (ctx, body, &evaluated))
		return false;

	// It might a bit confusing that this doesn't evaluate arguments
	// but neither does "quote" and there's nothing to do here
	if (!evaluated)
		return true;

	bool ok = execute_resolved (ctx, evaluated, args, result);
	item_free_list (evaluated);
	return ok;
}

static bool
execute_statement
	(struct context *ctx, struct item *statement, struct item **result) {
	if (statement->type == ITEM_STRING)
		return check (ctx, (*result = new_clone (statement)));

	// Executing a nil value results in no value.  It's not very different from
	// calling a block that returns no value--it's for our callers to resolve.
	if (!statement->head
	 || execute_item (ctx, statement->head, result))
		return true;

	item_free_list (*result);
	*result = NULL;

	const char *name = "(block)";
	if (statement->head->type == ITEM_STRING)
		name = statement->head->value;

	if (can_modify_error (ctx)) {
		char *tmp = ctx->error;
		ctx->error = NULL;
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
set_single_argument (struct context *ctx, struct item *item) {
	struct item *single;
	if (!check (ctx, (single = new_clone (item))))
		return false;
	item_free_list (ctx->arguments);
	ctx->arguments = single;
	return true;
}

static struct item *
new_number (double n) {
	char *s;
	if (!(s = format ("%f", n)))
		return NULL;

	char *p = strchr (s, 0);
	while (--p > s && *p == '0')
		*p = 0;
	if (*p == '.')
		*p = 0;

	struct item *item = new_string (s, strlen (s));
	free (s);
	return item;
}

static bool
truthy (struct item *item) {
	return item && (item->head || item->len);
}

static struct item * new_boolean (bool b) { return new_string ("1", b); }

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

defn (fn_set) {
	struct item *name = args;
	if (!name || name->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");

	struct item *value;
	if ((value = name->next))
		return check (ctx, (value = new_clone (value)))
			&& check (ctx, (*result = new_clone (value)))
			&& set (ctx, name->value, value);

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

defn (fn_if) {
	struct item *cond, *body, *keyword;
	for (cond = args; ; cond = keyword->next) {
		if (!cond)
			return set_error (ctx, "missing condition");
		if (!(body = cond->next))
			return set_error (ctx, "missing body");

		struct item *res = NULL;
		if (!execute_statement (ctx, cond, &res))
			return false;
		bool match = truthy (res);
		item_free_list (res);
		if (match)
			return execute_statement (ctx, body, result);

		if (!(keyword = body->next))
			break;
		if (keyword->type != ITEM_STRING)
			return set_error (ctx, "expected keyword, got list");

		if (!strcmp (keyword->value, "else")) {
			if (!(body = keyword->next))
				return set_error (ctx, "missing body");
			return execute_statement (ctx, body, result);
		}
		if (strcmp (keyword->value, "elif"))
			return set_error (ctx, "invalid keyword: %s", keyword->value);
	}
	return true;
}

defn (fn_map) {
	struct item *body = args, *values;
	if (!body || body->type != ITEM_LIST)
		return set_error (ctx, "first argument must be a function");
	if (!(values = body->next) || values->type != ITEM_LIST)
		return set_error (ctx, "second argument must be a list");

	struct item *res = NULL, **out = &res;
	for (struct item *v = values->head; v; v = v->next) {
		if (!set_single_argument (ctx, v)
		 || !execute (ctx, body->head, out)) {
			item_free_list (res);
			return false;
		}
		while (*out)
			out = &(*out)->next;
	}
	return check (ctx, (*result = new_list (res)));
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

	bool ok = !(ctx->memory_failure |= buf.memory_failure)
		&& check (ctx, (*result = new_string (buf.s, buf.len - 1)));
	free (buf.s);
	return ok;
}

defn (fn_system) {
	struct item *command = args;
	if (!command || command->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	if (command->next)
		return set_error (ctx, "cannot deal with multiple arguments");
	return check (ctx, (*result = new_number (system (command->value))));
}

defn (fn_parse) {
	struct item *body = args;
	if (!body || body->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");

	struct parser parser;
	parser_init (&parser, args->value, args->len);
	const char *e = NULL;
	bool ok = check (ctx, (*result = new_list (parser_run (&parser, &e))));
	if (e)
		ok = set_error (ctx, "%s", e);
	parser_free (&parser);
	return ok;
}

defn (fn_try) {
	struct item *body = args, *handler;
	if (!body || body->type != ITEM_LIST)
		return set_error (ctx, "first argument must be a function");
	if (!(handler = body->next) || handler->type != ITEM_LIST)
		return set_error (ctx, "second argument must be a function");
	if (execute (ctx, body->head, result))
		return true;

	struct item *message;
	if (ctx->memory_failure
	 || !check (ctx, (message = new_string (ctx->error, strlen (ctx->error)))))
		return false;

	free (ctx->error); ctx->error = NULL;
	item_free_list (*result); *result = NULL;

	bool ok = set_single_argument (ctx, message)
		&& execute (ctx, handler->head, result);
	item_free (message);
	return ok;
}

defn (fn_throw) {
	(void) result;

	struct item *message = args;
	if (!message || message->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	return set_error (ctx, message->value);
}

defn (fn_plus) {
	double res = 0.0;
	for (; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		res += strtod (args->value, NULL);
	}
	return check (ctx, (*result = new_number (res)));
}

defn (fn_minus) {
	if (!args || args->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	double res = strtod (args->value, NULL);
	if (!(args = args->next))
		res = -res;

	for (; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		res -= strtod (args->value, NULL);
	}
	return check (ctx, (*result = new_number (res)));
}

defn (fn_multiply) {
	double res = 1.0;
	for (; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		res *= strtod (args->value, NULL);
	}
	return check (ctx, (*result = new_number (res)));
}

defn (fn_divide) {
	if (!args || args->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	double res = strtod (args->value, NULL), x;
	for (args = args->next; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		if (!(x = strtod (args->value, NULL)))
			return set_error (ctx, "division by zero");
		res /= x;
	}
	return check (ctx, (*result = new_number (res)));
}

defn (fn_not) {
	if (!args)
		return set_error (ctx, "missing argument");
	return check (ctx, (*result = new_boolean (!truthy (args))));
}

// TODO: "and" and "or" should be short-circuiting special forms
defn (fn_and) {
	bool res = true;
	for (; args; args = args->next)
		 res &= truthy (args);
	return check (ctx, (*result = new_boolean (res)));
}

defn (fn_or) {
	bool res = false;
	for (; args; args = args->next)
		 res |= truthy (args);
	return check (ctx, (*result = new_boolean (res)));
}

defn (fn_eq) {
	struct item *etalon = args;
	if (!etalon || etalon->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		if (!(res &= !strcmp (etalon->value, args->value)))
			break;
	}
	return check (ctx, (*result = new_boolean (res)));
}

defn (fn_lt) {
	struct item *etalon = args;
	if (!etalon || etalon->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		if (!(res &= strcmp (etalon->value, args->value) < 0))
			break;
		etalon = args;
	}
	return check (ctx, (*result = new_boolean (res)));
}

defn (fn_equals) {
	struct item *etalon = args;
	if (!etalon || etalon->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		if (!(res &= strtod (etalon->value, NULL)
			== strtod (args->value, NULL)))
			break;
	}
	return check (ctx, (*result = new_boolean (res)));
}

defn (fn_less) {
	struct item *etalon = args;
	if (!etalon || etalon->type != ITEM_STRING)
		return set_error (ctx, "first argument must be string");
	bool res = true;
	for (args = etalon->next; args; args = args->next) {
		if (args->type != ITEM_STRING)
			return set_error (ctx, "arguments must be strings");
		if (!(res &= strtod (etalon->value, NULL) < strtod (args->value, NULL)))
			break;
		etalon = args;
	}
	return check (ctx, (*result = new_boolean (res)));
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
init_runtime_library (struct context *ctx) {
	struct {
		const char *name;               ///< Name of the function
		const char *definition;         ///< The defining script
	} functions[] = {
		{ "unless", "arg _cond _body; if (not (@_cond)) @_body"      },
		{ "filter", "arg _body _list;"
		  "map { arg _i; if (@_body @_i) { @_i } } @_list"           },
		{ "for",    "arg _list _body;"
		  "try { map {arg _i; @_body @_i } @_list"
		  "} { arg _e; if (ne? @_e _break) { throw @e } }"           },
		{ "break",  "throw _break"                                   },
		// TODO: we should be able to apply them to all arguments
		{ "ne?",    "arg _ne1 _ne2; not (eq? @_ne1 @_ne2)"           },
		{ "ge?",    "arg _ge1 _ge2; not (lt? @_ge1 @_ge2)"           },
		{ "le?",    "arg _le1 _le2; ge? @_le2 @_le1"                 },
		{ "gt?",    "arg _gt1 _gt2; lt? @_gt2 @_gt1"                 },
		{ "<>",     "arg _<>1 _<>2; not (= @_<>1 @_<>2)"             },
		{ ">=",     "arg _>=1 _>=2; not (< @_>=1 @_>=2)"             },
		{ "<=",     "arg _<=1 _<=2; >= @_<=2 @_<=1"                  },
		{ ">",      "arg _>1  _>2;  <  @_>2  @_>1"                   },
	};

	bool ok = true;
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
		} else if (!check (ctx, (body = new_list (body)))
			|| !set (ctx, functions[i].name, body)) {
			ok = false;
		} else
			body = NULL;
		item_free_list (body);
		parser_free (&parser);
	}

	return ok
		&& native_register (ctx, "set",    fn_set)
		&& native_register (ctx, "list",   fn_list)
		&& native_register (ctx, "if",     fn_if)
		&& native_register (ctx, "map",    fn_map)
		&& native_register (ctx, "print",  fn_print)
		&& native_register (ctx, "..",     fn_concatenate)
		&& native_register (ctx, "system", fn_system)
		&& native_register (ctx, "parse",  fn_parse)
		&& native_register (ctx, "try",    fn_try)
		&& native_register (ctx, "throw",  fn_throw)
		&& native_register (ctx, "+",      fn_plus)
		&& native_register (ctx, "-",      fn_minus)
		&& native_register (ctx, "*",      fn_multiply)
		&& native_register (ctx, "/",      fn_divide)
		&& native_register (ctx, "not",    fn_not)
		&& native_register (ctx, "and",    fn_and)
		&& native_register (ctx, "or",     fn_or)
		&& native_register (ctx, "eq?",    fn_eq)
		&& native_register (ctx, "lt?",    fn_lt)
		&& native_register (ctx, "=",      fn_equals)
		&& native_register (ctx, "<",      fn_less);
}
