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
	size_t size = sizeof *item;
	if (item->type == ITEM_STRING)
		size += item->len + 1;

	struct item *clone = malloc (size);
	if (!clone)
		return NULL;

	memcpy (clone, item, size);
	if (item->type == ITEM_LIST) {
		if (clone->head && !(clone->head = new_clone_list (clone->head))) {
			free (clone);
			return NULL;
		}
	}
	clone->next = NULL;
	return clone;
}

static struct item *
new_clone_list (const struct item *item) {
	struct item *head = NULL, *clone;
	for (struct item **out = &head; item; item = item->next) {
		if (!(clone = *out = new_clone (item))) {
			item_free_list (head);
			return NULL;
		}
		clone->next = NULL;
		out = &clone->next;
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
	struct item *item = calloc (1, sizeof *item);
	if (!item)
		return NULL;

	item->type = ITEM_LIST;
	item->head = head;
	return item;
}

// --- Lexer -------------------------------------------------------------------

enum token {
	T_ABORT,                            ///< EOF or error

	T_LPAREN,                           ///< Left parenthesis
	T_RPAREN,                           ///< Right parenthesis
	T_LBRACKET,                         ///< Left bracket
	T_RBRACKET,                         ///< Right bracket
	T_LBRACE,                           ///< Left curly bracket
	T_RBRACE,                           ///< Right curly bracket
	T_STRING,                           ///< Everything else that's not space
	T_NEWLINE,                          ///< New line
	T_AT                                ///< At symbol
};

static const char *
token_name (enum token token) {
	switch (token) {
	case T_ABORT:    return "end of input";

	case T_LPAREN:   return "left parenthesis";
	case T_RPAREN:   return "right parenthesis";
	case T_LBRACKET: return "left bracket";
	case T_RBRACKET: return "right bracket";
	case T_LBRACE:   return "left brace";
	case T_RBRACE:   return "right brace";
	case T_STRING:   return "string";
	case T_NEWLINE:  return "newline";
	case T_AT:       return "at symbol";

	default:
		abort ();
		return NULL;
	}
}

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

// FIXME: other isspace() stuff is missing
static bool lexer_is_word_char (int c) { return !strchr ("()[]{}\n@#' ", c); }

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

static void lexer_error (struct lexer *self, char **e, const char *fmt, ...)
	ATTRIBUTE_PRINTF (3, 4);

// TODO: see "script", we can just use error constants to avoid allocation
static void
lexer_error (struct lexer *self, char **e, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *description = vformat (fmt, ap);
	va_end (ap);

	*e = format ("near line %u, column %u: %s",
		self->line + 1, self->column + 1, description);

	// TODO: see above, we should be able to indicate error without allocation
	if (!*e)
		abort ();

	free (description);
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

static bool
lexer_escape_sequence (struct lexer *self, struct buffer *output, char **e) {
	if (!self->len) {
		lexer_error (self, e, "premature end of escape sequence");
		return false;
	}

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
			return true;

		lexer_error (self, e, "invalid hexadecimal escape");
		return false;

	default:
		lexer_error (self, e, "unknown escape sequence");
		return false;
	}

	buffer_append_c (output, c);
	lexer_advance (self);
	return true;
}

static bool
lexer_string (struct lexer *self, struct buffer *output, char **e) {
	unsigned char c;
	while (self->len) {
		if ((c = lexer_advance (self)) == '\'')
			return true;
		if (c != '\\')
			buffer_append_c (output, c);
		else if (!lexer_escape_sequence (self, output, e))
			return false;
	}
	lexer_error (self, e, "premature end of string");
	return false;
}

static enum token
lexer_next (struct lexer *self, char **e) {
	// Skip over any whitespace between tokens
	while (self->len && isspace (*self->p) && *self->p != '\n')
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
		if (!lexer_string (self, &self->string, e))
			return T_ABORT;
		return T_STRING;
	}

	assert (lexer_is_word_char (*self->p));
	do
		buffer_append_c (&self->string, lexer_advance (self));
	while (lexer_is_word_char (*self->p));
	return T_STRING;
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

struct parser
{
	struct lexer lexer;                 ///< Tokenizer
	char *error;                        ///< Tokenizer error
	enum token token;                   ///< Current token in the lexer
	bool replace_token;                 ///< Replace the token
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
	if (self->replace_token)
	{
		self->token = lexer_next (&self->lexer, &self->error);
		if (self->error)
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

	lexer_error (&self->lexer, &self->error, "unexpected `%s', expected `%s'",
		token_name (self->token),
		token_name (token));
	longjmp (out, 1);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// We don't need no generator, but a few macros will come in handy.
// From time to time C just doesn't have the right features.

#define PEEK()         parser_peek   (self, err)
#define ACCEPT(token)  parser_accept (self, token, err)
#define EXPECT(token)  parser_expect (self, token, err)
#define SKIP_NL()      do {} while (ACCEPT (T_NEWLINE))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct item * parse_line (struct parser *self, jmp_buf out);

static struct item *
parse_prefix_list (struct item *list, const char *name) {
	struct item *prefix = new_string (name, strlen (name));
	prefix->next = list;
	return new_list (prefix);
}

static struct item *
parse_item (struct parser *self, jmp_buf out) {
	struct item *volatile result = NULL, *volatile *tail = &result;
	jmp_buf err;

	if (setjmp (err)) {
		item_free_list (result);
		longjmp (out, 1);
	}

	SKIP_NL ();
	if (ACCEPT (T_STRING))
		return new_string (self->lexer.string.s, self->lexer.string.len);
	if (ACCEPT (T_AT)) {
		result = parse_item (self, out);
		return parse_prefix_list (result, "set");
	}
	if (ACCEPT (T_LPAREN)) {
		while (!ACCEPT (T_RPAREN)) {
			*tail = parse_item (self, err);
			tail = &(*tail)->next;
			SKIP_NL ();
		}
		return new_list (result);
	}
	if (ACCEPT (T_LBRACKET)) {
		while (!ACCEPT (T_RBRACKET)) {
			*tail = parse_item (self, err);
			tail = &(*tail)->next;
			SKIP_NL ();
		}
		return parse_prefix_list (result, "list");
	}
	if (ACCEPT (T_LBRACE)) {
		while ((*tail = parse_line (self, err)))
			tail = &(*tail)->next;
		EXPECT (T_RBRACE);
		return parse_prefix_list (result, "quote");
	}

	lexer_error (&self->lexer, &self->error,
		"unexpected `%s', expected a value", token_name (self->token));
	longjmp (out, 1);
}

static struct item *
parse_line (struct parser *self, jmp_buf out) {
	struct item *volatile result = NULL, *volatile *tail = &result;
	jmp_buf err;

	if (setjmp (err)) {
		item_free_list (result);
		longjmp (out, 1);
	}

	while (PEEK () != T_RBRACE && PEEK () != T_ABORT) {
		if (ACCEPT (T_NEWLINE)) {
			if (result)
				return new_list (result);
		} else {
			*tail = parse_item (self, err);
			tail = &(*tail)->next;
		}
	}
	if (result)
		return new_list (result);
	return NULL;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#undef PEEK
#undef ACCEPT
#undef EXPECT
#undef SKIP_NL

static struct item *
parse (const char *s, size_t len, char **e) {
	struct parser parser;
	parser_init (&parser, s, len);

	struct item *volatile result = NULL, *volatile *tail = &result;
	jmp_buf err;

	if (setjmp (err)) {
		item_free_list (result);
		*e = parser.error;
		lexer_free (&parser.lexer);
		return NULL;
	}

	while ((*tail = parse_line (&parser, err)))
		tail = &(*tail)->next;
	parser_expect (&parser, T_ABORT, err);

	parser_free (&parser);
#ifndef NDEBUG
	printf ("\x1b[1m%s\x1b[0m\n", s);
	print_tree (result, 0);
	printf ("\n\n");
#endif
	return new_list (result);
}

// --- Runtime -----------------------------------------------------------------

struct context;
typedef bool (*handler_fn) (struct context *);

struct native_fn {
	struct native_fn *next;             ///< The next link in the chain
	handler_fn handler;                 ///< Internal C handler, or NULL
	char name[];                        ///< The name of the function
};

struct native_fn *g_native;             ///< Maps words to functions

static bool
register_native (const char *name, handler_fn handler) {
	struct native_fn *fn = NULL;
	for (fn = g_native; fn; fn = fn->next)
		if (!strcmp (fn->name, name))
			break;

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
set_error (struct context *ctx, const char *format, ...) {
	free (ctx->error);

	va_list ap;
	va_start (ap, format);
	ctx->error = vformat (format, ap);
	va_end (ap);

	if (!ctx->error)
		ctx->memory_failure = true;
	return false;
}

static struct item *
var (struct context *ctx, const char *name) {
	for (struct item *iter = ctx->variables; iter; iter = iter->next)
		if (!strcmp (iter->head->value, name))
			return iter->head->next;
	return NULL;
}

static void
set (struct context *ctx, const char *name, struct item *value) {
	for (struct item *iter = ctx->variables; iter; iter = iter->next)
		if (!strcmp (iter->head->value, name)) {
			item_free (iter->head->next);
			iter->head->next = value;
			return;
		}
	struct item *key = new_string (name, strlen (name));
	key->next = value;
	struct item *pair = new_list (key);
	pair->next = ctx->variables;
	ctx->variables = pair;
}

static struct item *execute (struct context *, struct item *);

static bool
call_function (struct context *ctx, const char *name) {
	struct item *body = var (ctx, name);
	if (!body) {
		struct native_fn *fn;
		for (fn = g_native; fn; fn = fn->next)
			if (!strcmp (name, fn->name))
				break;
		if (!fn)
			return set_error (ctx, "unknown function: %s", name);
		if (fn->handler (ctx))
			return true;
	} else if (body->type == ITEM_STRING) {
		return set_error (ctx, "strings aren't callable: %s", name);
	} else if (execute (ctx, body))
		return true;

	// In this case, `error' is NULL
	if (ctx->memory_failure)
		return false;

	// This creates some form of a stack trace
	char *tmp = ctx->error;
	ctx->error = NULL;
	set_error (ctx, "%s -> %s", name, tmp);
	free (tmp);
	return false;
}

static struct item *execute (struct context *ctx, struct item *script);

static struct item *
execute_one (struct context *ctx, struct item *statement) {
	if (!statement->head)
		return NULL;

	struct item *fn = statement->head->head;
	if (statement->head->type == ITEM_STRING) {
		if (!strcmp (statement->head->value, "quote")) {
			return statement->head->next;
		} else if (!strcmp (statement->head->value, "arg")) {
			// TODO: rename \d+ variables to arguments
		} else {
			// TODO: resolve the string
			fn = NULL;
		}
	}
	// TODO: assign the rest of items to variables
	return execute (ctx, fn);
}

// Execute a block and return whatever the last statement returned
static struct item *
execute (struct context *ctx, struct item *script) {
	struct item *result = NULL;
	for (; script; script = script->next) {
		assert (script->type == ITEM_LIST);
		item_free_list (result);
		result = execute_one (ctx, script);
	}
	return result;
}

// --- Runtime library ---------------------------------------------------------

#define defn(name) static bool name (struct context *ctx)

static bool
init_runtime_library_scripts (struct context *ctx) {
	bool ok = true;

	// It's much cheaper (and more fun) to define functions in terms of other
	// ones.  The "unit tests" serve a secondary purpose of showing the usage.
	struct {
		const char *name;               ///< Name of the function
		const char *definition;         ///< The defining script
	} functions[] = {
		{ "greet", "arg _name\n" "print (.. 'hello ' (.. @_name))" },
	};

	for (size_t i = 0; i < N_ELEMENTS (functions); i++) {
		char *e = NULL;
		struct item *body = parse (functions[i].definition,
			strlen (functions[i].definition), &e);
		if (e) {
			printf ("error parsing internal function `%s': %s\n",
				functions[i].definition, e);
			free (e);
			ok = false;
		} else
			set (ctx, functions[i].name, body);
	}
	return ok;
}

defn (fn_print) {
	struct buffer buf = BUFFER_INITIALIZER;
	struct item *item = var (ctx, "1");
	buffer_append (&buf, item->value, item->len);
	buffer_append_c (&buf, '\0');
	if (buf.memory_failure) {
		ctx->memory_failure = true;
		return false;
	}

	printf ("%s\n", buf.s);
	free (buf.s);
	return true;
}

defn (fn_concatenate) {
	// TODO: concatenate string arguments, error on list
	return true;
}

static bool
init_runtime_library (void)
{
	return register_native ("..",     fn_concatenate)
		&& register_native ("print",  fn_print);
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
	// TODO: load the entirety of stdin
	const char *program = "print 'hello world\\n'";

	char *e = NULL;
	struct item *tree = parse (program, strlen (program), &e);
	if (e) {
		printf ("%s: %s\n", "parse error", e);
		free (e);
		return 1;
	}

	struct context ctx;
	context_init (&ctx);
	if (!init_runtime_library ()
	 || !init_runtime_library_scripts (&ctx))
		printf ("%s\n", "runtime library initialization failed");
	ctx.user_data = NULL;
	item_free_list (execute (&ctx, tree));
	item_free_list (tree);

	const char *failure = NULL;
	if (ctx.memory_failure)
		failure = "memory allocation failure";
	else if (ctx.error)
		failure = ctx.error;
	if (failure)
		printf ("%s: %s\n", "runtime error", failure);
	context_free (&ctx);

	free_runtime_library ();
	return 0;
}

