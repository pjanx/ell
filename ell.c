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

#if defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__ ((format (printf, x, y)))
#else // ! __GNUC__
#define ATTRIBUTE_PRINTF(x, y)
#endif // ! __GNUC__

#define N_ELEMENTS(a) (sizeof (a) / sizeof ((a)[0]))

// --- Utilities ---------------------------------------------------------------

static char *format (const char *format, ...) ATTRIBUTE_PRINTF (1, 2);

static char *
strdup_vprintf (const char *format, va_list ap) {
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
	char *result = strdup_vprintf (format, ap);
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
		item_free_list (get_list (item));
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

	unsigned line;                      ///< Current line
	unsigned column;                    ///< Current column

	int64_t integer;                    ///< Parsed boolean or integer value
	struct str string;                  ///< Parsed string value
};

/// Input has to be null-terminated anyway
static void
lexer_init (struct lexer *self, const char *p, size_t len) {
	memset (self, 0, sizeof *self);
	self->p = p;
	self->len = len;
	str_init (&self->string);
}

static void
lexer_free (struct lexer *self) {
	str_free (&self->string);
}

static bool lexer_is_word_char (int c) { return !strchr ("()[]{}\n@#'", c); }

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

static void lexer_error (struct lexer *self,
	struct error **e, const char *format, ...) ATTRIBUTE_PRINTF (3, 4);

static void
lexer_error (struct lexer *self, struct error **e, const char *format, ...) {
	struct str description;
	str_init (&description);

	va_list ap;
	va_start (ap, format);
	str_append_vprintf (&description, format, ap);
	va_end (ap);

	if (self->report_line)
		error_set (e, "near line %u, column %u: %s",
			self->line + 1, self->column + 1, description.str);
	else if (self->len)
		error_set (e, "near character %u: %s",
			self->column + 1, description.str);
	else
		error_set (e, "near end: %s", description.str);

	str_free (&description);
}

static bool
lexer_hexa_escape (struct lexer *self, struct str *output) {
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

	str_append_c (output, code);
	return true;
}

static bool
lexer_escape_sequence
	(struct lexer *self, struct str *output, struct error **e) {
	if (!self->len) {
		lexer_error (self, e, "premature end of escape sequence");
		return false;
	}

	unsigned char c;
	switch ((c = *self->p)) {
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

	str_append_c (output, c);
	lexer_advance (self);
	return true;
}

static bool
lexer_string (struct lexer *self, struct str *output, struct error **e) {
	unsigned char c;
	while (self->len) {
		if ((c = lexer_advance (self)) == '\'')
			return true;
		if (c != '\\')
			str_append_c (output, c);
		else if (!lexer_escape_sequence (self, output, e))
			return false;
	}
	lexer_error (self, e, "premature end of string");
	return false;
}

static enum token
lexer_next (struct lexer *self, struct error **e) {
	// Skip over any whitespace between tokens
	while (self->len && isspace_ascii (*self->p) && *self->p != '\n')
		lexer_advance (self);
	if (!self->len)
		return T_ABORT;

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
		str_reset (&self->string);
		if (!lexer_string (self, &self->string, e))
			return T_ABORT;
		return T_STRING;
	}

	assert (lexer_is_word_char (*self->p));
	str_reset (&self->string);
	do
		str_append_c (&self->string, lexer_advance (self));
	while (lexer_is_word_char (*self->p));
	return T_STRING;
}

// --- Parsing -----------------------------------------------------------------

#define PARSE_ERROR_TABLE(XX)                                                  \
	XX( OK,                  NULL                                  )           \
	XX( EOF,                 "unexpected end of input"             )           \
	XX( INVALID_HEXA_ESCAPE, "invalid hexadecimal escape sequence" )           \
	XX( INVALID_ESCAPE,      "unrecognized escape sequence"        )           \
	XX( MEMORY,              "memory allocation failure"           )           \
	XX( FLOAT_RANGE,         "floating point value out of range"   )           \
	XX( INTEGER_RANGE,       "integer out of range"                )           \
	XX( INVALID_INPUT,       "invalid input"                       )           \
	XX( UNEXPECTED_INPUT,    "unexpected input"                    )

enum tokenizer_error {
#define XX(x, y) PARSE_ERROR_ ## x,
	PARSE_ERROR_TABLE (XX)
#undef XX
	PARSE_ERROR_COUNT
};

struct tokenizer {
	const char *cursor;
	enum tokenizer_error error;
};

static bool
decode_hexa_escape (struct tokenizer *self, struct buffer *buf) {
	int i;
	char c, code = 0;

	for (i = 0; i < 2; i++) {
		c = tolower (*self->cursor);
		if (c >= '0' && c <= '9')
			code = (code << 4) | (c - '0');
		else if (c >= 'a' && c <= 'f')
			code = (code << 4) | (c - 'a' + 10);
		else
			break;

		self->cursor++;
	}

	if (!i)
		return false;

	buffer_append_c (buf, code);
	return true;
}

static bool
decode_escape_sequence (struct tokenizer *self, struct buffer *buf) {
	// Support some basic escape sequences from the C language
	char c;
	switch ((c = *self->cursor)) {
	case '\0':
		self->error = PARSE_ERROR_EOF;
		return false;
	case 'x':
	case 'X':
		self->cursor++;
		if (decode_hexa_escape (self, buf))
			return true;

		self->error = PARSE_ERROR_INVALID_HEXA_ESCAPE;
		return false;
	default:
		self->cursor++;
		const char *from = "abfnrtv\"\\", *to = "\a\b\f\n\r\t\v\"\\", *x;
		if ((x = strchr (from, c))) {
			buffer_append_c (buf, to[x - from]);
			return true;
		}
		self->error = PARSE_ERROR_INVALID_ESCAPE;
		return false;
	}
}

static struct item *
parse_string (struct tokenizer *self) {
	struct buffer buf = BUFFER_INITIALIZER;
	struct item *item = NULL;
	char c;

	while (true)
	switch ((c = *self->cursor++)) {
	case '\0':
		self->cursor--;
		self->error = PARSE_ERROR_EOF;
		goto end;
	case '"':
		if (buf.memory_failure
		 || !(item = new_string (buf.s, buf.len)))
			self->error = PARSE_ERROR_MEMORY;
		goto end;
	case '\\':
		if (decode_escape_sequence (self, &buf))
			break;
		goto end;
	default:
		buffer_append_c (&buf, c);
	}

end:
	free (buf.s);
	return item;
}

static struct item *
parse_word (struct tokenizer *self) {
	struct buffer buf = BUFFER_INITIALIZER;
	struct item *item = NULL;
	char c;

	// Here we accept almost anything that doesn't break the grammar
	while (!strchr (" []\"", (c = *self->cursor++)) && (unsigned char) c > ' ')
		buffer_append_c (&buf, c);
	self->cursor--;

	if (buf.memory_failure)
		self->error = PARSE_ERROR_MEMORY;
	else if (!buf.len)
		self->error = PARSE_ERROR_INVALID_INPUT;
	else if (!(item = new_word (buf.s, buf.len)))
		self->error = PARSE_ERROR_MEMORY;

	free (buf.s);
	return item;
}

static struct item *parse_item_list (struct tokenizer *);

static struct item *
parse_list (struct tokenizer *self) {
	struct item *list = parse_item_list (self);
	if (self->error) {
		assert (list == NULL);
		return NULL;
	}
	if (!*self->cursor) {
		self->error = PARSE_ERROR_EOF;
		item_free_list (list);
		return NULL;
	}
	assert (*self->cursor == ']');
	self->cursor++;
	return new_list (list);
}

static struct item *
parse_item (struct tokenizer *self) {
	char c;
	switch ((c = *self->cursor++)) {
	case '[':  return parse_list (self);
	case '"':  return parse_string (self);
	default:;
	}

	self->cursor--;
	return parse_word (self);
}

static struct item *
parse_item_list (struct tokenizer *self) {
	struct item *head = NULL;
	struct item **tail = &head;

	char c;
	bool expected = true;
	while ((c = *self->cursor) && c != ']') {
		if (isspace (c)) {
			self->cursor++;
			expected = true;
			continue;
		} else if (!expected) {
			self->error = PARSE_ERROR_UNEXPECTED_INPUT;
			goto fail;
		}

		if (!(*tail = parse_item (self)))
			goto fail;
		tail = &(*tail)->next;
		expected = false;
	}
	return head;

fail:
	item_free_list (head);
	return NULL;
}

static struct item *
parse (const char *s, const char **error) {
	struct tokenizer self = { .cursor = s, .error = PARSE_ERROR_OK };
	struct item *list = parse_item_list (&self);
	if (!self.error && *self.cursor != '\0') {
		self.error = PARSE_ERROR_UNEXPECTED_INPUT;
		item_free_list (list);
		list = NULL;
	}

#define XX(x, y) y,
	static const char *strings[PARSE_ERROR_COUNT] =
		{ PARSE_ERROR_TABLE (XX) };
#undef XX

	static char error_buf[128];
	if (self.error && error) {
		snprintf (error_buf, sizeof error_buf, "at character %d: %s",
			(int) (self.cursor - s) + 1, strings[self.error]);
		*error = error_buf;
	}
	return list;
}

// --- Runtime -----------------------------------------------------------------

struct context {
	struct item *stack;                 ///< The current top of the stack
	size_t stack_size;                  ///< Number of items on the stack

	char *error;                        ///< Error information
	bool error_is_fatal;                ///< Whether the error can be catched
	bool memory_failure;                ///< Memory allocation failure

	void *user_data;                    ///< User data
};

/// Internal handler for a function
typedef bool (*handler_fn) (struct context *);

struct fn {
	struct fn *next;                    ///< The next link in the chain

	handler_fn handler;                 ///< Internal C handler, or NULL
	struct item *script;                ///< Alternatively runtime code
	char name[];                        ///< The name of the function
};

struct fn *g_functions;                 ///< Maps words to functions

static void
context_init (struct context *ctx) {
	ctx->stack = NULL;
	ctx->stack_size = 0;

	ctx->error = NULL;
	ctx->error_is_fatal = false;
	ctx->memory_failure = false;

	ctx->user_data = NULL;
}

static void
context_free (struct context *ctx) {
	item_free_list (ctx->stack);
	ctx->stack = NULL;

	free (ctx->error);
	ctx->error = NULL;
}

static bool
set_error (struct context *ctx, const char *format, ...) {
	free (ctx->error);

	va_list ap;
	va_start (ap, format);
	ctx->error = strdup_vprintf (format, ap);
	va_end (ap);

	if (!ctx->error)
		ctx->memory_failure = true;
	return false;
}

static bool
push (struct context *ctx, struct item *item) {
	// The `item' is typically a result from new_<type>(), thus when it is null,
	// that function must have failed.  This is a shortcut for convenience.
	if (!item) {
		ctx->memory_failure = true;
		return false;
	}

	assert (item->next == NULL);
	item->next = ctx->stack;
	ctx->stack = item;
	ctx->stack_size++;
	return true;
}

static bool execute (struct context *, struct item *);

static bool
call_function (struct context *ctx, const char *name) {
	struct fn *iter;
	for (iter = g_functions; iter; iter = iter->next)
		if (!strcmp (name, iter->name))
			goto found;
	return set_error (ctx, "unknown function: %s", name);

found:
	if (iter->handler
		? iter->handler (ctx)
		: execute (ctx, iter->script))
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

static void
free_function (struct fn *fn) {
	item_free_list (fn->script);
	free (fn);
}

static void
unregister_function (const char *name) {
	for (struct fn **iter = &g_functions; *iter; iter = &(*iter)->next)
		if (!strcmp ((*iter)->name, name)) {
			struct fn *tmp = *iter;
			*iter = tmp->next;
			free_function (tmp);
			break;
		}
}

static struct fn *
prepend_new_fn (const char *name) {
	struct fn *fn = calloc (1, sizeof *fn + strlen (name) + 1);
	if (!fn)
		return NULL;

	strcpy (fn->name, name);
	fn->next = g_functions;
	return g_functions = fn;
}

static bool
register_handler (const char *name, handler_fn handler) {
	unregister_function (name);
	struct fn *fn = prepend_new_fn (name);
	if (!fn)
		return false;
	fn->handler = handler;
	return true;
}

static bool
register_script (const char *name, struct item *script) {
	unregister_function (name);
	struct fn *fn = prepend_new_fn (name);
	if (!fn)
		return false;
	fn->script = script;
	return true;
}

static bool
execute (struct context *ctx, struct item *script) {
	for (; script; script = script->next) {
		if (script->type != ITEM_STRING) {
			if (!push (ctx, new_clone (script)))
				return false;
		}
		else if (!call_function (ctx, get_word (script)))
			return false;
	}
	return true;
}

// --- Runtime library ---------------------------------------------------------

#define defn(name) static bool name (struct context *ctx)

static bool
init_runtime_library_scripts (void) {
	bool ok = true;

	// It's much cheaper (and more fun) to define functions in terms of other
	// ones.  The "unit tests" serve a secondary purpose of showing the usage.
	struct script {
		const char *name;               ///< Name of the function
		const char *definition;         ///< The defining script
	} scripts[] = {
		{ "greet", "print (.. 'hello ' (.. @1))" },
	};

	for (size_t i = 0; i < N_ELEMENTS (scripts); i++) {
		const char *error = NULL;
		struct item *script = parse (scripts[i].definition, &error);
		if (error) {
			printf ("error parsing internal script `%s': %s\n",
				scripts[i].definition, error);
			ok = false;
		} else
			ok &= register_script (scripts[i].name, script);
	}
	return ok;
}

defn (fn_print) {
	check_stack (1);
	struct item *item = pop (ctx);
	struct user_info *info = ctx->user_data;

	struct buffer buf = BUFFER_INITIALIZER;
	item_to_str (item, &buf);
	item_free (item);
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
	return register_handler ("..",     fn_concatenate);
		&& register_handler ("print",  fn_print);
		&& init_runtime_library_scripts ();
}

static void
free_runtime_library (void) {
	struct fn *next, *iter;
	for (iter = g_functions; iter; iter = next) {
		next = iter->next;
		free_function (iter);
	}
}

// --- Main --------------------------------------------------------------------

static void
process_message (const char *msg) {
	// Finally parse and execute the macro
	const char *error = NULL;
	struct item *script = parse (msg, &error);
	if (error) {
		printf ("%s: %s\r\n", "parse error", error);
		goto end;
	}

	struct context ctx;
	context_init (&ctx);
	ctx.user_data = &info;
	execute (&ctx, script);
	item_free_list (script);

	const char *failure = NULL;
	if (ctx.memory_failure)
		failure = "memory allocation failure";
	else if (ctx.error)
		failure = ctx.error;
	if (failure)
		printf ("%s: %s\r\n", "runtime error", failure);
	context_free (&ctx);
end:
	free (msg_ctx_quote);
}

int
main (int argc, char *argv[]) {
	freopen (NULL, "rb", stdin);   setvbuf (stdin,  NULL, _IOLBF, BUFSIZ);
	freopen (NULL, "wb", stdout);  setvbuf (stdout, NULL, _IOLBF, BUFSIZ);

	if (!init_runtime_library ()
	 || !register_handler (".", fn_dot))
		printf ("%s\n", "runtime library initialization failed");

	// TODO: load the entirety of stdin and execute it
	process_message ("print 'hello world\n'");

	free_runtime_library ();
	return 0;
}

