CFLAGS = -std=c99 -Wall -Wextra -ggdb

all: interpreter
interpreter: interpreter.c ell.c
	$(CC) $(CFLAGS) $< -o $@
repl: repl.c ell.c
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm -f interpreter repl
.PHONY: all clean
