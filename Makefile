CFLAGS = -std=c99 -Wall -Wextra -ggdb
all: ell
ell: ell.c
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm ell
.PHONY: all clean
