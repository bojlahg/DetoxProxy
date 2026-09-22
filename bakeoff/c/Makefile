CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11

all: proxy

proxy: proxy.c
	$(CC) $(CFLAGS) -o proxy proxy.c

asan: proxy-asan

proxy-asan: proxy.c
	$(CC) -g -fsanitize=address,undefined -Wall -Wextra -std=c11 -o proxy-asan proxy.c

clean:
	rm -f proxy proxy-asan

.PHONY: all asan clean