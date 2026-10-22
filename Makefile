CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server server.c -lcrypt

client: client.c
	$(CC) $(CFLAGS) -o client client.c

clean:
	rm -f server client

# Deletes all bank data; the server recreates the demo data on next start.
reset:
	rm -rf data

.PHONY: all clean reset
