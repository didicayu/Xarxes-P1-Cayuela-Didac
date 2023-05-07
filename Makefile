all:
	gcc client.c -o client -ansi -pedantic -Wall -std=c17
clean:
	$(RM) client
