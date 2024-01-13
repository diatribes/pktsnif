CC = gcc 
#CFLAGS=-g -Wall -pedantic -std=c89 -DDEBUG=1
CFLAGS=-O3 -Wall -pedantic -std=c89
pktsnif: pktsnif.c clean
	$(CC) $(CFLAGS) -o pktsnif -Wall pktsnif.c

.PHONY: clean
clean:
	rm -f pktsnif 
