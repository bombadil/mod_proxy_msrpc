APR_CFLAGS=$(shell pkg-config --cflags apr-1)
APR_LIBS=$(shell pkg-config --libs apr-1)
CHECK_CFLAGS=$(shell pkg-config --cflags check)
CHECK_LIBS=-lpthread $(shell pkg-config --libs check)
UUID_LIBS=-luuid
CFLAGS ?= -Wall -Werror

all:	check_msrpc_pdu_parser check_msrpc_sync

check_msrpc_pdu_parser.o:       check_msrpc_pdu_parser.c ../src/msrpc_pdu_parser.h ../src/msrpc_pdu_private.h
	gcc $(CFLAGS) $(APR_CFLAGS) -I../src -c -o check_msrpc_pdu_parser.o check_msrpc_pdu_parser.c

check_msrpc_sync.o:       check_msrpc_sync.c ../src/msrpc_sync.h
	gcc $(CFLAGS) -I../src -c -o check_msrpc_sync.o check_msrpc_sync.c

msrpc_pdu_parser.o:	../src/msrpc_pdu_parser.c ../src/msrpc_pdu_parser.h ../src/msrpc_pdu_private.h
	gcc $(CFLAGS) $(APR_CFLAGS) $(APR_LIBS) -I../src -c ../src/msrpc_pdu_parser.c

msrpc_sync.o:   ../src/msrpc_sync.c ../src/msrpc_sync.h
	gcc $(CFLAGS) -D_GNU_SOURCE -I../src -c ../src/msrpc_sync.c

check_msrpc_pdu_parser: check_msrpc_pdu_parser.o msrpc_pdu_parser.o
	gcc $(CFLAGS) $(APR_CFLAGS) $(APR_LIBS) $(UUID_LIBS) -o check_msrpc_pdu_parser check_msrpc_pdu_parser.o msrpc_pdu_parser.o $(CHECK_LIBS)

check_msrpc_sync: check_msrpc_sync.o msrpc_sync.o
	gcc $(CFLAGS) -o check_msrpc_sync check_msrpc_sync.o msrpc_sync.o $(CHECK_LIBS)

clean:
	rm -f check_msrpc_pdu_parser check_msrpc_sync *.o check.log

check:	check_msrpc_pdu_parser check_msrpc_sync
	./check_msrpc_pdu_parser
	./check_msrpc_sync
