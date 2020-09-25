INC=-I/usr/local/include
OPT=-O2 -g
CFLAGS=$(INC) $(OPT)
LFLAGS=-L/usr/local/lib
LIBS=-lJudy

all: arvid

arvid: main.o mrt.o carp.o mempool.o peers.o attrs.o prefixes.o rib.o bgp.o util.o
	cc $(CFLAGS) -o arvid \
	    main.o mrt.o carp.o mempool.o peers.o attrs.o \
	    prefixes.o rib.o bgp.o util.o \
	    $(LFLAGS) $(LIBS)

main.o: main.c carp.h mrt.h
	cc -c $(CFLAGS) -o main.o main.c

mrt.o: mrt.c carp.h mempool.h mrt.h peers.h attrs.h prefixes.h bgp.h
	cc -c $(CFLAGS) -o mrt.o mrt.c

carp.o: carp.c carp.h
	cc -c $(CFLAGS) -o carp.o carp.c

mempool.o: mempool.c mempool.h carp.h
	cc -c $(CFLAGS) -o mempool.o mempool.c

peers.o: peers.c peers.h carp.h prefixes.h
	cc -c $(CFLAGS) -o peers.o peers.c

peers.h: rib.h

rib.h: prefixes.h

attrs.o: attrs.c attrs.h carp.h
	cc -c $(CFLAGS) -o attrs.o attrs.c

prefixes.o: prefixes.c prefixes.h carp.h
	cc -c $(CFLAGS) -o prefixes.o prefixes.c

rib.o: rib.c rib.h prefixes.h
	cc -c $(CFLAGS) -o rib.o rib.c

bgp.o: bgp.c bgp.h carp.h util.h prefixes.h
	cc -c $(CFLAGS) -o bgp.o bgp.c

util.o: util.c util.h carp.h
	cc -c $(CFLAGS) -o util.o util.c
