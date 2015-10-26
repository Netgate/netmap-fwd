
OUT=netmap-fwd
OBJS=arp.o cleanup.o cli.o config.o ether.o event.o icmp.o if.o inet.o
OBJS+=ip.o net.o netmap.o netmap-fwd.o radix.o util.o
INCLUDES=arp.h cleanup.h cli.h config.h counters.h ether.h event.h icmp.h
INCLUDES+=if.h inet.h ip.h net.h netmap.h radix.h util.h

LDFLAGS=-L/usr/local/lib -levent -lutil -lucl
CCFLAGS=-O2 -fPIC -g -Wall -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CCFLAGS=-O2 -fPIC -g -Wall -Wshadow -Wcast-qual -Wwrite-strings
CCFLAGS+=-Wredundant-decls -Wnested-externs -Winline -I/usr/local/include

all: $(OUT)

$(OUT): $(OBJS) $(INCLUDES)
	$(CC) $(CCFLAGS) -o $(OUT) $(OBJS) $(LDFLAGS)

.c.o: $(INCLUDES)
	$(CC) $(CCFLAGS) -c $<

clean:
	rm -f *.o *.core tags $(OUT)

install: $(OUT)
	install -m 0755 netmap-fwd $(PREFIX)/usr/local/sbin
	install -b -m 0644 netmap-fwd.conf $(PREFIX)/usr/local/etc

svn-propset:
	svn propset svn:keywords "Id" *c *h
