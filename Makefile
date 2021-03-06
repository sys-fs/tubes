CC=cc
override CFLAGS+=-std=c99 -Wall -pedantic -O2 -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE
LDFLAGS=-lcrypto -lssl
PREFIX=/usr/local
MANPREFIX=${PREFIX}/share/man

it:
	${CC} -s tubes.c ${CFLAGS} ${LDFLAGS} -o tubes

install: it
	echo installing executable to ${DESTDIR}${PREFIX}/bin
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f tubes ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/tubes
	echo installing manpage to ${DESTDIR}/${MANPREFIX}/man1
	cp -f tubes.1 ${DESTDIR}/${MANPREFIX}/man1
	chmod 644 ${DESTDIR}/${MANPREFIX}/man1/tubes.1

uninstall:
	echo removing executable file from ${DESTDIR}${PREFIX}/bin
	rm -f ${DESTDIR}${PREFIX}/bin/tubes
	echo removing manpage from ${DESTDIR}/${MANPREFIX}/man1
	rm -f ${DESTDIR}/${MANPREFIX}/man1/tubes.1
