CC=gcc
CFLAGS=-O2
LIBS=-lpcap

sipffer:
	gcc -o $@ $@.c $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f sipffer sipffer.o core

install: sipffer
  @cp sipffer /usr/bin
  @echo 'Done!'