CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: mkrand16 rsagenkey
	LD_LIBRARY_PATH="$(OPENSSL102)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./mkrand16
	LD_LIBRARY_PATH="$(OPENSSL102)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./rsagenkey

mkrand16: mkrand16.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

rsagenkey: rsagenkey.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f mkrand16 rsagenkey
