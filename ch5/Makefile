CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: rsa_sha1_sign_test
	@printf './rsa_sha1_sign_test\n'
	@LD_LIBRARY_PATH="$(OPENSSL102)/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./rsa_sha1_sign_test

rsa_sha1_sign_test: rsa_sha1_sign_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f rsa_sha1_sign_test
