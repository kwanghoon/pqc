CC = gcc
OPENSSL358 ?= $(HOME)/pqc/openssl-3.5.8/install
OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL358)/lib64),$(OPENSSL358)/lib64,$(OPENSSL358)/lib)

CPPFLAGS += -I$(OPENSSL358)/include
LDFLAGS += -L$(OPENSSL_LIBDIR)
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: pqc_mldsa_sign_test
	@printf './pqc_mldsa_sign_test\n'
	@LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./pqc_mldsa_sign_test

pqc_mldsa_sign_test: pqc_mldsa_sign_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f pqc_mldsa_sign_test
