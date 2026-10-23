CC = gcc
OPENSSL358 ?= $(HOME)/pqc/openssl-3.5.8/install
OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL358)/lib64),$(OPENSSL358)/lib64,$(OPENSSL358)/lib)
INPUT ?= ../foo.txt
CIPHER ?= foo.enc
OUTPUT ?= foo.dec

CPPFLAGS += -I$(OPENSSL358)/include
LDFLAGS += -L$(OPENSSL_LIBDIR)
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: pqc_aes_256_cbc
	@printf './pqc_aes_256_cbc "%s" "%s" "%s"\n' "$(INPUT)" "$(CIPHER)" "$(OUTPUT)"
	@LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./pqc_aes_256_cbc "$(INPUT)" "$(CIPHER)" "$(OUTPUT)"

pqc_aes_256_cbc: pqc_aes_256_cbc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f pqc_aes_256_cbc foo.enc foo.dec
