CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install
INPUT ?= foo.txt
CIPHER ?= foo.enc
OUTPUT ?= foo.dec

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: aes_128_cbc
	@printf './aes_128_cbc "%s" "%s" "%s"\n' "$(INPUT)" "$(CIPHER)" "$(OUTPUT)"
	@LD_LIBRARY_PATH="$(OPENSSL102)/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./aes_128_cbc "$(INPUT)" "$(CIPHER)" "$(OUTPUT)"

aes_128_cbc: aes_128_cbc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f aes_128_cbc foo.enc foo.dec
