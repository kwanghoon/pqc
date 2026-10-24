CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install
INPUT ?= foo.txt
RSA_PRIVATE ?= rsatest-test-priv.pem
RSA_PUBLIC ?= rsatest-test-pub.pem
RSA_CIPHER ?= rsatest-test.enc
RSA_OUTPUT ?= rsatest-test.dec
ENVELOPE_CIPHER ?= rsa-envelope-test.enc
ENVELOPE_OUTPUT ?= rsa-envelope-test.dec

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: rsatest rsa_des_crc
	@printf './rsatest "%s" "%s" "%s" "%s" "%s"\n' "$(RSA_PRIVATE)" "$(RSA_PUBLIC)" "$(INPUT)" "$(RSA_CIPHER)" "$(RSA_OUTPUT)"
	@LD_LIBRARY_PATH="$(OPENSSL102)/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./rsatest "$(RSA_PRIVATE)" "$(RSA_PUBLIC)" "$(INPUT)" "$(RSA_CIPHER)" "$(RSA_OUTPUT)"
	@cmp "$(INPUT)" "$(RSA_OUTPUT)"
	@printf './rsa_des_crc "%s" "%s" "%s" "%s" "%s"\n' "$(RSA_PUBLIC)" "$(RSA_PRIVATE)" "$(INPUT)" "$(ENVELOPE_CIPHER)" "$(ENVELOPE_OUTPUT)"
	@LD_LIBRARY_PATH="$(OPENSSL102)/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./rsa_des_crc "$(RSA_PUBLIC)" "$(RSA_PRIVATE)" "$(INPUT)" "$(ENVELOPE_CIPHER)" "$(ENVELOPE_OUTPUT)"
	@cmp "$(INPUT)" "$(ENVELOPE_OUTPUT)"

rsatest: rsatest.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

rsa_des_crc: rsa_des_crc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f rsatest rsa_des_crc rsatest-test-priv.pem rsatest-test-pub.pem rsatest-test.enc rsatest-test.dec rsa-envelope-test.enc rsa-envelope-test.dec
