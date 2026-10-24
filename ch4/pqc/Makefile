CC = gcc
OPENSSL358 ?= $(HOME)/pqc/openssl-3.5.8/install
OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL358)/lib64),$(OPENSSL358)/lib64,$(OPENSSL358)/lib)
OPENSSL_CLI ?= $(OPENSSL358)/bin/openssl
INPUT ?= ../foo.txt
FILE_PRIVATE ?= mlkem-file-test-priv.pem
FILE_PUBLIC ?= mlkem-file-test-pub.pem
FILE_ENVELOPE ?= mlkem-file-test.enc
FILE_OUTPUT ?= mlkem-file-test.dec
ENVELOPE_PUBLIC ?= mlkem-envelope-test-pub.pem
ENVELOPE_PRIVATE ?= mlkem-envelope-test-priv.pem
ENVELOPE_CIPHER ?= mlkem-envelope-test.enc
ENVELOPE_OUTPUT ?= mlkem-envelope-test.dec

CPPFLAGS += -I$(OPENSSL358)/include
LDFLAGS += -L$(OPENSSL_LIBDIR)
LDLIBS += -lcrypto

.PHONY: all run clean

all: run

run: pqc_mlkem_file pqc_mlkem_envelope
	@printf './pqc_mlkem_file "%s" "%s" "%s" "%s" "%s"\n' "$(FILE_PRIVATE)" "$(FILE_PUBLIC)" "$(INPUT)" "$(FILE_ENVELOPE)" "$(FILE_OUTPUT)"
	@LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./pqc_mlkem_file "$(FILE_PRIVATE)" "$(FILE_PUBLIC)" "$(INPUT)" "$(FILE_ENVELOPE)" "$(FILE_OUTPUT)"
	@cmp "$(INPUT)" "$(FILE_OUTPUT)"
	@printf 'umask 077; openssl genpkey -algorithm ML-KEM-768 -out "%s"\n' "$(ENVELOPE_PRIVATE)"
	@umask 077; LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" "$(OPENSSL_CLI)" genpkey -algorithm ML-KEM-768 -out "$(ENVELOPE_PRIVATE)"
	@printf 'openssl pkey -in "%s" -pubout -out "%s"\n' "$(ENVELOPE_PRIVATE)" "$(ENVELOPE_PUBLIC)"
	@LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" "$(OPENSSL_CLI)" pkey -in "$(ENVELOPE_PRIVATE)" -pubout -out "$(ENVELOPE_PUBLIC)"
	@printf './pqc_mlkem_envelope "%s" "%s" "%s" "%s" "%s"\n' "$(ENVELOPE_PUBLIC)" "$(ENVELOPE_PRIVATE)" "$(INPUT)" "$(ENVELOPE_CIPHER)" "$(ENVELOPE_OUTPUT)"
	@LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./pqc_mlkem_envelope "$(ENVELOPE_PUBLIC)" "$(ENVELOPE_PRIVATE)" "$(INPUT)" "$(ENVELOPE_CIPHER)" "$(ENVELOPE_OUTPUT)"
	@cmp "$(INPUT)" "$(ENVELOPE_OUTPUT)"

pqc_mlkem_file: pqc_mlkem_file.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

pqc_mlkem_envelope: pqc_mlkem_envelope.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f pqc_mlkem_file pqc_mlkem_envelope mlkem-file-test-priv.pem mlkem-file-test-pub.pem mlkem-file-test.enc mlkem-file-test.dec mlkem-envelope-test-pub.pem mlkem-envelope-test-priv.pem mlkem-envelope-test.enc mlkem-envelope-test.dec
