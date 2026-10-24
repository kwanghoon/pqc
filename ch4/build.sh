#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OPENSSL102=${OPENSSL102:-"$SCRIPT_DIR/../../openssl-1.0.2u/install"}
OPENSSL358=${OPENSSL358:-"$SCRIPT_DIR/../../openssl-3.5.8/install"}

cd "$SCRIPT_DIR"
make OPENSSL102="$OPENSSL102"
cmp foo.txt rsatest-test.dec
printf '%s\n' "RSA file encryption test passed."
cmp foo.txt rsa-envelope-test.dec
printf '%s\n' "RSA envelope test passed."

cd pqc
make OPENSSL358="$OPENSSL358"
cmp ../foo.txt mlkem-file-test.dec
printf '%s\n' "ML-KEM file encryption test passed."
cmp ../foo.txt mlkem-envelope-test.dec
printf '%s\n' "ML-KEM envelope test passed."
