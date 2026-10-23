#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OPENSSL102=${OPENSSL102:-"$SCRIPT_DIR/../../openssl-1.0.2u/install"}
OPENSSL358=${OPENSSL358:-"$SCRIPT_DIR/../../openssl-3.5.8/install"}

cd "$SCRIPT_DIR"
make OPENSSL102="$OPENSSL102"
cmp foo.txt foo.dec
printf '%s\n' "AES-128-CBC test passed."

cd pqc
make OPENSSL358="$OPENSSL358"
cmp ../foo.txt foo.dec
printf '%s\n' "AES-256-CBC test passed."

cd ..
