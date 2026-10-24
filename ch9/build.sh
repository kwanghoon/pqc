#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OPENSSL102=${OPENSSL102:-"$SCRIPT_DIR/../../openssl-1.0.2u/install"}
OPENSSL358=${OPENSSL358:-"$SCRIPT_DIR/../../openssl-3.5.8/install"}

cd "$SCRIPT_DIR"
make OPENSSL102="$OPENSSL102"
printf '%s\n' "RSA ssl_client/ssl_server test passed."

cd pqc
make OPENSSL358="$OPENSSL358"
printf '%s\n' "ML-KEM/ML-DSA pqc_ssl_client/pqc_ssl_server test passed."
