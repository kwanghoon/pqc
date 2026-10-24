#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OPENSSL102=${OPENSSL102:-"$SCRIPT_DIR/../../openssl-1.0.2u/install"}
OPENSSL358=${OPENSSL358:-"$SCRIPT_DIR/../../openssl-3.5.8/install"}

cd "$SCRIPT_DIR"
make OPENSSL102="$OPENSSL102"
printf '%s\n' "DES client0/server0 test passed."

cd pqc
make OPENSSL358="$OPENSSL358"
printf '%s\n' "AES-256-GCM pqc_client0/pqc_server0 test passed."
