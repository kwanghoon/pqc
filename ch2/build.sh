#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OPENSSL102=${OPENSSL102:-"$SCRIPT_DIR/../../openssl-1.0.2u/install"}
OPENSSL358=${OPENSSL358:-"$SCRIPT_DIR/../../../openssl-3.5.8/install"}

cd "$SCRIPT_DIR"

make OPENSSL102="$OPENSSL102"
cd pqc
make OPENSSL358="$OPENSSL358"
cd ..
