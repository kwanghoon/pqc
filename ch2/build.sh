#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

make OPENSSL102=../../openssl-1.0.2u/install
cd pqc
make OPENSSL358=../../../openssl-3.5.8/install
cd ..
