#!/bin/sh
set -eu

# README.md (RSA, OpenSSL 1.0.2u)와 README_PQC.md (ML-DSA-65, OpenSSL 3.5.8)의
# 인증서 발급 절차를 한 번에 실행한다. 기존 PEM 샘플을 덮어쓰지 않도록
# WORKDIR(기본값: 임시 디렉터리)에서 실행한다.
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
OPENSSL102=${OPENSSL102:-"$SCRIPT_DIR/../../openssl-1.0.2u/install"}
OPENSSL358=${OPENSSL358:-"$SCRIPT_DIR/../../openssl-3.5.8/install"}

if [ -z "${WORKDIR:-}" ]; then
    WORKDIR=$(mktemp -d)
    trap 'rm -rf "$WORKDIR"' EXIT
else
    mkdir -p "$WORKDIR"
fi

OSSL102="$OPENSSL102/bin/openssl"
OSSL358="$OPENSSL358/bin/openssl"
if [ -d "$OPENSSL358/lib64" ]; then
    LIB358="$OPENSSL358/lib64"
else
    LIB358="$OPENSSL358/lib"
fi

ossl102() { "$OSSL102" "$@"; }
ossl358() { LD_LIBRARY_PATH="$LIB358${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$OSSL358" "$@"; }

# ---------------------------------------------------------------- RSA
cp "$SCRIPT_DIR/test.txt" "$WORKDIR/test.txt"
cd "$WORKDIR"

# CA 개인키와 자기서명 인증서 (루트 인증서)
ossl102 genrsa -out CAPriv.pem 1024
ossl102 req -new -key CAPriv.pem -subj '/C=KR/ST=CA-State/L=Gwangju/O=JNU/CN=Gil-Dong' -out CAReq.pem
ossl102 x509 -req -days 3650 -in CAReq.pem -signkey CAPriv.pem -out CACert.pem
ossl102 verify -CAfile CACert.pem CACert.pem
ossl102 x509 -noout -in CACert.pem -fingerprint

# Alice 인증서 (개인키는 암호로 보호)
ossl102 req -new -keyout AlicePriv.pem -subj '/C=KR/ST=CA-State/O=JNU/CN=Alice' \
    -passout 'pass:Alice is making cert' -out AliceReq.pem
ossl102 x509 -req -days 365 -CA CACert.pem -CAkey CAPriv.pem -CAcreateserial \
    -in AliceReq.pem -out AliceCert.pem
ossl102 verify -CAfile CACert.pem AliceCert.pem

# Bob 인증서 (기존 일련번호 파일 사용)
ossl102 req -new -keyout BobPriv.pem -subj '/C=KR/ST=CA-State/O=JNU/CN=Bob' -out BobReq.pem -nodes
ossl102 x509 -req -days 365 -CA CACert.pem -CAkey CAPriv.pem -CAserial CACert.srl \
    -in BobReq.pem -out BobCert.pem
ossl102 verify -CAfile CACert.pem BobCert.pem
ossl102 x509 -text -noout -in BobCert.pem >/dev/null

# 전자 서명 및 검증
ossl102 smime -sign -in test.txt -inkey AlicePriv.pem -signer AliceCert.pem \
    -passin 'pass:Alice is making cert' -out mail.msg
ossl102 smime -verify -in mail.msg -signer AliceCert.pem -CAfile CACert.pem -out recover.txt
# S/MIME은 줄바꿈을 CRLF로 정규화하므로 CR을 제거하고 비교한다.
tr -d '\r' < recover.txt | cmp - test.txt

# 서명 + 암호화, 복호화 + 검증
ossl102 smime -sign -in test.txt -signer AliceCert.pem -inkey AlicePriv.pem \
    -passin 'pass:Alice is making cert' -text -out signed.msg
ossl102 smime -encrypt -in signed.msg -out sien.msg -from Alice -to Bob \
    -subject "Sign and Encryption test" -aes128 BobCert.pem
ossl102 smime -decrypt -in sien.msg -out decryp.msg -recip BobCert.pem -inkey BobPriv.pem
ossl102 smime -verify -in decryp.msg -out verif.txt -signer AliceCert.pem -CAfile CACert.pem
grep -qF "$(head -n 1 test.txt)" verif.txt
printf '%s\n' "RSA certificate test passed."

# ---------------------------------------------------------------- ML-DSA-65
mkdir pqc
cd pqc

# CA: ML-DSA-65 키 생성 + 자체 서명 인증서
ossl358 genpkey -algorithm ML-DSA-65 -out CAPriv.pem
ossl358 req -new -x509 -key CAPriv.pem -days 3650 \
    -subj "/C=KR/O=PQC Test/CN=PQC Test CA" -out CACert.pem

# Bob: ML-DSA-65 키 생성 + 인증서 요청
ossl358 genpkey -algorithm ML-DSA-65 -out BobPriv.pem
ossl358 req -new -key BobPriv.pem -subj "/C=KR/O=PQC Test/CN=localhost" -out BobReq.pem

# CA가 Bob 인증서 발급
ossl358 x509 -req -in BobReq.pem -CA CACert.pem -CAkey CAPriv.pem \
    -CAcreateserial -days 365 -out BobCert.pem

# 검증
ossl358 verify -CAfile CACert.pem BobCert.pem
ossl358 x509 -in BobCert.pem -noout -text | grep -E "Signature Algorithm|Public Key Algorithm"
ossl358 x509 -in BobCert.pem -noout -text | grep -q "ML-DSA-65"
printf '%s\n' "ML-DSA-65 certificate test passed."

if [ -n "${KEEP_WORKDIR:-}" ]; then
    trap - EXIT
    printf '%s\n' "Generated files are in $WORKDIR"
fi
