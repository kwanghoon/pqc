# OpenSSL 3.5.8 설치 방법 (PQC 실습용)

OpenSSL 3.5 계열은 ML-KEM, ML-DSA, SLH-DSA 등 포스트 양자 암호(PQC) 알고리즘을 기본 제공합니다.
아래는 openssl-3.5.8 소스를 내려받아 프로젝트 내 `install` 디렉터리에 빌드/설치하는 방법입니다.

## 설치

```bash
cd pqc
wget https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz

tar xzf openssl-3.5.8.tar.gz
cd openssl-3.5.8
export OPENSSL358=`pwd`/install
echo $OPENSSL358

./config --prefix=$OPENSSL358 --openssldir=$OPENSSL358/openssl

make
make install
```

## 설치 확인

```bash
$OPENSSL358/bin/openssl version

OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)
```

