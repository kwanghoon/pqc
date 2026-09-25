# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=$HOME/pqc/openssl-1.0.2u

gcc -o mkrand16 mkrand16.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
gcc -o rsagenkey rsagenkey.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```

```
export LD_LIBRARY_PATH=$OPENSSL102:$LD_LIBRARY_PATH
./mkrand16
./rsagenkey
```

mkrand16을 실행하면 16바이트 난수가 생성

rsagenkey를 실행하면 pubkey.pem과 privkey.pem 파일이 생성
