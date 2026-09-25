# ch8 빌드 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o client0 client0.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
gcc -o server0 server0.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```

