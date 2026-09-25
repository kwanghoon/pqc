# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o aes_128_cbc aes_128_cbc.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```

```
export LD_LIBRARY_PATH=$OPENSSL102:$LD_LIBRARY_PATH
./aes_128_cbc ./ch3/foo.txt foo.enc foo.dec
```

foo.txt를 암호화한 foo.enc 파일과 다시 푼 foo.dec 파일을 생성