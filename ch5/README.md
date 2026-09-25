# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o rsa_sha1_sign_test ./ch5/rsa_sha1_sign_test.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```

```
export LD_LIBRARY_PATH=$OPENSSL102:$LD_LIBRARY_PATH
./rsa_sha1_sign_test
```

교재 예제에서 signature를 고의로 변형해서 실패하는 경우를 테스트하는데 주석 처리함
