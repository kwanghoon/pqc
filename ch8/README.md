# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o client0 ./ch8/client0.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
gcc -o server0 ./ch8/server0.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```

```
cp ./ch8/symmKey.sec .
./server0 &
./client0
```

성공하면 connected 메시지를 출력
