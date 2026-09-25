# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o ssl_client ./ch9/ssl_client.c -I$OPENSSL102/include -L$OPENSSL102 -lssl -lcrypto -ldl -lpthread
gcc -o ssl_server ./ch9/ssl_server.c -I$OPENSSL102/include -L$OPENSSL102 -lssl -lcrypto -ldl -lpthread
```

정적 라이브러리(`libssl.a`, `libcrypto.a`)로 링크하므로 `-ldl -lpthread`가 추가로 필요합니다.
