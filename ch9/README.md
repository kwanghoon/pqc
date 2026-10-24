# 빌드 및 실행 방법

`$OPENSSL102`는 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 설치 경로(`.../openssl-1.0.2u/install`)입니다.

## 구성

- [ssl_server.c](ssl_server.c): 포트 4433에서 연결 하나를 받아 TLS 핸드셰이크를 수행하고 요청 헤더를 되돌려 줍니다. 현재 디렉터리의 `BobCert.pem`, `BobPriv.pem`을 읽습니다.
- [ssl_client.c](ssl_client.c): `127.0.0.1:4433`에 접속해 `CACert.pem`과 호스트명 `localhost`로 서버 인증서를 검증하고, `GET /`을 보냅니다. 협상 결과를 `Negotiated: 버전, group 그룹, cipher 암호`로 출력합니다.

## 원본 소스의 수정 사항

[pqc/](pqc/README.md)의 전환본과 구조를 맞추기 위해 다음을 수정했습니다.

- 파일 상단에 설명 주석을 추가하고 `int main()`으로 바꿨습니다.
- 클라이언트에 서버 인증서 검증(`SSL_CTX_load_verify_locations`, `SSL_VERIFY_PEER`, `X509_VERIFY_PARAM_set1_host`)을 추가했습니다. 인증서의 이름은 `localhost`여야 합니다.
- `SSL_CTX_new`, `BIO_new*`, 인증서/키 로딩 등의 반환값 검사를 추가하고, 서버의 `assert`를 `if`로 바꿨습니다(`<assert.h>` 제거). 오류 시 종료 코드는 `exit(1)`/`return 0` 대신 모두 `return 1`입니다.
- 클라이언트가 협상 결과를 출력합니다. 1.0.2에는 `SSL_get0_group_name`이 없으므로 `SSL_get_server_tmp_key`로 EC 곡선 이름을 구합니다. 서버가 기본 설정으로 RSA 키 교환을 협상하면 `group none`이 출력됩니다.

## 빌드 및 실행

```bash
export OPENSSL102=$HOME/pqc/openssl-1.0.2u/install

gcc -o ssl_client ssl_client.c -I$OPENSSL102/include -L$OPENSSL102/lib -lssl -lcrypto -ldl -lpthread
gcc -o ssl_server ssl_server.c -I$OPENSSL102/include -L$OPENSSL102/lib -lssl -lcrypto -ldl -lpthread
```

정적 라이브러리(`libssl.a`, `libcrypto.a`)로 링크하므로 `-ldl -lpthread`가 추가로 필요합니다.

`CN=localhost` 서버 인증서와 CA 인증서를 준비합니다. 아래는 현재 디렉터리에 `CACert.pem`, `BobCert.pem`, `BobPriv.pem`을 만드는 예입니다. 자세한 인증서 발급은 [ch6](../ch6/README.md)을 참고하십시오.

```bash
OSSL=$OPENSSL102/bin/openssl
$OSSL genrsa -out CAPriv.pem 2048
$OSSL req -new -key CAPriv.pem -subj "/C=KR/O=Test/CN=Test CA" -out CAReq.pem
$OSSL x509 -req -days 365 -in CAReq.pem -signkey CAPriv.pem -out CACert.pem
$OSSL genrsa -out BobPriv.pem 2048
$OSSL req -new -key BobPriv.pem -subj "/C=KR/O=Test/CN=localhost" -out BobReq.pem
$OSSL x509 -req -days 365 -in BobReq.pem -CA CACert.pem -CAkey CAPriv.pem -CAcreateserial -out BobCert.pem
```

```
./ssl_server &
./ssl_client
Negotiated: TLSv1.2, group none, cipher AES256-GCM-SHA384
HTTP/1.0 200 OK
Content-type: text/plain


Connection Established
Request headers:

GET / HTTP/1.0

-----------------------------------

```

서버는 연결 하나를 처리하고 종료합니다. 다른 CA의 `CACert.pem`으로 클라이언트를 실행하면 인증서 검증에 실패해 `Error connecting to server`와 `certificate verify failed`를 출력하고 종료 코드 1로 끝납니다.

## Makefile

```bash
make OPENSSL102=$HOME/pqc/openssl-1.0.2u/install
```

`ssl_client`, `ssl_server`를 빌드하고 `tls-test/`에 위 인증서를 발급한 뒤, 정상 연결과 다른 CA 거부를 확인합니다. `make clean`으로 산출물을 지웁니다.

## build.sh

```bash
./build.sh
```

`ch9`에서 위 `make`(OpenSSL 1.0.2u)를 실행한 뒤 `pqc`로 이동해 `make`(OpenSSL 3.5.8)를 실행합니다. 두 번째 단계는 [pqc/README.md](pqc/README.md)를 참고하십시오. 경로는 환경 변수 `OPENSSL102`, `OPENSSL358`로 바꿀 수 있습니다(기본값: `../../openssl-1.0.2u/install`, `../../openssl-3.5.8/install`).
