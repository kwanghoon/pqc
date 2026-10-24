# ch9 PQC 전환: ssl_client.c/ssl_server.c → pqc_ssl_client.c/pqc_ssl_server.c

[../ssl_client.c](../ssl_client.c), [../ssl_server.c](../ssl_server.c)(RSA 인증서 기반 TLS)를 TLS 1.3 + 양자내성 키 교환·인증으로 전환한 예제 [pqc_ssl_client.c](pqc_ssl_client.c), [pqc_ssl_server.c](pqc_ssl_server.c)이다.

## 알고리즘 전환에 필요한 차이

| 항목 | 원본 | 전환본 |
|---|---|---|
| 초기화 | `SSL_library_init()`, `SSL_load_error_strings()`, `bio_err` | 삭제 (OpenSSL 3.x는 자동 초기화) |
| 메서드 | `SSLv23_client_method()` / `SSLv23_server_method()` | `TLS_client_method()` / `TLS_server_method()` |
| 프로토콜 | 협상 (TLS 1.2 등) | `SSL_CTX_set_min/max_proto_version`으로 TLS 1.3만 허용 (하이브리드 ML-KEM 그룹은 TLS 1.2에 없음) |
| 키 교환 | 협상 (RSA 또는 ECDHE) | `SSL_CTX_set1_groups_list("X25519MLKEM768:SecP384r1MLKEM1024")`, 고전 단독 그룹 제거 |
| 서명 알고리즘 | 협상 | `SSL_CTX_set1_sigalgs_list("mldsa65")` |
| 서버 키 | RSA 인증서/키 | ML-DSA-65 인증서/키. `EVP_PKEY_is_a(SSL_CTX_get0_privatekey(ctx), "ML-DSA-65")`로 다른 키는 거부 (`<openssl/evp.h>` 추가) |
| 협상 결과 출력 | `SSL_get_server_tmp_key`로 EC 곡선 이름 | `SSL_get0_group_name(ssl)` (1.0.2에는 없는 API) |

원본은 소스에 알고리즘이 없고 OpenSSL 기본값과 PEM 파일이 정하므로, 전환은 위 설정 코드를 삽입하는 것과 입력 파일을 ML-DSA 인증서로 바꾸는 것이다.

## 원본과 같게 유지한 부분

파일 상단 주석, 헤더 순서, `int main()`, 변수 선언, 파일 이름(`BobCert.pem`, `BobPriv.pem`, `CACert.pem`), 접속 주소(`127.0.0.1:4433`), 호스트명(`localhost`), BIO 구성과 호출 순서, 요청/응답 출력, 오류 메시지를 그대로 두었다. 명령행 인자, `static` 보조 함수, `goto`는 쓰지 않는다.

## 원본과 함께 수정한 부분

양쪽 모두 다음을 동일하게 고쳤다(`ssl_client.c`, `ssl_server.c`, `pqc_ssl_client.c`, `pqc_ssl_server.c`).

- 클라이언트의 서버 인증서 검증 추가: `SSL_CTX_load_verify_locations("CACert.pem")`, `SSL_VERIFY_PEER`, `X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), "localhost", 0)`. 인증서 이름이 `localhost`인 경우를 처리하며, 접속 주소는 원본처럼 `127.0.0.1`이다. (`SSL_set1_host`는 1.0.2에 없어서 `X509_VERIFY_PARAM_*`을 썼다.)
- 반환값 검사 추가: `SSL_CTX_new`, `SSL_CTX_*` 설정/로딩, `BIO_new*`, `BIO_new_accept`, `BIO_new_fp`. 서버의 `assert`는 `if`로 바꿨다. `int` 결과는 `res != 1`, 포인터는 `== NULL`로 검사한다.
- 오류 시 종료 코드를 `return 1`로 통일했다(`exit(1)`, 서버의 `return 0` 포함). 이에 따라 `<assert.h>`는 뺐다.
- 클라이언트의 협상 결과 출력 한 줄(`Negotiated: ...`) 추가.

서버는 연결 하나만 처리하고 종료한다. 오류 경로에서 자원을 해제하지 않는 점은 원본 그대로이다.

## 빌드 및 실행 방법

`$OPENSSL358`은 OpenSSL 3.5.8 설치 경로(`.../openssl-3.5.8/install`)이다.

```bash
export OPENSSL358=$HOME/pqc/openssl-3.5.8/install
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH

cd ch9/pqc
gcc -o pqc_ssl_server pqc_ssl_server.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lssl -lcrypto
gcc -o pqc_ssl_client pqc_ssl_client.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lssl -lcrypto

# ML-DSA-65 인증서: ch6/pqc의 CACert.pem, BobCert.pem(CN=localhost), BobPriv.pem을 현재 디렉터리에 복사
cp ../../ch6/pqc/{CACert.pem,BobCert.pem,BobPriv.pem} .

./pqc_ssl_server &
./pqc_ssl_client
```

서버는 연결 1개를 처리하고 종료한다. 성공하면 `Negotiated: TLSv1.3, group X25519MLKEM768, cipher TLS_AES_256_GCM_SHA384`와 HTTP 200 응답이 출력된다. RSA 키를 서버에 주면 `BobPriv.pem is not an ML-DSA-65 key`로 종료하고, 다른 CA를 쓰면 클라이언트가 `certificate verify failed`로 종료한다.

### Makefile

```bash
make OPENSSL358=$HOME/pqc/openssl-3.5.8/install
```

`pqc_ssl_client`, `pqc_ssl_server`를 빌드하고 `pqc-tls-test/`에 ML-DSA-65 CA와 `CN=localhost` 서버 인증서를 발급한 뒤 다음을 확인한다. `ch6/pqc`의 샘플 파일은 건드리지 않는다. `make clean`으로 산출물을 지운다.

1. TLS 1.3과 하이브리드 ML-KEM 그룹으로 연결하고 응답을 받는다.
2. 다른 CA로 검증하는 클라이언트가 서버 인증서를 거부한다.
3. RSA 키를 준 서버가 종료한다.

상위 디렉터리의 [../build.sh](../build.sh)는 원본(OpenSSL 1.0.2u)과 이 전환본(OpenSSL 3.5.8)을 차례로 실행한다.
