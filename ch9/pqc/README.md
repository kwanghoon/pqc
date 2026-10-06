# ch9 PQC 전환: ssl_client.c/ssl_server.c → pqc_ssl_client.c/pqc_ssl_server.c

[../ssl_client.c](../ssl_client.c), [../ssl_server.c](../ssl_server.c)(RSA 인증서 기반 TLS)를 TLS 1.3 + 양자내성 키 교환·인증으로 전환한 예제 [pqc_ssl_client.c](pqc_ssl_client.c), [pqc_ssl_server.c](pqc_ssl_server.c)이다.

## 변경 내용

| 항목 | 원본 | 전환본 |
|---|---|---|
| 프로토콜 | `SSLv23_*_method` | `TLS_*_method`, TLS 1.3만 허용 |
| 키 교환 | 협상된 (EC)DHE/RSA | `X25519MLKEM768`, `SecP384r1MLKEM1024` (하이브리드 ML-KEM만 허용, 고전 단독 그룹 제거) |
| 서버 인증 | RSA 인증서 | ML-DSA-65 인증서/키 ([ch6/pqc](../../ch6/pqc)), `mldsa65` 서명 알고리즘만 허용 |
| 클라이언트 검증 | 없음 | CA 인증서로 체인과 호스트명 검증 (`SSL_VERIFY_PEER`, `SSL_set1_host`) |
| 파일/주소 | 하드코딩 | 인자로 지정 (기본값 있음) |
| 오류 처리 | `assert` | 오류 출력과 종료 코드 |

이전 전환본은 TLS 1.2를 허용하고 그룹 목록에 `secp256r1`이 있어 양자내성이 아닌 연결로 협상될 수 있었고, 서버 인증서도 RSA(`rsa_pss_rsae_sha256`)였다. TLS 1.2에는 하이브리드 ML-KEM 그룹이 없으므로 TLS 1.3만 허용한다. 서버는 ML-DSA-65가 아닌 키를 거부한다.

## 빌드 및 실행 방법

```bash
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH

cd ch9/pqc
gcc -o pqc_ssl_server pqc_ssl_server.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lssl -lcrypto
gcc -o pqc_ssl_client pqc_ssl_client.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lssl -lcrypto

C=../../ch6/pqc
./pqc_ssl_server $C/BobCert.pem $C/BobPriv.pem &   # 인자: cert key [port]
./pqc_ssl_client $C/CACert.pem                     # 인자: CA [host [port]]
```

서버는 연결 1개를 처리하고 종료한다. 성공하면 `Negotiated: TLSv1.3, group X25519MLKEM768, ...`와 HTTP 200 응답이 출력된다. 기존 RSA 인증서(`ch6/BobCert.pem`)를 주면 서버가 거부하고, 다른 CA를 주면 클라이언트가 인증서 검증 실패로 종료한다.
