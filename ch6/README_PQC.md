# ch6 PQC 전환: ML-DSA-65 기반 CA / Bob 인증서 발급

ch6에는 전환할 C 프로그램이 없다. 대신 이후 장에서 읽는 PEM 파일을 만든다.
기존 PEM(`CACert.pem`, `BobCert.pem` 등)은 모두 RSA이므로, ch9 TLS 서버 인증을 양자내성으로 만들려면 아래 절차로 ML-DSA-65 인증서를 새로 발급한다.

## 1. 이후 장에서의 사용처

| ch6 파일 | 사용처 |
|---|---|
| `BobCert.pem`, `BobPriv.pem` | ch9 `ssl_server.c`, `pqc/pqc_ssl_server.c`가 현재 디렉터리에서 로드 |
| `CACert.pem` | 서버 인증서 검증 시(`openssl s_client -CAfile`) 사용. 현재 클라이언트 코드는 검증하지 않음 |
| Alice 관련 파일, `CAPriv.pem` | ch6 S/MIME 시연에서만 사용 |

## 2. 원본과 전환본

| 원본 (RSA) | 전환본 (ML-DSA-65) |
|---|---|
| `CAPriv.pem` / `CACert.pem` | 동일 이름으로 새로 발급 (또는 별도 디렉터리) |
| `BobPriv.pem` / `BobReq.pem` / `BobCert.pem` | 동일 이름으로 새로 발급 |

기존 RSA 파일과 분리하기 위해 전환 키와 인증서는 [ch6/pqc/](pqc)에 보관한다. 이 디렉터리에는 `CAPriv.pem`, `CACert.pem`, `CACert.srl`, `BobPriv.pem`, `BobReq.pem`, `BobCert.pem`이 들어 있다(테스트용 키).

## 3. 발급 절차 (OpenSSL 3.5 이상)

`ch6/pqc/`의 파일은 아래 절차로 이미 생성되어 있다. 다시 만들려면 `ch6`에서 실행한다.

```bash
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH
OSSL=$OPENSSL358/bin/openssl
mkdir -p pqc && cd pqc

# 1) CA: ML-DSA-65 키 생성 + 자체 서명 인증서
$OSSL genpkey -algorithm ML-DSA-65 -out CAPriv.pem
$OSSL req -new -x509 -key CAPriv.pem -days 3650 \
    -subj "/C=KR/O=PQC Test/CN=PQC Test CA" -out CACert.pem

# 2) Bob: ML-DSA-65 키 생성 + 인증서 요청
$OSSL genpkey -algorithm ML-DSA-65 -out BobPriv.pem
$OSSL req -new -key BobPriv.pem \
    -subj "/C=KR/O=PQC Test/CN=localhost" -out BobReq.pem

# 3) CA가 Bob 인증서 발급
$OSSL x509 -req -in BobReq.pem -CA CACert.pem -CAkey CAPriv.pem \
    -CAcreateserial -days 365 -out BobCert.pem
```

원본과 달리 다음이 바뀌었다.

- `genrsa`는 `genpkey -algorithm ML-DSA-65`로 대체한다.
- ML-DSA는 서명 안에서 해시를 처리하므로 `-sha256` 옵션을 주지 않는다.
- `-nodes`는 필요 없다. `genpkey`는 기본적으로 개인키를 암호화하지 않는다. 필요하면 `-aes256`을 추가한다.
- Bob의 CN은 접속 호스트명(`localhost`)으로 맞춘다.

## 4. 검증

```bash
$OSSL verify -CAfile CACert.pem BobCert.pem
$OSSL x509 -in BobCert.pem -noout -text | grep -E "Signature Algorithm|Public Key Algorithm"
```

기대 결과: `BobCert.pem: OK`, 서명/공개키 알고리즘 모두 `ML-DSA-65`.

## 5. ch9 TLS와 함께 확인

`BobCert.pem`, `BobPriv.pem`을 ch9 서버 실행 디렉터리에 복사하고 서버를 띄운 뒤 접속한다.

```bash
# ch9/pqc 빌드: gcc -o pqc_ssl_server pqc_ssl_server.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lssl -lcrypto
./pqc_ssl_server &
echo | $OSSL s_client -connect localhost:4433 -CAfile CACert.pem
```

실제 확인 결과 (OpenSSL 3.5.8):

```
Negotiated TLS1.3 group: X25519MLKEM768
Verification: OK
Protocol: TLSv1.3
```

키 교환(X25519MLKEM768)과 서버 인증(ML-DSA-65 인증서)이 모두 양자내성이 된다. ch9 코드는 수정할 필요가 없다.

## 6. 참고 및 제한

- Alice 인증서와 S/MIME(`openssl smime`) 시연은 이 문서의 범위에 포함하지 않았다. 필요하면 Bob과 같은 방식으로 발급할 수 있으나 S/MIME 서명의 ML-DSA 지원은 별도 검증이 필요하다.
- 개인키 파일(`*Priv.pem`)은 테스트용이므로 평문이다. 실제 환경에서는 권한(`chmod 600`)과 암호화를 적용한다.
- 클라이언트(`pqc_ssl_client.c`)는 인증서를 검증하지 않는다. 검증하려면 `SSL_CTX_load_verify_locations`와 `SSL_VERIFY_PEER` 설정을 추가해야 한다.
