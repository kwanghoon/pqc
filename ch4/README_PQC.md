# ch4 PQC 파일 암호화 예제

## 목적

[rsatest.c](rsatest.c)는 RSA 공개키로 파일 내용을 직접 암호화하고 개인키로 복호화하는 예제다. RSA는 양자 컴퓨터 공격에 취약하고, 공개키 암호화는 처리 가능한 입력 크기도 제한적이다.

[pqc/pqc_mlkem_file.c](pqc/pqc_mlkem_file.c)는 이 흐름을 ML-KEM 기반 키 캡슐화와 AES-256-GCM 파일 암호화로 대체한다. RSA 암호 관련 API는 사용하지 않는다.

## 원본과 전환본

| 원본 | 전환본 | 변경 내용 |
|---|---|---|
| [rsatest.c](rsatest.c) | [pqc/pqc_mlkem_file.c](pqc/pqc_mlkem_file.c) | RSA-OAEP 직접 암호화 → ML-KEM-768 + AES-256-GCM |
| [rsa_des_crc.c](rsa_des_crc.c) | [pqc/pqc_mlkem_envelope.c](pqc/pqc_mlkem_envelope.c) | RSA + 3DES-CBC 전자 봉투 → ML-KEM-768 + AES-256-GCM 봉투 |

## 암호화 흐름

1. OpenSSL 3.5.8의 `ML-KEM-768`으로 임시 키 쌍을 생성한다.
2. `EVP_PKEY_encapsulate_init()`과 `EVP_PKEY_encapsulate()`로 공유 비밀과 KEM 암호문을 만든다.
3. 공유 비밀의 32바이트 키를 사용하고, `RAND_bytes()`로 생성한 12바이트 nonce와 함께 `EVP_aes_256_gcm()`으로 입력 파일을 암호화한다.
4. 봉투 파일에 KEM 암호문, nonce, AES-GCM 암호문 및 16바이트 인증 태그를 기록한다.
5. `EVP_PKEY_decapsulate_init()`과 `EVP_PKEY_decapsulate()`로 공유 비밀을 복원한 뒤, 인증 태그를 검증하며 AES-GCM 복호화를 수행한다.

봉투 형식은 다음 순서다.

| 필드 | 크기 |
|---|---:|
| 매직 값 `PQM1` | 4바이트 |
| KEM 암호문 길이 | 4바이트 (big-endian) |
| ML-KEM 암호문 | 길이 필드에 지정된 크기 |
| AES-GCM nonce | 12바이트 |
| AES-GCM 암호문 | 나머지 데이터에서 태그 크기를 뺀 길이 |
| AES-GCM 인증 태그 | 16바이트 |

인증 태그 검증에 실패하면 복호화는 실패하며 부분 출력 파일을 제거한다.

## 빌드 및 실행

아래 예시는 OpenSSL 3.5.8이 `/home/khchoi/work/pqc/openssl-3.5.8/install`에 설치된 환경을 기준으로 한다. `pqc_mlkem_file.c`는 `../foo.txt`를 입력으로 사용하므로 `ch4/pqc` 디렉터리에서 실행한다.

```sh
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
cd /home/khchoi/work/pqc/ch4/pqc

gcc -o pqc_mlkem_file pqc_mlkem_file.c \
    -I"$OPENSSL358/include" -L"$OPENSSL358/lib64" -lcrypto

export LD_LIBRARY_PATH="$OPENSSL358/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./pqc_mlkem_file
diff ../foo.txt ./pqc_mlkem_file.dec
```

정상 실행 시 `pqc_mlkem_file.enc`와 `pqc_mlkem_file.dec`가 생성된다. `diff` 출력이 없으면 복호화 결과가 입력 파일과 일치한다.

이 예제는 시연을 위해 키 쌍을 매 실행마다 메모리에서 생성하고 같은 실행 중 복호화한다. 개인키를 저장하거나 봉투와 함께 배포하지 않으므로, 생성된 봉투는 다음 실행에서 복호화할 수 없다.

## 전자 봉투 예제

[rsa_des_crc.c](rsa_des_crc.c)는 RSA로 3DES 세션 키를 보호하는 전자 봉투 예제다. 대응하는 [pqc/pqc_mlkem_envelope.c](pqc/pqc_mlkem_envelope.c)는 RSA 대신 ML-KEM-768으로 AES-256 키를 캡슐화하고, 3DES-CBC 대신 AES-256-GCM으로 데이터를 암호화·인증한다. 봉투 헤더(매직 값, KEM 암호문, nonce)도 GCM의 추가 인증 데이터로 보호한다.

인자는 원본과 동일하게 `공개키 개인키 평문 봉투 복호문` 순서다. 키 파일이 없으면 ML-KEM-768 키 쌍을 PEM(`PUBLIC KEY`, `PRIVATE KEY`)으로 생성하며, 개인키는 0600 권한으로 저장한다.

```sh
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
cd /home/khchoi/work/pqc/ch4/pqc

gcc -o pqc_mlkem_envelope pqc_mlkem_envelope.c \
    -I"$OPENSSL358/include" -L"$OPENSSL358/lib64" -lcrypto

export LD_LIBRARY_PATH="$OPENSSL358/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./pqc_mlkem_envelope mlkem_pub.pem mlkem_priv.pem ../plain.txt envelope.bin plain_out.txt
diff ../plain.txt plain_out.txt
```

봉투 형식은 `PQE1`(4바이트), KEM 암호문 길이(4바이트, big-endian), ML-KEM 암호문, nonce(12바이트), AES-GCM 암호문, 인증 태그(16바이트) 순서다. 인증에 실패하면 복호문 파일을 남기지 않는다.
