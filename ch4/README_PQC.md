# ch4 RSA에서 ML-KEM으로의 전환

## 전환 대상과 대응 구조

[rsatest.c](rsatest.c)는 RSA 공개키로 파일 데이터를 직접 암호화하는 예제이고,
[pqc/pqc_mlkem_file.c](pqc/pqc_mlkem_file.c)는 ML-KEM 키 캡슐화와
AES-256-GCM을 결합한 하이브리드 암호화 예제입니다. ML-KEM은 파일 데이터를
직접 암호화하는 알고리즘이 아니므로, 공유 비밀을 만들고 대칭키 암호로
파일을 처리합니다.

두 프로그램의 `main()` 흐름은 다음과 같이 대응합니다.

| RSA 원본 | ML-KEM 전환본 | 역할 |
|---|---|---|
| `generate_rsa_key()` | `generate_mlkem_key()` | 메모리의 키 객체 생성 |
| `write_key_files()` | `write_key_files()` | 개인키·공개키 PEM 기록 |
| `encryptRSAFile()` | `encrypt_file()` | 입력 파일 암호화 |
| `decryptRSAFile()` | `decrypt_file()` | 암호문 복호화 |

RSA는 개인키와 복제한 공개키를 별도 `RSA` 객체로 관리합니다. ML-KEM은
키 쌍을 `EVP_PKEY` 객체 하나로 관리합니다. 두 프로그램 모두 키 파일을
기록하지만, 현재 실행의 암·복호화에는 메모리 키 객체를 사용합니다.

## RSA 원본의 입력 크기 제한

RSA 원본은 RSA-1024와 RSA-OAEP를 사용합니다. OAEP 입력 한도는 86바이트이며,
`encryptRSAFile()`은 입력 파일에서 최대 그 크기만 읽어 한 번에 암호화합니다.
따라서 더 긴 파일의 나머지는 암호화 결과에 포함되지 않습니다.
또한 원본은 `getTimeSubstr()`로 만든 시간 문자열을 `RAND_seed()`에 전달합니다.
이는 ML-KEM 전환본에는 없는 레거시 난수 초기화 코드입니다.

## ML-KEM 파일 암호화 흐름

전환본은 OpenSSL 3.5.8의 ML-KEM-768을 사용합니다.

1. `EVP_PKEY_generate()`로 새 ML-KEM 키 쌍을 생성하고, 지정한 경로에
   개인키와 공개키를 PEM으로 기록합니다. 기존 키 파일은 덮어씁니다.
2. `EVP_PKEY_encapsulate()`로 공유 비밀과 KEM 암호문을 생성합니다.
3. `RAND_bytes()`로 12바이트 nonce를 생성하고, 공유 비밀을 AES-256-GCM 키로
   사용해 입력 파일을 4096바이트 단위로 암호화합니다.
4. 봉투에 KEM 암호문, nonce, AES-GCM 암호문, 16바이트 인증 태그를 기록합니다.
5. `EVP_PKEY_decapsulate()`로 공유 비밀을 복원하고 GCM 인증 태그를 검증하며
   복호화합니다. 암호화 실패 시 지정된 봉투 경로가 제거되며, 복호화 실패
   후 출력 파일을 만든 경우 부분 복호화 파일을 제거합니다.

난수 시드 데이터를 직접 구성하거나 `RAND_seed()`를 호출하지 않습니다.
키 생성, KEM 캡슐화, nonce 생성에 필요한 난수는 OpenSSL 난수 생성기가
처리합니다.

봉투 파일 필드 순서:

| 필드 | 크기 |
|---|---:|
| 매직 값 `PQM1` | 4바이트 |
| KEM 암호문 길이 | 4바이트, big-endian |
| ML-KEM 암호문 | 길이 필드에 지정된 크기 |
| AES-GCM nonce | 12바이트 |
| AES-GCM 암호문 | 태그 직전까지의 데이터 |
| AES-GCM 인증 태그 | 16바이트 |

## 빌드 및 실행

ch4 통합 빌드와 왕복 테스트는 상위 디렉터리의 [build.sh](build.sh)로
수행합니다. 상세한 명령은 [README.md](README.md#빌드-및-통합-테스트)를
참고하세요. ML-KEM 프로그램만 빌드·실행하려면:

```sh
cd pqc
make OPENSSL358=/path/to/openssl-3.5.8/install
```

`pqc_mlkem_file`의 인자 순서는 원본과 동일합니다.

```text
pqc_mlkem_file <private key file> <public key file> <input file> <envelope file> <output file>
```

실행마다 새 키 쌍을 생성해 PEM 파일에 기록(덮어쓰기)하고, 같은 실행에서
그 키 객체로 봉투를 암·복호화합니다. 기존 키 파일을 읽지 않으므로 이전
실행에서 만든 봉투를 복호화하는 프로그램은 아닙니다. 개인키는 PKCS#8
`PRIVATE KEY`, 공개키는 SubjectPublicKeyInfo `PUBLIC KEY` PEM으로 기록하며,
파일 권한은 프로세스의 umask를 따릅니다.

## ML-KEM 전자 봉투 예제

[rsa_des_crc.c](rsa_des_crc.c)는 RSA로 3DES 세션 키를 보호하는 별도
예제입니다. 대응 예제인 [pqc/pqc_mlkem_envelope.c](pqc/pqc_mlkem_envelope.c)는
ML-KEM-768과 AES-256-GCM을 사용합니다. 이는 `pqc_mlkem_file.c`와 별도의
프로그램이며, 키 파일 읽기 및 재사용을 지원합니다. 빌드·인자 사용법은
[pqc/README.md](pqc/README.md)를 참고하세요.
