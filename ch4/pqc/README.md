# ch4 PQC 예제

## ML-KEM 파일 암호화 예제

[pqc_mlkem_file.c](pqc_mlkem_file.c)는 [../rsatest.c](../rsatest.c)의 RSA-OAEP
직접 암호화를 ML-KEM-768 키 캡슐화와 AES-256-GCM 파일 암호화로 대체한
예제입니다. 두 프로그램의 처리 흐름은 키 생성 → 키 파일 기록 → 파일
암호화 → 파일 복호화 순서입니다.

- ML-KEM 키 쌍은 하나의 `EVP_PKEY` 객체로 생성합니다.
- KEM 공유 비밀을 AES-256-GCM 키로 사용하며, 파일을 4096바이트 단위로
  스트리밍 암호화합니다.
- 난수 시드를 직접 만들거나 `RAND_seed()`를 호출하지 않습니다. OpenSSL
  난수 생성기가 키 생성, KEM 캡슐화, nonce 생성에 필요한 난수를 처리합니다.
- 인자 순서는 원본과 같습니다: `개인키 파일 공개키 파일 입력 파일 봉투 파일 복호화 결과 파일`.
- 매 실행마다 새 키를 생성해 지정한 PEM 파일을 덮어쓰고, 저장한 파일을
  다시 읽는 대신 같은 실행의 메모리 키로 봉투를 복호화합니다. 따라서
  이전 실행의 봉투를 이 프로그램으로 복호화할 수 없습니다.
- 개인키는 PKCS#8 `PRIVATE KEY`, 공개키는 SubjectPublicKeyInfo `PUBLIC KEY`
  PEM으로 기록합니다. 파일 권한은 프로세스의 umask를 따릅니다.
- 암호화 실패 시 지정된 봉투 경로를 제거합니다. 복호화 실패 후 출력 파일을
  만든 경우 부분 복호화 파일을 제거합니다.

인자 형식:

```text
pqc_mlkem_file <private key file> <public key file> <input file> <envelope file> <output file>
```

## 빌드 및 실행

이 디렉터리의 Makefile은 OpenSSL 3.5.8로 ML-KEM 파일 암호화 예제와 ML-KEM
전자 봉투 예제를 빌드하고 실행합니다. 기본 OpenSSL 설치 경로는
`$(HOME)/pqc/openssl-3.5.8/install`이며 `OPENSSL358`로 변경할 수 있습니다.

```sh
make OPENSSL358=/path/to/openssl-3.5.8/install
```

기본 설정에서는 두 프로그램이 `../foo.txt`를 입력으로 사용하고, 각각의
복호화 결과를 `foo.txt`와 비교하는 통합 테스트는 상위 디렉터리의
[build.sh](../build.sh)에서 수행합니다.

## ML-KEM 전자 봉투 예제

[pqc_mlkem_envelope.c](pqc_mlkem_envelope.c)는 [../rsa_des_crc.c](../rsa_des_crc.c)의
RSA + 3DES 전자 봉투를 ML-KEM-768 + AES-256-GCM으로 대체한 별도 예제입니다.
키 파일이 없으면 키 쌍을 생성하며, 저장된 키 파일을 이후 실행에서 읽어
재사용할 수 있습니다. `pqc_mlkem_file.c`와 키 파일 사용 방식이 다릅니다.
