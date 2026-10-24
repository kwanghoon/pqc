# ch4 빌드 및 실행

## 빌드 및 통합 테스트

ch4는 OpenSSL 1.0.2u 기반 RSA 예제와 OpenSSL 3.5.8 기반 ML-KEM 예제를
포함합니다. 기본 OpenSSL 설치 경로는 각각
`$(HOME)/pqc/openssl-1.0.2u/install`과
`$(HOME)/pqc/openssl-3.5.8/install`입니다. 다른 경로를 사용하는 경우:

```sh
export OPENSSL102=/path/to/openssl-1.0.2u/install
export OPENSSL358=/path/to/openssl-3.5.8/install
./build.sh
```

`build.sh`는 RSA 파일 암호화와 RSA 전자 봉투 예제를 실행하고, 이어서 두
ML-KEM 예제를 실행합니다. 각 복호화 결과를 `foo.txt`와 비교합니다.

각 Makefile을 별도로 실행할 수도 있습니다.

```sh
make OPENSSL102=/path/to/openssl-1.0.2u/install
cd pqc
make OPENSSL358=/path/to/openssl-3.5.8/install
```

`make clean`은 해당 Makefile이 생성한 실행 파일과 기본 테스트 산출물을
정리합니다.

## RSA 파일 암호화

[rsatest.c](rsatest.c)는 RSA-1024 키 쌍을 만들고 RSA-OAEP로 입력 파일을
암호화한 뒤 같은 실행에서 복호화하는 예제입니다. `main()`의 처리 순서는
키 생성(`generate_rsa_key`) → PEM 기록(`write_key_files`) → 암호화
(`encryptRSAFile`) → 복호화(`decryptRSAFile`)입니다.

명령행 인자는 다음 순서입니다.

```text
rsatest <private key file> <public key file> <input file> <ciphertext file> <output file>
```

실행할 때마다 새 키 쌍을 생성해 지정한 PEM 파일을 덮어씁니다. 키 파일은
저장하지만 암호화와 복호화에는 파일을 다시 읽지 않고 메모리에 있는 키
객체를 사용합니다. 개인키 파일은 OpenSSL RSA 전용 PEM 형식으로, 공개키
파일은 PKCS#1 `RSA PUBLIC KEY` PEM 형식으로 기록됩니다.

RSA-OAEP의 입력 크기는 RSA-1024 키에서 최대 86바이트입니다. 이 예제는
입력 파일의 앞부분에서 최대 그 크기만 읽어 한 번에 암호화하며, 더 긴
파일은 나머지 내용을 처리하지 않습니다.

## ML-KEM 파일 암호화

ML-KEM 전환 예제의 설명은 [README_PQC.md](README_PQC.md)와
[pqc/README.md](pqc/README.md)를 참고하세요. [pqc/pqc_mlkem_file.c](pqc/pqc_mlkem_file.c)는
원본과 같은 인자 순서로 실행하며, ML-KEM-768 키 생성 → PEM 기록 →
암호화 → 복호화 순서로 처리합니다.

```text
pqc_mlkem_file <private key file> <public key file> <input file> <envelope file> <output file>
```

매 실행마다 새 키 쌍을 만들고 지정된 키 파일에 저장(기존 파일 덮어쓰기)한
뒤, 같은 실행에서 생성한 메모리 키 객체로 입력 파일을 봉투 암호화하고
복호화합니다. 키 파일을 저장하지만 다음 실행에서 다시 읽어 사용하지는
않으므로 이전 실행의 봉투를 복호화할 수 없습니다.

## 전자 봉투 예제

[rsa_des_crc.c](rsa_des_crc.c)는 RSA로 3DES 세션 키를 보호하는 전자 봉투
예제입니다. `main()`은 공개키 PEM 읽기 → 개인키 PEM 읽기 → 봉투 생성
(`makeEnvelope`) → 봉투 열기 (`openEnvelope`) 순서로 처리합니다.

```text
rsa_des_crc <public key file> <private key file> <input file> <envelope file> <output file>
```

두 키 파일은 미리 준비해야 합니다. 프로그램은 키 파일이 없을 때 새 키를
생성하지 않습니다. 공개키는 PKCS#1 `RSA PUBLIC KEY` PEM, 개인키는 RSA
개인키 PEM 형식으로 읽습니다. 인자 수나 키 파일, 암호 연산에 문제가 있으면
실패 상태로 종료합니다. 3DES-CBC는 인증 기능을 제공하지 않습니다.

대응하는 [pqc/pqc_mlkem_envelope.c](pqc/pqc_mlkem_envelope.c)는 같은 인자
순서와 처리 단계를 사용하지만 ML-KEM-768과 AES-256-GCM으로 전환합니다.
이 프로그램도 전달된 키 파일만 읽으며 키를 생성하지 않습니다. 봉투 형식과
비교 기준은 [README_PQC.md](README_PQC.md)를 참고하세요.
