# PQC 비교 문서: mkrand16.c vs pqc_mkrand16.c

## 목적

이 문서는 원본 [../mkrand16.c](../mkrand16.c) 와 양자내성 전환 버전 [pqc_mkrand16.c](pqc_mkrand16.c) 의 차이를 비교하기 위한 문서이다.

목표는 다음과 같다.

- 원본 코드의 동작과 구조를 최대한 유지한다.
- 이 예제에서는 공개키 알고리즘이 없으므로, OpenSSL 3 API 변경을 PQC 전환과 같은 범주의 필수 전환으로 취급한다.
- API 변경에 필요한 부분 이외의 차이를 만들지 않는다.
- 원본 코드와 전환본의 차이를 코드 레벨에서 명확히 확인할 수 있게 한다.

## 핵심 비교 개요

원본 코드는 다음 흐름을 따른다.

- 현재 시간 기반으로 시드를 만든다.
- `RAND_seed()`로 시드를 주입한다.
- `RAND_bytes()`로 16바이트 난수를 생성한다.
- 출력은 16바이트 hex 문자열이다.

전환본은 같은 흐름을 유지하며 난수 생성 호출만 OpenSSL 3.x API인 `RAND_bytes_ex()`로 바꾼다. `NULL` libctx를 사용해 `RAND_seed()`와 같은 기본 컨텍스트를 사용한다.

## 비교용 diff

```diff
--- a/ch2/mkrand16.c
+++ b/ch2/pqc/pqc_mkrand16.c
@@
     RAND_seed (seedbuf, 8);
-    RAND_bytes (randbuf, 16);
+    if (RAND_bytes_ex(NULL, randbuf, 16, 0) != 1)
+        return 1;
     printStr(randbuf, 16);
```

## 변경 범위

- `RAND_bytes()`를 OpenSSL 3.x의 `RAND_bytes_ex()`로 변경한다.
- 호출 결과가 성공(1)이 아닌 경우 실패 코드로 종료한다.
- 출력 함수, 시드 생성, 버퍼 크기, 함수 시그니처, 서식 등 나머지 코드는 원본과 동일하게 유지한다.
- `RAND_priv_bytes_ex()`와 별도 `OSSL_LIB_CTX`는 이 비교에 필요하지 않으므로 사용하지 않는다. 별도 컨텍스트를 생성하면 기본 컨텍스트에 적용한 `RAND_seed()`와 난수 생성이 서로 다른 컨텍스트를 사용할 수 있다.

## 결론

이 비교 문서는 PQC 전환을 위해 필요한 최소 변경만 반영한 버전이다.

- 원본 성격 유지
- OpenSSL 3.5.8 요구사항 반영
- 코드 비교가 쉬운 구조 유지
- 불필요한 부가 기능 제거

## 빌드 및 실행 방법

OpenSSL 3.5.8 설치는 [../../README_PQC.md](../../README_PQC.md)를 참고한다. 설치 후 `OPENSSL358` 환경 변수가 설정되어 있어야 한다.

```bash
export OPENSSL358=your-openss-3.5.8-install-dir
cd ch2/pqc
make
```

`make`는 두 프로그램을 빌드한 뒤 차례로 실행합니다. `pqc_mkrand16`은 16바이트 난수를 hex 문자열(32자)로 출력하고, `pqc_mldsa_genkey`는 기본적으로 `pubKey.pem`과 `privKey.pem`을 생성합니다. Makefile은 OpenSSL 라이브러리 경로로 `lib64` 또는 `lib`를 자동으로 선택합니다.

## pqc_mldsa_genkey.c (rsagenkey.c 전환본)

[../rsagenkey.c](../rsagenkey.c)의 RSA-512 키 생성을 ML-DSA-65(FIPS 204) 키 생성으로 바꾼 [pqc_mldsa_genkey.c](pqc_mldsa_genkey.c)이다. 서명용 키이므로 ML-DSA를 선택했다(암호화/키 합의용 ML-KEM 키 생성은 [ch4](../../ch4/pqc/pqc_mlkem_envelope.c) 참고).

- `RSA_generate_key`, `RSAPublicKey_dup`, `RAND_seed` 제거 → `EVP_PKEY_CTX_new_from_name("ML-DSA-65")` + `EVP_PKEY_keygen`
- 공개키는 `PEM_write_PUBKEY`(`BEGIN PUBLIC KEY`), 개인키는 `PEM_write_PrivateKey`(PKCS#8)로 저장하고 개인키 파일 권한은 0600
- `assert` 대신 오류 메시지와 종료 코드 사용
- 생성한 키는 ch7 `pqc_hash_sign`, ch5 `pqc_mldsa_sign_test`에서 그대로 사용할 수 있다.

```bash
export OPENSSL358=<프로젝트 경로>/openssl-3.5.8/install
cd ch2/pqc
make
```

다른 키 파일명을 사용하려면 `make`로 빌드한 뒤 `./pqc_mldsa_genkey pub.pem priv.pem`처럼 실행합니다.
