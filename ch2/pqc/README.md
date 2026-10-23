# 비교 문서: mkrand16.c와 pqc_mkrand16.c

## 목적

이 문서는 원본 [../mkrand16.c](../mkrand16.c)와 [pqc_mkrand16.c](pqc_mkrand16.c)의 동작과 코드를 비교한다.

목표는 다음과 같다.

- 두 소스의 동작과 구조를 동일하게 유지한다.
- 난수 생성 예제에는 공개키 PQC 알고리즘이 없으므로, 이 파일은 OpenSSL 3 API 전환 예제로도 변경하지 않는다.
- 양자내성 키 생성은 별도 프로그램인 `pqc_mldsa_genkey.c`에서 다룬다.

## 핵심 비교 개요

두 소스 모두 다음과 같이 동작한다.

- 현재 시간 기반으로 시드를 만든다.
- `RAND_seed()`로 시드를 주입한다.
- `RAND_bytes()`로 16바이트 난수를 생성한다.
- 출력은 16바이트 hex 문자열이다.

`RAND_bytes()`는 OpenSSL 3.5.8에서도 사용할 수 있는 API이며, 현재 두 소스는 이 호출을 동일하게 사용한다. 따라서 이 난수 예제에는 PQC 알고리즘 전환이나 OpenSSL 3 전용 API 변경이 포함되어 있지 않다.

## 비교 결과

코드 내용과 동작의 차이는 없다. 원본 파일에는 마지막 개행이 없고 전환본에는 마지막 개행이 있다는 파일 끝 형식 차이만 있다. 반환값을 검사해 난수 생성 실패 시 `main`이 `1`을 반환하는 처리도 두 파일에 동일하게 들어 있다.

## 결론

`pqc_mkrand16.c`는 현재 원본 `mkrand16.c`와 같은 동작을 유지한다. 이 예제에서는 PQC 알고리즘 전환을 주장하지 않으며, ML-DSA 키 생성 같은 실제 PQC 전환은 `pqc_mldsa_genkey.c`에서 수행한다.

## 빌드 및 실행 방법

OpenSSL 3.5.8 설치는 [../../README_PQC.md](../../README_PQC.md)를 참고한다. Makefile의 기본 설치 경로는 `$HOME/pqc/openssl-3.5.8/install`이며, 다른 경로를 사용하려면 `OPENSSL358` 변수를 지정한다.

```bash
cd ch2/pqc
make OPENSSL358=/path/to/openssl-3.5.8/install
```

`make`는 `pqc_mkrand16`과 `pqc_mldsa_genkey`를 빌드한 뒤 차례로 실행한다. `pqc_mkrand16`은 16바이트 난수를 hex 문자열(32자)로 출력하고, `pqc_mldsa_genkey`는 기본적으로 `pubKey.pem`과 `privKey.pem`을 생성한다. Makefile은 OpenSSL 라이브러리 경로로 `lib64` 또는 `lib`를 자동으로 선택한다.

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
