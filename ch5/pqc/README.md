# ch5 PQC 전자서명 예제

[pqc_mldsa_sign_test.c](pqc_mldsa_sign_test.c)는 [../rsa_sha1_sign_test.c](../rsa_sha1_sign_test.c)의 RSA + SHA-1 전자서명을 ML-DSA-65 서명으로 대체한 예제다. RSA API와 SHA-1은 사용하지 않는다. 전환에 필요한 부분만 바꾸고 나머지 구조는 원본과 같게 유지했다.

## 원본과 같은 부분

- `main()`이 파일 앞에 있고, 뒤에 `printStr`, `printResult`, `makeSignature`, `signatureVerify` 순서로 함수가 이어진다. 함수에는 `static`을 쓰지 않는다.
- 처리 흐름은 키 생성 → 서명 → 서명 출력 → 검증 → 결과 출력이다. 키는 프로그램 안에서 생성하며 인자를 받지 않는다.
- `makeSignature()`는 성공 시 1, 실패 시 0을 반환하고 서명과 길이를 출력 인자로 돌려준다. `signatureVerify()`는 1(성공), 0(검증 실패), -1(오류)을 반환한다.
- `assert` 대신 명시적 `if` 검사로 오류를 처리한다. `int` 반환값은 `result == 0`(또는 `!= 1`)으로, 포인터는 `== NULL`로 검사한다. 종료 코드는 숫자 상수 `0`/`1`을 쓴다.
- 변조 테스트는 `main()`에 `//` 주석으로 남아 있다.

## 전환 때문에 달라진 부분

| 원본 (RSA + SHA-1) | 전환본 (ML-DSA-65) | 이유 |
|---|---|---|
| `RSA_generate_key(512, ...)` | `generateKey()`: `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)`, `EVP_PKEY_keygen_init`, `EVP_PKEY_generate` | 키 생성 API 변경 |
| `RSA *rsaPriv`, `rsaPub` (`RSAPublicKey_dup`) | `EVP_PKEY *key` 하나를 서명과 검증에 사용 | RSA 구조체가 없고 같은 `EVP_PKEY`로 서명과 검증이 가능 |
| `EVP_SignInit_ex(EVP_sha1())`, `EVP_SignUpdate`, `EVP_SignFinal` | `EVP_DigestSignInit_ex`(다이제스트 `NULL`), `EVP_DigestSign` | ML-DSA는 메시지를 직접 서명하므로 해시를 지정하지 않음 |
| `EVP_VerifyInit_ex`, `EVP_VerifyUpdate`, `EVP_VerifyFinal` | `EVP_DigestVerifyInit_ex`, `EVP_DigestVerify` | 위와 같음 |
| `MAXSIGNSZ 1024`, `unsigned int` 서명 길이 | `MAXSIGNSZ 4096`, `size_t` 서명 길이 | ML-DSA-65 서명은 3309바이트이고 `EVP_DigestSign`이 `size_t`를 요구 |
| `EVP_MD_CTX ctx`, `EVP_MD_CTX_init/cleanup` | `EVP_MD_CTX_new/free` | OpenSSL 3에서 `EVP_MD_CTX`는 불투명 구조체 |
| `RAND_seed()`, `rsa.h`/`engine.h`/`rand.h`/`sha.h` | 삭제, `<openssl/err.h>` 추가 | OpenSSL 난수 생성기가 시딩을 처리하고, 오류 스택을 출력함 |
| `EVP_VerifyFinal error.` 메시지 | `EVP_DigestVerify error.` 메시지 | API 이름 변경 |

`main()`은 정상 서명이면 0, 키 생성이나 서명 또는 검증에 실패하면 1을 반환한다. 원본은 항상 1을 반환했으나 같은 방식으로 맞췄다.

## 빌드 및 실행

이 디렉터리의 Makefile은 OpenSSL 3.5.8로 `pqc_mldsa_sign_test`를 빌드하고 실행한다. 기본 설치 경로는 `$(HOME)/pqc/openssl-3.5.8/install`이며 `OPENSSL358`로 변경할 수 있다. `lib64`와 `lib` 중 존재하는 라이브러리 디렉터리를 자동으로 선택한다.

```sh
make OPENSSL358=/path/to/openssl-3.5.8/install
```

`Signature is verified to be clear.`가 출력되면 검증에 성공한 것이다. 상위 디렉터리의 [build.sh](../build.sh)는 RSA 원본과 이 예제를 차례로 실행한다. 서명 변조 시 실패하는 경우를 시험하려면 `main()`의 주석 처리된 변조 테스트를 활성화한다.
