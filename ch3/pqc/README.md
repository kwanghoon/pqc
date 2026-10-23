# 비교 문서: aes_128_cbc.c와 pqc_aes_256_cbc.c

## 목적

이 문서는 [../aes_128_cbc.c](../aes_128_cbc.c)와 [pqc_aes_256_cbc.c](pqc_aes_256_cbc.c)의 차이를 비교한다.

- 원본 예제의 동작 유지: 파일 암호화와 복호화
- AES 키 길이 강화: AES-128에서 AES-256-CBC로 변경
- OpenSSL 3에서 opaque 타입인 cipher context에 맞게 관리
- 비교 목적 외의 불필요한 로직 추가 금지

AES-256-CBC는 대칭키 보안 강도를 높이는 변경이며, 그 자체로 PQC 알고리즘 또는 양자내성 키 배포를 구현하지 않는다. 이 예제의 범위는 AES 키 길이 강화와 OpenSSL 3 호환이다.

프로그램은 실행할 때마다 `RAND_bytes()`로 키와 IV를 생성해 같은 실행 안에서 암호화와 복호화를 수행한다. 키와 IV를 암호문에 저장하지 않으므로 출력 암호문만으로는 후속 실행에서 복호화할 수 없다. `RAND_bytes()` 반환값은 현재 소스에서 검사하지 않는다.

## 핵심 차이

필요한 변경은 AES 키 길이와 cipher context 관리다.

- 키 버퍼와 난수 생성 길이를 16바이트에서 32바이트로 변경한다.
- 암·복호화 알고리즘을 `EVP_aes_128_cbc()`에서 `EVP_aes_256_cbc()`로 변경한다.
- OpenSSL 3에서 구조가 opaque인 `EVP_CIPHER_CTX`를 `EVP_CIPHER_CTX_new()`로 생성하고 `EVP_CIPHER_CTX_free()`로 해제한다.
- CBC IV는 AES 블록 크기인 16바이트를 그대로 사용한다.
- 기존의 공통 `EVP_Cipher*` 호출과 파일 처리 흐름은 유지한다.
- 컨텍스트는 암호화·복호화 함수에서 각각 생성·해제한다.

## 비교용 diff

```diff
--- a/ch3/aes_128_cbc.c
+++ b/ch3/pqc/pqc_aes_256_cbc.c
@@ main
-    unsigned char mykey [16] = "\0";
+    unsigned char mykey [32] = "\0";
-    RAND_bytes (mykey, 16);
+    RAND_bytes (mykey, 32);
@@ AES_encryption / AES_decryption
-    EVP_CIPHER_CTX ctx;
+    EVP_CIPHER_CTX *ctx;
+    ctx = EVP_CIPHER_CTX_new(); assert(ctx);
-    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_ENCRYPT);
+    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, AES_ENCRYPT);
-    EVP_CipherUpdate(&ctx, ...);
+    EVP_CipherUpdate(ctx, ...);
-    EVP_CipherFinal_ex(&ctx, ...);
+    EVP_CipherFinal_ex(ctx, ...);
-    EVP_CIPHER_CTX_cleanup(&ctx);
+    EVP_CIPHER_CTX_free(ctx);
```

## 세부 변경 포인트

- 키 길이 변경
  - 원본: `unsigned char mykey[16]`
  - 전환: `unsigned char mykey[32]`
  - 이유: AES-256 키 요구사항 반영

- IV 유지
  - 원본과 전환 모두 `unsigned char iv[16]`을 사용
  - CBC 모드의 IV 길이는 128비트로 유지

- 랜덤 값 생성
  - 원본: `RAND_bytes(mykey, 16);`
  - 전환: `RAND_bytes(mykey, 32);`
  - 이유: 256비트 키 생성

- 함수 사용 패턴: 원본과 전환본 모두 `EVP_CipherInit_ex()`, `EVP_CipherUpdate()`, `EVP_CipherFinal_ex()`를 유지한다.

## 결론

이 버전은 파일 암호화/복호화 흐름과 공통 EVP 호출을 유지하면서 AES-256 키 길이와 OpenSSL 3 cipher context 관리를 적용한다. 키 합의·배포를 위한 PQC 알고리즘은 포함하지 않는다.

## 빌드 및 실행 방법

OpenSSL 3.5.8 설치는 [../../README_PQC.md](../../README_PQC.md)를 참고한다. Makefile은 `lib64` 또는 `lib` 라이브러리 디렉터리를 자동 선택한다.

```sh
cd ch3/pqc
make OPENSSL358=/path/to/openssl-3.5.8/install
diff ../foo.txt ./foo.dec
```

`diff`에서 출력이 없으면 복호화한 `foo.dec`가 원본 `../foo.txt`와 일치한다.
기본 `make`는 `../foo.txt`를 입력으로 사용하며, 입력·암호문·복호문 경로는 `INPUT`, `CIPHER`, `OUTPUT` 변수로 변경할 수 있다.
통합 [../build.sh](../build.sh)는 OpenSSL 1.0.2 및 3.5.8 버전을 각각 실행하고 복호화 결과를 `cmp`로 검증한다.
