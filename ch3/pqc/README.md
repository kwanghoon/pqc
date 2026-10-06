# PQC 비교 문서: aes_128_cbc.c vs pqc_aes_256_cbc.c

## 목적

이 문서는 [../aes_128_cbc.c](../aes_128_cbc.c)와 [pqc_aes_256_cbc.c](pqc_aes_256_cbc.c)의 차이를 비교한다.

- 원본 예제의 동작 유지: 파일 암호화와 복호화
- PQC 전환 목표 반영: AES-128에서 AES-256-CBC로 강화
- OpenSSL 3.x API 규격에 맞게 정리
- 비교 목적 외의 불필요한 로직 추가 금지

## 핵심 차이

원본 코드와 전환 코드의 가장 큰 차이는 다음 두 가지다.

1. 알고리즘 선택 변경
   - 원본: `EVP_aes_128_cbc()`
   - 전환: `EVP_aes_256_cbc()`

2. OpenSSL 3.x 컨텍스트 관리 방식
   - 원본: 스택 기반 `EVP_CIPHER_CTX ctx`
   - 전환: 힙 기반 `EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new()`

## 비교용 diff

```diff
--- a/ch3/aes_128_cbc.c
+++ b/ch3/pqc/pqc_aes_256_cbc.c
@@
-    EVP_CIPHER_CTX ctx;
+    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
@@
-    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_ENCRYPT);
+    ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
+    assert(ret == 1);
@@
-        ret = EVP_CipherUpdate(&ctx, cipherbuff, &out_len, plainbuff, in_len);
+        ret = EVP_EncryptUpdate(ctx, cipherbuff, &out_len, plainbuff, in_len);
@@
-    ret = EVP_CipherFinal_ex(&ctx, cipherbuff, &out_len);
+    ret = EVP_EncryptFinal_ex(ctx, cipherbuff, &out_len);
@@
-    EVP_CIPHER_CTX_cleanup(&ctx);
+    EVP_CIPHER_CTX_free(ctx);
@@
-    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_DECRYPT);
+    ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
+    assert(ret == 1);
@@
-        ret = EVP_CipherUpdate(&ctx, plainbuff, &out_len, cipherbuff, in_len);
+        ret = EVP_DecryptUpdate(ctx, plainbuff, &out_len, cipherbuff, in_len);
@@
-    ret = EVP_CipherFinal_ex(&ctx, plainbuff, &out_len);
+    ret = EVP_DecryptFinal_ex(ctx, plainbuff, &out_len);
@@
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

- 함수 사용 패턴
  - 원본: `EVP_CipherInit_ex()`, `EVP_CipherUpdate()`, `EVP_CipherFinal_ex()`
  - 전환: `EVP_EncryptInit_ex()`, `EVP_EncryptUpdate()`, `EVP_EncryptFinal_ex()`
  - 복호화도 `EVP_Decrypt*` 계열로 정리

## 결론

이 전환 버전은 원본의 파일 암호화/복호화 흐름을 유지하면서, OpenSSL 3.x API 규격으로 바꾸고 동시에 AES-256 기준을 반영한 버전이다. 즉, “동작 유지”와 “PQC 전환 목표 반영”을 함께 만족한다.

## 빌드 및 실행 방법

OpenSSL 3.5.8이 `<프로젝트 경로>/openssl-3.5.8/install`에 설치되어 있다고 가정한다. 아래 명령의 `<프로젝트 경로>`를 실제 프로젝트의 절대 경로로 바꾼다.

```sh
export OPENSSL358=<프로젝트 경로>/openssl-3.5.8/install
echo "$OPENSSL358"

cd ch3/pqc
gcc -o pqc_aes_256_cbc pqc_aes_256_cbc.c \
    -I"$OPENSSL358/include" -L"$OPENSSL358/lib64" -lcrypto

export LD_LIBRARY_PATH="$OPENSSL358/lib64:$LD_LIBRARY_PATH"
./pqc_aes_256_cbc ../foo.txt foo.enc foo.dec
diff ../foo.txt ./foo.dec
```

`diff`에서 출력이 없으면 복호화한 `foo.dec`가 원본 `../foo.txt`와 일치한다.
