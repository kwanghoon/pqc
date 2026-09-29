# PQC 비교 문서: rsa_sha1_sign_test.c vs pqc_rsa_sha1_sign_test.c

## 목적

이 문서는 [../rsa_sha1_sign_test.c](../rsa_sha1_sign_test.c)와 [pqc_rsa_sha1_sign_test.c](pqc_rsa_sha1_sign_test.c)의 차이를 비교한다.

- 원본 동작 유지: 메시지 서명과 검증
- SHA-1 의존을 제거하고 SHA-256으로 전환
- OpenSSL 3.x 스타일에 맞게 정리
- 필요 없는 새 기능 추가 금지

## 비교용 diff

```diff
--- a/ch5/rsa_sha1_sign_test.c
+++ b/ch5/pqc/pqc_rsa_sha1_sign_test.c
@@
-    EVP_MD_CTX ctx;
+    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
@@
-    EVP_MD_CTX_init(&ctx);
-    result = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
+    result = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
@@
-    result = EVP_SignUpdate(&ctx, plaintext, plsize);
+    result = EVP_DigestSignUpdate(ctx, plaintext, plsize);
@@
-    result = EVP_SignFinal(&ctx, sign, signSize, pkey);
+    result = EVP_DigestSignFinal(ctx, NULL, signSize);
+    result = EVP_DigestSignFinal(ctx, sign, signSize);
@@
-    EVP_MD_CTX_cleanup(&ctx);
+    EVP_MD_CTX_free(ctx);
```

## 변경 포인트

- 원본은 SHA-1을 사용한 RSA 서명을 수행했다.
- 전환 버전은 서명 로직과 검증 로직은 유지하면서, 실제 해시를 `EVP_sha256()`으로 올려 취약한 SHA-1 의존을 제거했다.
- `EVP_MD_CTX`는 스택 구조체 대신 힙 할당 객체를 사용한다.
- 구식 `EVP_Sign*` 계열 함수 대신 `EVP_DigestSign*` 계열을 사용해 OpenSSL 3.x 문법에 맞춘다.

## 결론

이 문서는 원본의 RSA 서명 동작을 유지하되, 실무적으로 더 안전한 SHA-256 기반으로 정리한 비교 예제이다. Full PQC 알고리즘 전환은 구조 변경이 크므로, 이 단계에서는 해시 수준 보강과 OpenSSL 3.x API 정리가 우선된 형태로 구현했다.
