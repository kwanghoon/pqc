# PQC 비교 문서: hash_sign.c vs pqc_hash_sign.c

## 목적

이 문서는 [../hash_sign.c](../hash_sign.c)와 [pqc_hash_sign.c](pqc_hash_sign.c)의 차이를 비교한다.

- 원본 동작 유지: 파일 해싱, 서명, 검증
- SHA-1 의존 제거 및 SHA-256 사용
- OpenSSL 3.x API로 정리
- 비교 용도에 필요한 최소 변화만 반영

## 비교용 diff

```diff
--- a/ch7/hash_sign.c
+++ b/ch7/pqc/pqc_hash_sign.c
@@
-    EVP_MD_CTX ctx;
+    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
@@
-    result = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
+    result = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
@@
-    result = EVP_SignUpdate(&ctx, buff, inLen);
+    result = EVP_DigestSignUpdate(ctx, buff, inLen);
@@
-    result = EVP_SignFinal(&ctx, sign, &signSize, pkey);
+    result = EVP_DigestSignFinal(ctx, NULL, &signSize);
+    result = EVP_DigestSignFinal(ctx, sign, &signSize);
@@
-    EVP_MD_CTX_cleanup(&ctx);
+    EVP_MD_CTX_free(ctx);
```

## 변경 포인트

- 서명 API는 `EVP_Sign*` 계열에서 `EVP_DigestSign*` 계열로 바뀌었다.
- 검증도 `EVP_Verify*`에서 `EVP_DigestVerify*`로 정리되었다.
- 실제 예제는 `EVP_sha256()`로 고정되어 있어 SHA-1 의존을 제거했다.
- 파일 무결성의 동작 자체는 동일하게 유지하면서, OpenSSL 3.x 현대화와 더 안전한 해시를 함께 반영했다.

## 결론

기존의 파일 무결성 로직을 유지하면서, OpenSSL 3.x 스타일로 정리하고 SHA-1 의존을 제거한 버전이다. 다만 RSA 기반 서명 자체는 원본 동작을 유지하는 수준에서 비교를 수행했다.
