# PQC 비교 문서: client0.c/server0.c vs pqc_client0.c/pqc_server0.c

## 목적

이 문서는 [../client0.c](../client0.c), [../server0.c](../server0.c)와 [pqc_client0.c](pqc_client0.c), [pqc_server0.c](pqc_server0.c)의 차이를 비교한다.

- 원본 동작 유지: 타임스탬프 인증 및 yes/no 응답
- DES 기반 인증을 AES-256-CBC로 강화
- OpenSSL 3.x API로 정리
- 추가 기능이나 로깅 텍스트는 최소화

## 비교용 diff

```diff
--- a/ch8/client0.c
+++ b/ch8/pqc/pqc_client0.c
@@
-    DES_cblock rawkey;
-    DES_key_schedule keySched;
+    unsigned char rawkey[32] = {0};
+    unsigned char iv[16] = {0};
+    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
@@
-    DES_set_key(&rawkey, &keySched);
-    DES_ncbc_encrypt(..., DES_ENCRYPT);
+    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, rawkey, iv);
+    EVP_EncryptUpdate(ctx, buff, &outLen, ...);
+    EVP_EncryptFinal_ex(ctx, buff + outLen, &finalLen);
```

## 변경 포인트

- 원본은 DES CBC로 타임스탬프를 암호화했다.
- 전환 버전은 같은 소켓 플로우와 yes/no 인증 로직을 유지하면서, 대칭 암호를 `EVP_aes_256_cbc()`로 바꿨다.
- 키 버퍼를 8바이트 DES 키에서 32바이트 AES 키로 확장해 보안 강도를 높였다.
- OpenSSL 3.x 스타일에 맞게 컨텍스트를 힙으로 관리하고 `EVP_Encrypt*` / `EVP_Decrypt*` 계열로 정리했다.

## 결론

이 문서는 네트워크 인증 동작 자체는 유지하면서, DES 기반의 취약한 대칭 암호를 더 강한 AES-256 체계로 바꾼 비교 예제이다.
