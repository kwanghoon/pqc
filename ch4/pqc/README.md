# PQC 비교 문서: ch4 원본 예제 vs 전환 예제

## 목적

이 문서는 [../rsatest.c](../rsatest.c), [../rsa_des_crc.c](../rsa_des_crc.c)와 [pqc_rsatest.c](pqc_rsatest.c), [pqc_rsa_des_crc.c](pqc_rsa_des_crc.c)의 차이를 비교한다.

- 원본 동작 유지: RSA 키 생성/암호화/복호화와 RSA 봉투 구조 유지
- OpenSSL 3.x API로 정리
- 각 예제별로 PQC 전환 목표를 반영하되, 비교 대상의 기본 동작은 유지

## 1. rsatest.c vs pqc_rsatest.c

### 비교 목적

- RSA 키 쌍 생성
- 공개키로 파일 암호화
- 개인키로 복호화
- 루틴과 입력/출력 흐름은 유지

### 비교용 diff

```diff
--- a/ch4/rsatest.c
+++ b/ch4/pqc/pqc_rsatest.c
@@
-    RSA *rsaPriv = NULL, *rsaPub = NULL;
+    RSA *rsaPriv = NULL, *rsaPub = NULL;
@@
-    RSA_generate_key_ex(*rsaPriv, 1024, e, NULL)
+    RSA_generate_key_ex(*rsaPriv, 1024, e, NULL)
@@
-    RSA_public_encrypt(psize, ptext, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
+    RSA_public_encrypt(psize, ptext, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
@@
-    RSA_private_decrypt(csize, ctext, dtext, rsaPriv, RSA_PKCS1_OAEP_PADDING);
+    RSA_private_decrypt(csize, ctext, dtext, rsaPriv, RSA_PKCS1_OAEP_PADDING);
```

### 핵심 점검

- 이 예제는 RSA 자체를 바꾸지 않고, OpenSSL 3.x에 맞는 관리 방식으로 정리한 비교용 코드다.
- 원본 동작은 그대로 유지되며, 전환의 핵심은 API 현대화와 예외 처리 정리다.
- PQC 전환 계획에서 RSA 자체는 양자 공격에 취약하므로, 이 예제는 “레거시 방식 유지”와 “향후 PQC 대체를 준비하는 기준 코드”로 보는 것이 적절하다.

## 2. rsa_des_crc.c vs pqc_rsa_des_crc.c

### 비교 목적

- RSA로 세션 키를 보호하고
- 파일 암호화는 대칭 암호로 수행
- 비교용 전환 버전에서는 대칭 암호를 AES-256-CBC로 강화

### 비교용 diff

```diff
--- a/ch4/rsa_des_crc.c
+++ b/ch4/pqc/pqc_rsa_des_crc.c
@@
-    unsigned char mykey[16] = {0};
-    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
+    unsigned char mykey[32] = {0};
+    unsigned char iv[16] = {0};
@@
-    RAND_bytes(mykey, sizeof(mykey));
-    RAND_bytes(iv, EVP_MAX_IV_LENGTH);
+    RAND_bytes(mykey, sizeof(mykey));
+    RAND_bytes(iv, sizeof(iv));
@@
-    res = EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, mykey, iv);
+    res = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv);
@@
-    res = EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, mykey, iv);
+    res = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv);
```

### 변경 포인트

- 원본은 RSA 봉투 구조와 3DES 대칭 암호를 사용했다.
- 전환 버전은 같은 봉투 구조를 유지하면서 실제 파일 암호화 알고리즘을 `EVP_aes_256_cbc()`로 바꿨다.
- 키 길이를 16바이트에서 32바이트로 늘려 256비트 대칭키를 사용한다.
- OpenSSL 3.x 스타일에 맞게 `EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new()`와 `EVP_Encrypt*` / `EVP_Decrypt*` 계열을 사용한다.

## 3. pqc_rsatest.c vs pqs_ml_kem_dem_aes_256.c

### 비교 목적

- 기존 [pqc_rsatest.c](pqc_rsatest.c)는 RSA 기반의 “호환성 전환” 예제다.
- 새 [pqs_ml_kem_dem_aes_256.c](pqs_ml_kem_dem_aes_256.c)는 실제 ML-KEM 기반 PQC 키 캡슐화 + 대칭 암호화 흐름을 보여준다.
- 둘 다 OpenSSL 3.x 관점의 현대화 예제라는 점은 같지만, 구현 목표는 서로 다르다.

### 비교용 diff

```diff
--- a/ch4/pqc/pqc_rsatest.c
+++ b/ch4/pqc/pqs_ml_kem_dem_aes_256.c
@@
-    RSA *rsa = NULL;
-    RSA_generate_key_ex(rsa, 2048, e, NULL);
-    RSA_public_encrypt(..., rsa, RSA_PKCS1_OAEP_PADDING);
-    RSA_private_decrypt(..., rsa, RSA_PKCS1_OAEP_PADDING);
+    EVP_PKEY *pkey = NULL;
+    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
+    EVP_PKEY_generate(gen_ctx, &pkey);
+
+    EVP_PKEY_encapsulate(..., ciphertext, ..., shared_secret, ...);
+    EVP_PKEY_decapsulate(..., recovered_secret, ..., ciphertext, ...);
+
+    EVP_EncryptInit_ex(enc_aes, EVP_aes_256_cbc(), NULL, keybuf, iv);
+    EVP_DecryptInit_ex(dec_aes, EVP_aes_256_cbc(), NULL, keybuf, iv);
```

### 핵심 차이

- [pqc_rsatest.c](pqc_rsatest.c): 원본 RSA 흐름을 유지한 채 API만 현대화한다.
- [pqs_ml_kem_dem_aes_256.c](pqs_ml_kem_dem_aes_256.c): 양자 내성 키 교환(KEM)과 대칭 암호(DEM)를 실제로 연결한다.
- 전자는 “레거시 코드를 안전한 OpenSSL 3.x 스타일로 정리하는 예제”이며,
- 후자는 “실제 PQC 전환 시나리오를 시연하는 예제”로 구분된다.

즉, ch4에는 두 종류의 전환 코드가 함께 존재한다.

1. [pqc_rsatest.c](pqc_rsatest.c): 유지보수/호환성 중심의 현대화 예제
2. [pqs_ml_kem_dem_aes_256.c](pqs_ml_kem_dem_aes_256.c): 실제 양자 내성 암호 적용 예제

## 결론

ch4는 두 개의 원본 예제가 각각 다른 역할을 한다.

- [../rsatest.c](../rsatest.c): RSA 기본 동작을 그대로 비교하는 예제
- [../rsa_des_crc.c](../rsa_des_crc.c): RSA 봉투 + 대칭 암호 구조를 비교하는 예제

따라서 [ch4/pqc/README.md](README.md)에는 두 원본 예제를 모두 반영하는 문서 구조가 필요하며, 지금 문서는 두 프로그램의 비교를 함께 설명하도록 정리된 상태이다.
