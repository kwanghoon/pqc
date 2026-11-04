# Chapter별 파일 단위 1:1 매핑 및 API use-def 정리

다음 표는 각 chapter의 원본 파일과 PQC 전환 파일을 1:1로 매핑하고, 각 파일에서의 API 호출 순서와 리턴값/사용 관계를 요약한 것입니다.

## 전체 매핑 요약

| chapter | original | pqc | 비고 |
|---|---|---|---|
| ch2 | `mkrand16.c` | `pqc_mkrand16.c` | 난수/시드 생성 |
| ch2 | `rsagenkey.c` | `pqc_mldsa_genkey.c` | RSA 키 생성 → ML-DSA 키 생성 |
| ch3 | `aes_128_cbc.c` | `pqc_aes_256_cbc.c` | AES-128 CBC → AES-256 CBC |
| ch4 | `rsatest.c` | `pqc_mlkem_envelope.c` | RSA 암호문 봉투 → ML-KEM 봉투 |
| ch4 | `rsa_des_crc.c` | `pqc_mlkem_file.c` | RSA 파일 암호/복호 → ML-KEM 파일 암호/복호 |
| ch5 | `rsa_sha1_sign_test.c` | `pqc_mldsa_sign_test.c` | RSA-SHA1 서명/검증 → ML-DSA 서명/검증 |
| ch7 | `hash_sign.c` | `pqc_hash_sign.c` | 파일 서명/검증 |
| ch8 | `client0.c` | `pqc_client0.c` | 클라이언트 통신 |
| ch8 | `server0.c` | `pqc_server0.c` | 서버 통신 |
| ch9 | `ssl_client.c` | `pqc_ssl_client.c` | TLS 1.2 → TLS 1.3 |
| ch9 | `ssl_server.c` | `pqc_ssl_server.c` | TLS 1.2 → TLS 1.3 |

> ch6는 본 문서의 1:1 전환 대상을 구성하는 C 파일 집합에는 포함되지 않았고, 인증서/요청 생성 관련 파일 중심이라 별도 처리한 구조입니다.

---

## ch2

### ch2: `rsagenkey.c` → `pqc_mldsa_genkey.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `RAND_seed(seedbuf, 8)` → `RSA_generate_key(...)` → `RSAPublicKey_dup(rsaPriv)` → `PEM_write_RSAPublicKey(pubf, rsaPub)` → `PEM_write_RSAPrivateKey(privf, rsaPriv, ...)` → `RSA_free(rsaPriv)` / `RSA_free(rsaPub)` |
| 난수/시드 생성 단계 | `RAND_seed(seedbuf, 8)` |
| 키 생성 단계 | `RSA_generate_key(...)` → `RSAPublicKey_dup(rsaPriv)` |
| 파일 저장 단계 | `PEM_write_RSAPublicKey(pubf, rsaPub)` → `PEM_write_RSAPrivateKey(privf, rsaPriv, ...)` |
| 종료 단계 | `RSA_free(rsaPriv)` / `RSA_free(rsaPub)` |
| 리턴값 변수 | `rsaPriv`, `rsaPub` |
| 다음 함수에서 사용되는 변수 | `rsaPriv`는 `RSAPublicKey_dup(rsaPriv)`, `PEM_write_RSAPrivateKey(privf, rsaPriv, ...)`, `RSA_free(rsaPriv)`에서 사용됨. `rsaPub`는 `PEM_write_RSAPublicKey(pubf, rsaPub)`와 `RSA_free(rsaPub)`에서 사용됨. |
| 전환본 호출 순서 | `RAND_seed(seedbuf, 8)` → `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_keygen(ctx, &pkey)` → `PEM_write_PUBKEY(pubf, pkey)` → `PEM_write_PrivateKey(privf, pkey, ...)` → `EVP_PKEY_free(pkey)` |
| 전환본 난수/시드 생성 단계 | `RAND_seed(seedbuf, 8)` |
| 전환본 키 생성 단계 | `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_keygen(ctx, &pkey)` |
| 전환본 파일 저장 단계 | `PEM_write_PUBKEY(pubf, pkey)` → `PEM_write_PrivateKey(privf, pkey, ...)` |
| 전환본 종료 단계 | `EVP_PKEY_free(pkey)` |
| 전환본 리턴값 변수 | `ctx`, `pkey` |
| 전환본 use-def | `ctx`는 `EVP_PKEY_keygen_init(ctx)`와 `EVP_PKEY_keygen(ctx, &pkey)`로 사용되고, `pkey`는 `PEM_write_PUBKEY(pubf, pkey)`, `PEM_write_PrivateKey(..., pkey, ...)`, `EVP_PKEY_free(pkey)`로 사용됨. |

### ch2: `mkrand16.c` → `pqc_mkrand16.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `RAND_seed(seedbuf, 8)` → `RAND_bytes(...)` → 의사 난수 생성 후 사용 |
| 난수/시드 생성 단계 | `RAND_seed(seedbuf, 8)` → `RAND_bytes(...)` |
| 전환본 난수/시드 생성 단계 | `RAND_seed(seedbuf, 8)` → `RAND_bytes(...)` |
| 리턴값 변수 | `seedbuf`, 생성된 난수 버퍼 |
| 다음 함수에서 사용되는 변수 | `seedbuf`는 랜덤 시드로 사용되고, 난수 버퍼는 키/IV 생성에 사용됨. |
| 전환본 use-def | 전환본도 동일하게 `RAND_seed(seedbuf, 8)` 이후 난수 버퍼가 키/IV 생성의 입력으로 전달됨. |

---

## ch3

### ch3: `aes_128_cbc.c` → `pqc_aes_256_cbc.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `RAND_seed(seedbuff, 8)` → `RAND_bytes(mykey, 16)` → `RAND_bytes(iv, 16)` → `EVP_CIPHER_CTX_init(&ctx)` → `EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `EVP_CIPHER_CTX_cleanup(&ctx)` → 복호 경로 동일 반복 |
| 난수/시드 생성 단계 | `RAND_seed(seedbuff, 8)` → `RAND_bytes(mykey, 16)` → `RAND_bytes(iv, 16)` |
| 암호/복호 단계 | `EVP_CIPHER_CTX_init(&ctx)` → `EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `EVP_CIPHER_CTX_cleanup(&ctx)` |
| 복호 단계 | 복호 경로 동일 반복: `EVP_CIPHER_CTX_init(&ctx)` → `EVP_CipherInit_ex(..., AES_DECRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `EVP_CIPHER_CTX_cleanup(&ctx)` |
| 리턴값 변수 | `mykey`, `iv`, `ctx` |
| 다음 함수에서 사용되는 변수 | `mykey`와 `iv`는 `EVP_CipherInit_ex(..., mykey, iv, AES_ENCRYPT/DECRYPT)`의 인자로 사용됨. `ctx`는 `EVP_CipherUpdate`, `EVP_CipherFinal_ex`에 사용됨. |
| 전환본 호출 순서 | `RAND_seed(seedbuff, 8)` → `RAND_bytes(mykey, 32)` → `RAND_bytes(iv, 16)` → `EVP_CIPHER_CTX_new()` → `EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv, AES_ENCRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `EVP_CIPHER_CTX_free(ctx)` → 복호부 동일 |
| 전환본 난수/시드 생성 단계 | `RAND_seed(seedbuff, 8)` → `RAND_bytes(mykey, 32)` → `RAND_bytes(iv, 16)` |
| 전환본 암호/복호 단계 | `EVP_CIPHER_CTX_new()` → `EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv, AES_ENCRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `EVP_CIPHER_CTX_free(ctx)` |
| 전환본 복호 단계 | 복호부 동일: `EVP_CIPHER_CTX_new()` → `EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv, AES_DECRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `EVP_CIPHER_CTX_free(ctx)` |
| 전환본 리턴값 변수 | `ctx`, `mykey`, `iv` |
| 전환본 use-def | `mykey`와 `iv`는 암호화/복호화 초기화 함수의 인자로 이어지고, `ctx`는 업데이트와 종료 단계에서 사용됨. |

---

## ch4

### ch4: `rsatest.c` → `pqc_mlkem_envelope.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `RAND_seed(seedbuff, 8)` → `RSA_generate_key(1024, ... )` → `RSAPublicKey_dup(rsaPriv)` → `PEM_write_RSAPrivateKey(...)` → `PEM_write_RSAPublicKey(...)` → `RSA_public_encrypt(..., rsaPub, ...)` → `RSA_private_decrypt(..., rsaPriv, ...)` |
| 난수/시드 생성 단계 | `RAND_seed(seedbuff, 8)` |
| 키 생성 단계 | `RSA_generate_key(1024, ... )` → `RSAPublicKey_dup(rsaPriv)` |
| 암호/복호 단계 | `RSA_public_encrypt(..., rsaPub, ...)` → `RSA_private_decrypt(..., rsaPriv, ...)` |
| 리턴값 변수 | `rsaPriv`, `rsaPub` |
| 다음 함수에서 사용되는 변수 | `rsaPriv`은 `RSAPublicKey_dup(rsaPriv)`, `RSA_private_decrypt(..., rsaPriv, ...)`에 사용됨. `rsaPub`은 `RSA_public_encrypt(..., rsaPub, ...)`에 사용됨. |
| 전환본 호출 순서 | `generate_mlkem_key()` → `EVP_PKEY_CTX_new_from_name(..., "ML-KEM-768", ...)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_generate(ctx, &key)` → `PEM_write_PrivateKey(...)` / `PEM_write_PUBKEY(...)` → `EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)` → `EVP_PKEY_encapsulate_init(...)` → `EVP_PKEY_encapsulate(...)` → `EVP_EncryptInit_ex(...)` → `EVP_EncryptUpdate(...)` → `EVP_EncryptFinal_ex(...)` → 복호 단계 |
| 전환본 난수/시드 생성 단계 | `generate_mlkem_key()` 또는 내부 시드 및 키 생성 준비 |
| 전환본 키 생성 단계 | `EVP_PKEY_CTX_new_from_name(..., "ML-KEM-768", ...)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_generate(ctx, &key)` |
| 전환본 암호/복호 단계 | `EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)` → `EVP_PKEY_encapsulate_init(...)` → `EVP_PKEY_encapsulate(...)` → `EVP_EncryptInit_ex(...)` → `EVP_EncryptUpdate(...)` → `EVP_EncryptFinal_ex(...)` → 복호 단계 |
| 전환본 리턴값 변수 | `key`, `kem_ctx`, `shared_secret`, `cipher_ctx` |
| 전환본 use-def | `key`는 키 저장 및 `EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate`의 입력으로 사용됨. `shared_secret`은 암호화/복호화 키로 사용됨. |

### ch4: `rsa_des_crc.c` → `pqc_mlkem_file.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `RAND_seed(seedbuff, 8)` → `RAND_bytes(mykey,...)` → `RAND_bytes(iv,...)` → `RSA_public_encrypt(..., rsaPub, ...)` → `EVP_CipherInit_ex(..., mykey, iv, DES_ENCRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `RSA_private_decrypt(..., rsaPriv, ...)` → `EVP_CipherInit_ex(..., mykey, iv, DES_DECRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` |
| 난수/시드 생성 단계 | `RAND_seed(seedbuff, 8)` → `RAND_bytes(mykey, ...)` → `RAND_bytes(iv, ...)` |
| 암호/복호 단계 | `RSA_public_encrypt(..., rsaPub, ...)` → `EVP_CipherInit_ex(..., mykey, iv, DES_ENCRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` → `RSA_private_decrypt(..., rsaPriv, ...)` → `EVP_CipherInit_ex(..., mykey, iv, DES_DECRYPT)` → `EVP_CipherUpdate(...)` → `EVP_CipherFinal_ex(...)` |
| 리턴값 변수 | `mykey`, `iv`, `rsaPub`, `rsaPriv` |
| 다음 함수에서 사용되는 변수 | `mykey`는 RSA 암호화와 DES 초기화에 사용됨. `rsaPub`는 `RSA_public_encrypt`에 사용되고, `rsaPriv`는 `RSA_private_decrypt`에 사용됨. |
| 전환본 호출 순서 | `generate_mlkem_key()` → `EVP_PKEY_CTX_new_from_name(..., "ML-KEM-768", ...)` → `EVP_PKEY_keygen_init` → `EVP_PKEY_generate` → `PEM_write_PrivateKey` / `PEM_write_PUBKEY` → `EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)` → `EVP_PKEY_encapsulate(...)` → `RAND_bytes(nonce, ...)` → `EVP_EncryptInit_ex(...)` → `EVP_EncryptUpdate(...)` → `EVP_EncryptFinal_ex(...)` → `EVP_CIPHER_CTX_ctrl(...GCM_GET_TAG...)` → 복호 단계 |
| 전환본 난수/시드 생성 단계 | `RAND_bytes(nonce, ...)` |
| 전환본 키 생성 단계 | `generate_mlkem_key()` → `EVP_PKEY_CTX_new_from_name(..., "ML-KEM-768", ...)` → `EVP_PKEY_keygen_init` → `EVP_PKEY_generate` |
| 전환본 암호/복호 단계 | `EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)` → `EVP_PKEY_encapsulate(...)` → `EVP_EncryptInit_ex(...)` → `EVP_EncryptUpdate(...)` → `EVP_EncryptFinal_ex(...)` → `EVP_CIPHER_CTX_ctrl(...GCM_GET_TAG...)` → 복호 단계 |
| 전환본 리턴값 변수 | `key`, `shared_secret`, `nonce`, `cipher_ctx` |
| 전환본 use-def | `key`는 encapsulate/decapsulate 입력으로 사용되고, `shared_secret`과 `nonce`는 GCM 암호화/복호화 초기화 함수에 사용됨. |

---

## ch5

### ch5: `rsa_sha1_sign_test.c` → `pqc_mldsa_sign_test.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `RAND_seed(rands, 0)` → `RSA_generate_key(...)` → `RSAPublicKey_dup(rsaPriv)` → `EVP_PKEY_new()` → `EVP_PKEY_set1_RSA(pkey, rsaPriv)` → `EVP_MD_CTX_init(&ctx)` → `EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)` → `EVP_SignUpdate(...)` → `EVP_SignFinal(..., pkey)` → `EVP_PKEY_set1_RSA(pukey, rsaPub)` → `EVP_VerifyInit_ex(...)` → `EVP_VerifyUpdate(...)` → `EVP_VerifyFinal(..., pukey)` |
| 난수/시드 생성 단계 | `RAND_seed(rands, 0)` |
| 키 생성 단계 | `RSA_generate_key(...)` → `RSAPublicKey_dup(rsaPriv)` → `EVP_PKEY_new()` → `EVP_PKEY_set1_RSA(pkey, rsaPriv)` → `EVP_PKEY_set1_RSA(pukey, rsaPub)` |
| 서명/검증 단계 | `EVP_MD_CTX_init(&ctx)` → `EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)` → `EVP_SignUpdate(...)` → `EVP_SignFinal(..., pkey)` → `EVP_VerifyInit_ex(...)` → `EVP_VerifyUpdate(...)` → `EVP_VerifyFinal(..., pukey)` |
| 리턴값 변수 | `rsaPriv`, `rsaPub`, `pkey`, `pukey`, `sign` |
| 다음 함수에서 사용되는 변수 | `rsaPriv`는 `EVP_PKEY_set1_RSA(pkey, rsaPriv)`에 사용됨. `rsaPub`는 `EVP_PKEY_set1_RSA(pukey, rsaPub)`에 사용됨. `pkey`는 `EVP_SignFinal(..., pkey)`에 사용되고, `pukey`는 `EVP_VerifyFinal(..., pukey)`에 사용됨. |
| 전환본 호출 순서 | `key = generateKey()` → `EVP_MD_CTX_new()` → `EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, priv, NULL)` → `EVP_DigestSign(ctx, sign, signSize, plaintext, plsize)` → `EVP_MD_CTX_new()` → `EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pub, NULL)` → `EVP_DigestVerify(ctx, sign, signSize, plaintext, plsize)` |
| 전환본 키 생성 단계 | `key = generateKey()` |
| 전환본 서명/검증 단계 | `EVP_MD_CTX_new()` → `EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, priv, NULL)` → `EVP_DigestSign(ctx, sign, signSize, plaintext, plsize)` → `EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pub, NULL)` → `EVP_DigestVerify(ctx, sign, signSize, plaintext, plsize)` |
| 전환본 리턴값 변수 | `key`, `ctx`, `sign`, `signSize`, `priv`, `pub` |
| 전환본 use-def | `key`는 서명/검증의 키 인자로 사용되며, `sign`/`signSize`는 검증 단계 입력값으로 사용됨. |

---

## ch7

### ch7: `hash_sign.c` → `pqc_hash_sign.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `PEM_read_RSAPrivateKey(...)` → `EVP_PKEY_new()` → `EVP_PKEY_set1_RSA(pkey, rsaPriv)` → `EVP_MD_CTX_init(&ctx)` → `EVP_SignInit_ex(...)` → `EVP_SignUpdate(...)` → `EVP_SignFinal(...)` → `PEM_read_RSAPublicKey(...)` → `EVP_PKEY_set1_RSA(pkey, rsaPub)` → `EVP_VerifyInit_ex(...)` → `EVP_VerifyUpdate(...)` → `EVP_VerifyFinal(...)` |
| 키 로딩 단계 | `PEM_read_RSAPrivateKey(...)` → `PEM_read_RSAPublicKey(...)` |
| 서명/검증 단계 | `EVP_PKEY_new()` → `EVP_PKEY_set1_RSA(pkey, rsaPriv)` → `EVP_MD_CTX_init(&ctx)` → `EVP_SignInit_ex(...)` → `EVP_SignUpdate(...)` → `EVP_SignFinal(...)` → `EVP_PKEY_set1_RSA(pkey, rsaPub)` → `EVP_VerifyInit_ex(...)` → `EVP_VerifyUpdate(...)` → `EVP_VerifyFinal(...)` |
| 리턴값 변수 | `rsaPriv`, `rsaPub`, `pkey`, `sign`, `signSize` |
| 다음 함수에서 사용되는 변수 | `rsaPriv`는 `EVP_PKEY_set1_RSA(pkey, rsaPriv)`에 사용되고, `rsaPub`는 `EVP_PKEY_set1_RSA(pkey, rsaPub)`에 사용됨. `pkey`는 최종 서명/검증 함수에서 사용됨. |
| 전환본 호출 순서 | `PEM_read_PrivateKey(fp, NULL, NULL, NULL)` → `EVP_MD_CTX_new()` → `EVP_DigestInit_ex(ctx, EVP_sha512(), NULL)` → `EVP_DigestUpdate(ctx, buff, inLen)` → `EVP_DigestFinal_ex(ctx, hash, &hashSize)` → `signHashed(pkey, hash, hashSize, sign, &signSize)` → `PEM_read_PUBKEY(...)` → 재검증 경로 |
| 전환본 키 로딩 단계 | `PEM_read_PrivateKey(fp, NULL, NULL, NULL)` → `PEM_read_PUBKEY(...)` |
| 전환본 서명/검증 단계 | `EVP_MD_CTX_new()` → `EVP_DigestInit_ex(ctx, EVP_sha512(), NULL)` → `EVP_DigestUpdate(ctx, buff, inLen)` → `EVP_DigestFinal_ex(ctx, hash, &hashSize)` → `signHashed(pkey, hash, hashSize, sign, &signSize)` → 재검증 경로 |
| 전환본 리턴값 변수 | `pkey`, `ctx`, `hash`, `hashSize`, `sign` |
| 전환본 use-def | `pkey`는 서명 함수의 입력이며, `hash`는 서명/검증 함수에서 사용됨. |

---

## ch8

### ch8: `client0.c` → `pqc_client0.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `SSL_library_init()` → `SSL_load_error_strings()` → `SSLv23_client_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_load_verify_locations(...)` → `SSL_CTX_set_verify(...)` → `BIO_new_ssl_connect(ctx)` → `BIO_get_ssl(...)` → `SSL_set_mode(...)` → `X509_VERIFY_PARAM_set1_host(...)` → `BIO_set_conn_hostname(...)` → `BIO_do_connect(...)` → `BIO_do_handshake(...)` → `SSL_get_server_tmp_key(...)` → `SSL_get_version(...)` → `SSL_get_cipher_name(...)` → `BIO_puts(...)` → `BIO_read(...)` → `BIO_write(...)` |
| 리턴값 변수 | `meth`, `ctx`, `sbio`, `ssl`, `tmpkey`, `ver`, `name` |
| 다음 함수에서 사용되는 변수 | `ctx`는 `BIO_new_ssl_connect(ctx)`의 입력. `ssl`은 `SSL_set_mode(ssl, ...)`, `SSL_get_server_tmp_key(ssl, &tmpkey)`, `SSL_get_version(ssl)`의 입력. `sbio`는 핸드셰이크와 I/O API에 사용됨. |
| 전환본 호출 순서 | `TLS_client_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_set_min_proto_version(...)` → `SSL_CTX_set_max_proto_version(...)` → `SSL_CTX_set1_groups_list(...)` → `SSL_CTX_set1_sigalgs_list(...)` → `SSL_CTX_load_verify_locations(...)` → `BIO_new_ssl_connect(ctx)` → `BIO_get_ssl(...)` → `SSL_set_mode(...)` → `X509_VERIFY_PARAM_set1_host(...)` → `BIO_do_connect(...)` → `BIO_do_handshake(...)` → `SSL_get0_group_name(ssl)` → `SSL_get_cipher_name(ssl)` |
| 전환본 리턴값 변수 | `meth`, `ctx`, `sbio`, `ssl` |
| 전환본 use-def | `ctx`는 그룹/시그널 알고리즘 설정과 연결 단계의 입력으로 사용됨. `ssl`은 최종 TLS 1.3 파라미터 확인에 사용됨. |

### ch8: `server0.c` → `pqc_server0.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `SSL_library_init()` → `SSL_load_error_strings()` → `SSLv23_server_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_use_certificate_chain_file(...)` → `SSL_CTX_use_PrivateKey_file(...)` → `SSL_CTX_check_private_key(...)` → `BIO_new_ssl(ctx, 0)` → `BIO_new_accept(...)` → `BIO_do_accept(...)` → `BIO_do_handshake(...)` → `BIO_puts(...)` → `BIO_write(...)` |
| 리턴값 변수 | `meth`, `ctx`, `sbio`, `acpt` |
| 다음 함수에서 사용되는 변수 | `ctx`는 인증서/키 설정과 객체 연결에 사용됨. `sbio`는 handshake와 I/O에 사용됨. |
| 전환본 호출 순서 | `TLS_server_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_set_min_proto_version(...)` → `SSL_CTX_set_max_proto_version(...)` → `SSL_CTX_set1_groups_list(...)` → `SSL_CTX_set1_sigalgs_list(...)` → `SSL_CTX_use_certificate_chain_file(...)` → `SSL_CTX_use_PrivateKey_file(...)` → `SSL_CTX_check_private_key(...)` → `SSL_CTX_get0_privatekey(ctx)` → `EVP_PKEY_is_a(...)` |
| 전환본 리턴값 변수 | `meth`, `ctx`, `key` |
| 전환본 use-def | `ctx`는 인증서와 키 검증에 사용되고, `SSL_CTX_get0_privatekey(ctx)`의 결과 `key`는 `EVP_PKEY_is_a(key, "ML-DSA-65")`로 사용됨. |

---

## ch9

### ch9: `ssl_client.c` → `pqc_ssl_client.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `SSL_library_init()` → `SSL_load_error_strings()` → `SSLv23_client_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_load_verify_locations(...)` → `SSL_CTX_set_verify(...)` → `BIO_new_ssl_connect(ctx)` → `BIO_get_ssl(...)` → `SSL_set_mode(ssl, ...)` → `X509_VERIFY_PARAM_set1_host(...)` → `BIO_set_conn_hostname(...)` → `BIO_do_connect(...)` → `BIO_do_handshake(...)` → `SSL_get_server_tmp_key(ssl, &tmpkey)` → `SSL_get_version(ssl)` → `SSL_get_cipher_name(ssl)` |
| 리턴값 변수 | `meth`, `ctx`, `sbio`, `ssl`, `tmpkey` |
| 다음 함수에서 사용되는 변수 | `meth`는 `SSL_CTX_new(meth)`에 사용되고, `ctx`는 이후 연결/검증 단계에 사용됨. `ssl`은 `SSL_set_mode`, `SSL_get_server_tmp_key`, `SSL_get_version`의 입력. |
| 전환본 호출 순서 | `TLS_client_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)` → `SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)` → `SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP384r1MLKEM1024")` → `SSL_CTX_set1_sigalgs_list(ctx, "mldsa65")` → `SSL_CTX_load_verify_locations(ctx, "CACert.pem", NULL)` → `BIO_new_ssl_connect(ctx)` → `BIO_get_ssl(...)` → `SSL_set_mode(...)` → `X509_VERIFY_PARAM_set1_host(...)` → `BIO_do_connect(...)` → `BIO_do_handshake(...)` → `SSL_get_version(ssl)` → `SSL_get0_group_name(ssl)` → `SSL_get_cipher_name(ssl)` |
| 전환본 리턴값 변수 | `meth`, `ctx`, `sbio`, `ssl` |
| 전환본 use-def | `ctx`는 그룹/시그널 설정과 연결 단계의 입력으로 사용되고, `ssl`은 TLS 1.3 프로토콜 파라미터(그룹, cipher) 확인에 사용됨. |

### ch9: `ssl_server.c` → `pqc_ssl_server.c`

| 항목 | 내용 |
|---|---|
| API 호출 순서 | `SSL_library_init()` → `SSL_load_error_strings()` → `SSLv23_server_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_use_certificate_chain_file(ctx, ...)` → `SSL_CTX_use_PrivateKey_file(...)` → `SSL_CTX_check_private_key(ctx)` → `BIO_new_ssl(ctx, 0)` → `BIO_new_accept(...)` → `BIO_do_accept(...)` → `BIO_do_handshake(...)` → `BIO_puts(...)` → `BIO_write(...)` |
| 리턴값 변수 | `meth`, `ctx`, `sbio`, `acpt`, `ssl` |
| 다음 함수에서 사용되는 변수 | `ctx`는 인증서 파일 로딩, 키 확인, BIO 생성에 사용됨. `sbio`는 `BIO_do_handshake`와 I/O 함수에 사용됨. |
| 전환본 호출 순서 | `TLS_server_method()` → `SSL_CTX_new(meth)` → `SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)` → `SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)` → `SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP384r1MLKEM1024")` → `SSL_CTX_set1_sigalgs_list(ctx, "mldsa65")` → `SSL_CTX_use_certificate_chain_file(ctx, ...)` → `SSL_CTX_use_PrivateKey_file(...)` → `SSL_CTX_check_private_key(ctx)` → `SSL_CTX_get0_privatekey(ctx)` → `EVP_PKEY_is_a(...)` |
| 전환본 리턴값 변수 | `meth`, `ctx`, `key` |
| 전환본 use-def | `ctx`는 TLS 1.3 그룹과 키 설정에 사용되고, `key`는 `EVP_PKEY_is_a(key, "ML-DSA-65")`로 사용되어 ML-DSA 키를 확인한다. |

---

## 패턴 정리

1. 난수/시드 생성
   - Legacy: `RAND_seed(seedbuf, 8)` -> `RAND_bytes(buf, n)`
     * 선행 조건: `unsigned char seedbuf[8]`
     * 후행 조건: `unsigned char buf[n]`
   - PQC: `RAND_seed(seedbuf, 8)` -> `RAND_bytes(buf, n)`
     * 선행 조건: `unsigned char seedbuf[8]`
     * 후행 조건: `unsigned char buf[n]`

2. 키 생성
   - Legacy: `RSA_generate_key(1024, RSA_F4, NULL, NULL)` 또는 `EVP_PKEY_set1_RSA(pkey, rsaPriv)`
     * 선행 조건: `EVP_PKEY *pkey`, `RSA *rsaPriv`
     * 후행 조건: `RSA *rsaPriv`, `RSA *rsaPub`
   - PQC: `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_keygen(ctx, &pkey)`
     * 선행 조건: `EVP_PKEY_CTX *ctx`
     * 후행 조건: `EVP_PKEY *pkey`

3. 암호
   - Legacy: `EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT) -> EVP_CipherUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) -> EVP_CipherFinal_ex(ctx, ciphertext + ciphertext_len, &ciphertext_len)`
     * 선행 조건: `EVP_CIPHER_CTX *ctx`, `unsigned char mykey[16]`, `unsigned char iv[16]`, `unsigned char plaintext[plaintext_len]`
     * 후행 조건: `unsigned char ciphertext[ciphertext_len]`
   - PQC: `ret_ctx = EVP_CIPHER_CTX_new() -> EVP_EncryptInit_ex(ret_ctx, EVP_aes_256_cbc(), NULL, mykey, iv) -> EVP_EncryptUpdate(ret_ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) -> EVP_EncryptFinal_ex(ret_ctx, ciphertext + ciphertext_len, &ciphertext_len)`
     * 선행 조건: `EVP_CIPHER_CTX *ret_ctx`, `unsigned char mykey[32]`, `unsigned char iv[16]`, `unsigned char plaintext[plaintext_len]`
     * 후행 조건: `unsigned char ciphertext[ciphertext_len]`

3. 복호
   - Legacy: `EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_DECRYPT) -> EVP_CipherUpdate(ctx, decrypted, &decrypted_len, ciphertext, ciphertext_len) -> EVP_CipherFinal_ex(ctx, decrypted + decrypted_len, &decrypted_len)`
     * 선행 조건: `EVP_CIPHER_CTX *ctx`, `unsigned char mykey[16]`, `unsigned char iv[16]`, `unsigned char ciphertext[ciphertext_len]`
     * 후행 조건: `unsigned char decrypted[decrypted_len]`
   - PQC: `ret_ctx = EVP_CIPHER_CTX_new() -> EVP_DecryptInit_ex(ret_ctx, EVP_aes_256_cbc(), NULL, mykey, iv) -> EVP_DecryptUpdate(ret_ctx, decrypted, &decrypted_len, ciphertext, ciphertext_len) -> EVP_DecryptFinal_ex(ret_ctx, decrypted + decrypted_len, &decrypted_len)`
     * 선행 조건: `EVP_CIPHER_CTX *ret_ctx`, `unsigned char mykey[32]`, `unsigned char iv[16]`, `unsigned char ciphertext[ciphertext_len]`
     * 후행 조건: `unsigned char decrypted[decrypted_len]`

4. 서명
   - Legacy: `EVP_PKEY_set1_RSA(pkey, rsaPriv) -> EVP_SignInit_ex(ctx, EVP_sha1(), NULL) -> EVP_SignUpdate(ctx, message, message_len) -> EVP_SignFinal(ctx, sign, &sign_len, pkey)`
     * 선행 조건: `EVP_PKEY *pkey`, `RSA *rsaPriv`, `unsigned char message[message_len]`
     * 후행 조건: `unsigned char sign[sign_len]`
   - PQC: `ret_ctx = EVP_MD_CTX_new() -> EVP_DigestSignInit_ex(ret_ctx, NULL, EVP_sha256(), NULL, pkey, NULL) -> EVP_DigestSign(ret_ctx, sign, &sign_len, message, message_len)`
     * 선행 조건: `EVP_MD_CTX *ret_ctx`, `EVP_PKEY *pkey`, `unsigned char message[message_len]`
     * 후행 조건: `unsigned char sign[sign_len]`

4. 검증
   - Legacy: `EVP_PKEY_set1_RSA(pukey, rsaPub) -> EVP_VerifyInit_ex(ctx, EVP_sha1(), NULL) -> EVP_VerifyUpdate(ctx, message, message_len) -> EVP_VerifyFinal(ctx, sign, sign_len, pukey)`
     * 선행 조건: `EVP_PKEY *pukey`, `RSA *rsaPub`, `unsigned char sign[sign_len]`, `unsigned char message[message_len]`
     * 후행 조건: `int verify_result`
   - PQC: `ret_ctx = EVP_MD_CTX_new() -> EVP_DigestVerifyInit_ex(ret_ctx, NULL, EVP_sha256(), NULL, pukey, NULL) -> EVP_DigestVerify(ret_ctx, sign, sign_len, message, message_len)`
     * 선행 조건: `EVP_MD_CTX *ret_ctx`, `EVP_PKEY *pukey`, `unsigned char sign[sign_len]`, `unsigned char message[message_len]`
     * 후행 조건: `int verify_result`

5. TLS 클라이언트 설정
   - Legacy: `SSLv23_client_method() -> SSL_CTX_new(meth) -> SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL) -> SSL_CTX_load_verify_locations(ctx, CAfile, NULL)`
     * 선행 조건: `SSL_METHOD *meth`, `SSL_CTX *ctx`
     * 후행 조건: `SSL_CTX *ctx`
   - PQC: `TLS_client_method() -> SSL_CTX_new(meth) -> SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) -> SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) -> SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP384r1MLKEM1024") -> SSL_CTX_set1_sigalgs_list(ctx, "mldsa65")`
     * 선행 조건: `SSL_METHOD *meth`, `SSL_CTX *ctx`
     * 후행 조건: `SSL_CTX *ctx`

5. TLS 서버 설정
   - Legacy: `SSLv23_server_method() -> SSL_CTX_new(meth) -> SSL_CTX_use_certificate_chain_file(ctx, cert_file) -> SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) -> SSL_CTX_check_private_key(ctx)`
     * 선행 조건: `SSL_METHOD *meth`, `SSL_CTX *ctx`
     * 후행 조건: `SSL_CTX *ctx`
   - PQC: `TLS_server_method() -> SSL_CTX_new(meth) -> SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) -> SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) -> SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP384r1MLKEM1024") -> SSL_CTX_set1_sigalgs_list(ctx, "mldsa65") -> SSL_CTX_use_certificate_chain_file(ctx, cert_file) -> SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) -> SSL_CTX_check_private_key(ctx)`
     * 선행 조건: `SSL_METHOD *meth`, `SSL_CTX *ctx`
     * 후행 조건: `SSL_CTX *ctx`
