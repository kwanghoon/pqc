## ch2/pqc/pqc_mkrand16.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"buf"| C["randbuf <- RAND_bytes(randbuf, 16)
int RAND_bytes(unsigned char* buf, int num)"]
    C --> D["printStr(randbuf, 16)"]
```

## ch2/pqc/pqc_mldsa_genkey.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"libctx=NULL, name='ML-DSA-65'"| C["ctx <- EVP_PKEY_CTX_new_from_name(NULL, 'ML-DSA-65', NULL)
EVP_PKEY_CTX* ctx <- EVP_PKEY_CTX_new_from_name(OPENSSL_CTX* libctx, const char* name, const char* propq)"]
    C -->|"ctx"| D["EVP_PKEY_keygen_init(ctx)
int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx)"]
    D -->|"ctx, ppkey"| E["pkey <- EVP_PKEY_keygen(ctx, &pkey)
int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey)"]
    E -->|"pkey"| F["PEM_write_PUBKEY(pubf, pkey)
int PEM_write_PUBKEY(FILE* fp, EVP_PKEY* pkey)"]
    E -->|"pkey"| G["PEM_write_PrivateKey(privf, pkey, NULL, NULL, 0, NULL, NULL)
int PEM_write_PrivateKey(FILE* fp, EVP_PKEY* pkey, const EVP_CIPHER* enc, unsigned char* kstr, int klen, pem_password_cb* cb, void* u)"]
    E -->|"pkey"| H["EVP_PKEY_free(pkey)"]
```

## ch3/pqc/pqc_aes_256_cbc.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"mykey"| C["mykey <- RAND_bytes(mykey, 32)
int RAND_bytes(unsigned char* buf, int num)"]
    B -->|"iv"| D["iv <- RAND_bytes(iv, 16)
int RAND_bytes(unsigned char* buf, int num)"]
    C -->|"ctx, key=mykey, iv"| E["EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv, AES_ENCRYPT)
int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc)"]
    E -->|"ctx"| F["EVP_CipherUpdate(ctx, cipherbuf, &out_len, plainbuf, in_len)
int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    F -->|"ctx"| G["EVP_CipherFinal_ex(ctx, cipherbuf, &out_len)
int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    G --> H["EVP_CIPHER_CTX_free(ctx)"]
    D -->|"ctx, key=mykey, iv"| I["EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv, AES_DECRYPT)
int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc)"]
    I -->|"ctx"| J["EVP_CipherUpdate(ctx, plainbuf, &out_len, cipherbuf, in_len)
int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    J -->|"ctx"| K["EVP_CipherFinal_ex(ctx, plainbuf, &out_len)
int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    K --> L["EVP_CIPHER_CTX_free(ctx)"]
```

## ch4/pqc/pqc_mlkem_envelope.c

```mermaid
flowchart TD
    A["pub <- read_public_key(path)
EVP_PKEY* pub <- read_public_key(const char* path)"] -->|"pub"| B["kem <- EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL)
EVP_PKEY_CTX* kem <- EVP_PKEY_CTX_new_from_pkey(OPENSSL_CTX* libctx, EVP_PKEY* pkey, const char* propq)"]
    B -->|"kem"| C["EVP_PKEY_encapsulate_init(kem, NULL)
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])"]
    C -->|"kem, secret"| D["EVP_PKEY_encapsulate(kem, header + 4, &ct_len, secret, &secret_len)
int EVP_PKEY_encapsulate(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, unsigned char* secret, size_t* secretlen)"]
    D -->|"nonce"| E["RAND_bytes(header + ... , NONCE_LEN)
int RAND_bytes(unsigned char* buf, int num)"]
    E -->|"cipher, key=secret, iv=nonce"| F["EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, secret, nonce)
int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    F -->|"cipher"| G["EVP_EncryptUpdate(cipher, out_buf, &n, in_buf, r)
int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    G -->|"cipher"| H["EVP_EncryptFinal_ex(cipher, out_buf, &n)
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    H -->|"tag"| I["EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    I -->|"priv"| J["priv <- read_private_key(path)
EVP_PKEY* priv <- read_private_key(const char* path)"]
    J -->|"priv"| K["kem2 <- EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL)
EVP_PKEY_CTX* kem2 <- EVP_PKEY_CTX_new_from_pkey(OPENSSL_CTX* libctx, EVP_PKEY* pkey, const char* propq)"]
    K -->|"kem2"| L["EVP_PKEY_decapsulate_init(kem2, NULL)
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])"]
    L -->|"kem2, secret"| M["EVP_PKEY_decapsulate(kem2, secret, &secret_len, ct, ct_len)
int EVP_PKEY_decapsulate(EVP_PKEY_CTX* ctx, unsigned char* secret, size_t* secretlen, const unsigned char* in, size_t inlen)"]
    M -->|"cipher, key=secret, iv=nonce"| N["EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, secret, nonce)
int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    N -->|"cipher"| O["EVP_DecryptUpdate(cipher, out_buf, &n, in_buf, r)
int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    O -->|"cipher"| P["EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    P -->|"cipher"| Q["EVP_DecryptFinal_ex(cipher, out_buf, &n)
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
```

## ch4/pqc/pqc_mlkem_file.c

```mermaid
flowchart TD
    A["key <- generate_mlkem_key()
EVP_PKEY* key <- generate_mlkem_key(void)"] -->|"key"| B["PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL)
int PEM_write_PrivateKey(FILE* fp, EVP_PKEY* pkey, const EVP_CIPHER* enc, unsigned char* kstr, int klen, pem_password_cb* cb, void* u)"]
    A -->|"key"| C["PEM_write_PUBKEY(file, key)
int PEM_write_PUBKEY(FILE* fp, EVP_PKEY* pkey)"]
    A -->|"pkey=key"| D["kem_ctx <- EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)
EVP_PKEY_CTX* kem_ctx <- EVP_PKEY_CTX_new_from_pkey(OPENSSL_CTX* libctx, EVP_PKEY* pkey, const char* propq)"]
    D -->|"kem_ctx"| E["EVP_PKEY_encapsulate_init(kem_ctx, NULL)
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])"]
    E -->|"kem_ctx, out=kem_ciphertext, secret=shared_secret"| F["EVP_PKEY_encapsulate(kem_ctx, kem_ciphertext, &kem_ciphertext_len, shared_secret, &shared_secret_len)
int EVP_PKEY_encapsulate(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, unsigned char* secret, size_t* secretlen)"]
    F -->|"nonce"| G["RAND_bytes(nonce, sizeof(nonce))
int RAND_bytes(unsigned char* buf, int num)"]
    G -->|"key=shared_secret, iv=nonce"| H["EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, shared_secret, nonce)
int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    H -->|"ctx"| I["EVP_EncryptUpdate(cipher_ctx, output_buf, &out_len, input_buf, bytes_read)
int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    I -->|"ctx"| J["EVP_EncryptFinal_ex(cipher_ctx, output_buf, &final_len)
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    J -->|"ctx"| K["EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    K -->|"kem_ctx"| L["EVP_PKEY_decapsulate_init(kem_ctx, NULL)
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])"]
    L -->|"kem_ctx, in=kem_ciphertext, secret=shared_secret"| M["EVP_PKEY_decapsulate(kem_ctx, shared_secret, &shared_secret_len, kem_ciphertext, kem_ciphertext_len)
int EVP_PKEY_decapsulate(EVP_PKEY_CTX* ctx, unsigned char* secret, size_t* secretlen, const unsigned char* in, size_t inlen)"]
    M -->|"key=shared_secret, iv=nonce"| N["EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, shared_secret, nonce)
int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    N -->|"ctx"| O["EVP_DecryptUpdate(cipher_ctx, output_buf, &out_len, input_buf, bytes_read)
int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    O -->|"ctx"| P["EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag)
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    P -->|"ctx"| Q["EVP_DecryptFinal_ex(cipher_ctx, output_buf, &final_len)
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
```

## ch5/pqc/pqc_mldsa_sign_test.c

```mermaid
flowchart TD
    A["key <- generateKey()
EVP_PKEY* key <- generateKey(void)"] -->|"key"| B["ctx <- EVP_MD_CTX_new()
EVP_MD_CTX* ctx <- EVP_MD_CTX_new(void)"]
    B -->|"ctx, pkey=key"| C["EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL)
int EVP_DigestSignInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* mdname, OPENSSL_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[])"]
    C -->|"ctx, sign"| D["EVP_DigestSign(ctx, sign, &ssize, plaintext, plsize)
int EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen)"]
    D -->|"ctx"| E["EVP_MD_CTX_free(ctx)"]
    A -->|"key"| F["ctx2 <- EVP_MD_CTX_new()
EVP_MD_CTX* ctx2 <- EVP_MD_CTX_new(void)"]
    F -->|"ctx2, pkey=key"| G["EVP_DigestVerifyInit_ex(ctx2, NULL, NULL, NULL, NULL, key, NULL)
int EVP_DigestVerifyInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* mdname, OPENSSL_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[])"]
    G -->|"ctx2, sign"| H["EVP_DigestVerify(ctx2, sign, ssize, plaintext, plsize)
int EVP_DigestVerify(EVP_MD_CTX* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen)"]
    H -->|"ctx2"| I["EVP_MD_CTX_free(ctx2)"]
```

## ch7/pqc/pqc_hash_sign.c

```mermaid
flowchart TD
    A["pkey <- PEM_read_PrivateKey(fp, NULL, NULL, NULL)"] -->|"pkey"| B["ctx <- EVP_MD_CTX_new()
EVP_MD_CTX* ctx <- EVP_MD_CTX_new(void)"]
    B -->|"ctx"| C["EVP_DigestInit_ex(ctx, EVP_sha512(), NULL)
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    C -->|"ctx"| D["EVP_DigestUpdate(ctx, buff, inLen)
int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    D -->|"ctx"| E["EVP_DigestFinal_ex(ctx, hash, &hashSize)
int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)"]
    E -->|"hash, hashSize"| F["signHashed(pkey, hash, hashSize, sign, &signSize)"]
    F -->|"ctx"| G["EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params)
int EVP_DigestSignInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* mdname, OPENSSL_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[])"]
    G -->|"ctx"| H["EVP_DigestSign(ctx, sign, &signSize, msg, msgLen)
int EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen)"]
    I["pkey2 <- PEM_read_PUBKEY(fp, NULL, NULL, NULL)"] -->|"pkey2"| J["ctx2 <- EVP_MD_CTX_new()
EVP_MD_CTX* ctx2 <- EVP_MD_CTX_new(void)"]
    J -->|"ctx2"| K["EVP_DigestInit_ex(ctx2, EVP_sha512(), NULL)
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    K -->|"ctx2"| L["EVP_DigestUpdate(ctx2, buff, inLen)
int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    L -->|"ctx2"| M["EVP_DigestFinal_ex(ctx2, hash, &hashSize)
int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)"]
    M -->|"hash, hashSize"| N["verifyHashed(pkey2, hash, hashSize, sign, signSize)"]
    N -->|"ctx2"| O["EVP_DigestVerifyInit_ex(ctx2, NULL, NULL, NULL, NULL, pkey2, params)
int EVP_DigestVerifyInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* mdname, OPENSSL_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[])"]
    O -->|"ctx2"| P["EVP_DigestVerify(ctx2, sign, signSize, msg, msgLen)
int EVP_DigestVerify(EVP_MD_CTX* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen)"]
```

## ch8/pqc/pqc_client0.c

```mermaid
flowchart TD
    A["fd <- open('symmKey.sec', O_RDONLY)"] -->|"rawkey"| B["res <- read(fd, rawkey, KEYSZ)
ssize_t read(int fd, void* buf, size_t count)"]
    B -->|"nonce"| C["RAND_bytes(buff, NONCESZ)
int RAND_bytes(unsigned char* buf, int num)"]
    C -->|"key=rawkey, iv=buff"| D["EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, rawkey, buff)
int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    D -->|"ctx"| E["EVP_EncryptUpdate(ctx, buff + NONCESZ, &outLen, (unsigned char*)&timeStamp, sizeof(struct timeval))
int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    E -->|"ctx"| F["EVP_EncryptFinal_ex(ctx, buff + NONCESZ + outLen, &outLen)
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    F -->|"ctx"| G["EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAGSZ, buff + NONCESZ + sizeof(struct timeval))
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    G -->|"cipherBSz"| H["cipherBSz <- NONCESZ + sizeof(struct timeval) + TAGSZ"]
    H -->|"buff"| I["send(sockfd, &buff, cipherBSz, 0)"]
```

## ch8/pqc/pqc_server0.c

```mermaid
flowchart TD
    A["fd <- open('symmKey.sec', O_RDONLY)"] -->|"rawkey"| B["res <- read(fd, rawkey, KEYSZ)
ssize_t read(int fd, void* buf, size_t count)"]
    B -->|"key=rawkey, iv=buff"| C["EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, rawkey, buff)
int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    C -->|"ctx"| D["EVP_DecryptUpdate(ctx, (unsigned char*)&timeStamp, &outLen, buff + NONCESZ, sizeof(struct timeval))
int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    D -->|"ctx"| E["EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAGSZ, buff + NONCESZ + sizeof(struct timeval))
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    E -->|"ctx"| F["EVP_DecryptFinal_ex(ctx, buff, &outLen)
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    F -->|"timeStamp"| G["labs(myTime.tv_sec-timeStamp.tv_sec) < TIMESKEW"]
    G -->|"buff"| H["send(sockfd, &buff, 5, 0)"]
```

## ch9/pqc/pqc_ssl_client.c

```mermaid
flowchart TD
    A["meth <- TLS_client_method()
const SSL_METHOD* meth <- TLS_client_method(void)"] -->|"meth"| B["ctx <- SSL_CTX_new(meth)
SSL_CTX* ctx <- SSL_CTX_new(const SSL_METHOD* method)"]
    B -->|"ctx"| C["SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version)"]
    C -->|"ctx"| D["SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version)"]
    D -->|"ctx"| E["SSL_CTX_set1_groups_list(ctx, 'X25519MLKEM768:SecP384r1MLKEM1024')
int SSL_CTX_set1_groups_list(SSL_CTX* ctx, const char* groups)"]
    E -->|"ctx"| F["SSL_CTX_set1_sigalgs_list(ctx, 'mldsa65')
int SSL_CTX_set1_sigalgs_list(SSL_CTX* ctx, const char* sigalgs)"]
    F -->|"ctx"| G["SSL_CTX_load_verify_locations(ctx, 'CACert.pem', NULL)
int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath)"]
    G -->|"ctx"| H["SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)
void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX*))"]
    H -->|"ctx"| I["sbio <- BIO_new_ssl_connect(ctx)
BIO* sbio <- BIO_new_ssl_connect(SSL_CTX* ctx)"]
    I -->|"sbio"| J["BIO_get_ssl(sbio, &ssl)
void BIO_get_ssl(BIO* bio, SSL** sslp)"]
    J -->|"ssl"| K["SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)
long SSL_set_mode(SSL* ssl, int mode)"]
    K -->|"ssl"| L["X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), 'localhost', 0)
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen)"]
    L -->|"sbio"| M["BIO_set_conn_hostname(sbio, '127.0.0.1:4433')
void BIO_set_conn_hostname(BIO* bio, const char* name)"]
    M -->|"sbio"| N["BIO_do_connect(sbio)
int BIO_do_connect(BIO* bio)"]
    N -->|"sbio"| O["BIO_do_handshake(sbio)
int BIO_do_handshake(BIO* bio)"]
    O -->|"ssl"| P["SSL_get0_group_name(ssl)
const char* group <- SSL_get0_group_name(const SSL* ssl)"]
    O -->|"ssl"| Q["SSL_get_cipher_name(ssl)
const char* name <- SSL_get_cipher_name(const SSL* ssl)"]
    O -->|"sbio"| R["BIO_puts(sbio, 'GET / HTTP/1.0\r\n\r\n')
int BIO_puts(BIO* b, const char* buf)"]
    R -->|"len"| S["len <- BIO_read(sbio, tmpbuf, 1024)
int len <- BIO_read(BIO* bio, void* data, int len)"]
    S -->|"out"| T["BIO_write(out, tmpbuf, len)
int BIO_write(BIO* bio, const void* data, int dlen)"]
    T --> U["BIO_free_all(sbio)
void BIO_free_all(BIO* bio)"]
    U --> V["SSL_CTX_free(ctx)
void SSL_CTX_free(SSL_CTX* ctx)"]
```

## ch9/pqc/pqc_ssl_server.c

```mermaid
flowchart TD
    A["meth <- TLS_server_method()
const SSL_METHOD* meth <- TLS_server_method(void)"] -->|"meth"| B["ctx <- SSL_CTX_new(meth)
SSL_CTX* ctx <- SSL_CTX_new(const SSL_METHOD* method)"]
    B -->|"ctx"| C["SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version)"]
    C -->|"ctx"| D["SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version)"]
    D -->|"ctx"| E["SSL_CTX_set1_groups_list(ctx, 'X25519MLKEM768:SecP384r1MLKEM1024')
int SSL_CTX_set1_groups_list(SSL_CTX* ctx, const char* groups)"]
    E -->|"ctx"| F["SSL_CTX_set1_sigalgs_list(ctx, 'mldsa65')
int SSL_CTX_set1_sigalgs_list(SSL_CTX* ctx, const char* sigalgs)"]
    F -->|"ctx"| G["SSL_CTX_use_certificate_chain_file(ctx, 'BobCert.pem')
int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file)"]
    G -->|"ctx"| H["SSL_CTX_use_PrivateKey_file(ctx, 'BobPriv.pem', SSL_FILETYPE_PEM)
int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)"]
    H -->|"ctx"| I["SSL_CTX_check_private_key(ctx)
int SSL_CTX_check_private_key(SSL_CTX* ctx)"]
    I -->|"ctx"| J["key <- SSL_CTX_get0_privatekey(ctx)
EVP_PKEY* key <- SSL_CTX_get0_privatekey(const SSL_CTX* ctx)"]
    J -->|"key"| K["EVP_PKEY_is_a(key, 'ML-DSA-65')
int EVP_PKEY_is_a(EVP_PKEY* pkey, const char* name)"]
    K -->|"ctx"| L["sbio <- BIO_new_ssl(ctx, 0)
BIO* sbio <- BIO_new_ssl(SSL_CTX* ctx, int server)"]
    L -->|"sbio"| M["BIO_get_ssl(sbio, &ssl)
void BIO_get_ssl(BIO* bio, SSL** sslp)"]
    M -->|"ssl"| N["SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)
long SSL_set_mode(SSL* ssl, int mode)"]
    N -->|"acpt"| O["acpt <- BIO_new_accept('4433')
BIO* acpt <- BIO_new_accept(const char* host_port)"]
    O -->|"acpt"| P["BIO_set_accept_bios(acpt, sbio)
void BIO_set_accept_bios(BIO* bio, BIO* accept_bio)"]
    P -->|"acpt"| Q["BIO_do_accept(acpt)
int BIO_do_accept(BIO* bio)"]
    Q -->|"sbio"| R["BIO_do_handshake(sbio)
int BIO_do_handshake(BIO* bio)"]
    R -->|"sbio"| S["BIO_puts(sbio, 'HTTP/1.0 200 OK...')
int BIO_puts(BIO* b, const char* buf)"]
    S -->|"len"| T["len <- BIO_gets(sbio, tmpbuf, 1024)
int len <- BIO_gets(BIO* bio, void* buf, int size)"]
    T -->|"sbio"| U["BIO_write(sbio, tmpbuf, len)
int BIO_write(BIO* bio, const void* data, int dlen)"]
    U --> V["BIO_flush(sbio)
int BIO_flush(BIO* b)"]
    V --> W["BIO_free_all(sbio)
void BIO_free_all(BIO* bio)"]
    W --> X["SSL_CTX_free(ctx)
void SSL_CTX_free(SSL_CTX* ctx)"]
```