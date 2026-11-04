## ch2/mkrand16.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"buf"| C["randbuf <- RAND_bytes(randbuf, 16)
int RAND_bytes(unsigned char* buf, int num)"]
    C --> D["printStr(randbuf, 16)"]
```

## ch2/rsagenkey.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"bits=512, e=RSA_F4"| C["rsaPriv <- RSA_generate_key(512, RSA_F4, NULL, NULL)
RSA* rsaPriv <- RSA_generate_key(int bits, BIGNUM* e, BN_GENCB* cb, void* cb_arg)"]
    C -->|"rsaPriv"| D["rsaPub <- RSAPublicKey_dup(rsaPriv)
RSA* rsaPub <- RSAPublicKey_dup(RSA* rsaPriv)"]
    D -->|"rsaPub"| E["PEM_write_RSAPublicKey(pubf, rsaPub)
int PEM_write_RSAPublicKey(FILE* fp, RSA* rsaPub)"]
    C -->|"rsaPriv"| F["PEM_write_RSAPrivateKey(privf, rsaPriv, NULL, NULL, 0, NULL, NULL)
int PEM_write_RSAPrivateKey(FILE* fp, RSA* rsaPriv, const EVP_CIPHER* enc, unsigned char* kstr, int klen, pem_password_cb* cb, void* u)"]
    C -->|"rsaPriv"| G["RSA_free(rsaPriv)"]
    D -->|"rsaPub"| H["RSA_free(rsaPub)"]
```

## ch3/aes_128_cbc.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"mykey"| C["mykey <- RAND_bytes(mykey, 16)
int RAND_bytes(unsigned char* buf, int num)"]
    B -->|"iv"| D["iv <- RAND_bytes(iv, 16)
int RAND_bytes(unsigned char* buf, int num)"]
    C -->|"ctx, key=mykey, iv"| E["EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT)
int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc)"]
    E -->|"ctx"| F["EVP_CipherUpdate(&ctx, cipherbuf, &out_len, plainbuf, in_len)
int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    F -->|"ctx"| G["EVP_CipherFinal_ex(&ctx, cipherbuf, &out_len)
int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    D -->|"ctx, key=mykey, iv"| H["EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_DECRYPT)
int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc)"]
    H -->|"ctx"| I["EVP_CipherUpdate(&ctx, plainbuf, &out_len, cipherbuf, in_len)
int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    I -->|"ctx"| J["EVP_CipherFinal_ex(&ctx, plainbuf, &out_len)
int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    G --> K["EVP_CIPHER_CTX_cleanup(&ctx)"]
    J --> K
```

## ch4/rsa_des_crc.c

```mermaid
flowchart TD
    A["rsaPub <- PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)"] -->|"rsaPub"| B["RSA_public_encrypt(psize, mykey, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING)"]
    C["rsaPriv <- PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)"] -->|"rsaPriv"| D["RSA_private_decrypt(csize, ctext, mykey, rsaPriv, RSA_PKCS1_OAEP_PADDING)"]
    E["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| F["RAND_seed(seedbuf, 8)"]
    F -->|"mykey"| G["mykey <- RAND_bytes(mykey, sizeof(mykey))
int RAND_bytes(unsigned char* buf, int num)"]
    F -->|"iv"| H["iv <- RAND_bytes(iv, sizeof(iv))
int RAND_bytes(unsigned char* buf, int num)"]
    G -->|"ctx, key=mykey, iv"| I["EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv, DES_ENCRYPT)"]
    I -->|"ctx"| J["EVP_CipherUpdate(&ctx, ctext, &csize, ptext, psize)"]
    J -->|"ctx"| K["EVP_CipherFinal_ex(&ctx, ctext, &csize)"]
    H -->|"ctx, key=mykey, iv"| L["EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv, DES_DECRYPT)"]
    L -->|"ctx"| M["EVP_CipherUpdate(&ctx, ptext, &psize, ctext, csize)"]
    M -->|"ctx"| N["EVP_CipherFinal_ex(&ctx, ptext, &psize)"]
```

## ch4/rsatest.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"bits=1024, e=RSA_F4"| C["rsaPriv <- RSA_generate_key(1024, RSA_F4, NULL, NULL)
RSA* rsaPriv <- RSA_generate_key(int bits, BIGNUM* e, BN_GENCB* cb, void* cb_arg)"]
    C -->|"rsaPriv"| D["rsaPub <- RSAPublicKey_dup(rsaPriv)
RSA* rsaPub <- RSAPublicKey_dup(RSA* rsaPriv)"]
    D -->|"rsaPub"| E["PEM_write_RSAPublicKey(fp, rsaPub)"]
    C -->|"rsaPriv"| F["PEM_write_RSAPrivateKey(fp, rsaPriv, NULL, NULL, 0, NULL, NULL)"]
    D -->|"rsaPub"| G["csize <- RSA_public_encrypt(len, ptext, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING)
int RSA_public_encrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)"]
    C -->|"rsaPriv"| H["dsize <- RSA_private_decrypt(len, ctext, dtext, rsaPriv, RSA_PKCS1_OAEP_PADDING)
int RSA_private_decrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)"]
```

## ch5/rsa_sha1_sign_test.c

```mermaid
flowchart TD
    A["seedbuf <- getTimeSubstr()"] -->|"seedbuf"| B["RAND_seed(seedbuf, 8)
int RAND_seed(unsigned char* seedbuf, int num)"]
    B -->|"bits=512, e=RSA_F4"| C["rsaPriv <- RSA_generate_key(512, RSA_F4, NULL, NULL)"]
    C -->|"rsaPriv"| D["rsaPub <- RSAPublicKey_dup(rsaPriv)"]
    C -->|"pkey, rsaPriv"| E["EVP_PKEY_set1_RSA(pkey, rsaPriv)
int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key)"]
    E -->|"ctx"| F["EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)
int EVP_SignInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    F -->|"ctx"| G["EVP_SignUpdate(&ctx, plaintext, plsize)
int EVP_SignUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    G -->|"ctx, pkey"| H["EVP_SignFinal(&ctx, sign, &signSize, pkey)
int EVP_SignFinal(EVP_MD_CTX* ctx, unsigned char* sigret, unsigned int* siglen, EVP_PKEY* pkey)"]
    D -->|"pukey, rsaPub"| I["EVP_PKEY_set1_RSA(pukey, rsaPub)
int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key)"]
    I -->|"ctx"| J["EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL)
int EVP_VerifyInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    J -->|"ctx"| K["EVP_VerifyUpdate(&ctx, plaintext, plsize)
int EVP_VerifyUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    K -->|"ctx, pukey"| L["EVP_VerifyFinal(&ctx, sign, signSize, pukey)
int EVP_VerifyFinal(EVP_MD_CTX* ctx, const unsigned char* sigbuf, unsigned int siglen, EVP_PKEY* pkey)"]
```

## ch7/hash_sign.c

```mermaid
flowchart TD
    A["rsaPriv <- PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)"] -->|"rsaPriv"| B["pkey <- EVP_PKEY_new()
EVP_PKEY* pkey <- EVP_PKEY_new(void)"]
    B -->|"pkey, rsaPriv"| C["EVP_PKEY_set1_RSA(pkey, rsaPriv)
int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key)"]
    C -->|"ctx"| D["EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)
int EVP_SignInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    D -->|"ctx"| E["EVP_SignUpdate(&ctx, buff, inLen)
int EVP_SignUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    E -->|"ctx, pkey"| F["EVP_SignFinal(&ctx, sign, &signSize, pkey)
int EVP_SignFinal(EVP_MD_CTX* ctx, unsigned char* sigret, unsigned int* siglen, EVP_PKEY* pkey)"]
    G["rsaPub <- PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)"] -->|"rsaPub"| H["pkey2 <- EVP_PKEY_new()
EVP_PKEY* pkey2 <- EVP_PKEY_new(void)"]
    H -->|"pkey2, rsaPub"| I["EVP_PKEY_set1_RSA(pkey2, rsaPub)
int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key)"]
    I -->|"ctx"| J["EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL)"]
    J -->|"ctx"| K["EVP_VerifyUpdate(&ctx, buff, inLen)"]
    K -->|"ctx, pkey2"| L["EVP_VerifyFinal(&ctx, sign, signSize, pkey2)"]
```

## ch8/client0.c

```mermaid
flowchart TD
    A["fd <- open('symmKey.sec', O_RDONLY)"] -->|"rawkey"| B["res <- read(fd, rawkey, 8)
ssize_t read(int fd, void* buf, size_t count)"]
    B -->|"rawkey"| C["DES_set_key(&rawkey, &keySched)
void DES_set_key(const_DES_cblock* userKey, DES_key_schedule* schedule)"]
    C -->|"keySched, iv"| D["DES_ncbc_encrypt((unsigned char*)&timeStamp, buff, sizeof(struct timeval), &keySched, (DES_cblock*)iv, DES_ENCRYPT)
void DES_ncbc_encrypt(const unsigned char* in, unsigned char* out, long length, DES_key_schedule* ks, DES_cblock* iv, int enc)"]
    D -->|"cipherBSz"| E["cipherBSz <- multiple8(sizeof(struct timeval))
int multiple8(int size)"]
    E -->|"sockfd"| F["sockfd <- socket(AF_INET, SOCK_STREAM, 0)"]
    F -->|"sockfd"| G["connect(sockfd, (struct sockaddr*)&server, SOCKSZ)"]
    D -->|"buff"| H["send(sockfd, &buff, cipherBSz, 0)"]
```

## ch8/server0.c

```mermaid
flowchart TD
    A["fd <- open('symmKey.sec', O_RDONLY)"] -->|"rawkey"| B["res <- read(fd, rawkey, 8)
ssize_t read(int fd, void* buf, size_t count)"]
    B -->|"rawkey"| C["DES_set_key(&rawkey, &keySched)
void DES_set_key(const_DES_cblock* userKey, DES_key_schedule* schedule)"]
    C -->|"keySched, iv"| D["DES_ncbc_encrypt(buff, (unsigned char*)&timeStamp, cipherBSz, &keySched, &iv, DES_DECRYPT)
void DES_ncbc_encrypt(const unsigned char* in, unsigned char* out, long length, DES_key_schedule* ks, DES_cblock* iv, int enc)"]
    D -->|"myTime, timeStamp"| E["labs(myTime.tv_sec-timeStamp.tv_sec) < TIMESKEW"]
    E -->|"buff"| F["send(sockfd, &buff, 5, 0)"]
```

## ch9/ssl_client.c

```mermaid
flowchart TD
    A["SSL_library_init()
void SSL_library_init(void)"] --> B["SSL_load_error_strings()
void SSL_load_error_strings(void)"]
    B --> C["meth <- SSLv23_client_method()
const SSL_METHOD* meth <- SSLv23_client_method(void)"]
    C -->|"meth"| D["ctx <- SSL_CTX_new(meth)
SSL_CTX* ctx <- SSL_CTX_new(const SSL_METHOD* method)"]
    D -->|"ctx"| E["SSL_CTX_load_verify_locations(ctx, 'CACert.pem', NULL)
int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath)"]
    E -->|"ctx"| F["SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)
void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX*))"]
    F -->|"ctx"| G["sbio <- BIO_new_ssl_connect(ctx)
BIO* sbio <- BIO_new_ssl_connect(SSL_CTX* ctx)"]
    G -->|"sbio"| H["BIO_get_ssl(sbio, &ssl)
void BIO_get_ssl(BIO* bio, SSL** sslp)"]
    H -->|"ssl"| I["SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)
long SSL_set_mode(SSL* ssl, int mode)"]
    I -->|"ssl"| J["X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), 'localhost', 0)
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen)"]
    J -->|"sbio"| K["BIO_set_conn_hostname(sbio, '127.0.0.1:4433')
void BIO_set_conn_hostname(BIO* bio, const char* name)"]
    K -->|"sbio"| L["BIO_do_connect(sbio)
int BIO_do_connect(BIO* bio)"]
    L -->|"sbio"| M["BIO_do_handshake(sbio)
int BIO_do_handshake(BIO* bio)"]
    M -->|"ssl"| N["tmpkey <- SSL_get_server_tmp_key(ssl, &tmpkey)
int SSL_get_server_tmp_key(SSL* ssl, EVP_PKEY** pkey)"]
    N -->|"tmpkey"| O["eckey <- EVP_PKEY_get1_EC_KEY(tmpkey)
EC_KEY* eckey <- EVP_PKEY_get1_EC_KEY(EVP_PKEY* pkey)"]
    O -->|"eckey"| P["group <- OBJ_nid2sn(EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)))
const char* group <- OBJ_nid2sn(int nid)"]
    M -->|"ssl"| Q["SSL_get_version(ssl)
const char* ver <- SSL_get_version(const SSL* ssl)"]
    M -->|"ssl"| R["SSL_get_cipher_name(ssl)
const char* name <- SSL_get_cipher_name(const SSL* ssl)"]
    M -->|"sbio"| S["BIO_puts(sbio, 'GET / HTTP/1.0\r\n\r\n')
int BIO_puts(BIO* b, const char* buf)"]
    S -->|"len"| T["len <- BIO_read(sbio, tmpbuf, 1024)
int len <- BIO_read(BIO* bio, void* data, int len)"]
    T -->|"out"| U["BIO_write(out, tmpbuf, len)
int BIO_write(BIO* bio, const void* data, int dlen)"]
    U --> V["BIO_free_all(sbio)
void BIO_free_all(BIO* bio)"]
    V --> W["SSL_CTX_free(ctx)
void SSL_CTX_free(SSL_CTX* ctx)"]
```

## ch9/ssl_server.c

```mermaid
flowchart TD
    A["SSL_library_init()
void SSL_library_init(void)"] --> B["SSL_load_error_strings()
void SSL_load_error_strings(void)"]
    B --> C["meth <- SSLv23_server_method()
const SSL_METHOD* meth <- SSLv23_server_method(void)"]
    C -->|"meth"| D["ctx <- SSL_CTX_new(meth)
SSL_CTX* ctx <- SSL_CTX_new(const SSL_METHOD* method)"]
    D -->|"ctx"| E["SSL_CTX_use_certificate_chain_file(ctx, 'BobCert.pem')
int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file)"]
    E -->|"ctx"| F["SSL_CTX_use_PrivateKey_file(ctx, 'BobPriv.pem', SSL_FILETYPE_PEM)
int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)"]
    F -->|"ctx"| G["SSL_CTX_check_private_key(ctx)
int SSL_CTX_check_private_key(SSL_CTX* ctx)"]
    G -->|"ctx"| H["sbio <- BIO_new_ssl(ctx, 0)
BIO* sbio <- BIO_new_ssl(SSL_CTX* ctx, int server)"]
    H -->|"ssl"| I["SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)
long SSL_set_mode(SSL* ssl, int mode)"]
    I -->|"sbio"| J["acpt <- BIO_new_accept('4433')
BIO* acpt <- BIO_new_accept(const char* host_port)"]
    J -->|"acpt"| K["BIO_set_accept_bios(acpt, sbio)
void BIO_set_accept_bios(BIO* bio, BIO* accept_bio)"]
    K -->|"acpt"| L["BIO_do_accept(acpt)
int BIO_do_accept(BIO* bio)"]
    L -->|"sbio"| M["BIO_do_handshake(sbio)
int BIO_do_handshake(BIO* bio)"]
    M -->|"sbio"| N["BIO_puts(sbio, 'HTTP/1.0 200 OK...')
int BIO_puts(BIO* b, const char* buf)"]
    N -->|"len"| O["len <- BIO_gets(sbio, tmpbuf, 1024)
int len <- BIO_gets(BIO* bio, void* buf, int size)"]
    O -->|"sbio"| P["BIO_write(sbio, tmpbuf, len)
int BIO_write(BIO* bio, const void* data, int dlen)"]
    P --> Q["BIO_flush(sbio)
int BIO_flush(BIO* b)"]
    Q --> R["BIO_free_all(sbio)
void BIO_free_all(BIO* bio)"]
    R --> S["SSL_CTX_free(ctx)
void SSL_CTX_free(SSL_CTX* ctx)"]
```