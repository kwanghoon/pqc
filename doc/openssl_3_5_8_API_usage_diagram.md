```mermaid
flowchart TD
    %% random / PKI
    P1["RAND_seed<br/>int RAND_seed(unsigned char* seedbuf, int num)<br/>'seedbuf': use"]
    P2["RAND_bytes<br/>int RAND_bytes(unsigned char* buf, int num)<br/>'buf': out"]
    P3["EVP_PKEY_CTX_new_from_name<br/>EVP_PKEY_CTX* ctx <- EVP_PKEY_CTX_new_from_name(OPENSSL_CTX* libctx, const char* name, const char* propq)"]
    P4["EVP_PKEY_keygen_init<br/>int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx)"]
    P5["EVP_PKEY_keygen<br/>int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey)"]
    P6["EVP_PKEY_generate<br/>int EVP_PKEY_generate(EVP_PKEY_CTX* ctx, EVP_PKEY** pkey)"]
    P7["PEM_write_PUBKEY<br/>int PEM_write_PUBKEY(FILE* fp, EVP_PKEY* pkey)"]
    P8["PEM_write_PrivateKey<br/>int PEM_write_PrivateKey(FILE* fp, EVP_PKEY* pkey, const EVP_CIPHER* enc, unsigned char* kstr, int klen, pem_password_cb* cb, void* u)"]
    P9["EVP_PKEY_free<br/>void EVP_PKEY_free(EVP_PKEY* pkey)"]

    %% ML-KEM encapsulate / decapsulate
    P10["EVP_PKEY_CTX_new_from_pkey<br/>EVP_PKEY_CTX* kem_ctx <- EVP_PKEY_CTX_new_from_pkey(OPENSSL_CTX* libctx, EVP_PKEY* pkey, const char* propq)"]
    P11["EVP_PKEY_encapsulate_init<br/>int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])"]
    P12["EVP_PKEY_encapsulate<br/>int EVP_PKEY_encapsulate(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, unsigned char* secret, size_t* secretlen)"]
    P13["EVP_PKEY_decapsulate_init<br/>int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX* ctx, const OSSL_PARAM params[])"]
    P14["EVP_PKEY_decapsulate<br/>int EVP_PKEY_decapsulate(EVP_PKEY_CTX* ctx, unsigned char* secret, size_t* secretlen, const unsigned char* in, size_t inlen)"]

    %% symmetric encryption
    P15["EVP_CIPHER_CTX_new<br/>EVP_CIPHER_CTX* cipher_ctx <- EVP_CIPHER_CTX_new(void)"]
    P16["EVP_EncryptInit_ex<br/>int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    P17["EVP_EncryptUpdate<br/>int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    P18["EVP_EncryptFinal_ex<br/>int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    P19["EVP_CTRL_GCM_GET_TAG<br/>int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]
    P20["EVP_CIPHER_CTX_free<br/>void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx)"]
    P21["EVP_DecryptInit_ex<br/>int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)"]
    P22["EVP_DecryptUpdate<br/>int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    P23["EVP_DecryptFinal_ex<br/>int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    P24["EVP_CTRL_GCM_SET_TAG<br/>int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)"]

    %% ML-DSA sign/verify
    P25["EVP_MD_CTX_new<br/>EVP_MD_CTX* ctx <- EVP_MD_CTX_new(void)"]
    P26["EVP_DigestSignInit_ex<br/>int EVP_DigestSignInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* mdname, OPENSSL_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[])"]
    P27["EVP_DigestSign<br/>int EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen)"]
    P28["EVP_DigestVerifyInit_ex<br/>int EVP_DigestVerifyInit_ex(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const char* mdname, OPENSSL_CTX* libctx, const char* propq, EVP_PKEY* pkey, const OSSL_PARAM params[])"]
    P29["EVP_DigestVerify<br/>int EVP_DigestVerify(EVP_MD_CTX* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen)"]
    P30["EVP_MD_CTX_free<br/>void EVP_MD_CTX_free(EVP_MD_CTX* ctx)"]

    %% TLS 1.3 / PQC
    P31["TLS_client_method<br/>const SSL_METHOD* meth <- TLS_client_method(void)"]
    P32["TLS_server_method<br/>const SSL_METHOD* meth <- TLS_server_method(void)"]
    P33["SSL_CTX_new<br/>SSL_CTX* ctx <- SSL_CTX_new(const SSL_METHOD* method)"]
    P34["SSL_CTX_set_min_proto_version<br/>int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version)"]
    P35["SSL_CTX_set_max_proto_version<br/>int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version)"]
    P36["SSL_CTX_set1_groups_list<br/>int SSL_CTX_set1_groups_list(SSL_CTX* ctx, const char* groups)"]
    P37["SSL_CTX_set1_sigalgs_list<br/>int SSL_CTX_set1_sigalgs_list(SSL_CTX* ctx, const char* sigalgs)"]
    P38["SSL_CTX_use_certificate_chain_file<br/>int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file)"]
    P39["SSL_CTX_use_PrivateKey_file<br/>int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)"]
    P40["SSL_CTX_check_private_key<br/>int SSL_CTX_check_private_key(SSL_CTX* ctx)"]
    P41["SSL_CTX_get0_privatekey<br/>EVP_PKEY* key <- SSL_CTX_get0_privatekey(const SSL_CTX* ctx)"]
    P42["EVP_PKEY_is_a<br/>int EVP_PKEY_is_a(EVP_PKEY* pkey, const char* name)"]
    P43["BIO_new_ssl_connect<br/>BIO* sbio <- BIO_new_ssl_connect(SSL_CTX* ctx)"]
    P44["BIO_new_ssl<br/>BIO* sbio <- BIO_new_ssl(SSL_CTX* ctx, int server)"]
    P45["BIO_get_ssl<br/>void BIO_get_ssl(BIO* bio, SSL** sslp)"]
    P46["SSL_set_mode<br/>long SSL_set_mode(SSL* ssl, int mode)"]
    P47["X509_VERIFY_PARAM_set1_host<br/>int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen)"]
    P48["BIO_set_conn_hostname<br/>void BIO_set_conn_hostname(BIO* bio, const char* name)"]
    P49["BIO_do_connect<br/>int BIO_do_connect(BIO* bio)"]
    P50["BIO_do_handshake<br/>int BIO_do_handshake(BIO* bio)"]
    P51["SSL_get0_group_name<br/>const char* gname <- SSL_get0_group_name(const SSL* ssl)"]
    P52["SSL_get_cipher_name<br/>const char* cname <- SSL_get_cipher_name(const SSL* ssl)"]
    P53["BIO_puts<br/>int BIO_puts(BIO* b, const char* buf)"]
    P54["BIO_read<br/>int len <- BIO_read(BIO* bio, void* data, int len)"]
    P55["BIO_write<br/>int BIO_write(BIO* bio, const void* data, int dlen)"]
    P56["BIO_free_all<br/>void BIO_free_all(BIO* bio)"]
    P57["SSL_CTX_free<br/>void SSL_CTX_free(SSL_CTX* ctx)"]

    %% data-flow edges
    P1 -->|'seedbuf'| P2
    P1 -->|'seedbuf'| P3
    P3 -->|'ctx'| P4
    P4 -->|'ctx'| P5
    P5 -->|'pkey'| P6
    P6 -->|'pkey'| P7
    P6 -->|'pkey'| P8
    P6 -->|'pkey'| P9

    P6 -->|'pkey'| P10
    P10 -->|'kem_ctx'| P11
    P11 -->|'kem_ctx'| P12
    P10 -->|'kem_ctx'| P13
    P13 -->|'kem_ctx'| P14

    P15 -->|'cipher_ctx'| P16
    P16 -->|'ctx'| P17
    P17 -->|'ctx'| P18
    P18 -->|'ctx'| P19
    P19 -->|'ctx'| P20
    P21 -->|'ctx'| P22
    P22 -->|'ctx'| P23
    P23 -->|'ctx'| P24

    P25 -->|'ctx'| P26
    P25 -->|'ctx'| P28
    P6 -->|'pkey'| P26
    P6 -->|'pkey'| P28
    P26 -->|'ctx'| P27
    P28 -->|'ctx'| P29
    P27 -->|'sigret'| P29
    P29 -->|'ctx'| P30

    P31 -->|'meth'| P33
    P32 -->|'meth'| P33
    P33 -->|'ctx'| P34
    P34 -->|'ctx'| P35
    P35 -->|'ctx'| P36
    P36 -->|'ctx'| P37
    P37 -->|'ctx'| P38
    P38 -->|'ctx'| P39
    P39 -->|'ctx'| P40
    P33 -->|'ctx'| P41
    P41 -->|'key'| P42
    P33 -->|'ctx'| P43
    P33 -->|'ctx'| P44
    P43 -->|'sbio'| P45
    P44 -->|'sbio'| P45
    P45 -->|'ssl'| P46
    P45 -->|'ssl'| P47
    P47 -->|'param'| P49
    P45 -->|'ssl'| P51
    P45 -->|'ssl'| P52
    P45 -->|'sbio'| P49
    P49 -->|'bio'| P50
    P50 -->|'bio'| P53
    P50 -->|'bio'| P54
    P54 -->|'len'| P55
    P55 -->|'bio'| P56
    P33 -->|'ctx'| P57
