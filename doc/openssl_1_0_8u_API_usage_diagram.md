```mermaid
flowchart TD
    %% Random / seed
    N1["RAND_seed<br/>int RAND_seed(unsigned char* seedbuf, int num)<br/>'seedbuf': use"]
    N2["RAND_bytes<br/>int RAND_bytes(unsigned char* buf, int num)<br/>'buf': out"]
    N3["RSA_generate_key<br/>RSA* rsaPriv <- RSA_generate_key(int bits, BIGNUM* e, BN_GENCB* cb, void* cb_arg)"]
    N4["RSAPublicKey_dup<br/>RSA* rsaPub <- RSAPublicKey_dup(RSA* rsaPriv)"]
    N5["PEM_write_RSAPublicKey<br/>int PEM_write_RSAPublicKey(FILE* pubf, RSA* rsaPub)"]
    N6["PEM_write_RSAPrivateKey<br/>int PEM_write_RSAPrivateKey(FILE* privf, RSA* rsaPriv, const EVP_CIPHER* enc, unsigned char* kstr, int klen, pem_password_cb* cb, void* u)"]
    N7["RSA_free<br/>void RSA_free(RSA* rsa)"]

    N8["RSA_public_encrypt<br/>int csize <- RSA_public_encrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsaPub, int padding)"]
    N9["RSA_private_decrypt<br/>int dsize <- RSA_private_decrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsaPriv, int padding)"]

    N10["PEM_read_RSAPublicKey<br/>RSA* rsaPub <- PEM_read_RSAPublicKey(FILE* fp, RSA** x, pem_password_cb* cb, void* u)"]
    N11["PEM_read_RSAPrivateKey<br/>RSA* rsaPriv <- PEM_read_RSAPrivateKey(FILE* fp, RSA** x, pem_password_cb* cb, void* u)"]

    N12["EVP_CIPHER_CTX_init<br/>void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX* ctx)"]
    N13["EVP_CipherInit_ex<br/>int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc)"]
    N14["EVP_CipherUpdate<br/>int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)"]
    N15["EVP_CipherFinal_ex<br/>int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)"]
    N16["EVP_CIPHER_CTX_cleanup<br/>void EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX* ctx)"]

    N17["EVP_PKEY_new<br/>EVP_PKEY* pkey <- EVP_PKEY_new(void)"]
    N18["EVP_PKEY_set1_RSA<br/>int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key)"]
    N19["EVP_MD_CTX_init<br/>void EVP_MD_CTX_init(EVP_MD_CTX* ctx)"]
    N20["EVP_SignInit_ex<br/>int EVP_SignInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    N21["EVP_SignUpdate<br/>int EVP_SignUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    N22["EVP_SignFinal<br/>int EVP_SignFinal(EVP_MD_CTX* ctx, unsigned char* sigret, unsigned int* siglen, EVP_PKEY* pkey)"]
    N23["EVP_VerifyInit_ex<br/>int EVP_VerifyInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)"]
    N24["EVP_VerifyUpdate<br/>int EVP_VerifyUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt)"]
    N25["EVP_VerifyFinal<br/>int EVP_VerifyFinal(EVP_MD_CTX* ctx, const unsigned char* sigbuf, unsigned int siglen, EVP_PKEY* pkey)"]

    N26["DES_set_key<br/>void DES_set_key(const_DES_cblock* userKey, DES_key_schedule* schedule)"]
    N27["DES_ncbc_encrypt<br/>void DES_ncbc_encrypt(const unsigned char* in, unsigned char* out, long length, DES_key_schedule* ks, DES_cblock* iv, int enc)"]

    N28["SSL_library_init<br/>void SSL_library_init(void)"]
    N29["SSL_load_error_strings<br/>void SSL_load_error_strings(void)"]
    N30["SSLv23_client_method<br/>const SSL_METHOD* meth <- SSLv23_client_method(void)"]
    N31["SSLv23_server_method<br/>const SSL_METHOD* meth <- SSLv23_server_method(void)"]
    N32["SSL_CTX_new<br/>SSL_CTX* ctx <- SSL_CTX_new(const SSL_METHOD* method)"]
    N33["SSL_CTX_load_verify_locations<br/>int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath)"]
    N34["SSL_CTX_set_verify<br/>void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX*))"]
    N35["BIO_new_ssl_connect<br/>BIO* sbio <- BIO_new_ssl_connect(SSL_CTX* ctx)"]
    N36["BIO_new_ssl<br/>BIO* sbio <- BIO_new_ssl(SSL_CTX* ctx, int server)"]
    N37["BIO_get_ssl<br/>void BIO_get_ssl(BIO* bio, SSL** sslp)"]
    N38["SSL_set_mode<br/>long SSL_set_mode(SSL* ssl, int mode)"]
    N39["X509_VERIFY_PARAM_set1_host<br/>int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen)"]
    N40["BIO_set_conn_hostname<br/>void BIO_set_conn_hostname(BIO* bio, const char* name)"]
    N41["BIO_do_connect<br/>int BIO_do_connect(BIO* bio)"]
    N42["BIO_do_handshake<br/>int BIO_do_handshake(BIO* bio)"]
    N43["SSL_get_server_tmp_key<br/>int SSL_get_server_tmp_key(SSL* ssl, EVP_PKEY** pkey)"]
    N44["EVP_PKEY_get1_EC_KEY<br/>EC_KEY* eckey <- EVP_PKEY_get1_EC_KEY(EVP_PKEY* pkey)"]
    N45["OBJ_nid2sn<br/>const char* group <- OBJ_nid2sn(int nid)"]
    N46["EC_GROUP_get_curve_name<br/>int curveNid <- EC_GROUP_get_curve_name(const EC_GROUP* group)"]
    N47["EC_KEY_get0_group<br/>const EC_GROUP* g <- EC_KEY_get0_group(const EC_KEY* key)"]
    N48["SSL_get_version<br/>const char* ver <- SSL_get_version(const SSL* ssl)"]
    N49["SSL_get_cipher_name<br/>const char* name <- SSL_get_cipher_name(const SSL* ssl)"]
    N50["BIO_puts<br/>int BIO_puts(BIO* b, const char* buf)"]
    N51["BIO_read<br/>int len <- BIO_read(BIO* bio, void* data, int len)"]
    N52["BIO_write<br/>int BIO_write(BIO* bio, const void* data, int dlen)"]
    N53["BIO_free_all<br/>void BIO_free_all(BIO* bio)"]
    N54["SSL_CTX_free<br/>void SSL_CTX_free(SSL_CTX* ctx)"]

    N55["SSL_CTX_use_certificate_chain_file<br/>int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file)"]
    N56["SSL_CTX_use_PrivateKey_file<br/>int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)"]
    N57["SSL_CTX_check_private_key<br/>int SSL_CTX_check_private_key(SSL_CTX* ctx)"]
    N58["BIO_new_accept<br/>BIO* acpt <- BIO_new_accept(const char* host_port)"]
    N59["BIO_set_accept_bios<br/>void BIO_set_accept_bios(BIO* bio, BIO* accept_bio)"]
    N60["BIO_push<br/>BIO* BIO_push(BIO* b, BIO* append)"]
    N61["BIO_pop<br/>BIO* BIO_pop(BIO* b)"]
    N62["BIO_flush<br/>int BIO_flush(BIO* b)"]

    %% Data-flow edges: return value -> next API argument
    N1 -->|'seedbuf'| N2
    N1 -->|'seedbuf'| N3
    N2 -->|'buf'| N13
    N2 -->|'buf'| N27

    N3 -->|'rsaPriv'| N4
    N4 -->|'rsaPub'| N5
    N3 -->|'rsaPriv'| N6
    N3 -->|'rsaPriv'| N8
    N3 -->|'rsaPriv'| N9
    N3 -->|'rsaPriv'| N7
    N4 -->|'rsaPub'| N7
    N10 -->|'rsaPub'| N8
    N11 -->|'rsaPriv'| N9

    N12 -->|'ctx'| N13
    N13 -->|'ctx'| N14
    N14 -->|'ctx'| N15
    N15 -->|'ctx'| N16

    N17 -->|'pkey'| N18
    N3 -->|'rsaPriv'| N18
    N18 -->|'pkey'| N22
    N18 -->|'pkey'| N25
    N4 -->|'rsaPub'| N18
    N19 -->|'ctx'| N20
    N20 -->|'ctx'| N21
    N21 -->|'ctx'| N22
    N23 -->|'ctx'| N24
    N24 -->|'ctx'| N25

    N26 -->|'schedule'| N27
    N28 --> N29
    N29 --> N30
    N29 --> N31
    N30 -->|'meth'| N32
    N31 -->|'meth'| N32
    N32 -->|'ctx'| N33
    N32 -->|'ctx'| N34
    N32 -->|'ctx'| N35
    N32 -->|'ctx'| N36
    N35 -->|'sbio'| N37
    N36 -->|'sbio'| N37
    N37 -->|'ssl'| N38
    N37 -->|'ssl'| N39
    N39 -->|'param'| N41
    N37 -->|'ssl'| N43
    N43 -->|'eckey'| N44
    N44 -->|'group'| N45
    N45 -->|'curveNid'| N46
    N46 -->|'g'| N47
    N38 -->|'ssl'| N48
    N38 -->|'ssl'| N49
    N35 -->|'sbio'| N41
    N41 -->|'bio'| N42
    N42 -->|'bio'| N50
    N42 -->|'bio'| N51
    N51 -->|'len'| N52
    N52 -->|'bio'| N53
    N32 -->|'ctx'| N54
    N32 -->|'ctx'| N55
    N32 -->|'ctx'| N56
    N32 -->|'ctx'| N57
    N55 -->|'ctx'| N56
    N56 -->|'ctx'| N57
    N36 -->|'sbio'| N58
    N58 -->|'acpt'| N59
    N59 -->|'sbio'| N60
    N60 -->|'sbio'| N62
    N60 -->|'sbio'| N42
    N60 -->|'sbio'| N50
    N62 -->|'b'| N53
