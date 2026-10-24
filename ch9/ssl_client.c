/*
 * ssl_client.c
 *
 * TLS client. Connects to 127.0.0.1:4433, verifies the server certificate
 * against CACert.pem and the host name "localhost", prints the negotiated
 * protocol, key exchange group and cipher, sends "GET /" and prints the reply.
 *
 * Files read from the current directory: CACert.pem
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int main()
{
    BIO *sbio, *out;
    BIO *bio_err=0;
    int len, res;
    char tmpbuf[1024];
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    EVP_PKEY *tmpkey = NULL;
    EC_KEY *eckey;
    const char *group = "none";

    if(!bio_err) {
        SSL_library_init();
        SSL_load_error_strings();
        bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
    }
    meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);
    if(ctx == NULL) {
        fprintf(stderr, "Can't create SSL context\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_load_verify_locations(ctx, "CACert.pem", NULL);
    if(res != 1) {
        fprintf(stderr, "Can't load CACert.pem\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    sbio = BIO_new_ssl_connect(ctx);
    if(sbio == NULL) {
        fprintf(stderr, "Can't create SSL connect BIO\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    BIO_get_ssl (sbio, &ssl);
    if(!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        return 1;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    res = X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), "localhost", 0);
    if(res != 1) {
        fprintf(stderr, "Can't set expected host name\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    BIO_set_conn_hostname(sbio, "127.0.0.1:4433");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(out == NULL) {
        fprintf(stderr, "Can't create output BIO\n");
        return 1;
    }
    res = BIO_do_connect(sbio);
    if(res <= 0 ) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = BIO_do_handshake (sbio);
    if(res <= 0 ) {
        fprintf(stderr, "Error establishing SSL connection \n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if(SSL_get_server_tmp_key(ssl, &tmpkey) == 1 && EVP_PKEY_id(tmpkey) == EVP_PKEY_EC) {
        eckey = EVP_PKEY_get1_EC_KEY(tmpkey);
        group = OBJ_nid2sn(EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)));
        EC_KEY_free(eckey);
    }
    printf("Negotiated: %s, group %s, cipher %s\n", SSL_get_version(ssl),
    group, SSL_get_cipher_name(ssl));

    BIO_puts(sbio, "GET / HTTP/1.0\r\n\r\n");
    for(;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if(len <= 0) break;
        BIO_write(out, tmpbuf, len);
    }
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(ctx);

    return(0);
}
