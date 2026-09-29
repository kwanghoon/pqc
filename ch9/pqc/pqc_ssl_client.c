/*
 * pqc_ssl_client.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch9/ssl_client.c.
 * Same behavior: connect to TLS server and fetch HTTP response.
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int main(void)
{
    BIO *sbio, *out;
    BIO *bio_err = NULL;
    int len, res;
    char tmpbuf[1024];
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    if (!bio_err) {
        SSL_library_init();
        SSL_load_error_strings();
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }

    meth = TLS_client_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:secp256r1");
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    if (!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        exit(1);
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(sbio, "127.0.0.1:4433");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    res = BIO_do_connect(sbio);
    if (res <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    res = BIO_do_handshake(sbio);
    if (res <= 0) {
        fprintf(stderr, "Error establishing SSL connection\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    BIO_puts(sbio, "GET / HTTP/1.0\r\n\r\n");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0) break;
        BIO_write(out, tmpbuf, len);
    }

    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(ctx);

    return 0;
}
