/*
 * pqc_ssl_client.c
 *
 * PQC conversion of ch9/ssl_client.c.
 * TLS 1.3 client. Connects to 127.0.0.1:4433, verifies the server certificate
 * (ML-DSA-65) against CACert.pem and the host name "localhost", prints the
 * negotiated protocol, key exchange group and cipher, sends "GET /" and prints
 * the reply.
 *
 *   - TLS 1.3 only: hybrid ML-KEM groups do not exist in TLS 1.2
 *   - key exchange: X25519MLKEM768 / SecP384r1MLKEM1024 only, no classical-only
 *     group
 *   - signature algorithm: ML-DSA-65 only
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
    int len, res;
    char tmpbuf[1024];
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    meth = TLS_client_method();
    ctx = SSL_CTX_new(meth);
    if(ctx == NULL) {
        fprintf(stderr, "Can't create SSL context\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if(res != 1) {
        fprintf(stderr, "Can't set minimum protocol version\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if(res != 1) {
        fprintf(stderr, "Can't set maximum protocol version\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP384r1MLKEM1024");
    if(res != 1) {
        fprintf(stderr, "Can't set ML-KEM groups\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_set1_sigalgs_list(ctx, "mldsa65");
    if(res != 1) {
        fprintf(stderr, "Can't set ML-DSA signature algorithm\n");
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

    printf("Negotiated: %s, group %s, cipher %s\n", SSL_get_version(ssl),
    SSL_get0_group_name(ssl), SSL_get_cipher_name(ssl));

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
