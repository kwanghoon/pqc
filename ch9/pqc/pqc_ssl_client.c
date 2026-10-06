/*
 * pqc_ssl_client.c
 *
 * PQC conversion of ch9/ssl_client.c: a TLS 1.3 client that fetches "/".
 *
 *   - TLS 1.3 only, hybrid ML-KEM key exchange only (no classical-only group)
 *   - the server certificate (ML-DSA-65) is verified against a CA file and the
 *     host name; the original client verified nothing
 *
 * Usage: pqc_ssl_client [CACert.pem [host [port]]]
 *        defaults: CACert.pem localhost 4433
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

static int fail(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(int argc, char *argv[])
{
    const char *caFile = argc > 1 ? argv[1] : "CACert.pem";
    const char *host = argc > 2 ? argv[2] : "localhost";
    const char *port = argc > 3 ? argv[3] : "4433";
    char target[256], tmpbuf[1024];
    BIO *sbio, *out;
    SSL_CTX *ctx;
    SSL *ssl;
    int len, ret = 1;

    snprintf(target, sizeof(target), "%s:%s", host, port);

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return fail("SSL_CTX_new failed");
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP384r1MLKEM1024") != 1 ||
        SSL_CTX_set1_sigalgs_list(ctx, "mldsa65") != 1) {
        ret = fail("Cannot set PQC groups/signature algorithms");
        goto free_ctx;
    }
    if (SSL_CTX_load_verify_locations(ctx, caFile, NULL) != 1) {
        ret = fail("Cannot load CA certificate");
        goto free_ctx;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    if (!ssl) {
        ret = fail("Can't locate SSL pointer");
        BIO_free_all(sbio);
        goto free_ctx;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_tlsext_host_name(ssl, host);
    if (SSL_set1_host(ssl, host) != 1) {
        ret = fail("Cannot set expected host name");
        BIO_free_all(sbio);
        goto free_ctx;
    }
    BIO_set_conn_hostname(sbio, target);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (BIO_do_connect(sbio) <= 0 || BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection (verify: %s)\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        ret = fail("TLS connection failed");
        goto free_bios;
    }

    printf("Negotiated: %s, group %s, cipher %s\n", SSL_get_version(ssl),
           SSL_get0_group_name(ssl), SSL_get_cipher_name(ssl));

    BIO_puts(sbio, "GET / HTTP/1.0\r\n\r\n");
    while ((len = BIO_read(sbio, tmpbuf, sizeof(tmpbuf))) > 0)
        BIO_write(out, tmpbuf, len);
    ret = 0;

free_bios:
    BIO_free_all(sbio);
    BIO_free(out);
free_ctx:
    SSL_CTX_free(ctx);
    return ret;
}
