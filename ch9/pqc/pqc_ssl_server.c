/*
 * pqc_ssl_server.c
 *
 * PQC conversion of ch9/ssl_server.c: a TLS 1.3 server that accepts one
 * connection and echoes the request headers.
 *
 *   - TLS 1.3 only (hybrid ML-KEM groups do not exist in TLS 1.2)
 *   - key exchange: X25519MLKEM768 / SecP384r1MLKEM1024 only, no classical-only
 *     fallback group
 *   - authentication: ML-DSA-65 certificate and key (see ch6/pqc)
 *
 * Usage: pqc_ssl_server [cert.pem [key.pem [port]]]
 *        defaults: BobCert.pem BobPriv.pem 4433
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

static int fail(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(int argc, char *argv[])
{
    const char *certFile = argc > 1 ? argv[1] : "BobCert.pem";
    const char *keyFile = argc > 2 ? argv[2] : "BobPriv.pem";
    const char *port = argc > 3 ? argv[3] : "4433";
    BIO *sbio, *bbio, *acpt, *out;
    char tmpbuf[1024];
    SSL_CTX *ctx;
    SSL *ssl;
    int len, ret = 1;

    ctx = SSL_CTX_new(TLS_server_method());
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

    if (SSL_CTX_use_certificate_chain_file(ctx, certFile) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        ret = fail("Cannot load certificate/private key");
        goto free_ctx;
    }
    if (!EVP_PKEY_is_a(SSL_CTX_get0_privatekey(ctx), "ML-DSA-65")) {
        fprintf(stderr, "%s is not an ML-DSA-65 key\n", keyFile);
        goto free_ctx;
    }

    sbio = BIO_new_ssl(ctx, 0);
    BIO_get_ssl(sbio, &ssl);
    if (!ssl) {
        ret = fail("Can't locate SSL pointer");
        goto free_ctx;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    bbio = BIO_new(BIO_f_buffer());
    sbio = BIO_push(bbio, sbio);
    acpt = BIO_new_accept(port);
    BIO_set_accept_bios(acpt, sbio);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (BIO_do_accept(acpt) <= 0 || BIO_do_accept(acpt) <= 0) {
        ret = fail("Error setting up or accepting connection");
        BIO_free_all(acpt);
        BIO_free(out);
        goto free_ctx;
    }

    sbio = BIO_pop(acpt);
    BIO_free_all(acpt);
    if (BIO_do_handshake(sbio) <= 0) {
        ret = fail("Error in SSL handshake");
        BIO_free_all(sbio);
        BIO_free(out);
        goto free_ctx;
    }

    BIO_get_ssl(sbio, &ssl);
    printf("Negotiated: %s, group %s\n", SSL_get_version(ssl), SSL_get0_group_name(ssl));

    BIO_puts(sbio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");
    BIO_puts(sbio, "\nConnection Established\nRequest headers:\n\n");
    for (;;) {
        len = BIO_gets(sbio, tmpbuf, sizeof(tmpbuf));
        if (len <= 0)
            break;
        BIO_write(sbio, tmpbuf, len);
        BIO_write(out, tmpbuf, len);
        if (tmpbuf[0] == '\r' || tmpbuf[0] == '\n')
            break;
    }

    BIO_puts(sbio, "-----------------------------------\n\n");
    (void)BIO_flush(sbio);
    BIO_free_all(sbio);
    BIO_free(out);
    ret = 0;

free_ctx:
    SSL_CTX_free(ctx);
    return ret;
}
