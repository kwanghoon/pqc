/*
 * pqc_ssl_server.c
 *
 * PQC conversion of ch9/ssl_server.c.
 * TLS 1.3 server. Listens on port 4433, accepts one connection, performs the
 * handshake and echoes the request headers back to the client.
 *
 *   - TLS 1.3 only: hybrid ML-KEM groups do not exist in TLS 1.2
 *   - key exchange: X25519MLKEM768 / SecP384r1MLKEM1024 only, no classical-only
 *     group
 *   - authentication: ML-DSA-65 certificate and private key; any other key
 *     type is rejected
 *
 * Files read from the current directory: BobCert.pem, BobPriv.pem
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

int main()
{
    BIO *sbio, *bbio, *acpt, *out;
    int len;
    char tmpbuf[1024];
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    int res;

    meth = TLS_server_method();
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
    res = SSL_CTX_use_certificate_chain_file(ctx, "BobCert.pem");
    if(res != 1) {
        fprintf(stderr, "Can't load BobCert.pem\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_use_PrivateKey_file(ctx, "BobPriv.pem", SSL_FILETYPE_PEM);
    if(res != 1) {
        fprintf(stderr, "Can't load BobPriv.pem\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = SSL_CTX_check_private_key(ctx);
    if(res != 1) {
        fprintf(stderr, "Private key does not match the certificate\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    res = EVP_PKEY_is_a(SSL_CTX_get0_privatekey(ctx), "ML-DSA-65");
    if(res != 1) {
        fprintf(stderr, "BobPriv.pem is not an ML-DSA-65 key\n");
        return 1;
    }

    sbio = BIO_new_ssl(ctx,0);
    if(sbio == NULL) {
        fprintf(stderr, "Can't create SSL BIO\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    BIO_get_ssl (sbio, &ssl);
    if(!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        return 1;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    bbio = BIO_new(BIO_f_buffer());
    if(bbio == NULL) {
        fprintf(stderr, "Can't create buffer BIO\n");
        return 1;
    }
    sbio = BIO_push(bbio, sbio);
    acpt = BIO_new_accept("4433");
    if(acpt == NULL) {
        fprintf(stderr, "Can't create accept BIO\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    BIO_set_accept_bios(acpt, sbio);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(out == NULL) {
        fprintf(stderr, "Can't create output BIO\n");
        return 1;
    }
    if (BIO_do_accept(acpt) <= 0 ) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (BIO_do_accept (acpt) <= 0 ) {
        fprintf(stderr, "Error in connection\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    sbio = BIO_pop(acpt);
    BIO_free_all(acpt);
    if (BIO_do_handshake (sbio) <= 0 ) {
        fprintf(stderr, "Error in SSL handshake\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    BIO_puts (sbio, "HTTP/1.0 200 OK\r\n" "Content-type: text/plain\r\n" "\r\n");
    BIO_puts(sbio, "\nConnection Established\nRequest headers:\n");
    BIO_puts (sbio, "\n");
    for(;;) {
        len = BIO_gets(sbio, tmpbuf, 1024);
        if(len <= 0) break;
        BIO_write(sbio, tmpbuf, len);
        BIO_write(out, tmpbuf, len);
        if((tmpbuf[0] == '\r') || (tmpbuf[0] == '\n')) break;
    }
    BIO_puts (sbio, "-----------------------------------\n");
    BIO_puts(sbio, "\n");

    BIO_flush(sbio);
    BIO_free_all(sbio);
    SSL_CTX_free(ctx);

    return(0);
}
