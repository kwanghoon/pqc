#include <stdio.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int main(void)
{
    BIO *sbio, *bbio, *acpt, *out;
    BIO *bio_err = 0;
    int len;
    char tmpbuf[1024];
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    int res;

    if(!bio_err) {
        SSL_library_init();
        SSL_load_error_strings();
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }

    meth = SSLv23_server_method();
    ctx = SSL_CTX_new(meth);
    res = SSL_CTX_use_certificate_chain_file(ctx, "BobCert.pem");
    assert(res);
    res = SSL_CTX_use_PrivateKey_file(ctx, "BobPriv.pem", SSL_FILETYPE_PEM);
    assert(res);
    res = SSL_CTX_check_private_key(ctx);
    assert(res);

    sbio = BIO_new_ssl(ctx,0);
    BIO_get_ssl (sbio, &ssl);
    assert(ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    bbio = BIO_new(BIO_f_buffer());
    sbio = BIO_push(bbio, sbio);
    acpt = BIO_new_accept("4433");
    BIO_set_accept_bios(acpt, sbio);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_accept(acpt) <= 0 ) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (BIO_do_accept (acpt) <= 0 ) {
        fprintf(stderr, "Error in connection\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    sbio = BIO_pop(acpt);
    BIO_free_all(acpt);
    if (BIO_do_handshake (sbio) <= 0 ) {
        fprintf(stderr, "Error in SSL handshake\n");
        ERR_print_errors_fp(stderr);
        return 0;
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