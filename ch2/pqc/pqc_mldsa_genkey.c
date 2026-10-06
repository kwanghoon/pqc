/*
 * pqc_mldsa_genkey.c
 *
 * PQC conversion of ch2/rsagenkey.c: generates an ML-DSA-65 (FIPS 204) key
 * pair and writes it as PEM files. The key pair can be used for signing in
 * ch5 (pqc_mldsa_sign_test), ch7 (pqc_hash_sign) and for certificates (ch6).
 *
 * Differences from the RSA version:
 *   - RSA_generate_key(512) -> EVP_PKEY_keygen with ML-DSA-65
 *   - manual RAND_seed from the clock removed (OpenSSL seeds its DRBG itself)
 *   - public key is written as SubjectPublicKeyInfo ("BEGIN PUBLIC KEY"),
 *     the private key as PKCS#8; the private key file is created with mode 0600
 *
 * Usage: pqc_mldsa_genkey [pubKey.pem [privKey.pem]]
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static FILE *openOutput(const char *path, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    FILE *fp;

    if (fd < 0)
        return NULL;
    fchmod(fd, mode);
    fp = fdopen(fd, "w");
    if (!fp)
        close(fd);
    return fp;
}

int main(int argc, char *argv[])
{
    const char *pubFile = argc > 1 ? argv[1] : "pubKey.pem";
    const char *privFile = argc > 2 ? argv[2] : "privKey.pem";
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    FILE *pubf, *privf;
    int ret = 1;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pkey) != 1) {
        fprintf(stderr, "ML-DSA-65 key generation error.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    pubf = fopen(pubFile, "w");
    privf = openOutput(privFile, 0600);
    if (!pubf || !privf) {
        perror(!pubf ? pubFile : privFile);
        goto done;
    }

    if (!PEM_write_PUBKEY(pubf, pkey)) {
        fprintf(stderr, "writing public key to a file fails.\n");
        goto done;
    }
    if (!PEM_write_PrivateKey(privf, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "writing private key to a file fails.\n");
        goto done;
    }
    ret = 0;

done:
    if (pubf && fclose(pubf) != 0)
        ret = 1;
    if (privf && fclose(privf) != 0)
        ret = 1;
    EVP_PKEY_free(pkey);
    return ret;
}
