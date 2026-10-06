/*
 * pqc_mldsa_sign_test.c
 *
 * ML-DSA-65 digital signature test: generate a key pair, sign a message,
 * and verify the signature. ML-DSA signs the message directly, so no
 * separate digest algorithm is selected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define SIG_ALG "ML-DSA-65"

static void printStr(const unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void printResult(int result)
{
    switch (result) {
    case 1:
        printf("Signature is verified to be clear.\n");
        break;
    case 0:
        printf("WARNING: Signature verification fails.\n");
        break;
    default:
        fprintf(stderr, "EVP_DigestVerify error.\n");
        ERR_print_errors_fp(stderr);
        break;
    }
}

static EVP_PKEY *generateKey(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, SIG_ALG, NULL);
    EVP_PKEY *key = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_generate(ctx, &key) <= 0) {
        fprintf(stderr, "ML-DSA key generation failed\n");
        ERR_print_errors_fp(stderr);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static unsigned char *makeSignature(const unsigned char *msg, size_t msglen,
                                    size_t *siglen, EVP_PKEY *priv)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *sig = NULL;

    if (ctx == NULL ||
        EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, priv, NULL) != 1 ||
        EVP_DigestSign(ctx, NULL, siglen, msg, msglen) != 1)
        goto err;
    sig = OPENSSL_malloc(*siglen);
    if (sig == NULL || EVP_DigestSign(ctx, sig, siglen, msg, msglen) != 1)
        goto err;
    EVP_MD_CTX_free(ctx);
    return sig;

err:
    fprintf(stderr, "ML-DSA signing failed\n");
    ERR_print_errors_fp(stderr);
    OPENSSL_free(sig);
    EVP_MD_CTX_free(ctx);
    return NULL;
}

static int signatureVerify(const unsigned char *msg, size_t msglen,
                           const unsigned char *sig, size_t siglen,
                           EVP_PKEY *pub)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = -1;

    if (ctx != NULL &&
        EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pub, NULL) == 1)
        result = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);
    EVP_MD_CTX_free(ctx);
    return result;
}

int main(void)
{
    unsigned char pt[] = "This is a plaintext.";
    size_t plsize = strlen((char *)pt);
    unsigned char *sign;
    size_t ssize = 0;
    EVP_PKEY *key;
    int result;

    printf("org text: %s ", pt);
    printStr(pt, plsize);

    key = generateKey();
    if (key == NULL)
        return EXIT_FAILURE;

    sign = makeSignature(pt, plsize, &ssize, key);
    if (sign == NULL) {
        EVP_PKEY_free(key);
        return EXIT_FAILURE;
    }
    printf("signature: ");
    printStr(sign, ssize);

    result = signatureVerify(pt, plsize, sign, ssize, key);
    printResult(result);

    /* For a failure test:
     * pt[5] = '5';
     * printResult(signatureVerify(pt, plsize, sign, ssize, key));
     */

    OPENSSL_free(sign);
    EVP_PKEY_free(key);
    return result == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
