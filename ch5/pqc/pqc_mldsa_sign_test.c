/*
 * pqc_mldsa_sign_test.c
 *
 * ML-DSA-65 digital signature test: generate a key pair, sign a message,
 * and verify the signature. ML-DSA signs the message directly, so no
 * separate digest algorithm is selected.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define SIG_ALG "ML-DSA-65"
#define MAXSIGNSZ 4096
#define BUFFSZ 1024

EVP_PKEY *generateKey(void);
int makeSignature (unsigned char *plaintext, int plsize, unsigned char *sign, size_t *signSize, EVP_PKEY *priv);
int signatureVerify(unsigned char plaintext[], int plsize, unsigned char sign[], int signSize, EVP_PKEY *pub);
void printStr(unsigned char astr[], int len);
void printResult(int result);

int main()
{
    EVP_PKEY *key = NULL;
    unsigned char pt [BUFFSZ] = "This is a plaintext.";
    unsigned char sign [MAXSIGNSZ] ={ 0 ,};
    int plsize, result;
    size_t ssize;

    plsize = strlen((char *)pt);
    printf("org text: %s", pt); printStr(pt, plsize);
    key = generateKey();
    if (key == NULL)
        return 1;
    result = makeSignature(pt, plsize, sign, &ssize, key);
    if (result == 0) {
        EVP_PKEY_free(key);
        return 1;
    }
    printf("signature: "); printStr(sign, ssize);
    result = signatureVerify(pt, plsize, sign, ssize, key);
    printResult(result);
    // For a failure test:
    // pt[5] = '5';
    // result = signatureVerify(pt, plsize, sign, ssize, key);
    // printResult(result);
    EVP_PKEY_free(key);
    if (result != 1)
        return 1;
    return 0;
}

void printStr(unsigned char astr[], int len)
{
    register int i;
    for (i = 0; i < len; i++)
    printf("%02x", astr[i]);
    printf("\n");
}

void printResult(int result)
{
    switch(result) {
    case 1:
        printf("Signature is verified to be clear.\n");
        break;
    case 0:
        printf("WARNING: Signature verification fails.\n");
        break;
    case -1:
        fprintf(stderr, "EVP_DigestVerify error.\n");
        ERR_print_errors_fp(stderr);
        break;
    default:
        fprintf(stderr, "Invalid result from EVP_DigestVerify()\n");
        break;
    }
}

EVP_PKEY *generateKey(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    int result;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, SIG_ALG, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    result = EVP_PKEY_keygen_init(ctx);
    if (result <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    result = EVP_PKEY_generate(ctx, &key);
    if (result <= 0) {
        fprintf(stderr, "EVP_PKEY_generate failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int makeSignature (unsigned char *plaintext, int plsize, unsigned char *sign, size_t *signSize, EVP_PKEY *priv)
{
    EVP_MD_CTX *ctx;
    int result;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return 0;
    }

    result = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, priv, NULL);
    if (result != 1) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        goto err;
    }

    *signSize = MAXSIGNSZ;
    result = EVP_DigestSign(ctx, sign, signSize, plaintext, plsize);
    if (result != 1) {
        fprintf(stderr, "EVP_DigestSign failed\n");
        goto err;
    }

    EVP_MD_CTX_free(ctx);
    return 1;

err:
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    return 0;
}

int signatureVerify(unsigned char plaintext[], int plsize, unsigned char
sign[], int signSize, EVP_PKEY *pub)
{
    EVP_MD_CTX *ctx;
    int result;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return -1;
    }

    result = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pub, NULL);
    if (result != 1) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        result = -1;
        goto done;
    }

    result = EVP_DigestVerify(ctx, sign, signSize, plaintext, plsize);

done:
    EVP_MD_CTX_free(ctx);

    return(result);
}
