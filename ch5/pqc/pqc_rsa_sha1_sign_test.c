/*
 * pqc_rsa_sha1_sign_test.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch5/rsa_sha1_sign_test.c.
 * Same behavior: generate signature and verify it.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAXSIGNSZ 1024
#define BUFFSZ 1024

static void printStr(unsigned char astr[], int len)
{
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", astr[i]);
    }
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
    case -1:
        fprintf(stderr, "EVP_VerifyFinal error.\n");
        break;
    default:
        fprintf(stderr, "Invalid result from EVP_VerifyFinal()\n");
        break;
    }
}

static void makeSignature(unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    int result;

    result = EVP_PKEY_set1_RSA(pkey, rsaPriv);
    assert(result == 1);

    result = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    assert(result == 1);

    result = EVP_DigestSignUpdate(ctx, plaintext, plsize);
    assert(result == 1);

    result = EVP_DigestSignFinal(ctx, NULL, signSize);
    assert(result == 1);
    result = EVP_DigestSignFinal(ctx, sign, signSize);
    assert(result == 1);

    assert(*signSize <= MAXSIGNSZ);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
}

static int signatureVerify(unsigned char plaintext[], int plsize, unsigned char sign[], int signSize, RSA *rsaPub)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *pukey = EVP_PKEY_new();
    int result;

    result = EVP_PKEY_set1_RSA(pukey, rsaPub);
    assert(result == 1);

    result = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pukey);
    assert(result == 1);

    result = EVP_DigestVerifyUpdate(ctx, plaintext, plsize);
    assert(result == 1);

    result = EVP_DigestVerifyFinal(ctx, sign, signSize);
    EVP_PKEY_free(pukey);
    EVP_MD_CTX_free(ctx);

    return result;
}

int main(void)
{
    RSA *rsaPriv = NULL, *rsaPub = NULL;
    unsigned char pt[BUFFSZ] = "This is a plaintext.";
    unsigned char rands[BUFFSZ] = {0};
    unsigned char sign[MAXSIGNSZ] = {0};
    int plsize, result;
    unsigned int ssize;

    plsize = strlen((char *)pt);
    printf("org text: %s", pt); printStr(pt, plsize);
    RAND_seed(rands, 0);

    rsaPriv = RSA_generate_key(512, RSA_F4, NULL, NULL);
    assert(rsaPriv);
    rsaPub = RSAPublicKey_dup(rsaPriv); assert(rsaPub);

    makeSignature(pt, plsize, sign, &ssize, rsaPriv);
    RSA_free(rsaPriv);

    printf("signature: "); printStr(sign, ssize);
    result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
    printResult(result);

    RSA_free(rsaPub);
    return 1;
}
