/*
 * rsa_sha1_sign_test.c
 *
 * RSA-SHA1 digital signature test: generate a key pair, sign a message,
 * and verify the signature.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAXSIGNSZ 1024
#define BUFFSZ 1024

int makeSignature (unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv);
int signatureVerify(unsigned char plaintext[], int plsize, unsigned char sign[], int signSize, RSA *rsaPub);
void printStr(unsigned char astr[], int len);
void printResult(int result);

int main()
{
    RSA *rsaPriv = NULL, *rsaPub = NULL;
    unsigned char pt [BUFFSZ] = "This is a plaintext.";
    unsigned char rands [BUFFSZ] ={ 0 ,};
    unsigned char sign [MAXSIGNSZ] ={ 0 ,};
    int plsize, result;
    unsigned int ssize;

    plsize = strlen((char *)pt);
    printf("org text: %s", pt); printStr(pt, plsize);
    RAND_seed (rands, 0); // TODO: seed 바이트 수가 0?
    rsaPriv = RSA_generate_key(512, RSA_F4, NULL, NULL);
    if (rsaPriv == NULL) {
        fprintf(stderr, "RSA key generation failed\n");
        return 1;
    }
    rsaPub = RSAPublicKey_dup(rsaPriv);
    if (rsaPub == NULL) {
        fprintf(stderr, "RSAPublicKey_dup failed\n");
        RSA_free(rsaPriv);
        return 1;
    }
    result = makeSignature(pt, plsize, sign, &ssize, rsaPriv);
    RSA_free(rsaPriv);
    if (result == 0) {
        RSA_free(rsaPub);
        return 1;
    }
    printf("signature: "); printStr(sign, ssize);
    result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
    printResult(result);
    // For a failure test:
    // pt[5] = '5';
    // result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
    // printResult(result);
    RSA_free (rsaPub);
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
        fprintf(stderr, "EVP_VerifyFinal error.\n");
        break;
    default:
        fprintf(stderr, "Invalid result from EVP_VerifyFinal()\n");
        break;
    }
}

int makeSignature (unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv)
{
    EVP_MD_CTX ctx;
    EVP_PKEY *pkey;
    int result;
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        return 0;
    }
    result = EVP_PKEY_set1_RSA(pkey, rsaPriv);
    if (result == 0) {
        fprintf(stderr, "EVP_PKEY_set1_RSA failed\n");
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_MD_CTX_init(&ctx);

    result = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
    if (result == 0) {
        fprintf(stderr, "EVP_SignInit_ex failed\n");
        goto err;
    }

    result = EVP_SignUpdate(&ctx, plaintext, plsize);
    if (result == 0) {
        fprintf(stderr, "EVP_SignUpdate failed\n");
        goto err;
    }

    result = EVP_SignFinal(&ctx, sign, signSize, pkey);
    if (result == 0) {
        fprintf(stderr, "EVP_SignFinal failed\n");
        goto err;
    }

    if (*signSize > MAXSIGNSZ) {
        fprintf(stderr, "Signature is too large\n");
        goto err;
    }

    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free(pkey);
    return 1;

err:
    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free(pkey);
    return 0;
}

int signatureVerify(unsigned char plaintext[], int plsize, unsigned char
sign[], int signSize, RSA *rsaPub)
{
    EVP_MD_CTX ctx;
    EVP_PKEY *pukey;
    int result;
    pukey = EVP_PKEY_new();
    if (pukey == NULL) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        return -1;
    }

    result = EVP_PKEY_set1_RSA(pukey, rsaPub);
    if (result == 0) {
        fprintf(stderr, "EVP_PKEY_set1_RSA failed\n");
        EVP_PKEY_free(pukey);
        return -1;
    }

    EVP_MD_CTX_init(&ctx);

    result = EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL);
    if (result == 0) {
        fprintf(stderr, "EVP_VerifyInit_ex failed\n");
        result = -1;
        goto done;
    }

    result = EVP_VerifyUpdate(&ctx, plaintext, plsize);
    if (result == 0) {
        fprintf(stderr, "EVP_VerifyUpdate failed\n");
        result = -1;
        goto done;
    }

    result = EVP_VerifyFinal(&ctx, sign, signSize, pukey);

done:
    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free (pukey);

    return(result);
}
