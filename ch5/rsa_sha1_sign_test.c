#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAXSIGNSZ 1024
#define BUFFSZ 1024

void makeSignature (unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv);
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
    assert(rsaPriv);
    rsaPub = RSAPublicKey_dup(rsaPriv); assert(rsaPub);
    makeSignature(pt, plsize, sign, &ssize, rsaPriv);
    RSA_free(rsaPriv);
    printf("signature: "); printStr(sign, ssize);
    result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
    printResult(result);
    // For a failure test:
    // pt[5] = '5';
    // result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
    // printResult(result);
    RSA_free (rsaPub);
    return(1);
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

void makeSignature (unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv)
{
    EVP_MD_CTX ctx;
    EVP_PKEY *pkey;
    int result;
    pkey = EVP_PKEY_new();
    result = EVP_PKEY_set1_RSA(pkey, rsaPriv);

    assert(result);

    EVP_MD_CTX_init(&ctx);

    result = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
    assert(result);

    result = EVP_SignUpdate(&ctx, plaintext, plsize);
    assert(result);

    result = EVP_SignFinal(&ctx, sign, signSize, pkey);
    assert(result);

    assert(*signSize <= MAXSIGNSZ);

    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free(pkey);
}

int signatureVerify(unsigned char plaintext[], int plsize, unsigned char
sign[], int signSize, RSA *rsaPub)
{
    EVP_MD_CTX ctx;
    EVP_PKEY *pukey;
    int result;
    pukey = EVP_PKEY_new();

    result = EVP_PKEY_set1_RSA(pukey, rsaPub);
    assert(result);

    EVP_MD_CTX_init(&ctx);

    result = EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL);
    assert(result);

    result = EVP_VerifyUpdate(&ctx, plaintext, plsize);
    assert(result);

    result = EVP_VerifyFinal(&ctx, sign, signSize, pukey);
    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free (pukey);

    return(result);
}