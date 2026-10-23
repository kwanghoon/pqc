/*
 - ch1
 - rsagenkey.c
 - ML-DSA 개인키 및 공개키 생성 프로그램
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MAXBUFF 128

void getTimeSubstr(char buff[])
{
    struct timeval atime;
    gettimeofday(&atime, NULL);

    memcpy(buff, &(atime.tv_sec), 4);
    memcpy(buff + 4, &(atime.tv_usec), 4);
}

int main(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    char seedbuf [MAXBUFF];
    FILE *pubf, *privf;
    int ret = 0;

    getTimeSubstr(seedbuf);
    RAND_seed (seedbuf, 8);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if(ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
       EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "ML-DSA-65 key generation error.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    pubf = fopen("pubKey.pem", "w"); assert(pubf);
    privf = fopen("privKey.pem", "w"); assert(privf);

    if(!PEM_write_PUBKEY(pubf, pkey)) {
        fprintf(stderr, "writing public key to a file fails.\n");
        ret = 1;
    }

    if(!PEM_write_PrivateKey(privf, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "writing private key to a file fails.\n");
        ret = 1;
    }

    fclose(pubf);
    fclose(privf);

    EVP_PKEY_free(pkey);

    return ret;
}
