/*
 - ch1
 - rsagenkey.c
 - RSA 개인키 및 공개키 생성 프로그램
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
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
    RSA *rsaPriv = NULL, *rsaPub = NULL;
    char seedbuf [MAXBUFF];
    FILE *pubf, *privf;
    getTimeSubstr(seedbuf);
    RAND_seed (seedbuf, 8);

    rsaPriv = RSA_generate_key(512, RSA_F4, NULL, NULL);
    if(rsaPriv == NULL) {
     fprintf(stderr, "RSA generate key error.\n");
        return(1);
    }

    rsaPub = RSAPublicKey_dup(rsaPriv);
    if(rsaPub == NULL) {
        fprintf(stderr, "RSA public key copy error.\n");
        return(2);
    }

    pubf = fopen("pubkey.pem", "w"); assert(pubf);
    privf = fopen("privkey.pem", "w"); assert(privf);

    if(!PEM_write_RSAPublicKey(pubf, rsaPub))
        fprintf(stderr, "writing public key to a file fails.\n");

    if(!PEM_write_RSAPrivateKey(privf, rsaPriv, NULL, NULL, 0, NULL, NULL))
        fprintf(stderr, "writing private key to a file fails.\n");

    fclose(pubf);
    fclose(privf);

    RSA_free(rsaPriv);
    RSA_free (rsaPub);

    exit(0);
}