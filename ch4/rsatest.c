/*
 - ch4
 - rsatest.c
 - RSA 키를 생성하고, 파일을 암호화와 복호화
*/
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#define MAXBUFF 1024

void getTimeSubstr(unsigned char *seedbuff);

void makeRSAKeyFile(RSA **rsaPriv, RSA **rsaPub,
                    char *privkeyFn, char *pubKeyFn);

void encryptRSAFile(RSA *rsaPub, char *pfn, char *cfn);

void decryptRSAFile(RSA *rsaPriv, char *cfn, char *dfn);

int main(int argc, char *argv[])
{
    RSA *rsaPriv = NULL, *rsaPub = NULL;
    unsigned char seedbuff[MAXBUFF];
    assert(argc == 6);
    getTimeSubstr(seedbuff);
    RAND_seed(seedbuff, 8);

    makeRSAKeyFile(&rsaPriv, &rsaPub, argv[1], argv[2]);

    encryptRSAFile(rsaPub, argv[3], argv[4]);

    decryptRSAFile(rsaPriv, argv[4], argv[5]);
    
    RSA_free(rsaPriv);
    RSA_free(rsaPub);
    return (0);
}

void makeRSAKeyFile(RSA **rsaPriv, RSA **rsaPub, char *privKeyFn, char *pubKeyFn)
{
    FILE *fp;
    int res;
    *rsaPriv = RSA_generate_key(1024, RSA_F4, NULL, NULL);

    assert(*rsaPriv);
    *rsaPub = RSAPublicKey_dup(*rsaPriv);
    assert(*rsaPub);

    fp = fopen(privKeyFn, "wb");
    assert(fp);

    res = PEM_write_RSAPrivateKey(fp, *rsaPriv, NULL, NULL, 0, NULL, NULL);

    assert(res);

    fclose(fp);
    fp = fopen(pubKeyFn, "wb");
    assert(fp);

    res = PEM_write_RSAPublicKey(fp, *rsaPub);
    assert(res);

    fclose(fp);
}

void encryptRSAFile(RSA *rsaPub, char *pfn, char *cfn)
{
    FILE *fp;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    int psize, csize;
    fp = fopen(pfn, "rb");
    assert(fp);

    psize = fread(ptext, 1, RSA_size(rsaPub) - 42, fp);
    fclose(fp);

    csize = RSA_public_encrypt(psize, ptext, ctext, rsaPub, RSA_PKCS1_0AEP_PADDING);
    assert(csize >= 0);
    fp = fopen(cfn, "wb");
    assert(fp);

    fwrite(ctext, 1, csize, fp);

    fclose(fp);
}

void decryptRSAFile(RSA *rsaPriv, char *cfn, char *dfn)
{
    FILE *fp;
    unsigned char ctext[MAXBUFF];
    unsigned char dtext[MAXBUFF];
    int csize, dsize;
    fp = fopen(cfn, "rb");
    assert(fp);

    csize = fread(ctext, 1, MAXBUFF, fp);
    fclose(fp);

    dsize = RSA_private_decrypt(csize, ctext, dtext, rsaPriv, RSA_PKCS1_0AEP_PADDING);

    assert(dsize >= 0);

    fp = fopen(dfn, "wb");
    assert(fp);

    fwrite(dtext, 1, dsize, fp);

    fclose(fp);
}

void getTimeSubstr(unsigned char *buff)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    sprintf((char *)buff, "%ld%06ld",
            (long)tv.tv_sec,
            (long)tv.tv_usec);
}
