/*
 * pqc_rsatest.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch4/rsatest.c.
 * Same behavior: generate RSA key pair, encrypt a file, decrypt it.
 */

#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define MAXBUFF 1024

static void getTimeSubstr(unsigned char *buff)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    sprintf((char *)buff, "%ld%06ld", (long)tv.tv_sec, (long)tv.tv_usec);
}

static void makeRSAKeyFile(RSA **rsaPriv, RSA **rsaPub, const char *privKeyFn, const char *pubKeyFn)
{
    FILE *fp;
    int res;

    *rsaPriv = RSA_new();
    *rsaPub = RSA_new();

    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    assert(RSA_generate_key_ex(*rsaPriv, 1024, e, NULL) == 1);

    *rsaPub = RSAPublicKey_dup(*rsaPriv);
    assert(*rsaPub);

    fp = fopen(privKeyFn, "wb"); assert(fp);
    res = PEM_write_RSAPrivateKey(fp, *rsaPriv, NULL, NULL, 0, NULL, NULL);
    assert(res);
    fclose(fp);

    fp = fopen(pubKeyFn, "wb"); assert(fp);
    res = PEM_write_RSAPublicKey(fp, *rsaPub);
    assert(res);
    fclose(fp);

    BN_free(e);
}

static void encryptRSAFile(RSA *rsaPub, const char *pfn, const char *cfn)
{
    FILE *fp;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    int psize, csize;

    fp = fopen(pfn, "rb"); assert(fp);
    psize = fread(ptext, 1, RSA_size(rsaPub) - 42, fp);
    fclose(fp);

    csize = RSA_public_encrypt(psize, ptext, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
    assert(csize >= 0);

    fp = fopen(cfn, "wb"); assert(fp);
    fwrite(ctext, 1, csize, fp);
    fclose(fp);
}

static void decryptRSAFile(RSA *rsaPriv, const char *cfn, const char *dfn)
{
    FILE *fp;
    unsigned char ctext[MAXBUFF];
    unsigned char dtext[MAXBUFF];
    int csize, dsize;

    fp = fopen(cfn, "rb"); assert(fp);
    csize = fread(ctext, 1, MAXBUFF, fp);
    fclose(fp);

    dsize = RSA_private_decrypt(csize, ctext, dtext, rsaPriv, RSA_PKCS1_OAEP_PADDING);
    assert(dsize >= 0);

    fp = fopen(dfn, "wb"); assert(fp);
    fwrite(dtext, 1, dsize, fp);
    fclose(fp);
}

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
    return 0;
}
