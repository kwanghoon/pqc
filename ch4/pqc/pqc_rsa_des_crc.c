/*
 * pqc_rsa_des_crc.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch4/rsa_des_crc.c.
 * Same behavior: encrypt a file with a symmetric key protected by RSA.
 * PQC-aligned adjustment: the protected session key is still delivered by RSA,
 * but the actual payload encryption uses AES-256-CBC for stronger symmetric
 * protection while preserving the original file-envelope workflow.
 */

#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
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

static RSA *readRSAKeyFile(const char *pubKeyFn)
{
    FILE *fp;
    RSA *rsaPub;
    fp = fopen(pubKeyFn, "rb"); assert(fp != NULL);
    rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    assert(rsaPub != NULL);
    fclose(fp);
    return rsaPub;
}

static RSA *readRSAPrivKeyFile(const char *privKeyFn)
{
    FILE *fp;
    RSA *rsaPriv;
    fp = fopen(privKeyFn, "rb"); assert(fp != NULL);
    rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    assert(rsaPriv != NULL);
    fclose(fp);
    return rsaPriv;
}

static void makeEnvelope(RSA *rsaPub, const char *pfn, const char *cfn)
{
    FILE *ifp, *ofp;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    int psize, csize;
    unsigned char seedbuff[MAXBUFF];
    unsigned char mykey[32] = {0};
    unsigned char iv[16] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int res;

    getTimeSubstr(seedbuff);
    RAND_seed(seedbuff, 8);
    RAND_bytes(mykey, sizeof(mykey));
    RAND_bytes(iv, sizeof(iv));

    csize = RSA_public_encrypt(sizeof(mykey), mykey, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
    assert(csize >= 0);

    ofp = fopen(cfn, "wb"); assert(ofp);
    fwrite(&csize, 1, sizeof(int), ofp);
    fwrite(ctext, 1, csize, ofp);
    fwrite(iv, 1, sizeof(iv), ofp);

    ifp = fopen(pfn, "rb"); assert(ifp);
    res = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv);
    assert(res == 1);

    psize = fread(ptext, 1, MAXBUFF, ifp);
    while (psize > 0) {
        res = EVP_EncryptUpdate(ctx, ctext, &csize, ptext, psize);
        assert(res == 1);
        fwrite(ctext, 1, csize, ofp);
        psize = fread(ptext, 1, MAXBUFF, ifp);
    }

    res = EVP_EncryptFinal_ex(ctx, ctext, &csize);
    assert(res == 1);
    fwrite(ctext, 1, csize, ofp);
    fclose(ifp);
    fclose(ofp);
    EVP_CIPHER_CTX_free(ctx);
}

static void openEnvelope(RSA *rsaPriv, const char *cfn, const char *dfn)
{
    FILE *ifp, *ofp;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    int csize, psize;
    unsigned char mykey[32] = {0};
    unsigned char iv[16] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int res;

    ifp = fopen(cfn, "rb"); assert(ifp);
    fread(&csize, 1, sizeof(int), ifp);
    fread(ctext, 1, csize, ifp);
    res = RSA_private_decrypt(csize, ctext, mykey, rsaPriv, RSA_PKCS1_OAEP_PADDING);
    assert(res == sizeof(mykey));
    fread(iv, 1, sizeof(iv), ifp);

    ofp = fopen(dfn, "wb"); assert(ofp);
    res = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, mykey, iv);
    assert(res == 1);

    csize = fread(ctext, 1, MAXBUFF, ifp);
    while (csize > 0) {
        res = EVP_DecryptUpdate(ctx, ptext, &psize, ctext, csize);
        assert(res == 1);
        fwrite(ptext, 1, psize, ofp);
        csize = fread(ctext, 1, MAXBUFF, ifp);
    }

    res = EVP_DecryptFinal_ex(ctx, ptext, &psize);
    assert(res == 1);
    fwrite(ptext, 1, psize, ofp);

    fclose(ifp);
    fclose(ofp);
    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    RSA *rsaPub, *rsaPriv;
    assert(argc == 6);
    rsaPub = readRSAKeyFile(argv[1]);
    rsaPriv = readRSAPrivKeyFile(argv[2]);
    makeEnvelope(rsaPub, argv[3], argv[4]);
    openEnvelope(rsaPriv, argv[4], argv[5]);
    RSA_free(rsaPub);
    RSA_free(rsaPriv);
    return 0;
}
