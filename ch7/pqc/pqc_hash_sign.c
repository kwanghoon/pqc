/*
 * pqc_hash_sign.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch7/hash_sign.c.
 * Same behavior: hash file and sign/verify it.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define BUFFSZ 1024
#define SIGNSZ 1024
#define FNSZ 128

static void hashNsign(const char privFile[], const char fn[]);
static void verify(const char pubFile[], const char fn[]);
static void provideSubdir(char sfn[], char dirn[], const char fn[]);

int main(int argc, char *argv[])
{
    DIR *dirp;
    struct dirent *dentry;
    struct stat statBuf;
    char fpath[FNSZ];
    int res, n;

    assert(argc == 4);
    dirp = opendir(argv[3]);
    assert(dirp);

    while ((dentry = readdir(dirp)) != NULL) {
        if (dentry->d_ino != 0) {
            n = snprintf(fpath, FNSZ, "%s/%s", argv[3], dentry->d_name);
            assert(n >= 0 && n < FNSZ);
            res = stat(fpath, &statBuf);
            if (res == 0 && S_ISREG(statBuf.st_mode)) {
                if (strcmp(argv[1], "-i") == 0)
                    hashNsign(argv[2], fpath);
                else if (strcmp(argv[1], "-c") == 0)
                    verify(argv[2], fpath);
                else
                    assert(0);
            }
        }
    }

    closedir(dirp);
    return 0;
}

static void hashNsign(const char privFile[], const char fn[])
{
    FILE *fp;
    RSA *rsaPriv = NULL;
    int res;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int inLen;
    unsigned int signSize;
    unsigned char buff[BUFFSZ];
    unsigned char sign[BUFFSZ];
    char sfn[FNSZ], dirn[FNSZ];
    struct stat finfo;

    fp = fopen(privFile, "rb"); assert(fp);
    rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL); assert(rsaPriv);
    fclose(fp);

    pkey = EVP_PKEY_new();
    res = EVP_PKEY_set1_RSA(pkey, rsaPriv); assert(res == 1);

    fp = fopen(fn, "rb"); assert(fp);
    res = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey); assert(res == 1);

    while ((inLen = fread(buff, 1, BUFFSZ, fp)) > 0) {
        res = EVP_DigestSignUpdate(ctx, buff, inLen); assert(res == 1);
    }
    fclose(fp);

    res = EVP_DigestSignFinal(ctx, NULL, &signSize); assert(res == 1);
    res = EVP_DigestSignFinal(ctx, sign, &signSize); assert(res == 1);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    RSA_free(rsaPriv);

    provideSubdir(sfn, dirn, fn);
    if (stat(dirn, &finfo) == -1) {
        res = mkdir(dirn, 0700);
        assert(res == 0);
    }

    fp = fopen(sfn, "wb"); assert(fp);
    fwrite(sign, 1, signSize, fp);
    fclose(fp);
}

static void verify(const char pubFile[], const char fn[])
{
    FILE *fp;
    RSA *rsaPub = NULL;
    int res;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buff[BUFFSZ];
    unsigned char sign[SIGNSZ];
    int inLen;
    unsigned int signSize;
    char sfn[FNSZ], dirn[FNSZ];

    fp = fopen(pubFile, "rb"); assert(fp);
    rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL); assert(rsaPub);
    fclose(fp);

    pkey = EVP_PKEY_new();
    res = EVP_PKEY_set1_RSA(pkey, rsaPub); assert(res == 1);
    provideSubdir(sfn, dirn, fn);

    fp = fopen(sfn, "rb"); assert(fp);
    signSize = fread(sign, 1, SIGNSZ, fp);
    fclose(fp);

    fp = fopen(fn, "rb"); assert(fp);
    res = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey); assert(res == 1);

    while ((inLen = fread(buff, 1, BUFFSZ, fp)) > 0) {
        res = EVP_DigestVerifyUpdate(ctx, buff, inLen); assert(res == 1);
    }
    fclose(fp);

    res = EVP_DigestVerifyFinal(ctx, sign, signSize);
    if (res == 1)
        printf("Signature verification of File %s succeeds.\n", fn);
    else if (res == 0)
        printf("Signature verification of File %s fails.\n", fn);
    else if (res < 0)
        printf("Something wrong with File %s and its signature.\n", fn);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    RSA_free(rsaPub);
}

static void provideSubdir(char sfn[], char dirn[], const char fn[])
{
    char *slash;
    char *base;
    int n, dirLen;

    slash = strrchr(fn, '/');
    if (slash != NULL) {
        n = slash - fn;
        assert(n < FNSZ);
        memcpy(dirn, fn, n);
        dirn[n] = '\0';
        base = slash + 1;
    } else {
        strcpy(dirn, ".");
        base = (char *)fn;
    }

    dirLen = strlen(dirn);
    n = snprintf(dirn + dirLen, FNSZ - dirLen, "/.hash");
    assert(n >= 0 && n < FNSZ - dirLen);

    n = snprintf(sfn, FNSZ, "%s/%s.sig", dirn, base);
    assert(n >= 0 && n < FNSZ);
}
