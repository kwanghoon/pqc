/*
 * pqc_hash_sign.c
 *
 * PQC conversion of ch7/hash_sign.c: sign / verify every regular file in a
 * directory with ML-DSA-65 (OpenSSL 3.5+) instead of RSA + SHA-1.
 *
 * Usage:
 *   pqc_hash_sign -i <mldsa_priv.pem> <dir>   sign files, store <dir>/.hash/<name>.sig
 *   pqc_hash_sign -c <mldsa_pub.pem>  <dir>   verify files against the stored signatures
 *
 * ML-DSA signs the whole message in one call (no streaming, no separate hash),
 * so each file is read into memory and passed to EVP_DigestSign/EVP_DigestVerify.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define FNSZ 512
#define ALG "ML-DSA-65"

static int hashNsign(const char privFile[], const char fn[]);
static int verify(const char pubFile[], const char fn[]);
static void provideSubdir(char sfn[], char dirn[], const char fn[]);
static unsigned char *readAll(const char fn[], size_t *len);
static EVP_PKEY *loadKey(const char file[], int isPrivate);

int main(int argc, char *argv[])
{
    DIR *dirp;
    struct dirent *dentry;
    struct stat statBuf;
    char fpath[FNSZ];
    int sign, failed = 0;

    if (argc != 4 || (strcmp(argv[1], "-i") != 0 && strcmp(argv[1], "-c") != 0)) {
        fprintf(stderr, "Usage: %s -i <mldsa_priv.pem> <dir>\n"
                        "       %s -c <mldsa_pub.pem> <dir>\n", argv[0], argv[0]);
        return 2;
    }
    sign = strcmp(argv[1], "-i") == 0;

    dirp = opendir(argv[3]);
    if (!dirp) {
        perror(argv[3]);
        return 1;
    }

    while ((dentry = readdir(dirp)) != NULL) {
        int n = snprintf(fpath, FNSZ, "%s/%s", argv[3], dentry->d_name);
        if (n < 0 || n >= FNSZ || stat(fpath, &statBuf) != 0 || !S_ISREG(statBuf.st_mode))
            continue;
        if ((sign ? hashNsign(argv[2], fpath) : verify(argv[2], fpath)) != 1)
            failed = 1;
    }

    closedir(dirp);
    return failed;
}

static EVP_PKEY *loadKey(const char file[], int isPrivate)
{
    FILE *fp = fopen(file, "rb");
    EVP_PKEY *pkey;

    if (!fp) {
        perror(file);
        return NULL;
    }
    pkey = isPrivate ? PEM_read_PrivateKey(fp, NULL, NULL, NULL)
                     : PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Cannot read key %s\n", file);
    } else if (!EVP_PKEY_is_a(pkey, ALG)) {
        fprintf(stderr, "%s is not an %s key\n", file, ALG);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return pkey;
}

static unsigned char *readAll(const char fn[], size_t *len)
{
    FILE *fp = fopen(fn, "rb");
    unsigned char *buf = NULL;
    long sz;

    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) == 0 && (sz = ftell(fp)) >= 0 && fseek(fp, 0, SEEK_SET) == 0) {
        buf = malloc(sz ? (size_t)sz : 1);
        if (buf && fread(buf, 1, (size_t)sz, fp) == (size_t)sz) {
            *len = (size_t)sz;
        } else {
            free(buf);
            buf = NULL;
        }
    }
    fclose(fp);
    return buf;
}

static int hashNsign(const char privFile[], const char fn[])
{
    EVP_PKEY *pkey = loadKey(privFile, 1);
    EVP_MD_CTX *ctx = NULL;
    unsigned char *msg = NULL, *sig = NULL;
    size_t msgLen = 0, sigLen = 0;
    char sfn[FNSZ], dirn[FNSZ];
    struct stat finfo;
    FILE *fp;
    int ok = 0;

    if (!pkey)
        return 0;
    msg = readAll(fn, &msgLen);
    ctx = EVP_MD_CTX_new();
    if (!msg || !ctx) {
        fprintf(stderr, "Cannot read %s\n", fn);
        goto done;
    }

    if (EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) != 1 ||
        EVP_DigestSign(ctx, NULL, &sigLen, msg, msgLen) != 1)
        goto done;
    sig = malloc(sigLen);
    if (!sig || EVP_DigestSign(ctx, sig, &sigLen, msg, msgLen) != 1)
        goto done;

    provideSubdir(sfn, dirn, fn);
    if (stat(dirn, &finfo) == -1 && mkdir(dirn, 0700) != 0) {
        perror(dirn);
        goto done;
    }
    fp = fopen(sfn, "wb");
    if (!fp) {
        perror(sfn);
        goto done;
    }
    ok = fwrite(sig, 1, sigLen, fp) == sigLen;
    if (fclose(fp) != 0)
        ok = 0;
    if (ok)
        printf("Signed %s -> %s (%zu bytes)\n", fn, sfn, sigLen);

done:
    free(sig);
    free(msg);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static int verify(const char pubFile[], const char fn[])
{
    EVP_PKEY *pkey = loadKey(pubFile, 0);
    EVP_MD_CTX *ctx = NULL;
    unsigned char *msg = NULL, *sig = NULL;
    size_t msgLen = 0, sigLen = 0;
    char sfn[FNSZ], dirn[FNSZ];
    int res, ok = 0;

    if (!pkey)
        return 0;
    provideSubdir(sfn, dirn, fn);
    msg = readAll(fn, &msgLen);
    sig = readAll(sfn, &sigLen);
    ctx = EVP_MD_CTX_new();
    if (!msg || !sig || !ctx) {
        printf("Signature file %s for File %s is missing or unreadable.\n", sfn, fn);
        goto done;
    }

    if (EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) != 1)
        goto done;
    res = EVP_DigestVerify(ctx, sig, sigLen, msg, msgLen);
    if (res == 1) {
        printf("Signature verification of File %s succeeds.\n", fn);
        ok = 1;
    } else if (res == 0) {
        printf("Signature verification of File %s fails.\n", fn);
    } else {
        printf("Something wrong with File %s and its signature.\n", fn);
    }

done:
    free(sig);
    free(msg);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static void provideSubdir(char sfn[], char dirn[], const char fn[])
{
    const char *slash = strrchr(fn, '/');
    const char *base = fn;
    size_t n = 0;

    if (slash) {
        n = (size_t)(slash - fn);
        base = slash + 1;
        memcpy(dirn, fn, n);
        dirn[n] = '\0';
    } else {
        strcpy(dirn, ".");
        n = 1;
    }
    snprintf(dirn + n, FNSZ - n, "/.hash");
    snprintf(sfn, FNSZ, "%s/%s.sig", dirn, base);
}
