/*
 * hash_sign.c
 *
 * Sign / verify every regular file in a directory with RSA + SHA-1.
 * Each signature is stored as <dir>/.hash/<name>.sig.
 *
 * Usage:
 *   hash_sign -i <private key file> <dir>   sign files
 *   hash_sign -c <public key file> <dir>    verify files
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define BUFFSZ 1024
#define SIGNSZ 1024
#define FNSZ 128

int hashNsign (char privFile[], char fn[]);
int verify(char pubFile[], char fn[]);
int provideSubdir(char sfn[], char dirn[], char fn[]);

int main(int argc, char *argv[])
{
    DIR *dirp;
    struct dirent *dentry;
    struct stat statBuf;
    char fpath [FNSZ];
    int res, n, result, failed = 0;
    if (argc != 4) {
        fprintf(stderr, "Usage: %s -i <private key file> <dir>\n"
                        "       %s -c <public key file> <dir>\n", argv[0], argv[0]);
        return 1;
    }
    dirp = opendir(argv[3]);
    if (dirp == NULL) {
        fprintf(stderr, "Cannot open directory %s\n", argv[3]);
        return 1;
    }
    while((dentry = readdir(dirp)) != NULL)
        if (dentry->d_ino != 0) {
            n = snprintf(fpath, FNSZ, "%s/%s", argv[3], dentry->d_name);
            if (n < 0 || n >= FNSZ) {
                fprintf(stderr, "Path is too long: %s/%s\n", argv[3], dentry->d_name);
                failed = 1;
                continue;
            }
            res = stat (fpath, &statBuf);
        if(res == 0 && S_ISREG(statBuf.st_mode)) {
            if(strcmp(argv[1], "-i")==0)
                result = hashNsign (argv[2], fpath);
            else if(strcmp(argv[1], "-c")==0)
                result = verify(argv[2], fpath);
            else {
                fprintf(stderr, "Unknown option %s\n", argv[1]);
                closedir(dirp);
                return 1;
            }
            if (result == 0)
                failed = 1;
        }
    }
    closedir(dirp);
    return(failed);
}

int hashNsign (char privFile[], char fn[])
{
    FILE *fp = NULL;
    RSA *rsaPriv = NULL;
    int res, ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX ctx;
    int inLen;
    unsigned int signSize;
    unsigned char buff [BUFFSZ];
    unsigned char sign [SIGNSZ];
    char sfn [FNSZ], dirn [FNSZ];
    struct stat finfo;

    EVP_MD_CTX_init(&ctx);
    fp = fopen(privFile, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", privFile);
        goto done;
    }
    rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    if (rsaPriv == NULL) {
        fprintf(stderr, "Cannot read key %s\n", privFile);
        goto done;
    }
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        goto done;
    }
    res = EVP_PKEY_set1_RSA(pkey, rsaPriv);
    if (res == 0) {
        fprintf(stderr, "EVP_PKEY_set1_RSA failed\n");
        goto done;
    }

    fp = fopen(fn, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", fn);
        goto done;
    }
    res = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
    if (res == 0) {
        fprintf(stderr, "EVP_SignInit_ex failed\n");
        goto done;
    }
    inLen = fread(buff, 1, BUFFSZ, fp);
    while(inLen > 0){
        res = EVP_SignUpdate(&ctx, buff, inLen);
        if (res == 0) {
            fprintf(stderr, "EVP_SignUpdate failed\n");
            goto done;
        }
        inLen = fread(buff, 1, BUFFSZ, fp);
    }
    fclose(fp);
    fp = NULL;
    res = EVP_SignFinal(&ctx, sign, &signSize, pkey);
    if (res == 0) {
        fprintf(stderr, "EVP_SignFinal failed\n");
        goto done;
    }
    res = provideSubdir(sfn, dirn, fn);
    if (res == 0)
        goto done;
    if(stat(dirn, &finfo) == -1) {
        res = mkdir(dirn, 0700);
        if (res != 0) {
            fprintf(stderr, "Cannot create directory %s\n", dirn);
            goto done;
        }
    }
    fp = fopen(sfn, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", sfn);
        goto done;
    }
    if (fwrite(sign, 1, signSize, fp) != signSize) {
        fprintf(stderr, "Cannot write %s\n", sfn);
        goto done;
    }
    res = fclose(fp);
    fp = NULL;
    if (res != 0) {
        fprintf(stderr, "Cannot write %s\n", sfn);
        goto done;
    }
    ret = 1;

done:
    if (fp != NULL)
        fclose(fp);
    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free(pkey);
    RSA_free(rsaPriv);
    return(ret);
}

int verify(char pubFile[], char fn[])
{
    FILE *fp = NULL;
    RSA *rsaPub = NULL;
    int res, ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX ctx;
    unsigned char buff[BUFFSZ];
    unsigned char sign[SIGNSZ];
    int inLen;
    unsigned int signSize;
    char sfn [FNSZ], dirn [FNSZ];

    EVP_MD_CTX_init(&ctx);
    fp = fopen(pubFile, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", pubFile);
        goto done;
    }
    rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    if (rsaPub == NULL) {
        fprintf(stderr, "Cannot read key %s\n", pubFile);
        goto done;
    }
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        fprintf(stderr, "EVP_PKEY_new failed\n");
        goto done;
    }
    res = EVP_PKEY_set1_RSA(pkey, rsaPub);
    if (res == 0) {
        fprintf(stderr, "EVP_PKEY_set1_RSA failed\n");
        goto done;
    }
    res = provideSubdir(sfn, dirn, fn);
    if (res == 0)
        goto done;
    fp = fopen(sfn, "rb");
    if (fp == NULL) {
        printf("Something wrong with File %s and its signature.\n", fn);
        goto done;
    }
    signSize= fread(sign, 1, SIGNSZ, fp);
    fclose(fp);
    fp = fopen(fn, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", fn);
        goto done;
    }
    res = EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL);
    if (res == 0) {
        fprintf(stderr, "EVP_VerifyInit_ex failed\n");
        goto done;
    }
    inLen = fread(buff, 1, BUFFSZ, fp);
    while(inLen > 0){
        res = EVP_VerifyUpdate(&ctx, buff, inLen);
        if (res == 0) {
            fprintf(stderr, "EVP_VerifyUpdate failed\n");
            goto done;
        }
        inLen = fread(buff, 1, BUFFSZ, fp);
    }
    fclose(fp);
    fp = NULL;
    res = EVP_VerifyFinal(&ctx, sign, signSize, pkey);
    if (res == 1) {
        printf("Signature verification of File %s succeeds.\n", fn);
        ret = 1;
    }
    else if(res == 0)
        printf("Signature verification of File %s fails.\n", fn);
    else if (res < 0)
        printf("Something wrong with File %s and its signature.\n", fn);

done:
    if (fp != NULL)
        fclose(fp);
    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free (pkey);
    RSA_free(rsaPub);
    return(ret);
}

// fn이 위치한 디렉토리 아래에 .hash 디렉토리 경로(dirn)와
// 그 안의 서명 파일 경로(sfn)를 만든다.
int provideSubdir(char sfn[], char dirn[], char fn[])
{
    char *slash;
    char *base;
    int n, dirLen;

    slash = strrchr(fn, '/');
    if (slash != NULL) {
        n = slash - fn;
        if (n >= FNSZ) {
            fprintf(stderr, "Path is too long: %s\n", fn);
            return(0);
        }
        memcpy(dirn, fn, n);
        dirn[n] = '\0';
        base = slash + 1;
    } else {
        strcpy(dirn, ".");
        base = fn;
    }

    dirLen = strlen(dirn);
    n = snprintf(dirn + dirLen, FNSZ - dirLen, "/.hash");
    if (n < 0 || n >= FNSZ - dirLen) {
        fprintf(stderr, "Path is too long: %s\n", fn);
        return(0);
    }

    n = snprintf(sfn, FNSZ, "%s/%s.sig", dirn, base);
    if (n < 0 || n >= FNSZ) {
        fprintf(stderr, "Path is too long: %s\n", fn);
        return(0);
    }
    return(1);
}
