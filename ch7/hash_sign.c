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

void hashNsign (char privFile[], char fn[]);
void verify(char pubFile[], char fn[]);
void provideSubdir(char sfn[], char dirn[], char fn[]);

int main(int argc, char *argv[])
{
    DIR *dirp;
    struct dirent *dentry;
    struct stat statBuf;
    int res;
    assert(argc == 3);
    assert(dirp = opendir("."));
    while((dentry = readdir(dirp)) != NULL)
        if (dentry->d_ino != 0) {
            res = stat (dentry->d_name, &statBuf);
        if(res == 0 && S_ISREG(statBuf.st_mode)) {
            if(strcmp(argv[1], "-i")==0)
                hashNsign (argv[2], dentry->d_name);
            else if(strcmp(argv[1], "-c")==0)
                verify(argv[2], dentry->d_name);
            else
                assert(0);
        }
    }
    closedir(dirp);
    return(0);
}

void hashNsign (char privFile[], char fn[])
{
    FILE *fp;
    RSA *rsaPriv = NULL;
    int res;
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    int inLen;
    unsigned int signSize;
    unsigned char buff [BUFFSZ];
    unsigned char sign [BUFFSZ];
    char sfn [FNSZ], dirn [FNSZ];
    struct stat finfo;

    fp = fopen(privFile, "rb"); assert(fp);
    rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    assert(rsaPriv);
    fclose(fp);
    pkey = EVP_PKEY_new();
    res = EVP_PKEY_set1_RSA(pkey, rsaPriv);
    assert(res);

    fp = fopen(fn, "rb"); assert(fp);
    EVP_MD_CTX_init(&ctx);
    res = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
    assert(res);
    inLen = fread(buff, 1, BUFFSZ, fp);
    while(inLen > 0){
        res = EVP_SignUpdate(&ctx, buff, inLen); assert(res);
        inLen = fread(buff, 1, BUFFSZ, fp);
    }
    fclose(fp);
    res = EVP_SignFinal(&ctx, sign, &signSize, pkey);
    assert(res);
    assert(signSize <= BUFFSZ); // cf. signSize <= FNSZ
    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free(pkey);
    RSA_free(rsaPriv);
    provideSubdir(sfn, dirn, fn);
    if(stat(dirn, &finfo) == -1) {
        res = mkdir(dirn, 0700);
        assert(res == 0);
    }
    fp = fopen(sfn, "wb"); assert(fp);
    fwrite(sign, 1, signSize, fp);
    fclose(fp);
}

void verify(char pubFile[], char fn[])
{
    FILE *fp;
    RSA *rsaPub = NULL;
    int res;
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    unsigned char buff[BUFFSZ];
    unsigned char sign[SIGNSZ];
    int inLen;
    unsigned int signSize;
    char sfn [FNSZ], dirn [FNSZ];

    fp = fopen(pubFile, "rb"); assert(fp);
    rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL); assert(rsaPub);
    fclose(fp);
    pkey = EVP_PKEY_new();
    res = EVP_PKEY_set1_RSA(pkey, rsaPub); assert(res);
    provideSubdir(sfn, dirn, fn);
    fp = fopen(sfn, "rb"); assert(fp);
    signSize= fread(sign, 1, SIGNSZ, fp);
    fclose(fp);
    fp = fopen(fn, "rb"); assert(fp);
    EVP_MD_CTX_init(&ctx);
    res = EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL); assert(res);
    inLen = fread(buff, 1, BUFFSZ, fp);
    while(inLen > 0){
        res = EVP_VerifyUpdate(&ctx, buff, inLen);
        inLen = fread(buff, 1, BUFFSZ, fp);
    }
    fclose(fp);
    res = EVP_VerifyFinal(&ctx, sign, signSize, pkey);
    if (res == 1)
        printf("Signature verification of File %s succeeds.\n", fn);
    else if(res == 0)
        printf("Signature verification of File %s fails.\n", fn);
    else if (res < 0)
        printf("Something wrong with File %s and its signature.\n", fn);

    EVP_MD_CTX_cleanup(&ctx);
    EVP_PKEY_free (pkey);
    RSA_free(rsaPub);
}

void provideSubdir(char sfn[], char dirn[], char fn[])
{
    int n;

    n = snprintf(dirn, FNSZ, "signatures");
    assert(n >= 0 && n < FNSZ);

    n = snprintf(sfn, FNSZ, "%s/%s.sig", dirn, fn);
    assert(n >= 0 && n < FNSZ);
}