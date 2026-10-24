/*
 * pqc_hash_sign.c
 *
 * Sign / verify every regular file in a directory with HashML-DSA-65
 * (ML-DSA-65 with SHA-512 pre-hash, FIPS 204 Algorithm 4 / 5).
 * Each signature is stored as <dir>/.hash/<name>.sig.
 *
 * Usage:
 *   pqc_hash_sign -i <private key file> <dir>   sign files
 *   pqc_hash_sign -c <public key file> <dir>    verify files
 *
 * ML-DSA has no streaming API, so each file is hashed incrementally with
 * SHA-512 and the digest is signed. OpenSSL 3.5 does not expose the
 * pre-hash mode through EVP, so signHashed()/verifyHashed() build the
 * HashML-DSA message M' themselves and pass it with "message-encoding" = 0.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#define BUFFSZ 1024
#define SIGNSZ 4096
#define FNSZ 128
#define SIG_ALG "ML-DSA-65"
#define HASHMSGSZ 77

int hashNsign (char privFile[], char fn[]);
int verify(char pubFile[], char fn[]);
int provideSubdir(char sfn[], char dirn[], char fn[]);
int buildHashMsg(unsigned char msg[], unsigned char hash[], unsigned int hashSize);
int signHashed(EVP_PKEY *pkey, unsigned char hash[], unsigned int hashSize, unsigned char sign[], size_t *signSize);
int verifyHashed(EVP_PKEY *pkey, unsigned char hash[], unsigned int hashSize, unsigned char sign[], size_t signSize);

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
    int res, ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int inLen;
    unsigned int hashSize;
    size_t signSize;
    unsigned char buff [BUFFSZ];
    unsigned char hash [EVP_MAX_MD_SIZE];
    unsigned char sign [SIGNSZ];
    char sfn [FNSZ], dirn [FNSZ];
    struct stat finfo;

    fp = fopen(privFile, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", privFile);
        goto done;
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    if (pkey == NULL) {
        fprintf(stderr, "Cannot read key %s\n", privFile);
        goto done;
    }

    fp = fopen(fn, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", fn);
        goto done;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto done;
    }
    res = EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    if (res == 0) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        goto done;
    }
    inLen = fread(buff, 1, BUFFSZ, fp);
    while(inLen > 0){
        res = EVP_DigestUpdate(ctx, buff, inLen);
        if (res == 0) {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            goto done;
        }
        inLen = fread(buff, 1, BUFFSZ, fp);
    }
    fclose(fp);
    fp = NULL;
    res = EVP_DigestFinal_ex(ctx, hash, &hashSize);
    if (res == 0) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        goto done;
    }
    res = signHashed(pkey, hash, hashSize, sign, &signSize);
    if (res == 0)
        goto done;
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
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return(ret);
}

int verify(char pubFile[], char fn[])
{
    FILE *fp = NULL;
    int res, ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char buff[BUFFSZ];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char sign[SIGNSZ];
    int inLen;
    unsigned int hashSize;
    size_t signSize;
    char sfn [FNSZ], dirn [FNSZ];

    fp = fopen(pubFile, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open %s\n", pubFile);
        goto done;
    }
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    if (pkey == NULL) {
        fprintf(stderr, "Cannot read key %s\n", pubFile);
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
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto done;
    }
    res = EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    if (res == 0) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        goto done;
    }
    inLen = fread(buff, 1, BUFFSZ, fp);
    while(inLen > 0){
        res = EVP_DigestUpdate(ctx, buff, inLen);
        if (res == 0) {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            goto done;
        }
        inLen = fread(buff, 1, BUFFSZ, fp);
    }
    fclose(fp);
    fp = NULL;
    res = EVP_DigestFinal_ex(ctx, hash, &hashSize);
    if (res == 0) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        goto done;
    }
    res = verifyHashed(pkey, hash, hashSize, sign, signSize);
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
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free (pkey);
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

// HashML-DSA(SHA-512)의 메시지 M' = 0x01 || len(ctx) || ctx || OID || hash.
// context string은 비어 있다. M'의 길이를 반환하고, 실패하면 0을 반환한다.
int buildHashMsg(unsigned char msg[], unsigned char hash[], unsigned int hashSize)
{
    unsigned char oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
    int n = 0;

    if (hashSize != SHA512_DIGEST_LENGTH) {
        fprintf(stderr, "Unexpected digest size %u\n", hashSize);
        return(0);
    }
    msg[n++] = 0x01;
    msg[n++] = 0x00;
    memcpy(msg + n, oid, sizeof(oid));
    n += sizeof(oid);
    memcpy(msg + n, hash, hashSize);
    n += hashSize;
    return(n);
}

// 해시 값에 대한 HashML-DSA 서명. M'을 그대로 서명하도록 message-encoding을 0으로 지정한다.
int signHashed(EVP_PKEY *pkey, unsigned char hash[], unsigned int hashSize, unsigned char sign[], size_t *signSize)
{
    EVP_MD_CTX *ctx;
    OSSL_PARAM params[2];
    unsigned char msg [HASHMSGSZ];
    int msgLen, encoding = 0, res;

    if (EVP_PKEY_is_a(pkey, SIG_ALG) == 0) {
        fprintf(stderr, "Key is not an %s key\n", SIG_ALG);
        return(0);
    }
    msgLen = buildHashMsg(msg, hash, hashSize);
    if (msgLen == 0)
        return(0);
    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return(0);
    }
    res = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
    if (res != 1) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return(0);
    }
    *signSize = SIGNSZ;
    res = EVP_DigestSign(ctx, sign, signSize, msg, msgLen);
    EVP_MD_CTX_free(ctx);
    if (res != 1) {
        fprintf(stderr, "EVP_DigestSign failed\n");
        return(0);
    }
    return(1);
}

// signHashed()와 같은 M'에 대한 서명 검증. 1: 성공, 0: 검증 실패, -1: 오류.
int verifyHashed(EVP_PKEY *pkey, unsigned char hash[], unsigned int hashSize, unsigned char sign[], size_t signSize)
{
    EVP_MD_CTX *ctx;
    OSSL_PARAM params[2];
    unsigned char msg [HASHMSGSZ];
    int msgLen, encoding = 0, res;

    if (EVP_PKEY_is_a(pkey, SIG_ALG) == 0) {
        fprintf(stderr, "Key is not an %s key\n", SIG_ALG);
        return(-1);
    }
    msgLen = buildHashMsg(msg, hash, hashSize);
    if (msgLen == 0)
        return(-1);
    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return(-1);
    }
    res = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
    if (res != 1) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return(-1);
    }
    res = EVP_DigestVerify(ctx, sign, signSize, msg, msgLen);
    EVP_MD_CTX_free(ctx);
    return(res);
}
