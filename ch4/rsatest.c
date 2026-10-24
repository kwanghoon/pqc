/*
 - ch4
 - rsatest.c
 - RSA 키를 생성하고, 파일을 암호화와 복호화
*/
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#define MAXBUFF 1024

void getTimeSubstr(unsigned char *seedbuff);

int generate_rsa_key(RSA **rsaPriv, RSA **rsaPub);

int write_key_files(RSA *rsaPriv, RSA *rsaPub,
                    const char *privkeyFn, const char *pubKeyFn);

int encryptRSAFile(RSA *rsaPub, char *pfn, char *cfn);

int decryptRSAFile(RSA *rsaPriv, char *cfn, char *dfn);

int main(int argc, char *argv[])
{
    RSA *rsaPriv = NULL, *rsaPub = NULL;
    unsigned char seedbuff[MAXBUFF];
    int result = 1;
    int operation_result;

    if (argc != 6) {
        fprintf(stderr, "usage: %s <private key file> <public key file> "
                "<input file> <ciphertext/envelope file> <output file>\n",
                argv[0]);
        return 1;
    }
    getTimeSubstr(seedbuff);
    RAND_seed(seedbuff, 8);

    operation_result = generate_rsa_key(&rsaPriv, &rsaPub);
    if (operation_result == 0)
        goto cleanup;
    operation_result = write_key_files(rsaPriv, rsaPub, argv[1], argv[2]);
    if (operation_result == 0)
        goto cleanup;
    operation_result = encryptRSAFile(rsaPub, argv[3], argv[4]);
    if (operation_result == 0)
        goto cleanup;
    operation_result = decryptRSAFile(rsaPriv, argv[4], argv[5]);
    if (operation_result == 0)
        goto cleanup;
    result = 0;

cleanup:
    RSA_free(rsaPriv);
    RSA_free(rsaPub);
    return result;
}

int generate_rsa_key(RSA **rsaPriv, RSA **rsaPub)
{
    *rsaPriv = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    if (*rsaPriv == NULL) {
        fprintf(stderr, "RSA_generate_key failed\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    *rsaPub = RSAPublicKey_dup(*rsaPriv);
    if (*rsaPub == NULL) {
        fprintf(stderr, "RSAPublicKey_dup failed\n");
        ERR_print_errors_fp(stderr);
        RSA_free(*rsaPriv);
        *rsaPriv = NULL;
        return 0;
    }
    return 1;
}

int write_key_files(RSA *rsaPriv, RSA *rsaPub,
                    const char *privKeyFn, const char *pubKeyFn)
{
    FILE *fp = NULL;
    int res;
    int result = 0;

    fp = fopen(privKeyFn, "wb");
    if (fp == NULL) {
        perror(privKeyFn);
        goto cleanup;
    }

    res = PEM_write_RSAPrivateKey(fp, rsaPriv, NULL, NULL, 0, NULL, NULL);
    if (res != 1) {
        fprintf(stderr, "PEM_write_RSAPrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        perror(privKeyFn);
        goto cleanup;
    }
    fp = NULL;
    fp = fopen(pubKeyFn, "wb");
    if (fp == NULL) {
        perror(pubKeyFn);
        goto cleanup;
    }

    res = PEM_write_RSAPublicKey(fp, rsaPub);
    if (res != 1) {
        fprintf(stderr, "PEM_write_RSAPublicKey failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        perror(pubKeyFn);
        goto cleanup;
    }
    fp = NULL;
    result = 1;

cleanup:
    if (fp != NULL && fclose(fp) != 0)
        perror("fclose");
    return result;
}

int encryptRSAFile(RSA *rsaPub, char *pfn, char *cfn)
{
    FILE *fp = NULL;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    size_t bytes_read;
    int csize;
    int output_created = 0;
    int result = 0;

    fp = fopen(pfn, "rb");
    if (fp == NULL) {
        perror(pfn);
        goto cleanup;
    }

    bytes_read = fread(ptext, 1, (size_t)(RSA_size(rsaPub) - 42), fp);
    if (ferror(fp)) {
        perror(pfn);
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        perror(pfn);
        goto cleanup;
    }
    fp = NULL;

    csize = RSA_public_encrypt((int)bytes_read, ptext, ctext, rsaPub,
                               RSA_PKCS1_OAEP_PADDING);
    if (csize <= 0) {
        fprintf(stderr, "RSA_public_encrypt failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    fp = fopen(cfn, "wb");
    if (fp == NULL) {
        perror(cfn);
        goto cleanup;
    }
    output_created = 1;

    if (fwrite(ctext, 1, (size_t)csize, fp) != (size_t)csize) {
        perror(cfn);
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        perror(cfn);
        goto cleanup;
    }
    fp = NULL;
    result = 1;

cleanup:
    if (fp != NULL && fclose(fp) != 0)
        perror("fclose");
    if (!result && output_created)
        remove(cfn);
    return result;
}

int decryptRSAFile(RSA *rsaPriv, char *cfn, char *dfn)
{
    FILE *fp = NULL;
    unsigned char ctext[MAXBUFF];
    unsigned char dtext[MAXBUFF];
    size_t bytes_read;
    int dsize;
    int output_created = 0;
    int result = 0;

    fp = fopen(cfn, "rb");
    if (fp == NULL) {
        perror(cfn);
        goto cleanup;
    }

    bytes_read = fread(ctext, 1, sizeof(ctext), fp);
    if (ferror(fp)) {
        perror(cfn);
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        perror(cfn);
        goto cleanup;
    }
    fp = NULL;

    dsize = RSA_private_decrypt((int)bytes_read, ctext, dtext, rsaPriv,
                                RSA_PKCS1_OAEP_PADDING);
    if (dsize < 0) {
        fprintf(stderr, "RSA_private_decrypt failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    fp = fopen(dfn, "wb");
    if (fp == NULL) {
        perror(dfn);
        goto cleanup;
    }
    output_created = 1;

    if (fwrite(dtext, 1, (size_t)dsize, fp) != (size_t)dsize) {
        perror(dfn);
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        perror(dfn);
        goto cleanup;
    }
    fp = NULL;
    result = 1;

cleanup:
    if (fp != NULL && fclose(fp) != 0)
        perror("fclose");
    if (!result && output_created)
        remove(dfn);
    return result;
}

void getTimeSubstr(unsigned char *buff)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    sprintf((char *)buff, "%ld%06ld",
            (long)tv.tv_sec,
            (long)tv.tv_usec);
}
