/*
 - ch4
 - rsa_des_crc.c
 - RSA와 DES-CRC를 이용한 전자 봉투를 만들기
*/

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define MAXBUFF 1024

void getTimeSubstr(unsigned char *buff);
RSA *readRSAPubKeyFile(char *pubKeyFn);
RSA *readRSAPrivKeyFile(char *privKeyFn);
int makeEnvelope(RSA *rsaPub, char *pfn, char *cfn);
int openEnvelope(RSA *rsaPriv, char *cfn, char *dfn);

int main(int argc, char *argv[])
{
    RSA *rsaPub = NULL, *rsaPriv = NULL;
    int result = 1;
    int operation_result;

    if (argc != 6) {
        fprintf(stderr,
                "usage: %s <public key file> <private key file> "
                "<input file> <envelope file> <output file>\n",
                argv[0]);
        return 1;
    }
    rsaPub = readRSAPubKeyFile(argv[1]);
    if (rsaPub == NULL)
        goto done;
    rsaPriv = readRSAPrivKeyFile(argv[2]);
    if (rsaPriv == NULL)
        goto done;
    operation_result = makeEnvelope(rsaPub, argv[3], argv[4]);
    if (operation_result == 0)
        goto done;
    operation_result = openEnvelope(rsaPriv, argv[4], argv[5]);
    if (operation_result == 0)
        goto done;
    result = 0;

done:
    RSA_free(rsaPub);
    RSA_free(rsaPriv);
    return result;
}

RSA *readRSAPubKeyFile(char *pubKeyFn)
{
    FILE *fp = fopen(pubKeyFn, "rb");
    RSA *rsaPub;

    if (fp == NULL) {
        perror(pubKeyFn);
        return NULL;
    }
    rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    if (rsaPub == NULL) {
        fprintf(stderr, "PEM_read_RSAPublicKey failed\n");
        ERR_print_errors_fp(stderr);
    }
    if (fclose(fp) != 0) {
        perror(pubKeyFn);
        RSA_free(rsaPub);
        return NULL;
    }
    return rsaPub;
}

RSA *readRSAPrivKeyFile(char *privKeyFn)
{
    FILE *fp = fopen(privKeyFn, "rb");
    RSA *rsaPriv;

    if (fp == NULL) {
        perror(privKeyFn);
        return NULL;
    }
    rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (rsaPriv == NULL) {
        fprintf(stderr, "PEM_read_RSAPrivateKey failed\n");
        ERR_print_errors_fp(stderr);
    }
    if (fclose(fp) != 0) {
        perror(privKeyFn);
        RSA_free(rsaPriv);
        return NULL;
    }
    return rsaPriv;
}

// makeEnvelope
// 
// envelope 형식
// +------------------------+
// | RSA ciphertext size    |  sizeof(int)
// +------------------------+
// | RSA(mykey)             |  csize bytes
// +------------------------+
// | IV                     |  8 bytes   (추가)
// +------------------------+
// | 3DES-CBC ciphertext    |  remaining
// +------------------------+

int makeEnvelope(RSA *rsaPub, char *pfn, char *cfn)
{
    FILE *ifp = NULL, *ofp = NULL;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    int psize = 16, csize;
    unsigned char seedbuff[MAXBUFF];
    unsigned char mykey[16] = "\0";
    unsigned char iv[EVP_MAX_IV_LENGTH] = "\0";
    EVP_CIPHER_CTX ctx;
    int res;
    int result = 0;
    int output_created = 0;

    getTimeSubstr(seedbuff);
    RAND_seed(seedbuff, 8);
    if (RAND_bytes(mykey, sizeof(mykey)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    csize = RSA_public_encrypt(psize, mykey, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
    if (csize <= 0) {
        fprintf(stderr, "RSA_public_encrypt failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ifp = fopen(pfn, "rb");
    if (ifp == NULL) {
        perror(pfn);
        goto cleanup;
    }
    ofp = fopen(cfn, "wb");
    if (ofp == NULL) {
        perror(cfn);
        goto cleanup;
    }
    output_created = 1;
    if (fwrite(&csize, 1, sizeof(int), ofp) != sizeof(int) ||
        fwrite(ctext, 1, (size_t)csize, ofp) != (size_t)csize ||
        fwrite(iv, 1, sizeof(iv), ofp) != sizeof(iv)) {
        perror(cfn);
        goto cleanup;
    }
    EVP_CIPHER_CTX_init(&ctx);
    res = EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv,
                            DES_ENCRYPT);
    if (res != 1) {
        fprintf(stderr, "EVP_CipherInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup_ctx;
    }
    while ((psize = (int)fread(ptext, 1, MAXBUFF - 8, ifp)) > 0) {
        res = EVP_CipherUpdate(&ctx, ctext, &csize, ptext, psize);
        if (res != 1) {
            fprintf(stderr, "EVP_CipherUpdate failed\n");
            ERR_print_errors_fp(stderr);
            goto cleanup_ctx;
        }
        if (fwrite(ctext, 1, (size_t)csize, ofp) != (size_t)csize) {
            perror(cfn);
            goto cleanup_ctx;
        }
    }
    if (ferror(ifp)) {
        perror(pfn);
        goto cleanup_ctx;
    }
    res = EVP_CipherFinal_ex(&ctx, ctext, &csize);
    if (res != 1) {
        fprintf(stderr, "EVP_CipherFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup_ctx;
    }
    if (fwrite(ctext, 1, (size_t)csize, ofp) != (size_t)csize) {
        perror(cfn);
        goto cleanup_ctx;
    }
    result = 1;

cleanup_ctx:
    EVP_CIPHER_CTX_cleanup(&ctx);
cleanup:
    if (ifp != NULL && fclose(ifp) != 0) {
        perror(pfn);
        result = 0;
    }
    if (ofp != NULL && fclose(ofp) != 0) {
        perror(cfn);
        result = 0;
    }
    if (!result && output_created)
        remove(cfn);
    return result;
}

// openEnvelope
//
// makeEnvelope로 만든 봉투(cfn)를 rsaPriv로 열어
// 평문을 dfn에 기록한다.

int openEnvelope(RSA *rsaPriv, char *cfn, char *dfn)
{
    FILE *ifp = NULL, *ofp = NULL;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF];
    int csize, psize;
    unsigned char mykey[16] = "\0";
    unsigned char iv[EVP_MAX_IV_LENGTH] = "\0";
    EVP_CIPHER_CTX ctx;
    int res;
    int result = 0;
    int output_created = 0;

    ifp = fopen(cfn, "rb");
    if (ifp == NULL) {
        perror(cfn);
        goto cleanup;
    }
    if (fread(&csize, 1, sizeof(int), ifp) != sizeof(int) ||
        csize <= 0 || csize > (int)sizeof(ctext) ||
        csize != RSA_size(rsaPriv)) {
        fprintf(stderr, "Invalid RSA envelope header\n");
        goto cleanup;
    }
    if (fread(ctext, 1, (size_t)csize, ifp) != (size_t)csize ||
        fread(iv, 1, sizeof(iv), ifp) != sizeof(iv)) {
        fprintf(stderr, "Truncated RSA envelope\n");
        goto cleanup;
    }
    res = RSA_private_decrypt(csize, ctext, mykey, rsaPriv, RSA_PKCS1_OAEP_PADDING);
    if (res != (int)sizeof(mykey)) {
        fprintf(stderr, "RSA_private_decrypt failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ofp = fopen(dfn, "wb");
    if (ofp == NULL) {
        perror(dfn);
        goto cleanup;
    }
    output_created = 1;
    EVP_CIPHER_CTX_init(&ctx);
    res = EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv,
                            DES_DECRYPT);
    if (res != 1) {
        fprintf(stderr, "EVP_CipherInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup_ctx;
    }
    while ((csize = (int)fread(ctext, 1, MAXBUFF, ifp)) > 0) {
        res = EVP_CipherUpdate(&ctx, ptext, &psize, ctext, csize);
        if (res != 1) {
            fprintf(stderr, "EVP_CipherUpdate failed\n");
            ERR_print_errors_fp(stderr);
            goto cleanup_ctx;
        }
        if (fwrite(ptext, 1, (size_t)psize, ofp) != (size_t)psize) {
            perror(dfn);
            goto cleanup_ctx;
        }
    }
    if (ferror(ifp)) {
        perror(cfn);
        goto cleanup_ctx;
    }
    res = EVP_CipherFinal_ex(&ctx, ptext, &psize);
    if (res != 1) {
        fprintf(stderr, "EVP_CipherFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup_ctx;
    }
    if (fwrite(ptext, 1, (size_t)psize, ofp) != (size_t)psize) {
        perror(dfn);
        goto cleanup_ctx;
    }
    result = 1;

cleanup_ctx:
    EVP_CIPHER_CTX_cleanup(&ctx);
cleanup:
    if (ifp != NULL && fclose(ifp) != 0) {
        perror(cfn);
        result = 0;
    }
    if (ofp != NULL && fclose(ofp) != 0) {
        perror(dfn);
        result = 0;
    }
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