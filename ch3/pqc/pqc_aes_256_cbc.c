/*
 * pqc_aes_256_cbc.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch3/aes_128_cbc.c.
 * PQC transition target: stronger 256-bit symmetric key while preserving the
 * original file encryption/decryption flow.
 */

#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAXBUFF 1024

void AES_encryption(const char plainfn[], const char cipherfn[], const unsigned char key[], const unsigned char iv[]);
void AES_decryption(const char cipherfn[], const char plainfn[], const unsigned char key[], const unsigned char iv[]);

static void getTimeSubstr(unsigned char *buf, size_t len)
{
    struct timeval atime;
    gettimeofday(&atime, NULL);

    if (len < 8) {
        return;
    }

    memcpy(buf, &(atime.tv_sec), 4);
    memcpy(buf + 4, &(atime.tv_usec), 4);
}

int main(int argc, char *argv[])
{
    unsigned char seedbuff[MAXBUFF];
    unsigned char mykey[32] = {0};
    unsigned char iv[16] = {0};

    assert(argc == 4);
    getTimeSubstr(seedbuff, sizeof(seedbuff));
    RAND_seed(seedbuff, 8);

    RAND_bytes(mykey, 32);
    RAND_bytes(iv, 16);

    AES_encryption(argv[1], argv[2], mykey, iv);
    AES_decryption(argv[2], argv[3], mykey, iv);

    return 0;
}

void AES_encryption(const char plainfn[], const char cipherfn[], const unsigned char key[], const unsigned char iv[])
{
    FILE *ptf, *ctf;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int in_len, out_len = 0, ret;
    unsigned char plainbuff[MAXBUFF + 8];
    unsigned char cipherbuff[MAXBUFF + 8];

    ptf = fopen(plainfn, "rb"); assert(ptf);
    ctf = fopen(cipherfn, "wb"); assert(ctf);

    ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    assert(ret == 1);

    while ((in_len = fread(plainbuff, 1, MAXBUFF, ptf)) > 0) {
        ret = EVP_EncryptUpdate(ctx, cipherbuff, &out_len, plainbuff, in_len);
        assert(ret == 1);
        fwrite(cipherbuff, 1, out_len, ctf);
    }

    ret = EVP_EncryptFinal_ex(ctx, cipherbuff, &out_len);
    assert(ret == 1);
    fwrite(cipherbuff, 1, out_len, ctf);

    fclose(ptf);
    fclose(ctf);
    EVP_CIPHER_CTX_free(ctx);
}

void AES_decryption(const char cipherfn[], const char plainfn[], const unsigned char key[], const unsigned char iv[])
{
    FILE *ctf, *ptf;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int in_len, out_len = 0, ret;
    unsigned char plainbuff[MAXBUFF + 8];
    unsigned char cipherbuff[MAXBUFF + 8];

    ctf = fopen(cipherfn, "rb"); assert(ctf);
    ptf = fopen(plainfn, "wb"); assert(ptf);

    ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    assert(ret == 1);

    while ((in_len = fread(cipherbuff, 1, MAXBUFF, ctf)) > 0) {
        ret = EVP_DecryptUpdate(ctx, plainbuff, &out_len, cipherbuff, in_len);
        assert(ret == 1);
        fwrite(plainbuff, 1, out_len, ptf);
    }

    ret = EVP_DecryptFinal_ex(ctx, plainbuff, &out_len);
    assert(ret == 1);
    fwrite(plainbuff, 1, out_len, ptf);

    fclose(ctf);
    fclose(ptf);
    EVP_CIPHER_CTX_free(ctx);
}

