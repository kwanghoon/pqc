/*
 - ch3
 - aes_128_cbc.c
 - AES-128 암호 알고리즘과 CBC 모드를 사용한 파일 암호화 및 복호화
*/
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAXBUFF 1024

void AES_encryption(char plainfn[], char cipherfn[], unsigned char key[], unsigned char iv[]);
void AES_decryption(char cipherfn[], char plainfn[], unsigned char key[], unsigned char iv[]);

void getTimeSubstr(char buff[])
{
    struct timeval atime;
    struct timezone tzone;
    gettimeofday(&atime, &tzone);
    memcpy(buff, &(atime.tv_sec), 4);
    memcpy(buff+4, &(atime.tv_usec), 4);
}

int main(int argc, char *argv[])
{
    unsigned char seedbuff [MAXBUFF];
    unsigned char mykey [16] = "\0"; // EVP_MAX_KEY_LENGTH
    unsigned char iv [16] = "\0"; // EVP_MAX_IV_LENGTH
    FILE *ptf, *ctf, *rptf;

    assert(argc == 4);
    getTimeSubstr(seedbuff);
    RAND_seed (seedbuff, 8);

    RAND_bytes (mykey, 16); // EVP_MAX_KEY_LENGTH
    RAND_bytes (iv, 16); // EVP_MAX_IV_LENGTH
    AES_encryption (argv[1],argv[2],mykey,iv);
    AES_decryption(argv[2],argv[3],mykey,iv);

    return(0);
}

void AES_encryption(char plainfn[], char cipherfn[], unsigned char key[], unsigned char iv[])
{
    FILE *ptf, *ctf;
    EVP_CIPHER_CTX ctx;
    int in_len, out_len = 0, ret;
    unsigned char plainbuff [MAXBUFF+8];
    unsigned char cipherbuff [MAXBUFF+8];

    ptf = fopen(plainfn, "rb"); assert(ptf);
    ctf = fopen(cipherfn, "wb"); assert(ctf);
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_ENCRYPT);
    while((in_len = fread(plainbuff, 1, MAXBUFF, ptf)) > 0 ) {
        ret = EVP_CipherUpdate(&ctx, cipherbuff, &out_len, plainbuff, in_len);
        assert(ret);
        fwrite(cipherbuff, 1, out_len, ctf);
    }
    fclose(ptf);
    ret = EVP_CipherFinal_ex(&ctx, cipherbuff, &out_len);
    assert(ret);
    fwrite(cipherbuff, 1, out_len, ctf);
    fclose(ctf);
    EVP_CIPHER_CTX_cleanup(&ctx);
}

void AES_decryption(char cipherfn[], char plainfn[], unsigned char key[], unsigned char iv[])
{
    FILE *ptf, *ctf;
    EVP_CIPHER_CTX ctx;
    int in_len, out_len=0, ret;
    unsigned char plainbuff [MAXBUFF+8];
    unsigned char cipherbuff [MAXBUFF+8];

    ctf = fopen(cipherfn, "rb"); assert(ctf);
    ptf = fopen(plainfn, "wb"); assert(ptf);
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_DECRYPT);
    while((in_len = fread(cipherbuff, 1, MAXBUFF, ctf)) > 0) {
        ret = EVP_CipherUpdate(&ctx, plainbuff, &out_len,
        cipherbuff, in_len);
        assert(ret);
        fwrite(plainbuff, 1, out_len, ptf);
    }
    fclose(ctf);
    ret = EVP_CipherFinal_ex(&ctx, plainbuff, &out_len);
    assert(ret);
    fwrite(plainbuff, 1, out_len, ptf);
    fclose(ptf);
    EVP_CIPHER_CTX_cleanup(&ctx);
}