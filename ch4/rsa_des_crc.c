/*
 - ch4
 - rsa_des_crc.c
 - RSA와 DES-CRC를 이용한 전자 봉투를 만들기
*/

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define MAXBUFF 1024

void getTimeSubstr(unsigned char *buff)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    sprintf((char *)buff, "%ld%06ld",
            (long)tv.tv_sec,
            (long)tv.tv_usec);
}

void makeEnvelope (RSA *rsaPub, char *pfn, char *cfn);
void openEnvelope (RSA *rsaPriv, char *cfn, char *dfn);

RSA *readRSAKeyFile(char *pubKeyFn)
{
    FILE *fp;
    RSA *rsaPub;
    fp = fopen(pubKeyFn, "rb"); assert(fp != NULL);
    rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    assert(rsaPub != NULL);
    fclose(fp);
    return (rsaPub);
}

RSA *readRSAPrivKeyFile(char *privKeyFn)
{
    FILE *fp;
    RSA *rsaPriv;
    fp = fopen(privKeyFn, "rb"); assert(fp != NULL);
    rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    assert(rsaPriv != NULL);
    fclose(fp);
    return (rsaPriv);
}

int main(int argc, char *argv[])
{
    RSA *rsaPub, *rsaPriv;
    assert (argc == 6);
    rsaPub = readRSAKeyFile(argv[1]);
    rsaPriv = readRSAPrivKeyFile(argv[2]);
    makeEnvelope(rsaPub, argv[3], argv[4]);
    openEnvelope(rsaPriv, argv[4], argv[5]);
    RSA_free(rsaPub);
    RSA_free(rsaPriv);
    return(0);
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

void makeEnvelope (RSA *rsaPub, char *pfn, char *cfn)
{
    FILE *ifp, *ofp;
    unsigned char ptext [MAXBUFF];
    unsigned char ctext [MAXBUFF];
    int psize = 16, csize;
    unsigned char seedbuff [MAXBUFF];
    unsigned char mykey [16] = "\0"; // EVP_MAX_KEY_LENGTH
    unsigned char iv [EVP_MAX_IV_LENGTH] = "\0";
    EVP_CIPHER_CTX ctx;
    int res;

    getTimeSubstr(seedbuff);
    RAND_seed (seedbuff, 8);
    RAND_bytes (mykey, sizeof(mykey));  // EVP_MAX_KEY_LENGTH
    RAND_bytes (iv, EVP_MAX_IV_LENGTH);
    csize = RSA_public_encrypt(psize, mykey, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
    ofp = fopen(cfn, "wb"); assert(ofp);
    fwrite(&csize, 1, sizeof(int), ofp);
    fwrite(ctext, 1, csize, ofp);
    fwrite(iv, 1, sizeof(iv), ofp); // iv 저장을 추가
    EVP_CIPHER_CTX_init(&ctx);
    ifp = fopen(pfn, "rb"); assert(ifp);
    // EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv, DES_ENCRYPT);
    psize = fread(ptext, 1, MAXBUFF-8, ifp);
    while (psize > 0){
        res = EVP_CipherUpdate(&ctx, ctext, &csize, ptext, psize); assert(res);
        fwrite(ctext, 1, csize, ofp);
        psize = fread(ptext, 1, MAXBUFF-8, ifp);
    }
    res = EVP_CipherFinal_ex(&ctx, ctext, &csize);
    assert(res);
    fwrite(ctext, 1, csize, ofp);
    fclose(ifp);
    fclose(ofp);
}

// openEnvelope
//
// makeEnvelope로 만든 봉투(cfn)를 rsaPriv로 열어
// 평문을 dfn에 기록한다.

void openEnvelope (RSA *rsaPriv, char *cfn, char *dfn)
{
    FILE *ifp, *ofp;
    unsigned char ptext [MAXBUFF];
    unsigned char ctext [MAXBUFF];
    int csize, psize;
    unsigned char mykey [16] = "\0";
    unsigned char iv [EVP_MAX_IV_LENGTH] = "\0";
    EVP_CIPHER_CTX ctx;
    int res;

    ifp = fopen(cfn, "rb"); assert(ifp);
    fread(&csize, 1, sizeof(int), ifp);
    fread(ctext, 1, csize, ifp);
    res = RSA_private_decrypt(csize, ctext, mykey, rsaPriv, RSA_PKCS1_OAEP_PADDING);
    assert(res == sizeof(mykey));
    fread(iv, 1, sizeof(iv), ifp);

    ofp = fopen(dfn, "wb"); assert(ofp);
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv, DES_DECRYPT);
    csize = fread(ctext, 1, MAXBUFF, ifp);
    while (csize > 0){
        res = EVP_CipherUpdate(&ctx, ptext, &psize, ctext, csize); assert(res);
        fwrite(ptext, 1, psize, ofp);
        csize = fread(ctext, 1, MAXBUFF, ifp);
    }
    res = EVP_CipherFinal_ex(&ctx, ptext, &psize);
    assert(res);
    fwrite(ptext, 1, psize, ofp);
    fclose(ifp);
    fclose(ofp);
}