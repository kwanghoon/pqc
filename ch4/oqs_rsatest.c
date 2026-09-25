#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAXBUFF 1024
#define IV_LEN 12
#define TAG_LEN 16

void makePQCKeyFile(OQS_KEM *kem,
                    unsigned char **public_key,
                    unsigned char **secret_key,
                    char *secretKeyFn,
                    char *publicKeyFn);

void encryptPQCFile(OQS_KEM *kem,
                    unsigned char *public_key,
                    char *pfn,
                    char *cfn);

void decryptPQCFile(OQS_KEM *kem,
                    unsigned char *secret_key,
                    char *cfn,
                    char *dfn);

int main(int argc, char *argv[])
{
    OQS_KEM *kem = NULL;
    unsigned char *public_key = NULL;
    unsigned char *secret_key = NULL;

    assert(argc == 6);

    OQS_init();

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    assert(kem);

    makePQCKeyFile(kem, &public_key, &secret_key, argv[1], argv[2]);

    encryptPQCFile(kem, public_key, argv[3], argv[4]);

    decryptPQCFile(kem, secret_key, argv[4], argv[5]);

    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    OQS_MEM_insecure_free(public_key);

    OQS_KEM_free(kem);
    OQS_destroy();

    return 0;
}

void makePQCKeyFile(OQS_KEM *kem,
                    unsigned char **public_key,
                    unsigned char **secret_key,
                    char *secretKeyFn,
                    char *publicKeyFn)
{
    FILE *fp;
    OQS_STATUS res;

    *public_key =
        OQS_MEM_malloc(kem->length_public_key);

    *secret_key =
        OQS_MEM_malloc(kem->length_secret_key);

    assert(*public_key);
    assert(*secret_key);

    res = OQS_KEM_keypair(kem,
                          *public_key,
                          *secret_key);
    assert(res == OQS_SUCCESS);

    fp = fopen(secretKeyFn, "wb");
    assert(fp);

    fwrite(*secret_key,
           1,
           kem->length_secret_key,
           fp);

    fclose(fp);

    fp = fopen(publicKeyFn, "wb");
    assert(fp);

    fwrite(*public_key,
           1,
           kem->length_public_key,
           fp);

    fclose(fp);
}

void encryptPQCFile(OQS_KEM *kem,
                    unsigned char *public_key,
                    char *pfn,
                    char *cfn)
{
    FILE *fp;
    unsigned char ptext[MAXBUFF];
    unsigned char ctext[MAXBUFF + 16];

    unsigned char *kem_ciphertext;
    unsigned char *shared_secret;

    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];

    EVP_CIPHER_CTX *ctx;

    int psize;
    int len;
    int csize;

    OQS_STATUS res;

    kem_ciphertext =
        OQS_MEM_malloc(kem->length_ciphertext);

    shared_secret =
        OQS_MEM_malloc(kem->length_shared_secret);

    assert(kem_ciphertext);
    assert(shared_secret);

    /*
     * ML-KEM encapsulation:
     *
     * public key
     *     |
     *     +--> KEM ciphertext
     *     |
     *     +--> shared secret
     */
    res = OQS_KEM_encaps(kem,
                         kem_ciphertext,
                         shared_secret,
                         public_key);

    assert(res == OQS_SUCCESS);

    /*
     * Random IV for AES-256-GCM
     */
    assert(RAND_bytes(iv, IV_LEN) == 1);

    /*
     * Read plaintext.
     * This example handles at most MAXBUFF bytes.
     */
    fp = fopen(pfn, "rb");
    assert(fp);

    psize = fread(ptext, 1, MAXBUFF, fp);
    fclose(fp);

    /*
     * Encrypt plaintext using the
     * ML-KEM shared secret as AES key.
     */
    ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    assert(EVP_EncryptInit_ex(ctx,
                              EVP_aes_256_gcm(),
                              NULL,
                              NULL,
                              NULL));

    assert(EVP_CIPHER_CTX_ctrl(ctx,
                               EVP_CTRL_GCM_SET_IVLEN,
                               IV_LEN,
                               NULL));

    assert(EVP_EncryptInit_ex(ctx,
                              NULL,
                              NULL,
                              shared_secret,
                              iv));

    assert(EVP_EncryptUpdate(ctx,
                             ctext,
                             &len,
                             ptext,
                             psize));

    csize = len;

    assert(EVP_EncryptFinal_ex(ctx,
                               ctext + csize,
                               &len));

    csize += len;

    assert(EVP_CIPHER_CTX_ctrl(ctx,
                               EVP_CTRL_GCM_GET_TAG,
                               TAG_LEN,
                               tag));

    EVP_CIPHER_CTX_free(ctx);

    /*
     * Output format:
     *
     * KEM ciphertext || IV || TAG || AES ciphertext
     */
    fp = fopen(cfn, "wb");
    assert(fp);

    fwrite(kem_ciphertext,
           1,
           kem->length_ciphertext,
           fp);

    fwrite(iv, 1, IV_LEN, fp);
    fwrite(tag, 1, TAG_LEN, fp);
    fwrite(ctext, 1, csize, fp);

    fclose(fp);

    OQS_MEM_secure_free(shared_secret,
                        kem->length_shared_secret);

    OQS_MEM_insecure_free(kem_ciphertext);
}

void decryptPQCFile(OQS_KEM *kem,
                    unsigned char *secret_key,
                    char *cfn,
                    char *dfn)
{
    FILE *fp;

    unsigned char *kem_ciphertext;
    unsigned char *shared_secret;

    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];

    unsigned char ctext[MAXBUFF + 16];
    unsigned char dtext[MAXBUFF + 16];

    EVP_CIPHER_CTX *ctx;

    int csize;
    int dsize;
    int len;

    OQS_STATUS res;

    kem_ciphertext =
        OQS_MEM_malloc(kem->length_ciphertext);

    shared_secret =
        OQS_MEM_malloc(kem->length_shared_secret);

    assert(kem_ciphertext);
    assert(shared_secret);

    /*
     * Read:
     * KEM ciphertext || IV || TAG || AES ciphertext
     */
    fp = fopen(cfn, "rb");
    assert(fp);

    fread(kem_ciphertext,
          1,
          kem->length_ciphertext,
          fp);

    fread(iv, 1, IV_LEN, fp);
    fread(tag, 1, TAG_LEN, fp);

    csize = fread(ctext,
                  1,
                  MAXBUFF + 16,
                  fp);

    fclose(fp);

    /*
     * ML-KEM decapsulation.
     *
     * secret key + KEM ciphertext
     *             |
     *             v
     *       shared secret
     */
    res = OQS_KEM_decaps(kem,
                         shared_secret,
                         kem_ciphertext,
                         secret_key);

    assert(res == OQS_SUCCESS);

    /*
     * AES-256-GCM decryption
     */
    ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    assert(EVP_DecryptInit_ex(ctx,
                              EVP_aes_256_gcm(),
                              NULL,
                              NULL,
                              NULL));

    assert(EVP_CIPHER_CTX_ctrl(ctx,
                               EVP_CTRL_GCM_SET_IVLEN,
                               IV_LEN,
                               NULL));

    assert(EVP_DecryptInit_ex(ctx,
                              NULL,
                              NULL,
                              shared_secret,
                              iv));

    assert(EVP_DecryptUpdate(ctx,
                             dtext,
                             &len,
                             ctext,
                             csize));

    dsize = len;

    assert(EVP_CIPHER_CTX_ctrl(ctx,
                               EVP_CTRL_GCM_SET_TAG,
                               TAG_LEN,
                               tag));

    assert(EVP_DecryptFinal_ex(ctx,
                               dtext + dsize,
                               &len) > 0);

    dsize += len;

    EVP_CIPHER_CTX_free(ctx);

    fp = fopen(dfn, "wb");
    assert(fp);

    fwrite(dtext, 1, dsize, fp);

    fclose(fp);

    OQS_MEM_secure_free(shared_secret,
                        kem->length_shared_secret);

    OQS_MEM_insecure_free(kem_ciphertext);
}