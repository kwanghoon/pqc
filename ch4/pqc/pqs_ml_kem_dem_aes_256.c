/*
 * pqs_ml_kem_dem_aes_256.c
 *
 * OpenSSL 3.5.8 example of a post-quantum key-encapsulation + data-
 * encapsulation workflow.
 *
 * Flow:
 *   1) Generate an ML-KEM-768 key pair.
 *   2) Encapsulate a shared secret for the recipient public key.
 *   3) Decapsulate with the private key to recover the shared secret.
 *   4) Use the recovered secret as the AES-256-CBC key for file/message
 *      encryption and decryption.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define DEM_KEY_LEN 32
#define DEM_IV_LEN 16
#define MAX_CIPHERTEXT_LEN 2048
#define MAX_MESSAGE_LEN 256

static void print_error_and_abort(const char *label)
{
    fprintf(stderr, "%s\n", label);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *enc_ctx = NULL;
    EVP_PKEY_CTX *dec_ctx = NULL;
    EVP_CIPHER_CTX *enc_aes = NULL;
    EVP_CIPHER_CTX *dec_aes = NULL;

    unsigned char ciphertext[MAX_CIPHERTEXT_LEN] = {0};
    size_t ciphertext_len = sizeof(ciphertext);
    unsigned char shared_secret[64] = {0};
    size_t shared_secret_len = sizeof(shared_secret);
    unsigned char recovered_secret[64] = {0};
    size_t recovered_secret_len = sizeof(recovered_secret);

    const unsigned char plaintext[] = "PQC KEM + DEM demo using ML-KEM-768 and AES-256-CBC";
    unsigned char encrypted[MAX_MESSAGE_LEN] = {0};
    unsigned char decrypted[MAX_MESSAGE_LEN] = {0};
    int out_len = 0;
    int final_len = 0;
    int ret;
    size_t msg_len = strlen((const char *)plaintext);
    size_t encrypted_len = 0;

    /* 1) Generate an ML-KEM-768 key pair. */
    gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (gen_ctx == NULL)
        print_error_and_abort("EVP_PKEY_CTX_new_from_name failed");

    ret = EVP_PKEY_keygen_init(gen_ctx);
    if (ret <= 0)
        print_error_and_abort("EVP_PKEY_keygen_init failed");

    ret = EVP_PKEY_generate(gen_ctx, &pkey);
    if (ret <= 0)
        print_error_and_abort("EVP_PKEY_generate failed");

    /* 2) Encapsulate a session secret using the recipient public key. */
    enc_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (enc_ctx == NULL)
        print_error_and_abort("EVP_PKEY_CTX_new_from_pkey (encapsulate) failed");

    ret = EVP_PKEY_encapsulate_init(enc_ctx);
    if (ret <= 0)
        print_error_and_abort("EVP_PKEY_encapsulate_init failed");

    ret = EVP_PKEY_encapsulate(enc_ctx, ciphertext, &ciphertext_len, shared_secret, &shared_secret_len);
    if (ret <= 0)
        print_error_and_abort("EVP_PKEY_encapsulate failed");

    /* 3) Decapsulate with the private key to recover the same shared secret. */
    dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (dec_ctx == NULL)
        print_error_and_abort("EVP_PKEY_CTX_new_from_pkey (decapsulate) failed");

    ret = EVP_PKEY_decapsulate_init(dec_ctx);
    if (ret <= 0)
        print_error_and_abort("EVP_PKEY_decapsulate_init failed");

    ret = EVP_PKEY_decapsulate(dec_ctx, recovered_secret, &recovered_secret_len, ciphertext, ciphertext_len);
    if (ret <= 0)
        print_error_and_abort("EVP_PKEY_decapsulate failed");

    if (shared_secret_len != recovered_secret_len ||
        memcmp(shared_secret, recovered_secret, shared_secret_len) != 0) {
        fprintf(stderr, "KEM shared secret mismatch\n");
        return 1;
    }

    /* 4) Use the recovered secret as an AES-256 key for DEM encryption. */
    enc_aes = EVP_CIPHER_CTX_new();
    if (enc_aes == NULL)
        print_error_and_abort("EVP_CIPHER_CTX_new (encrypt) failed");

    unsigned char keybuf[DEM_KEY_LEN];
    unsigned char iv[DEM_IV_LEN] = {0};
    memcpy(keybuf, recovered_secret, DEM_KEY_LEN);

    ret = EVP_EncryptInit_ex(enc_aes, EVP_aes_256_cbc(), NULL, keybuf, iv);
    if (ret <= 0)
        print_error_and_abort("EVP_EncryptInit_ex failed");

    ret = EVP_EncryptUpdate(enc_aes, encrypted, &out_len, plaintext, (int)msg_len);
    if (ret <= 0)
        print_error_and_abort("EVP_EncryptUpdate failed");

    ret = EVP_EncryptFinal_ex(enc_aes, encrypted + out_len, &final_len);
    if (ret <= 0)
        print_error_and_abort("EVP_EncryptFinal_ex failed");

    encrypted_len = (size_t)out_len + (size_t)final_len;

    dec_aes = EVP_CIPHER_CTX_new();
    if (dec_aes == NULL)
        print_error_and_abort("EVP_CIPHER_CTX_new (decrypt) failed");

    ret = EVP_DecryptInit_ex(dec_aes, EVP_aes_256_cbc(), NULL, keybuf, iv);
    if (ret <= 0)
        print_error_and_abort("EVP_DecryptInit_ex failed");

    ret = EVP_DecryptUpdate(dec_aes, decrypted, &out_len, encrypted, (int)encrypted_len);
    if (ret <= 0)
        print_error_and_abort("EVP_DecryptUpdate failed");

    ret = EVP_DecryptFinal_ex(dec_aes, decrypted + out_len, &final_len);
    if (ret <= 0)
        print_error_and_abort("EVP_DecryptFinal_ex failed");

    if (strncmp((const char *)plaintext, (const char *)decrypted, msg_len) != 0) {
        fprintf(stderr, "DEM round-trip failed\n");
        return 1;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_CTX_free(dec_ctx);
    EVP_CIPHER_CTX_free(enc_aes);
    EVP_CIPHER_CTX_free(dec_aes);

    return 0;
}
