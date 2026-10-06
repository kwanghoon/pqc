/*
 * pqc_mlkem_file.c
 *
 * Demonstrate file encryption with an ML-KEM-768 encapsulated key and
 * AES-256-GCM. The generated key pair is temporary and is used to decrypt
 * the envelope during the same run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEM_CIPHERTEXT_MAX 2048
#define KEM_SECRET_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define FILE_CHUNK_LEN 4096

static int report_openssl_error(const char *operation)
{
    fprintf(stderr, "%s failed\n", operation);
    ERR_print_errors_fp(stderr);
    return 0;
}

static int write_bytes(FILE *file, const unsigned char *data, size_t length)
{
    if (fwrite(data, 1, length, file) != length) {
        perror("fwrite");
        return 0;
    }
    return 1;
}

static int write_u32(FILE *file, unsigned int value)
{
    unsigned char encoded[4] = {
        (unsigned char)(value >> 24),
        (unsigned char)(value >> 16),
        (unsigned char)(value >> 8),
        (unsigned char)value
    };

    return write_bytes(file, encoded, sizeof(encoded));
}

static int read_u32(FILE *file, unsigned int *value)
{
    unsigned char encoded[4];

    if (fread(encoded, 1, sizeof(encoded), file) != sizeof(encoded)) {
        fprintf(stderr, "Could not read envelope header\n");
        return 0;
    }
    *value = ((unsigned int)encoded[0] << 24) |
             ((unsigned int)encoded[1] << 16) |
             ((unsigned int)encoded[2] << 8) |
             (unsigned int)encoded[3];
    return 1;
}

static EVP_PKEY *generate_mlkem_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *key = NULL;
    int result;

    if (ctx == NULL) {
        report_openssl_error("EVP_PKEY_CTX_new_from_name");
        return NULL;
    }
    result = EVP_PKEY_keygen_init(ctx);
    if (result <= 0) {
        report_openssl_error("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    result = EVP_PKEY_generate(ctx, &key);
    if (result <= 0) {
        report_openssl_error("EVP_PKEY_generate");
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int encrypt_file(EVP_PKEY *key, const char *input_path,
                        const char *envelope_path)
{
    static const unsigned char magic[] = {'P', 'Q', 'M', '1'};
    EVP_PKEY_CTX *kem_ctx = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    FILE *input = NULL;
    FILE *envelope = NULL;
    unsigned char kem_ciphertext[KEM_CIPHERTEXT_MAX];
    unsigned char shared_secret[64];
    unsigned char nonce[GCM_NONCE_LEN];
    unsigned char input_buffer[FILE_CHUNK_LEN];
    unsigned char output_buffer[FILE_CHUNK_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[GCM_TAG_LEN];
    size_t kem_ciphertext_len = sizeof(kem_ciphertext);
    size_t shared_secret_len = sizeof(shared_secret);
    int output_len;
    int final_len;
    int result;
    int success = 0;

    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (kem_ctx == NULL) {
        report_openssl_error("EVP_PKEY_CTX_new_from_pkey");
        goto cleanup;
    }
    result = EVP_PKEY_encapsulate_init(kem_ctx, NULL);
    if (result <= 0) {
        report_openssl_error("EVP_PKEY_encapsulate_init");
        goto cleanup;
    }
    result = EVP_PKEY_encapsulate(kem_ctx, kem_ciphertext,
                                  &kem_ciphertext_len, shared_secret,
                                  &shared_secret_len);
    if (result <= 0) {
        report_openssl_error("EVP_PKEY_encapsulate");
        goto cleanup;
    }
    if (kem_ciphertext_len > sizeof(kem_ciphertext) ||
        shared_secret_len != KEM_SECRET_LEN) {
        fprintf(stderr, "Unexpected ML-KEM-768 output size\n");
        goto cleanup;
    }
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        report_openssl_error("RAND_bytes");
        goto cleanup;
    }

    input = fopen(input_path, "rb");
    if (input == NULL) {
        perror(input_path);
        goto cleanup;
    }
    envelope = fopen(envelope_path, "wb");
    if (envelope == NULL) {
        perror(envelope_path);
        goto cleanup;
    }
    if (!write_bytes(envelope, magic, sizeof(magic)) ||
        !write_u32(envelope, (unsigned int)kem_ciphertext_len) ||
        !write_bytes(envelope, kem_ciphertext, kem_ciphertext_len) ||
        !write_bytes(envelope, nonce, sizeof(nonce))) {
        goto cleanup;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (cipher_ctx == NULL) {
        report_openssl_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    result = EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL,
                                shared_secret, nonce);
    if (result != 1) {
        report_openssl_error("EVP_EncryptInit_ex");
        goto cleanup;
    }

    while (1) {
        size_t bytes_read = fread(input_buffer, 1, sizeof(input_buffer), input);

        if (bytes_read > 0) {
            result = EVP_EncryptUpdate(cipher_ctx, output_buffer, &output_len,
                                       input_buffer, (int)bytes_read);
            if (result != 1) {
                report_openssl_error("EVP_EncryptUpdate");
                goto cleanup;
            }
            if (!write_bytes(envelope, output_buffer, (size_t)output_len))
                goto cleanup;
        }
        if (bytes_read < sizeof(input_buffer)) {
            if (ferror(input)) {
                perror(input_path);
                goto cleanup;
            }
            break;
        }
    }

    result = EVP_EncryptFinal_ex(cipher_ctx, output_buffer, &final_len);
    if (result != 1) {
        report_openssl_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    if (!write_bytes(envelope, output_buffer, (size_t)final_len))
        goto cleanup;
    result = EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG,
                                 sizeof(tag), tag);
    if (result != 1) {
        report_openssl_error("EVP_CTRL_GCM_GET_TAG");
        goto cleanup;
    }
    if (!write_bytes(envelope, tag, sizeof(tag)))
        goto cleanup;
    success = 1;

cleanup:
    if (input != NULL && fclose(input) != 0) {
        perror(input_path);
        success = 0;
    }
    if (envelope != NULL && fclose(envelope) != 0) {
        perror(envelope_path);
        success = 0;
    }
    EVP_PKEY_CTX_free(kem_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx);
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    if (!success)
        remove(envelope_path);
    return success;
}

static int decrypt_file(EVP_PKEY *key, const char *envelope_path,
                        const char *output_path)
{
    static const unsigned char expected_magic[] = {'P', 'Q', 'M', '1'};
    EVP_PKEY_CTX *kem_ctx = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    FILE *envelope = NULL;
    FILE *output = NULL;
    unsigned char magic[sizeof(expected_magic)];
    unsigned char kem_ciphertext[KEM_CIPHERTEXT_MAX];
    unsigned char shared_secret[64];
    unsigned char nonce[GCM_NONCE_LEN];
    unsigned char tag[GCM_TAG_LEN];
    unsigned char input_buffer[FILE_CHUNK_LEN];
    unsigned char output_buffer[FILE_CHUNK_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned int kem_ciphertext_len;
    size_t shared_secret_len = sizeof(shared_secret);
    long file_len;
    long ciphertext_len;
    long remaining;
    int output_len;
    int final_len;
    int result;
    int output_created = 0;
    int success = 0;

    envelope = fopen(envelope_path, "rb");
    if (envelope == NULL) {
        perror(envelope_path);
        goto cleanup;
    }
    if (fread(magic, 1, sizeof(magic), envelope) != sizeof(magic) ||
        memcmp(magic, expected_magic, sizeof(magic)) != 0) {
        fprintf(stderr, "Invalid envelope format\n");
        goto cleanup;
    }
    if (!read_u32(envelope, &kem_ciphertext_len) ||
        kem_ciphertext_len == 0 ||
        kem_ciphertext_len > sizeof(kem_ciphertext)) {
        fprintf(stderr, "Invalid ML-KEM ciphertext length\n");
        goto cleanup;
    }
    if (fread(kem_ciphertext, 1, kem_ciphertext_len, envelope) !=
        kem_ciphertext_len ||
        fread(nonce, 1, sizeof(nonce), envelope) != sizeof(nonce)) {
        fprintf(stderr, "Truncated envelope header\n");
        goto cleanup;
    }

    if (fseek(envelope, 0, SEEK_END) != 0 || (file_len = ftell(envelope)) < 0) {
        perror(envelope_path);
        goto cleanup;
    }
    ciphertext_len = file_len -
        (long)(sizeof(magic) + 4 + kem_ciphertext_len + sizeof(nonce) +
               sizeof(tag));
    if (ciphertext_len < 0) {
        fprintf(stderr, "Truncated envelope\n");
        goto cleanup;
    }
    if (fseek(envelope,
              (long)(sizeof(magic) + 4 + kem_ciphertext_len + sizeof(nonce)),
              SEEK_SET) != 0) {
        perror(envelope_path);
        goto cleanup;
    }

    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (kem_ctx == NULL) {
        report_openssl_error("EVP_PKEY_CTX_new_from_pkey");
        goto cleanup;
    }
    result = EVP_PKEY_decapsulate_init(kem_ctx, NULL);
    if (result <= 0) {
        report_openssl_error("EVP_PKEY_decapsulate_init");
        goto cleanup;
    }
    result = EVP_PKEY_decapsulate(kem_ctx, shared_secret,
                                  &shared_secret_len, kem_ciphertext,
                                  kem_ciphertext_len);
    if (result <= 0) {
        report_openssl_error("EVP_PKEY_decapsulate");
        goto cleanup;
    }
    if (shared_secret_len != KEM_SECRET_LEN) {
        fprintf(stderr, "Unexpected ML-KEM shared-secret length\n");
        goto cleanup;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (cipher_ctx == NULL) {
        report_openssl_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    result = EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL,
                                shared_secret, nonce);
    if (result != 1) {
        report_openssl_error("EVP_DecryptInit_ex");
        goto cleanup;
    }

    output = fopen(output_path, "wb");
    if (output == NULL) {
        perror(output_path);
        goto cleanup;
    }
    output_created = 1;
    remaining = ciphertext_len;
    while (remaining > 0) {
        size_t bytes_to_read = remaining < (long)sizeof(input_buffer)
            ? (size_t)remaining : sizeof(input_buffer);
        size_t bytes_read = fread(input_buffer, 1, bytes_to_read, envelope);

        if (bytes_read != bytes_to_read) {
            fprintf(stderr, "Could not read envelope ciphertext\n");
            goto cleanup;
        }
        result = EVP_DecryptUpdate(cipher_ctx, output_buffer, &output_len,
                                   input_buffer, (int)bytes_read);
        if (result != 1) {
            report_openssl_error("EVP_DecryptUpdate");
            goto cleanup;
        }
        if (!write_bytes(output, output_buffer, (size_t)output_len))
            goto cleanup;
        remaining -= (long)bytes_read;
    }

    if (fread(tag, 1, sizeof(tag), envelope) != sizeof(tag)) {
        fprintf(stderr, "Could not read envelope authentication tag\n");
        goto cleanup;
    }
    result = EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG,
                                 sizeof(tag), tag);
    if (result != 1) {
        report_openssl_error("EVP_CTRL_GCM_SET_TAG");
        goto cleanup;
    }
    result = EVP_DecryptFinal_ex(cipher_ctx, output_buffer, &final_len);
    if (result != 1) {
        fprintf(stderr, "Envelope authentication failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (!write_bytes(output, output_buffer, (size_t)final_len))
        goto cleanup;
    success = 1;

cleanup:
    if (output != NULL && fclose(output) != 0) {
        perror(output_path);
        success = 0;
    }
    if (envelope != NULL && fclose(envelope) != 0) {
        perror(envelope_path);
        success = 0;
    }
    EVP_PKEY_CTX_free(kem_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx);
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    if (!success && output_created)
        remove(output_path);
    return success;
}

int main(int argc, char *argv[])
{
    EVP_PKEY *key;
    int result = EXIT_FAILURE;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <input file> <envelope file> <output file>\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    key = generate_mlkem_key();
    if (key == NULL)
        return EXIT_FAILURE;
    if (!encrypt_file(key, argv[1], argv[2]))
        goto cleanup;
    if (!decrypt_file(key, argv[2], argv[3]))
        goto cleanup;
    result = EXIT_SUCCESS;

cleanup:
    EVP_PKEY_free(key);
    return result;
}
