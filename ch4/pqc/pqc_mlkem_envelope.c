/*
 * pqc_mlkem_envelope.c
 *
 * ML-KEM-768 and AES-256-GCM digital envelope.
 *
 * Usage:
 *   pqc_mlkem_envelope <pub.pem> <priv.pem> <plain> <envelope> <decrypted>
 *
 * If <pub.pem> or <priv.pem> does not exist, a new ML-KEM-768 key pair is
 * generated and written to both files.
 *
 * Envelope format:
 *   magic "PQE1"            4 bytes
 *   KEM ciphertext length   4 bytes, big-endian
 *   ML-KEM ciphertext       length bytes
 *   AES-GCM nonce           12 bytes
 *   AES-GCM ciphertext      remaining bytes
 *   AES-GCM tag             16 bytes
 *
 * The header (everything before the AES-GCM ciphertext) is authenticated as
 * additional authenticated data.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define KEM_NAME "ML-KEM-768"
#define KEM_CT_MAX 2048
#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16
#define CHUNK_LEN 4096
#define MAGIC_LEN 4
#define HEADER_MAX (MAGIC_LEN + 4 + KEM_CT_MAX + NONCE_LEN)

static const unsigned char MAGIC[MAGIC_LEN] = {'P', 'Q', 'E', '1'};

static int fail_ssl(const char *what)
{
    fprintf(stderr, "%s failed\n", what);
    ERR_print_errors_fp(stderr);
    return 0;
}

static int write_all(FILE *fp, const unsigned char *buf, size_t len)
{
    if (len > 0 && fwrite(buf, 1, len, fp) != len) {
        perror("fwrite");
        return 0;
    }
    return 1;
}

static int file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static FILE *open_private_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE *fp;

    if (fd < 0) {
        perror(path);
        return NULL;
    }
    fp = fdopen(fd, "wb");
    if (fp == NULL) {
        perror(path);
        close(fd);
    }
    return fp;
}

static int generate_key_files(const char *pub_path, const char *priv_path)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, KEM_NAME, NULL);
    EVP_PKEY *key = NULL;
    FILE *fp;
    int ok = 0;

    if (ctx == NULL)
        return fail_ssl("EVP_PKEY_CTX_new_from_name");
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fail_ssl("EVP_PKEY_keygen_init");
        goto done;
    }
    if (EVP_PKEY_generate(ctx, &key) <= 0) {
        fail_ssl("EVP_PKEY_generate");
        goto done;
    }

    fp = fopen(pub_path, "wb");
    if (fp == NULL) {
        perror(pub_path);
        goto done;
    }
    if (PEM_write_PUBKEY(fp, key) != 1) {
        fail_ssl("PEM_write_PUBKEY");
        fclose(fp);
        goto done;
    }
    if (fclose(fp) != 0) {
        perror(pub_path);
        goto done;
    }

    fp = open_private_file(priv_path);
    if (fp == NULL)
        goto done;
    if (PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1) {
        fail_ssl("PEM_write_PrivateKey");
        fclose(fp);
        goto done;
    }
    if (fclose(fp) != 0) {
        perror(priv_path);
        goto done;
    }
    ok = 1;

done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static EVP_PKEY *read_public_key(const char *path)
{
    FILE *fp = fopen(path, "rb");
    EVP_PKEY *key;

    if (fp == NULL) {
        perror(path);
        return NULL;
    }
    key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key == NULL)
        fail_ssl("PEM_read_PUBKEY");
    return key;
}

static EVP_PKEY *read_private_key(const char *path)
{
    FILE *fp = fopen(path, "rb");
    EVP_PKEY *key;

    if (fp == NULL) {
        perror(path);
        return NULL;
    }
    key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key == NULL)
        fail_ssl("PEM_read_PrivateKey");
    return key;
}

static int make_envelope(EVP_PKEY *pub, const char *plain_path,
                         const char *envelope_path)
{
    EVP_PKEY_CTX *kem = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    FILE *in = NULL, *out = NULL;
    unsigned char header[HEADER_MAX];
    unsigned char secret[64];
    unsigned char in_buf[CHUNK_LEN];
    unsigned char out_buf[CHUNK_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[TAG_LEN];
    size_t ct_len = KEM_CT_MAX, secret_len = sizeof(secret), header_len;
    int n, ok = 0;

    kem = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    if (kem == NULL) {
        fail_ssl("EVP_PKEY_CTX_new_from_pkey");
        goto done;
    }
    if (EVP_PKEY_encapsulate_init(kem, NULL) <= 0) {
        fail_ssl("EVP_PKEY_encapsulate_init");
        goto done;
    }
    memcpy(header, MAGIC, MAGIC_LEN);
    if (EVP_PKEY_encapsulate(kem, header + MAGIC_LEN + 4, &ct_len, secret,
                             &secret_len) <= 0) {
        fail_ssl("EVP_PKEY_encapsulate");
        goto done;
    }
    if (ct_len == 0 || ct_len > KEM_CT_MAX || secret_len != KEY_LEN) {
        fprintf(stderr, "Unexpected ML-KEM output size\n");
        goto done;
    }
    header[MAGIC_LEN] = (unsigned char)(ct_len >> 24);
    header[MAGIC_LEN + 1] = (unsigned char)(ct_len >> 16);
    header[MAGIC_LEN + 2] = (unsigned char)(ct_len >> 8);
    header[MAGIC_LEN + 3] = (unsigned char)ct_len;
    if (RAND_bytes(header + MAGIC_LEN + 4 + ct_len, NONCE_LEN) != 1) {
        fail_ssl("RAND_bytes");
        goto done;
    }
    header_len = MAGIC_LEN + 4 + ct_len + NONCE_LEN;

    in = fopen(plain_path, "rb");
    if (in == NULL) {
        perror(plain_path);
        goto done;
    }
    out = fopen(envelope_path, "wb");
    if (out == NULL) {
        perror(envelope_path);
        goto done;
    }
    if (!write_all(out, header, header_len))
        goto done;

    cipher = EVP_CIPHER_CTX_new();
    if (cipher == NULL ||
        EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, secret,
                           header + header_len - NONCE_LEN) != 1) {
        fail_ssl("EVP_EncryptInit_ex");
        goto done;
    }
    if (EVP_EncryptUpdate(cipher, NULL, &n, header, (int)header_len) != 1) {
        fail_ssl("EVP_EncryptUpdate (AAD)");
        goto done;
    }

    for (;;) {
        size_t r = fread(in_buf, 1, sizeof(in_buf), in);

        if (r > 0) {
            if (EVP_EncryptUpdate(cipher, out_buf, &n, in_buf, (int)r) != 1) {
                fail_ssl("EVP_EncryptUpdate");
                goto done;
            }
            if (!write_all(out, out_buf, (size_t)n))
                goto done;
        }
        if (r < sizeof(in_buf)) {
            if (ferror(in)) {
                perror(plain_path);
                goto done;
            }
            break;
        }
    }

    if (EVP_EncryptFinal_ex(cipher, out_buf, &n) != 1) {
        fail_ssl("EVP_EncryptFinal_ex");
        goto done;
    }
    if (!write_all(out, out_buf, (size_t)n))
        goto done;
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        fail_ssl("EVP_CTRL_GCM_GET_TAG");
        goto done;
    }
    if (!write_all(out, tag, sizeof(tag)))
        goto done;
    ok = 1;

done:
    if (in != NULL)
        fclose(in);
    if (out != NULL && fclose(out) != 0) {
        perror(envelope_path);
        ok = 0;
    }
    if (!ok && out != NULL)
        remove(envelope_path);
    EVP_CIPHER_CTX_free(cipher);
    EVP_PKEY_CTX_free(kem);
    OPENSSL_cleanse(secret, sizeof(secret));
    return ok;
}

static int open_envelope(EVP_PKEY *priv, const char *envelope_path,
                         const char *plain_path)
{
    EVP_PKEY_CTX *kem = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    FILE *in = NULL, *out = NULL;
    unsigned char header[HEADER_MAX];
    unsigned char secret[64];
    unsigned char in_buf[CHUNK_LEN];
    unsigned char out_buf[CHUNK_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[TAG_LEN];
    size_t secret_len = sizeof(secret), header_len, ct_len;
    long file_len, remaining;
    int n, ok = 0;

    in = fopen(envelope_path, "rb");
    if (in == NULL) {
        perror(envelope_path);
        goto done;
    }
    if (fread(header, 1, MAGIC_LEN + 4, in) != MAGIC_LEN + 4 ||
        memcmp(header, MAGIC, MAGIC_LEN) != 0) {
        fprintf(stderr, "Invalid envelope format\n");
        goto done;
    }
    ct_len = ((size_t)header[MAGIC_LEN] << 24) |
             ((size_t)header[MAGIC_LEN + 1] << 16) |
             ((size_t)header[MAGIC_LEN + 2] << 8) |
             (size_t)header[MAGIC_LEN + 3];
    if (ct_len == 0 || ct_len > KEM_CT_MAX) {
        fprintf(stderr, "Invalid ML-KEM ciphertext length\n");
        goto done;
    }
    header_len = MAGIC_LEN + 4 + ct_len + NONCE_LEN;
    if (fread(header + MAGIC_LEN + 4, 1, ct_len + NONCE_LEN, in) !=
        ct_len + NONCE_LEN) {
        fprintf(stderr, "Truncated envelope header\n");
        goto done;
    }

    if (fseek(in, 0, SEEK_END) != 0 || (file_len = ftell(in)) < 0) {
        perror(envelope_path);
        goto done;
    }
    remaining = file_len - (long)header_len - TAG_LEN;
    if (remaining < 0) {
        fprintf(stderr, "Truncated envelope\n");
        goto done;
    }
    if (fseek(in, (long)header_len, SEEK_SET) != 0) {
        perror(envelope_path);
        goto done;
    }

    kem = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
    if (kem == NULL) {
        fail_ssl("EVP_PKEY_CTX_new_from_pkey");
        goto done;
    }
    if (EVP_PKEY_decapsulate_init(kem, NULL) <= 0) {
        fail_ssl("EVP_PKEY_decapsulate_init");
        goto done;
    }
    if (EVP_PKEY_decapsulate(kem, secret, &secret_len, header + MAGIC_LEN + 4,
                             ct_len) <= 0) {
        fail_ssl("EVP_PKEY_decapsulate");
        goto done;
    }
    if (secret_len != KEY_LEN) {
        fprintf(stderr, "Unexpected ML-KEM shared-secret length\n");
        goto done;
    }

    cipher = EVP_CIPHER_CTX_new();
    if (cipher == NULL ||
        EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, secret,
                           header + header_len - NONCE_LEN) != 1) {
        fail_ssl("EVP_DecryptInit_ex");
        goto done;
    }
    if (EVP_DecryptUpdate(cipher, NULL, &n, header, (int)header_len) != 1) {
        fail_ssl("EVP_DecryptUpdate (AAD)");
        goto done;
    }

    out = fopen(plain_path, "wb");
    if (out == NULL) {
        perror(plain_path);
        goto done;
    }
    while (remaining > 0) {
        size_t want = remaining < (long)sizeof(in_buf)
                          ? (size_t)remaining : sizeof(in_buf);

        if (fread(in_buf, 1, want, in) != want) {
            fprintf(stderr, "Could not read envelope ciphertext\n");
            goto done;
        }
        if (EVP_DecryptUpdate(cipher, out_buf, &n, in_buf, (int)want) != 1) {
            fail_ssl("EVP_DecryptUpdate");
            goto done;
        }
        if (!write_all(out, out_buf, (size_t)n))
            goto done;
        remaining -= (long)want;
    }

    if (fread(tag, 1, sizeof(tag), in) != sizeof(tag)) {
        fprintf(stderr, "Could not read authentication tag\n");
        goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        fail_ssl("EVP_CTRL_GCM_SET_TAG");
        goto done;
    }
    if (EVP_DecryptFinal_ex(cipher, out_buf, &n) != 1) {
        fprintf(stderr, "Envelope authentication failed\n");
        goto done;
    }
    if (!write_all(out, out_buf, (size_t)n))
        goto done;
    ok = 1;

done:
    if (out != NULL && fclose(out) != 0) {
        perror(plain_path);
        ok = 0;
    }
    if (!ok && out != NULL)
        remove(plain_path);
    if (in != NULL)
        fclose(in);
    EVP_CIPHER_CTX_free(cipher);
    EVP_PKEY_CTX_free(kem);
    OPENSSL_cleanse(secret, sizeof(secret));
    return ok;
}

int main(int argc, char *argv[])
{
    EVP_PKEY *pub = NULL, *priv = NULL;
    int rc = EXIT_FAILURE;

    if (argc != 6) {
        fprintf(stderr,
                "usage: %s <pub.pem> <priv.pem> <plain> <envelope> <decrypted>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (!file_exists(argv[1]) || !file_exists(argv[2])) {
        if (!generate_key_files(argv[1], argv[2]))
            return EXIT_FAILURE;
    }
    pub = read_public_key(argv[1]);
    priv = read_private_key(argv[2]);
    if (pub == NULL || priv == NULL)
        goto done;
    if (!make_envelope(pub, argv[3], argv[4]))
        goto done;
    if (!open_envelope(priv, argv[4], argv[5]))
        goto done;
    rc = EXIT_SUCCESS;

done:
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    return rc;
}
