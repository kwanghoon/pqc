/*
 * pqc_client0.c
 *
 * PQC conversion of ch8/client0.c.
 * Same flow: encrypt a time stamp with a pre-shared key and send it to the
 * server, which answers "yes"/"no".
 *
 * A pre-shared symmetric key is already quantum-resistant if it is long
 * enough, so the protocol is kept and the weak parts are replaced:
 *   - DES with an 8-byte key       -> AES-256-GCM with a 32-byte random key
 *   - fixed/zero IV, no integrity  -> random 12-byte nonce + 16-byte GCM tag
 *   - key zero-padding             -> key file must be exactly 32 bytes
 *
 * Wire format: int32 length, then nonce(12) || ciphertext(sizeof timeval) || tag(16)
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEYSZ 32
#define NONCESZ 12
#define TAGSZ 16
#define TSSZ sizeof(struct timeval)
#define MSGSZ (NONCESZ + TSSZ + TAGSZ)

static int readKey(const char *file, unsigned char key[KEYSZ])
{
    FILE *fp = fopen(file, "rb");
    unsigned char extra;
    int ok;

    if (!fp) {
        perror(file);
        return 0;
    }
    ok = fread(key, 1, KEYSZ, fp) == KEYSZ && fread(&extra, 1, 1, fp) == 0;
    fclose(fp);
    if (!ok)
        fprintf(stderr, "%s must contain exactly %d bytes\n", file, KEYSZ);
    return ok;
}

static int sendAll(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0)
            return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    const char *keyFile = argc > 1 ? argv[1] : "symmKey.sec";
    unsigned char key[KEYSZ], msg[MSGSZ], reply[8] = {0};
    struct sockaddr_in server;
    struct timeval timeStamp;
    EVP_CIPHER_CTX *ctx;
    int sockfd, outLen, ok = 0;
    int msgSz = (int)MSGSZ;

    if (!readKey(keyFile, key))
        return 1;

    gettimeofday(&timeStamp, NULL);
    if (RAND_bytes(msg, NONCESZ) != 1)
        return 1;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, msg) == 1 &&
        EVP_EncryptUpdate(ctx, msg + NONCESZ, &outLen, (unsigned char *)&timeStamp, (int)TSSZ) == 1 &&
        EVP_EncryptFinal_ex(ctx, msg + NONCESZ + outLen, &outLen) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAGSZ, msg + NONCESZ + TSSZ) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    if (!ok) {
        fprintf(stderr, "encryption failed\n");
        return 1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(9999);
    server.sin_family = AF_INET;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }
    if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) != 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    if (!sendAll(sockfd, &msgSz, sizeof(msgSz)) || !sendAll(sockfd, msg, MSGSZ) ||
        recv(sockfd, reply, sizeof(reply) - 1, 0) <= 0) {
        fprintf(stderr, "communication error\n");
        close(sockfd);
        return 1;
    }
    close(sockfd);

    if (strcmp((char *)reply, "yes") == 0) {
        printf("connected.\n");
        return 0;
    }
    printf("authentication fails.\n");
    return 1;
}
