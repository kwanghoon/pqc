/*
 * pqc_server0.c
 *
 * PQC conversion of ch8/server0.c.
 * Receives nonce || AES-256-GCM(time stamp) || tag, authenticates and decrypts
 * it with the pre-shared 32-byte key, checks the time skew and answers
 * "yes"/"no". See pqc_client0.c for the rationale and wire format.
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

#define KEYSZ 32
#define NONCESZ 12
#define TAGSZ 16
#define TSSZ sizeof(struct timeval)
#define MSGSZ (NONCESZ + TSSZ + TAGSZ)
#define TIMESKEW 2

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

static int recvAll(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0)
            return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

/* Returns 1 and fills ts only if the GCM tag is valid. */
static int decryptStamp(const unsigned char key[KEYSZ], const unsigned char *msg, struct timeval *ts)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outLen, ok = 0;

    if (ctx &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, msg) == 1 &&
        EVP_DecryptUpdate(ctx, (unsigned char *)ts, &outLen, msg + NONCESZ, (int)TSSZ) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAGSZ, (void *)(msg + NONCESZ + TSSZ)) == 1 &&
        EVP_DecryptFinal_ex(ctx, (unsigned char *)ts + outLen, &outLen) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char *argv[])
{
    const char *keyFile = argc > 1 ? argv[1] : "symmKey.sec";
    unsigned char key[KEYSZ], msg[MSGSZ];
    struct sockaddr_in server;
    struct timeval timeStamp, myTime;
    int sockfd_li, sockfd, cipherBSz, one = 1;

    if (!readKey(keyFile, key))
        return 1;

    memset(&server, 0, sizeof(server));
    server.sin_port = htons(9999);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    sockfd_li = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_li == -1) {
        perror("socket");
        return 1;
    }
    setsockopt(sockfd_li, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(sockfd_li, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("bind");
        return 1;
    }
    if (listen(sockfd_li, 5) != 0) {
        perror("listen");
        return 1;
    }

    while (1) {
        const char *answer = "no";

        sockfd = accept(sockfd_li, NULL, NULL);
        if (sockfd < 0)
            continue;

        if (recvAll(sockfd, &cipherBSz, sizeof(cipherBSz)) && cipherBSz == (int)MSGSZ &&
            recvAll(sockfd, msg, MSGSZ)) {
            gettimeofday(&myTime, NULL);
            if (decryptStamp(key, msg, &timeStamp) &&
                labs((long)(myTime.tv_sec - timeStamp.tv_sec)) < TIMESKEW)
                answer = "yes";
            send(sockfd, answer, strlen(answer) + 1, 0);
        }
        close(sockfd);
    }
}
