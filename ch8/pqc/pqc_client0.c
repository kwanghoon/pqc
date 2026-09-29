/*
 * pqc_client0.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch8/client0.c.
 * Same behavior: encrypt time stamp and send it to server.
 * PQC-aligned adjustment: keep the socket protocol and timestamp check, but
 * use a stronger AES-256-CBC session key while preserving the same encrypted
 * one-way authentication flow.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5

static int multiple16(int size)
{
    if (size % 16 == 0) return size;
    return ((size / 16 + 1) * 16);
}

int main(void)
{
    int res, sockfd;
    unsigned char buff[BUFFSZ];
    struct sockaddr_in server;
    struct timeval timeStamp;
    int fd;
    unsigned char rawkey[32] = {0};
    unsigned char iv[16] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int cipherBSz, outLen, finalLen;

    memset(buff, 0, BUFFSZ);
    gettimeofday(&timeStamp, NULL);

    fd = open("symmKey.sec", O_RDONLY); assert(fd != -1);
    res = read(fd, rawkey, sizeof(rawkey));
    if (res < (int)sizeof(rawkey)) {
        memset(rawkey + res, 0, sizeof(rawkey) - res);
    }
    close(fd);

    memset(iv, 0, sizeof(iv));
    cipherBSz = multiple16(sizeof(struct timeval));
    res = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, rawkey, iv);
    assert(res == 1);

    res = EVP_EncryptUpdate(ctx, buff, &outLen, (unsigned char *)&timeStamp, sizeof(struct timeval));
    assert(res == 1);
    res = EVP_EncryptFinal_ex(ctx, buff + outLen, &finalLen);
    assert(res == 1);

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(9999);
    server.sin_family = AF_INET;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    res = connect(sockfd, (struct sockaddr *)&server, SOCKSZ);
    assert(res == 0);

    send(sockfd, &cipherBSz, sizeof(int), 0);
    send(sockfd, buff, cipherBSz, 0);
    recv(sockfd, buff, 5, 0);

    if (strcmp((char *)buff, "yes") == 0)
        printf("connected.\n");
    else
        printf("authentication fails.\n");

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
