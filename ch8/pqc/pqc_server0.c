/*
 * pqc_server0.c
 *
 * OpenSSL 3.5.8-compatible modernization of ch8/server0.c.
 * Same behavior: receive encrypted timestamp, verify it, answer yes/no.
 * PQC-aligned adjustment: the shared secret is still file-backed for behavior
 * parity, but it is used with AES-256-CBC instead of DES to preserve the same
 * authentication flow with stronger symmetric protection.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define TIMESKEW 2

int main(void)
{
    int res, sockfd_li, sockfd;
    unsigned char buff[BUFFSZ];
    struct sockaddr_in server;
    struct timeval timeStamp, myTime;
    unsigned char rawkey[32] = {0};
    unsigned char iv[16] = {0};
    EVP_CIPHER_CTX *ctx;
    int cipherBSz, outLen, finalLen;
    int fd;

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_port = htons(9999);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    sockfd_li = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_li == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    res = bind(sockfd_li, (struct sockaddr *)&server, SOCKSZ);
    if (res == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    res = listen(sockfd_li, 5); assert(res == 0);

    while (1) {
        sockfd = accept(sockfd_li, NULL, NULL);
        assert(sockfd >= 0);

        res = recv(sockfd, &cipherBSz, sizeof(int), 0);
        res = recv(sockfd, buff, BUFFSZ, 0);
        assert(res == cipherBSz);

        gettimeofday(&myTime, NULL);
        fd = open("symmKey.sec", O_RDONLY); assert(fd != -1);
        res = read(fd, rawkey, sizeof(rawkey));
        if (res < (int)sizeof(rawkey)) {
            memset(rawkey + res, 0, sizeof(rawkey) - res);
        }
        close(fd);

        memset(iv, 0, sizeof(iv));
        ctx = EVP_CIPHER_CTX_new();
        res = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, rawkey, iv);
        assert(res == 1);

        res = EVP_DecryptUpdate(ctx, (unsigned char *)&timeStamp, &outLen, buff, cipherBSz);
        assert(res == 1);
        res = EVP_DecryptFinal_ex(ctx, ((unsigned char *)&timeStamp) + outLen, &finalLen);
        assert(res == 1);
        EVP_CIPHER_CTX_free(ctx);

        if (abs((int)(myTime.tv_sec - timeStamp.tv_sec)) < TIMESKEW) {
            strcpy((char *)buff, "yes");
            send(sockfd, buff, 5, 0);
        } else {
            strcpy((char *)buff, "no");
            send(sockfd, buff, 5, 0);
        }

        close(sockfd);
    }
}
