/*
 * pqc_server0.c
 *
 * PQC conversion of ch8/server0.c.
 * Listens on port 9999. For each connection it receives an AES-256-GCM
 * encrypted time stamp, decrypts it with the pre-shared key (symmKey.sec,
 * 32 bytes) and answers "yes" if the GCM tag is valid and the time stamp is
 * within TIMESKEW seconds of its own time, otherwise "no".
 *
 * Message: int cipherBSz, then cipherBSz bytes of
 *          nonce(12) || ciphertext(sizeof timeval) || tag(16).
 * A message whose cipherBSz differs from the expected size is dropped.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define TIMESKEW 2
#define ACKSZ 5
#define KEYSZ 32
#define NONCESZ 12
#define TAGSZ 16

int main()
{
    int res;
    int sockfd_li, sockfd;
    unsigned char buff[BUFFSZ];
    struct sockaddr_in server;
    struct timeval timeStamp, myTime;
    unsigned char rawkey[KEYSZ];
    EVP_CIPHER_CTX *ctx;
    int outLen;
    int authOk;
    int cipherBSz;
    int fd;
    int on = 1;

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_port = htons(9999); // cf. 9999
    server.sin_family = AF_INET;
    server.sin_addr.s_addr= htonl (INADDR_ANY);
    sockfd_li = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd_li == -1) {
        perror("socket");
        return 1;
    } 
    setsockopt(sockfd_li, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    res = bind(sockfd_li, (struct sockaddr *)&server, SOCKSZ);
    if (res == -1) {
        perror("bind");
        return 1;
    } 
    res = listen(sockfd_li, 5);
    if (res != 0) {
        perror("listen");
        return 1;
    }
    while(1) {
        sockfd = accept(sockfd_li, NULL, NULL);
        if (sockfd < 0) {
            perror("accept");
            return 1;
        }
        res = recv(sockfd, &cipherBSz, sizeof(int), 0);
        res = recv(sockfd, &buff, BUFFSZ, 0); // cf. cipherBSz
        if (cipherBSz != NONCESZ + sizeof(struct timeval) + TAGSZ || res != cipherBSz) {
            close(sockfd);
            continue;
        }

        gettimeofday(&myTime, NULL);
        fd = open("symmKey.sec", O_RDONLY);
        if (fd == -1) {
            perror("symmKey.sec");
            return 1;
        }
        res = read(fd, rawkey, KEYSZ);
        if (res != KEYSZ) {
            fprintf(stderr, "symmKey.sec must contain %d bytes.\n", KEYSZ);
            return 1;
        }
        close(fd);

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            fprintf(stderr, "EVP_CIPHER_CTX_new error.\n");
            return 1;
        }
        authOk = 0;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, rawkey, buff) == 1 &&
        EVP_DecryptUpdate(ctx, (unsigned char *)&timeStamp, &outLen,
        buff + NONCESZ, sizeof(struct timeval)) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAGSZ,
        buff + NONCESZ + sizeof(struct timeval)) == 1 &&
        EVP_DecryptFinal_ex(ctx, buff, &outLen) == 1)
            authOk = 1;
        EVP_CIPHER_CTX_free(ctx);
        if (authOk == 1 && labs (myTime.tv_sec-timeStamp.tv_sec) < TIMESKEW) {
            strcpy((char *)buff, "yes");
            send(sockfd, &buff, 5, 0);
        } else {
            strcpy((char *)buff, "no");
            send(sockfd, &buff, 5, 0);
        }

        close(sockfd);
    }   
}
