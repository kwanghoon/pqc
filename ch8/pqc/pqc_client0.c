/*
 * pqc_client0.c
 *
 * PQC conversion of ch8/client0.c.
 * Encrypts the current time stamp with a pre-shared AES-256-GCM key
 * (symmKey.sec, 32 bytes) and sends it to the server (127.0.0.1:9999).
 * The server answers "yes" if the decrypted time stamp is close to its own
 * time, otherwise "no".
 *
 * Message: int cipherBSz, then cipherBSz bytes of
 *          nonce(12) || ciphertext(sizeof timeval) || tag(16).
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
#include <openssl/rand.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define KEYSZ 32
#define NONCESZ 12
#define TAGSZ 16

int main()
{
    int res;
    int sockfd;
    unsigned char buff [BUFFSZ];
    struct sockaddr_in server;
    struct timeval timeStamp;
    int fd;
    unsigned char rawkey[KEYSZ];
    EVP_CIPHER_CTX *ctx;
    int outLen;
    int cipherBSz;

    bzero(buff, BUFFSZ);
    gettimeofday(&timeStamp, NULL);
    fd = open("symmKey.sec", O_RDONLY);
    if(fd == -1){
        perror("symmKey.sec");
        return 1;
    }
    res = read(fd, rawkey, KEYSZ);
    if(res != KEYSZ){
        fprintf(stderr, "symmKey.sec must contain %d bytes.\n", KEYSZ);
        return 1;
    }
    close(fd);

    res = RAND_bytes(buff, NONCESZ);
    if(res != 1){
        fprintf(stderr, "RAND_bytes error.\n");
        return 1;
    }
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "EVP_CIPHER_CTX_new error.\n");
        return 1;
    }
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, rawkey, buff) != 1 ||
    EVP_EncryptUpdate(ctx, buff + NONCESZ, &outLen,
    (unsigned char *)&timeStamp, sizeof(struct timeval)) != 1 ||
    EVP_EncryptFinal_ex(ctx, buff + NONCESZ + outLen, &outLen) != 1 ||
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAGSZ,
    buff + NONCESZ + sizeof(struct timeval)) != 1){
        fprintf(stderr, "AES-256-GCM encryption error.\n");
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    cipherBSz = NONCESZ + sizeof(struct timeval) + TAGSZ;

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(9999); // cf. 9999
    server.sin_family = AF_INET;
    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("socket");
        return 1;
    }
    res = connect(sockfd, (struct sockaddr *)&server,
    SOCKSZ);
    if(res != 0){
        perror("connect");
        return 1;
    }

    send(sockfd, &cipherBSz, sizeof(int), 0);
    send(sockfd, &buff, cipherBSz, 0);
    recv(sockfd, &buff, 5, 0);

    if(strcmp((char *)buff, "yes")==0)
        printf("connected.\n" );
    else
        printf("authentication fails.\n");
    return(0);
}
