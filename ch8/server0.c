/*
 * server0.c
 *
 * Listens on port 9999. For each connection it receives a DES-CBC encrypted
 * time stamp, decrypts it with the pre-shared key (symmKey.sec) and answers
 * "yes" if the time stamp is within TIMESKEW seconds of its own time,
 * otherwise "no".
 *
 * Message: int cipherBSz, then cipherBSz bytes of DES-CBC ciphertext.
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
#include <openssl/des.h>
#include <openssl/evp.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define TIMESKEW 2
#define ACKSZ 5

int multiple8(int size);

int main()
{
    int res;
    int sockfd_li, sockfd;
    unsigned char buff[BUFFSZ];
    struct sockaddr_in server;
    struct timeval timeStamp, myTime;
    const_DES_cblock rawkey;
    DES_key_schedule keySched;
    DES_cblock iv;
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
        if (cipherBSz != multiple8(sizeof(struct timeval)) || res != cipherBSz) {
            close(sockfd);
            continue;
        }

        gettimeofday(&myTime, NULL);
        fd = open("symmKey.sec", O_RDONLY);
        if (fd == -1) {
            perror("symmKey.sec");
            return 1;
        }
        res = read(fd, rawkey, 8);
        if (res != 8) {
            fprintf(stderr, "symmKey.sec must contain 8 bytes.\n");
            return 1;
        }
        close(fd);

        DES_set_key(&rawkey, &keySched);

        bzero(iv, sizeof(DES_cblock));
        DES_ncbc_encrypt (buff, (unsigned char *)&timeStamp, cipherBSz, &keySched, &iv, DES_DECRYPT);
        if (labs (myTime.tv_sec-timeStamp.tv_sec) < TIMESKEW) {
            strcpy((char *)buff, "yes");
            send(sockfd, &buff, 5, 0);
        } else {
            strcpy((char *)buff, "no");
            send(sockfd, &buff, 5, 0);
        }

        close(sockfd);
    }   
}

int multiple8(int size)
{
    if(size % 8 == 0) return (size); 
    return( (size/ 8 + 1 ) * 8);
}
