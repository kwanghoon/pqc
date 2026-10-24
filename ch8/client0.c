/*
 * client0.c
 *
 * Encrypts the current time stamp with a pre-shared DES key (symmKey.sec)
 * and sends it to the server (127.0.0.1:9999).
 * The server answers "yes" if the decrypted time stamp is close to its own
 * time, otherwise "no".
 *
 * Message: int cipherBSz, then cipherBSz bytes of DES-CBC ciphertext.
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

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5

int multiple8(int size);

int main()
{
    int res;
    int sockfd;
    unsigned char buff [BUFFSZ];
    struct sockaddr_in server;
    struct timeval timeStamp;
    int fd;
    const_DES_cblock rawkey;
    DES_key_schedule keySched;
    unsigned char iv[BUFFSZ];
    int cipherBSz;

    bzero(buff, BUFFSZ);
    gettimeofday(&timeStamp, NULL);
    fd = open("symmKey.sec", O_RDONLY);
    if(fd == -1){
        perror("symmKey.sec");
        return 1;
    }
    res = read(fd, rawkey, 8);
    if(res != 8){
        fprintf(stderr, "symmKey.sec must contain 8 bytes.\n");
        return 1;
    }
    close(fd);
    DES_set_key(&rawkey, &keySched);

    bzero(iv, sizeof(DES_cblock));
    DES_ncbc_encrypt((unsigned char *)&timeStamp, buff,
    sizeof(struct timeval), &keySched, (DES_cblock *)iv,
    DES_ENCRYPT);
    cipherBSz = multiple8(sizeof(struct timeval));

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

int multiple8(int size)
{
    if(size % 8 == 0) return (size); 
    return( (size/ 8 + 1 ) * 8);
}
