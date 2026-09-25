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
#include <assert.h>
#include <openssl/des.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5

int multiple8(int size)
{
    if(size % 8 == 0) return (size); 
    return( (size/ 8 + 1 ) * 8);
}


int main(void)
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
    fd = open("symmKey.sec", O_RDONLY); assert(fd != -1 ) ;
    res = read(fd, rawkey, 8); assert (res == 8) ;
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
        exit(EXIT_FAILURE);
    }
    res = connect(sockfd, (struct sockaddr *)&server,
    SOCKSZ); assert(res==0);

    send(sockfd, &cipherBSz, sizeof(int), 0);
    send(sockfd, &buff, cipherBSz, 0);
    recv(sockfd, &buff, 5, 0);

    if(strcmp(buff, "yes")==0)
        printf("connected.\n" );
    else
        printf("authentication fails.\n");
    return(0);
}
