/*
 - ch1
 - mkrand16.c
 - 16바이트 난수를 생성하는 프로그램
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>

#define MAXBUFF 128

void printStr(void *buf, int size)
{
    int i;

    for(i = 0; i < size; i++)
    printf("%02x", ((unsigned char *)buf)[i]);
    printf("\n");
}

void getTimeSubstr(char buff[])
{
    struct timeval atime;
    struct timezone tzone;
    gettimeofday(&atime, &tzone);
    memcpy(buff, &(atime.tv_sec), 4);
    memcpy(buff+4, &(atime.tv_usec), 4);
}

int main(void)
{
    char seedbuf [MAXBUFF];
    char randbuf [MAXBUFF];
    getTimeSubstr(seedbuf);
    RAND_seed (seedbuf, 8);
    RAND_bytes (randbuf, 16);
    printStr(randbuf, 16);
    exit(0);
}