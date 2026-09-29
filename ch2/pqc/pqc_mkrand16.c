/*
 * pqc_mkrand16.c
 *
 * Original behavior:
 *   - create a short time-based seed
 *   - feed it to OpenSSL RNG
 *   - generate 16 random bytes and print them as hex
 *
 * OpenSSL 3.5.8-compatible modernization:
 *   - keep the same external behavior as ch2/mkrand16.c
 *   - use the modern OpenSSL 3.x libctx + RAND_priv_bytes_ex API
 *   - avoid unrelated additions; no extra formatting or diagnostics
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <openssl/rand.h>

#define MAXBUFF 128

static void printHex(const unsigned char *buf, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void getTimeSubstr(unsigned char *buf, size_t len)
{
    struct timeval atime;
    gettimeofday(&atime, NULL);

    if (len < 8) {
        return;
    }

    memcpy(buf, &(atime.tv_sec), 4);
    memcpy(buf + 4, &(atime.tv_usec), 4);
}

int main(void)
{
    unsigned char seedbuf[MAXBUFF];
    unsigned char randbuf[16];
    OSSL_LIB_CTX *libctx = NULL;
    int rc;

    getTimeSubstr(seedbuf, sizeof(seedbuf));
    RAND_seed(seedbuf, 8);

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        return 1;
    }

    rc = RAND_priv_bytes_ex(libctx, randbuf, sizeof(randbuf), 0);
    OSSL_LIB_CTX_free(libctx);

    if (rc != 1) {
        return 1;
    }

    printHex(randbuf, sizeof(randbuf));
    return 0;
}
