# PQC 비교 문서: mkrand16.c vs pqc_mkrand16.c

## 목적

이 문서는 원본 [../mkrand16.c](../mkrand16.c) 와 양자내성 전환 버전 [pqc_mkrand16.c](pqc_mkrand16.c) 의 차이를 비교하기 위한 문서이다.

목표는 다음과 같다.

- 원본 코드의 동작을 유지한다.
- OpenSSL 3.5.8 API에 맞게 갱신한다.
- 양자내성 암호 전환과 무관한 기능을 추가하지 않는다.
- 원본 코드와의 차이점을 코드 레벨에서 명확히 확인할 수 있게 한다.

## 핵심 비교 개요

원본 코드는 다음 흐름을 따른다.

- 현재 시간 기반으로 시드를 만든다.
- `RAND_seed()`로 시드를 주입한다.
- `RAND_bytes()`로 16바이트 난수를 생성한다.
- 출력은 16바이트 hex 문자열이다.

PQC 전환 버전은 같은 흐름을 유지하면서, OpenSSL 3.x 표준 API인 `OSSL_LIB_CTX_new()`와 `RAND_priv_bytes_ex()`를 사용한다.

## 비교용 diff

```diff
--- a/ch2/mkrand16.c
+++ b/ch2/pqc/pqc_mkrand16.c
@@
-#include <time.h>
-#include <assert.h>
-#include <openssl/rand.h>
+#include <openssl/rand.h>
@@
-void printStr(const unsigned char *buf, int size)
+static void printHex(const unsigned char *buf, size_t size)
 {
-    int i;
+    size_t i;
 
     for(i = 0; i < size; i++)
-    printf("%02x", buf[i]);
+        printf("%02x", buf[i]);
     printf("\n");
 }
 
-void getTimeSubstr(char buff[])
+static void getTimeSubstr(unsigned char *buf, size_t len)
 {
     struct timeval atime;
-    struct timezone tzone;
-    gettimeofday(&atime, &tzone);
-    memcpy(buff, &(atime.tv_sec), 4);
-    memcpy(buff+4, &(atime.tv_usec), 4);
+    gettimeofday(&atime, NULL);
+
+    if (len < 8) {
+        return;
+    }
+
+    memcpy(buf, &(atime.tv_sec), 4);
+    memcpy(buf + 4, &(atime.tv_usec), 4);
 }
 
 int main(void)
 {
-    char seedbuf [MAXBUFF];
-    unsigned char randbuf [MAXBUFF];
-    getTimeSubstr(seedbuf);
-    RAND_seed (seedbuf, 8);
-    RAND_bytes (randbuf, 16);
-    printStr(randbuf, 16);
-    exit(0);
+    unsigned char seedbuf[MAXBUFF];
+    unsigned char randbuf[16];
+    OSSL_LIB_CTX *libctx = NULL;
+    int rc;
+
+    getTimeSubstr(seedbuf, sizeof(seedbuf));
+    RAND_seed(seedbuf, 8);
+
+    libctx = OSSL_LIB_CTX_new();
+    if (libctx == NULL) {
+        return 1;
+    }
+
+    rc = RAND_priv_bytes_ex(libctx, randbuf, sizeof(randbuf), 0);
+    OSSL_LIB_CTX_free(libctx);
+
+    if (rc != 1) {
+        return 1;
+    }
+
+    printHex(randbuf, sizeof(randbuf));
+    return 0;
 }
```

## 변경 포인트 설명

### 1. 난수 생성 API 변경

원본:

```c
RAND_bytes(randbuf, 16);
```

전환 버전:

```c
libctx = OSSL_LIB_CTX_new();
rc = RAND_priv_bytes_ex(libctx, randbuf, sizeof(randbuf), 0);
OSSL_LIB_CTX_free(libctx);
```

변경 이유:

- OpenSSL 3.x에서는 `RAND_bytes()`가 유지되지만, libctx 기반의 컨텍스트를 명시적으로 관리하는 패턴이 더 현대적이다.
- `RAND_priv_bytes_ex()`는 3.x API 표준에 맞는 형태이며, 이 전환문서는 비교 목적이므로 기존 동작을 유지하면서 현대 API로 교체한 형태이다.

### 2. 함수 이름과 시그니처 변경

원본:

```c
void getTimeSubstr(char buff[])
```

전환 버전:

```c
static void getTimeSubstr(unsigned char *buf, size_t len)
```

변경 이유:

- 원본은 `char` 배열을 다뤘지만, 전환 버전은 `unsigned char`로 정렬하고 함수 인자에 `size_t len`을 추가해 다루기 쉽게 했다.
- `len < 8` 체크는 원본과 같은 8바이트 seed 사용을 명시하는 안전장치이다.

### 3. 출력 함수 변경

원본:

```c
void printStr(const unsigned char *buf, int size)
```

전환 버전:

```c
static void printHex(const unsigned char *buf, size_t size)
```

변경 이유:

- 함수 이름과 타입만 현대화했으며, 출력 형식은 그대로 hex 문자열과 개행을 사용한다.
- 추가 메시지나 출력 문구는 넣지 않았다.

### 4. 메인 함수 동작 유지

원본과 전환 버전 모두 핵심 동작은 동일하다.

- 현재 시간을 사용해 seed 생성
- `RAND_seed()`로 시드 반영
- 16바이트 난수 생성
- hex로 출력

다만 전환 버전은 OpenSSL 3.x 라이브러리 컨텍스트를 명시적으로 생성하고 종료한다.

## 결론

이 비교 문서는 PQC 전환을 위해 필요한 최소 변경만 반영한 버전이다.

- 원본 성격 유지
- OpenSSL 3.5.8 요구사항 반영
- 코드 비교가 쉬운 구조 유지
- 불필요한 부가 기능 제거
