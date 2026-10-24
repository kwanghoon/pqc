# 빌드 및 실행 방법

`$OPENSSL102`는 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 설치 경로(`.../openssl-1.0.2u/install`)입니다.

## 구성

- [client0.c](client0.c): 현재 시각(`struct timeval`)을 `symmKey.sec`의 8바이트 DES 키로 암호화해 `127.0.0.1:9999`로 전송합니다.
- [server0.c](server0.c): 포트 9999에서 대기하며 수신한 암호문을 복호화해 시각 차이가 `TIMESKEW`(2초) 미만이면 `yes`, 아니면 `no`를 응답합니다.
- 전송 형식은 `int cipherBSz`와 `cipherBSz` 바이트의 DES-CBC 암호문입니다. 서버는 `cipherBSz`가 기대 크기(`multiple8(sizeof(struct timeval))`)와 다르거나 수신 길이와 다르면 그 연결을 버립니다.

## 원본 소스의 수정 사항

`client0.c`와 `server0.c`는 [pqc/](pqc/README.md)의 전환본과 구조를 맞추기 위해 다음을 수정했습니다.

- 파일 상단에 설명 주석을 추가하고 `main`을 앞에 두었습니다. `multiple8()`는 전방 선언 후 `main` 뒤에 정의합니다. `main`은 `int main()`입니다.
- `assert`를 `if` 검사 후 메시지 출력과 `return 1`로 바꾸고, `exit(EXIT_FAILURE)`를 `return 1`로 바꿨습니다. 이에 따라 `<assert.h>`를 뺐습니다.
- `unsigned char` 버퍼에 쓰는 `strcpy`/`strcmp`에 `(char *)` 캐스트를 추가했습니다.
- 서버: `cipherBSz`가 `multiple8(sizeof(struct timeval))`와 다르면 복호화하지 않고 연결을 닫습니다.
- 서버: `SO_REUSEADDR`를 설정하고, `abs()`를 `labs()`로 바꿨습니다(`tv_sec`는 `long`).

## 빌드 및 실행

```bash
export OPENSSL102=$HOME/pqc/openssl-1.0.2u/install
export LD_LIBRARY_PATH=$OPENSSL102/lib:$LD_LIBRARY_PATH

gcc -o client0 client0.c -I$OPENSSL102/include -L$OPENSSL102/lib -lcrypto
gcc -o server0 server0.c -I$OPENSSL102/include -L$OPENSSL102/lib -lcrypto

./server0 &
./client0
```

성공하면 `connected.`, 키가 다르면 `authentication fails.`를 출력합니다. 키 파일 `symmKey.sec`는 실행 디렉터리에서 읽습니다. 서버는 `kill %1`로 종료합니다.

## Makefile

```bash
make OPENSSL102=$HOME/pqc/openssl-1.0.2u/install
```

`client0`, `server0`를 빌드하고 서버를 백그라운드로 실행한 뒤 다음을 확인하고 서버를 종료합니다.

1. `./client0` → `connected.`
2. 다른 키(`wrong-key-test/symmKey.sec`)로 `client0` 실행 → `authentication fails.`

서버는 `SO_REUSEADDR`를 설정하므로 연속 실행해도 TIME_WAIT 때문에 기다리지 않습니다. `make clean`으로 산출물을 지웁니다.

## build.sh

```bash
./build.sh
```

`ch8`에서 위 `make`(OpenSSL 1.0.2u)를 실행한 뒤 `pqc`로 이동해 `make`(OpenSSL 3.5.8)를 실행합니다. 두 번째 단계는 [pqc/README.md](pqc/README.md)를 참고하십시오. 경로는 환경 변수 `OPENSSL102`, `OPENSSL358`로 바꿀 수 있습니다(기본값: `../../openssl-1.0.2u/install`, `../../openssl-3.5.8/install`).
