# ch8 PQC 전환: client0.c/server0.c → pqc_client0.c/pqc_server0.c

[../client0.c](../client0.c), [../server0.c](../server0.c)(DES 기반 타임스탬프 인증)를 AES-256-GCM 기반으로 전환한 예제 [pqc_client0.c](pqc_client0.c), [pqc_server0.c](pqc_server0.c)이다.

## 전환 방향

사전 공유 대칭키 방식은 키가 충분히 길면 양자 컴퓨터(Grover 알고리즘)에도 안전하다. 그래서 RSA처럼 알고리즘을 통째로 바꾸지 않고, 프로토콜(타임스탬프 암호화 → 서버 검증 → yes/no)은 유지하며 약한 부분만 교체했다.

## 알고리즘 전환에 필요한 차이

| 항목 | 원본 | 전환본 |
|---|---|---|
| 헤더 | `<openssl/des.h>` | `<openssl/evp.h>`, 클라이언트는 `<openssl/rand.h>` 추가 |
| 암호 | `DES_set_key`, `DES_ncbc_encrypt` (DES-CBC, 56비트) | `EVP_aes_256_gcm()`의 `EVP_Encrypt*`/`EVP_Decrypt*` |
| 키 파일 | `symmKey.sec` 8바이트 | `symmKey.sec` 32바이트 (`KEYSZ`) |
| IV | 0으로 채운 IV | 매 요청 랜덤 12바이트 nonce (`RAND_bytes`) |
| 길이 | `multiple8()`로 8의 배수 패딩(서버의 길이 검사에도 사용) | 패딩 없음. `multiple8()` 삭제. `cipherBSz = NONCESZ + sizeof(struct timeval) + TAGSZ` |
| 전송 형식 | `int` 길이 + 암호문 | `int` 길이 + nonce(12) \|\| 암호문(16) \|\| 태그(16) = 44바이트 |
| 무결성 | 없음 | GCM 태그 검증에 실패하면 서버가 `no` 응답 |

이전 버전은 8바이트 키를 0으로 채워 AES-256 키로 썼기 때문에 실제 키 강도가 64비트에 불과했다. 전환본은 키 파일을 32바이트만큼 읽지 못하면 오류로 종료한다.

## 원본과 같게 유지한 부분

파일 상단 주석, 헤더 순서(`<assert.h>` 제외), 매크로(`BUFFSZ`, `SOCKSZ`, `TIMESKEW`, `ACKSZ`), 변수 선언 순서, `open`/`read`/`close`로 키 읽기, 소켓 호출 순서와 인자, 포트 9999, 응답(`send(..., 5, 0)`), 시간차 판정, `int main()`과 `main` 우선 배치를 그대로 두었다. `static`, 보조 함수, 명령행 인자는 쓰지 않는다. 클라이언트는 인증 실패에도 0을 반환한다.

## 원본과 함께 수정한 부분

양쪽 모두 다음 결함을 고쳤다(`client0.c`, `server0.c`, `pqc_client0.c`, `pqc_server0.c`). 서버 항목은 `server0.c`와 `pqc_server0.c`에만 해당한다.

- `unsigned char` 버퍼에 쓰는 `strcpy`/`strcmp`에 `(char *)` 캐스트를 추가했다.
- 서버 소켓에 `SO_REUSEADDR`를 설정해, 재실행 시 TIME_WAIT 때문에 `bind`가 실패하지 않게 했다.
- `abs()`에 `long`(`tv_sec` 차)을 넘기던 것을 `labs()`로 바꿨다.
- 서버가 클라이언트가 보낸 `cipherBSz`를 그대로 복호화 길이로 사용하던 것을, 기대 크기(원본은 `multiple8(sizeof(struct timeval))`, 전환본은 `NONCESZ + sizeof(struct timeval) + TAGSZ`)와 비교해 다르면 연결을 닫고 다음 연결을 받도록 했다.

`assert`는 `if` 검사와 메시지 출력 후 `return 1`로 바꿨고(양쪽 동일), `exit(EXIT_FAILURE)`는 `return 1`로 바꿨다. 서버가 `recv` 한 번으로 메시지 전체를 받는다고 가정하는 점은 원본 그대로이다.

## 한계

- 여전히 키를 사전에 공유해야 한다. 키 합의가 필요하면 ch4의 ML-KEM 방식이나 ch9의 TLS(`X25519MLKEM768`)를 사용한다.
- 시간차(2초) 이내의 재전송(replay)은 막지 못한다. 원본의 프로토콜 한계를 그대로 유지했다.

## 빌드 및 실행 방법

`$OPENSSL358`은 OpenSSL 3.5.8 설치 경로(`.../openssl-3.5.8/install`)이다.

```bash
export OPENSSL358=$HOME/pqc/openssl-3.5.8/install
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH

cd ch8/pqc
gcc -o pqc_server0 pqc_server0.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lcrypto
gcc -o pqc_client0 pqc_client0.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lcrypto

# 32바이트 랜덤 키 (이 디렉터리에 테스트용 symmKey.sec가 이미 있음)
head -c 32 /dev/urandom > symmKey.sec

./pqc_server0 &
./pqc_client0
```

성공하면 `connected.`, 키가 다르면 `authentication fails.`를 출력한다. 키 파일은 실행 디렉터리의 `symmKey.sec`이다. 서버는 `kill %1`로 종료한다.

### Makefile

```bash
make OPENSSL358=$HOME/pqc/openssl-3.5.8/install
```

`pqc_client0`, `pqc_server0`를 빌드하고 서버를 백그라운드로 띄워 올바른 키(`connected.`)와 다른 32바이트 키(`authentication fails.`)로 클라이언트를 실행한 뒤 서버를 종료한다. 키 파일 `symmKey.sec`는 수정하지 않는다. `make clean`으로 산출물을 지운다.

상위 디렉터리의 [../build.sh](../build.sh)는 원본(OpenSSL 1.0.2u)과 이 전환본(OpenSSL 3.5.8)을 차례로 실행한다.
