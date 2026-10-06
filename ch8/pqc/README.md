# ch8 PQC 전환: client0.c/server0.c → pqc_client0.c/pqc_server0.c

[../client0.c](../client0.c), [../server0.c](../server0.c)(DES 기반 타임스탬프 인증)를 AES-256-GCM 기반으로 전환한 예제 [pqc_client0.c](pqc_client0.c), [pqc_server0.c](pqc_server0.c)이다.

## 전환 방향

사전 공유 대칭키 방식은 키가 충분히 길면 양자 컴퓨터(Grover 알고리즘)에도 안전하다. 그래서 RSA처럼 알고리즘을 통째로 바꾸지 않고, 프로토콜(타임스탬프 암호화 → 서버 검증 → yes/no)은 유지하며 약한 부분만 교체했다.

| 항목 | 원본 | 전환본 |
|---|---|---|
| 암호 | DES-CBC (56비트) | AES-256-GCM |
| 키 파일 | `symmKey.sec` 8바이트 | `symmKey.sec` 정확히 32바이트 (랜덤) |
| IV | 고정 | 매 요청 랜덤 12바이트 nonce |
| 무결성 | 없음 | GCM 태그(16바이트)로 인증, 위변조 시 "no" |
| 전송 형식 | 길이 + 암호문 | 길이(int) + nonce \|\| 암호문 \|\| 태그 (총 36바이트 데이터) |
| 오류 처리 | `assert` | 오류 메시지/종료 코드, 부분 수신 처리(`recvAll`/`sendAll`) |

이전 버전은 8바이트 키를 0으로 채워 AES-256 키로 썼기 때문에 실제 키 강도는 64비트에 불과했다. 전환본은 32바이트가 아니면 키 파일을 거부한다.

## 한계

- 여전히 키를 사전에 공유해야 한다. 키 합의가 필요하면 ch4의 ML-KEM 방식이나 ch9의 TLS(`X25519MLKEM768`)를 사용한다.
- 시간차(2초) 이내의 재전송(replay)은 막지 못한다. 원본의 프로토콜 한계를 그대로 유지했다.

## 빌드 및 실행 방법

```bash
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH

cd ch8/pqc
gcc -o pqc_server0 pqc_server0.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lcrypto
gcc -o pqc_client0 pqc_client0.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lcrypto

# 32바이트 랜덤 키 (이 디렉터리에 테스트용 symmKey.sec가 이미 있음)
head -c 32 /dev/urandom > symmKey.sec

./pqc_server0 &            # 키 파일 경로를 인자로 줄 수 있음 (기본: ./symmKey.sec)
./pqc_client0
```

성공하면 `connected.`, 키가 다르면 `authentication fails.`를 출력한다.
