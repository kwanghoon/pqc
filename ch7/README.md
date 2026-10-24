# ch7 빌드 방법

`$OPENSSL102`는 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 설치 경로입니다. 기본값은 `$(HOME)/pqc/openssl-1.0.2u/install`입니다.

```bash
make OPENSSL102=/path/to/openssl-1.0.2u/install
```

`make`는 [hash_sign.c](hash_sign.c)를 빌드하고 다음 순서로 실행합니다. 입력으로 `sampledir`를 복사한 `hash-sign-test`를 쓰므로 `sampledir/.hash`의 기존 서명 파일은 바뀌지 않습니다.

1. `./hash_sign -i privKey.pem hash-sign-test`: 디렉터리의 각 파일을 SHA-1로 해시하고 RSA로 서명해 `.hash/<파일명>.sig`에 저장
2. `./hash_sign -c pubKey.pem hash-sign-test`: 저장된 서명과 각 파일을 비교해 검증
3. `file0.txt`를 변조한 뒤 다시 검증하여 실패하는지 확인

모든 파일이 검증에 성공하면 종료 코드 0, 서명 생성이나 검증에 실패한 파일이 하나라도 있으면 1을 반환합니다. 인자 개수가 틀리면 사용법을 출력하고 1을 반환합니다.

직접 실행하려면 다음과 같이 합니다.

```bash
gcc -o hash_sign hash_sign.c -I$OPENSSL102/include -L$OPENSSL102/lib -lcrypto
export LD_LIBRARY_PATH=$OPENSSL102/lib:$LD_LIBRARY_PATH
./hash_sign -i privKey.pem sampledir
./hash_sign -c pubKey.pem sampledir
```

[build.sh](build.sh)는 이 예제와 [pqc/](pqc)의 HashML-DSA 예제를 차례로 빌드하고 실행합니다. `OPENSSL102`와 `OPENSSL358` 환경 변수로 설치 경로를 바꿀 수 있습니다.

```bash
./build.sh
```
