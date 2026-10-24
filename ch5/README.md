# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 설치 경로입니다. 기본값은 `$(HOME)/pqc/openssl-1.0.2u/install`입니다.

```bash
make OPENSSL102=/path/to/openssl-1.0.2u/install
```

`make`는 [rsa_sha1_sign_test.c](rsa_sha1_sign_test.c)를 빌드하고 실행합니다. 서명이 검증되면 `Signature is verified to be clear.`를 출력하고 종료 코드 0을 반환하며, 키 생성, 서명 또는 검증에 실패하면 1을 반환합니다.

[build.sh](build.sh)는 이 예제와 [pqc/](pqc)의 ML-DSA 예제를 차례로 빌드하고 실행합니다. `OPENSSL102`와 `OPENSSL358` 환경 변수로 설치 경로를 바꿀 수 있습니다.

```bash
./build.sh
```

교재 예제에서 signature를 고의로 변형해서 실패하는 경우를 테스트하는데 `main()`에 주석 처리함
