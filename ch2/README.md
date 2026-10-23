# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
make OPENSSL102=your-openssl-102u-install-dir
```

`make`는 두 프로그램을 컴파일한 다음 차례로 실행합니다. `mkrand16`은 16바이트 난수를 출력하고, `rsagenkey`는 `pubKey.pem`과 `privKey.pem`을 생성합니다.

rsagenkey를 실행하면 pubkey.pem과 privkey.pem 파일이 생성

두 OpenSSL 버전의 예제를 함께 빌드하고 실행하려면 다음 스크립트를 사용합니다. 기본 경로는 프로젝트 루트와 같은 위치에 있는 `openssl-1.0.2u/` 및 `openssl-3.5.8/` 디렉터리를 기준으로 합니다.

```bash
./build.sh
```

설치 경로가 기본 위치와 다르면 환경 변수로 지정할 수 있습니다.

```bash
OPENSSL102=/path/to/openssl-1.0.2u/install \
OPENSSL358=/path/to/openssl-3.5.8/install \
./build.sh
```
