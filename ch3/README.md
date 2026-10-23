# 빌드 및 실행 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 설치 경로입니다.

```bash
make OPENSSL102=/path/to/openssl-1.0.2u/install
```

기본 `make`는 `foo.txt`를 입력으로 사용해 `aes_128_cbc`를 빌드·실행하고 현재 디렉터리에 `foo.enc`, `foo.dec`를 생성합니다. 프로그램은 실행할 때마다 난수 키와 IV를 생성하며, 이 값들을 파일에 저장하지 않습니다. 따라서 생성한 암호문을 나중에 별도 실행으로 복호화할 수 있는 파일 포맷은 아닙니다. 다른 파일을 사용하려면 `make INPUT=input.txt CIPHER=output.enc OUTPUT=decoded.txt`처럼 지정할 수 있습니다.

AES-256 전환본도 함께 실행하려면 다음 스크립트를 사용합니다. 기본 OpenSSL 설치 경로는 프로젝트 루트의 `openssl-1.0.2u/install` 및 `openssl-3.5.8/install`이며, 환경 변수로 재정의할 수 있습니다.

```bash
./build.sh
```

```bash
OPENSSL102=/path/to/openssl-1.0.2u/install \
OPENSSL358=/path/to/openssl-3.5.8/install \
./build.sh
```

스크립트는 두 버전을 차례로 실행하고, 각각 복호화 결과를 입력 파일과 `cmp`로 비교합니다. 비교가 실패하면 스크립트가 오류로 종료됩니다. 기본 입력은 ch3의 `foo.txt`이며, 스크립트는 출력 파일 경로를 기본값으로 사용합니다.