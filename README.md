# OpenSSL을 이용한 컴퓨터 시스템 보안 예제 모음

『OpenSSL을 이용한 컴퓨터 시스템 보안(2판)』(최태영 저)에서 발췌한 OpenSSL 예제 프로그램 모음입니다.
각 디렉터리는 책의 장(chapter)에 대응하며, 난수 생성부터 대칭키/공개키 암호화, 전자서명, 소켓 통신, SSL/TLS 통신까지 실습 코드를 담고 있습니다.

## 디렉터리 구성

각 장의 `chN/`에는 OpenSSL 1.0.2u용 원본 예제가, `chN/pqc/`에는 이를 OpenSSL 3.5.8의 양자내성암호(PQC)로 전환한 예제가 있습니다. 원본과 전환본은 전환에 필요한 부분만 다르도록 맞춰져 있습니다(`main` 위치, 함수 순서, 오류 처리 방식, 출력 문자열 등). 각 장의 `README.md`는 빌드와 실행 방법, `README_PQC.md`는 전환 계획, `pqc/README.md`는 원본과의 차이를 설명합니다.

| 디렉터리 | 원본 | PQC 전환본 (`pqc/`) | 전환 내용 |
| --- | --- | --- | --- |
| `ch2/` | `mkrand16.c`, `rsagenkey.c` | `pqc_mkrand16.c`, `pqc_mldsa_genkey.c` | 난수 생성은 그대로, RSA 키 생성 → ML-DSA-65 키 생성 |
| `ch3/` | `aes_128_cbc.c` | `pqc_aes_256_cbc.c` | AES-128-CBC → AES-256-CBC (Grover 알고리즘 대비 키 길이 확대) |
| `ch4/` | `rsatest.c`, `rsa_des_crc.c` | `pqc_mlkem_file.c`, `pqc_mlkem_envelope.c` | RSA 키 전송 → ML-KEM-768 키 캡슐화 + AES-256-GCM (전자 봉투) |
| `ch5/` | `rsa_sha1_sign_test.c` | `pqc_mldsa_sign_test.c` | RSA + SHA-1 서명 → ML-DSA-65 서명 |
| `ch6/` | (RSA 인증서 절차) | `pqc/` (ML-DSA-65 인증서 샘플) | 키 관리와 인증서. C 프로그램 없이 `openssl` 명령으로 CA와 인증서 발급 |
| `ch7/` | `hash_sign.c` | `pqc_hash_sign.c` | RSA 서명 → SHA-512 사전 해시 + ML-DSA-65 서명 (HashML-DSA 방식, 스트리밍 해시) |
| `ch8/` | `client0.c`, `server0.c` | `pqc_client0.c`, `pqc_server0.c` | DES 사전 공유 키 인증 → AES-256-GCM (프로토콜은 유지) |
| `ch9/` | `ssl_client.c`, `ssl_server.c` | `pqc_ssl_client.c`, `pqc_ssl_server.c` | RSA 기반 TLS → TLS 1.3 + 하이브리드 ML-KEM 키 교환 + ML-DSA-65 인증서 |

## 빌드와 테스트

`ch2`부터 `ch9`까지 각 장에는 `Makefile`, `pqc/Makefile`, `build.sh`가 있습니다(`ch6`은 `build.sh`만 있고, 각 `pqc/`에는 `Makefile`이 있습니다).

```bash
cd ch5
./build.sh      # 원본(OpenSSL 1.0.2u)을 빌드/실행한 뒤 pqc/에서 전환본(OpenSSL 3.5.8)을 빌드/실행
```

설치 경로는 환경 변수로 바꿀 수 있습니다. 기본값은 프로젝트와 같은 위치의 `openssl-1.0.2u/install`과 `openssl-3.5.8/install`입니다.

```bash
OPENSSL102=/path/to/openssl-1.0.2u/install \
OPENSSL358=/path/to/openssl-3.5.8/install \
./build.sh
```

`make`만 실행할 때는 `make OPENSSL102=...`(원본 디렉터리) 또는 `make OPENSSL358=...`(`pqc/`)처럼 경로를 지정합니다. 각 `make`는 프로그램을 빌드하고 실행한 뒤 결과를 확인합니다(예: 서명이 변조를 거부하는지, 다른 키로는 복호화나 인증이 실패하는지). `make clean`은 산출물을 지웁니다. PQC 예제를 쓰려면 먼저 [README_PQC.md](README_PQC.md)의 안내로 OpenSSL 3.5.8을 설치해야 합니다.

## OpenSSL 호환성

각 장의 원본 예제(`ch2`, `ch3`, `ch4`, `ch5`, `ch7`, `ch8`, `ch9`의 `pqc/` 밖 소스)는 OpenSSL **0.9.8 ~ 1.0.2** 시절의 API 관례로 작성되어 있으며, 아래와 같은 근거로 유추할 수 있습니다.

| 증거 | 위치 | 의미 |
| --- | --- | --- |
| `RSA_generate_key(...)` | `ch2/rsagenkey.c`, `ch4/rsatest.c`, `ch5/rsa_sha1_sign_test.c` | `RSA_generate_key_ex()`로 대체되기 전 API. 1.1.0에서 완전히 제거됨 → 1.0.x 이하 |
| `EVP_CIPHER_CTX ctx;` (스택 구조체 선언) | `ch3/aes_128_cbc.c`, `ch4/rsa_des_crc.c` | `EVP_CIPHER_CTX`가 1.1.0부터 opaque 타입이 되어 반드시 `EVP_CIPHER_CTX_new()`로 힙 할당해야 함. 스택 선언이 가능한 건 1.0.x 이하 |
| `EVP_MD_CTX ctx;` + `EVP_MD_CTX_init/cleanup` | `ch5/rsa_sha1_sign_test.c`, `ch7/hash_sign.c` | 동일하게 1.1.0 이후 opaque화(`EVP_MD_CTX_new/free`)됨 |
| `EVP_CIPHER_CTX_cleanup()` | 위 동일 | 1.1.0에서 `EVP_CIPHER_CTX_reset()`으로 대체(구 함수는 매크로로만 남음) |
| `SSLv23_client_method()` / `SSLv23_server_method()` | `ch9/ssl_client.c`, `ch9/ssl_server.c` | 1.1.0부터 `TLS_method()` 권장, `SSLv23_*`는 레거시 이름 |
| `SSL_library_init()` / `SSL_load_error_strings()` 명시적 호출 | 위 동일 | 1.1.0부터 라이브러리가 자동 초기화되어 이 호출들이 사실상 불필요(no-op 매크로)해짐. 명시적으로 호출한다는 건 1.0.x 관례 |
| `DES_set_key`, `DES_ncbc_encrypt`, `const_DES_cblock` | `ch8/client0.c`, `ch8/server0.c` | 저수준 DES API를 직접 사용하는 방식은 구식 예제에 전형적 |

이 원본 파일들은 `RSA_generate_key` 등 1.1.0에서 완전히 제거된 API를 사용하므로 **OpenSSL 1.1.0 이상에서는 컴파일이 되지 않으며**, 빌드하려면 OpenSSL 1.0.2 계열(또는 호환 레이어)이 필요합니다. `pqc/`의 전환본은 OpenSSL 3.5.8 이상에서 빌드합니다.

## openssl-1.0.2u 설치 방법

openssl-1.0.2u 소스를 내려받아 빌드하고 설치하는 방법 (윈도우즈 WSL 우분투)

```
wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz

tar xzf openssl-1.0.2u.tar.gz
cd openssl-1.0.2u
export OPENSSL102=`pwd`/install

./config --prefix=$OPENSSL102 --openssldir=$OPENSSL102/openssl 

make
make install

$OPENSSL102/bin/openssl version
```

버전 텍스트
```
OpenSSL 1.0.2u  20 Dec 2019
```

