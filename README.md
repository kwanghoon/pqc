# OpenSSL을 이용한 컴퓨터 시스템 보안 예제 모음

『OpenSSL을 이용한 컴퓨터 시스템 보안(2판)』(최태영 저)에서 발췌한 OpenSSL 예제 프로그램 모음입니다.
각 디렉터리는 책의 장(chapter)에 대응하며, 난수 생성부터 대칭키/공개키 암호화, 전자서명, 소켓 통신, SSL/TLS 통신까지 실습 코드를 담고 있습니다.

## 디렉터리 구성

| 디렉터리 | 파일 | 설명 |
| --- | --- | --- |
| `ch2/` | `mkrand16.c` | OpenSSL `RAND` API를 이용해 16바이트 난수를 생성 |
| `ch2/` | `rsagenkey.c` | RSA 개인키/공개키 쌍을 생성하고 PEM 파일로 저장 |
| `ch3/` | `aes_128_cbc.c` | AES-128 알고리즘과 CBC 모드를 이용한 파일 암호화/복호화 |
| `ch4/` | `rsatest.c` | RSA 키 생성 및 이를 이용한 파일 암호화/복호화 |
| `ch4/` | `rsa_des_crc.c` | RSA와 DES-CRC를 조합한 전자 봉투(digital envelope) 구현 |
| `ch5/` | `rsa_sha1_sign_test.c` | RSA와 SHA-1을 이용한 전자서명 생성 및 검증 |
| `ch7/` | `hash_sign.c` | 파일 해시 및 전자서명을 이용한 무결성 검증 |
| `ch8/` | `client0.c`, `server0.c` | 소켓 기반 클라이언트/서버 통신 및 DES 암호화 예제 |
| `ch9/` | `ssl_client.c`, `ssl_server.c` | OpenSSL `SSL`/`BIO` API를 이용한 SSL/TLS 클라이언트-서버 통신 |

## 빌드 방법

각 예제는 OpenSSL 라이브러리(`libssl`, `libcrypto`)에 의존합니다. 예시:

```bash
gcc -o mkrand16 ch2/mkrand16.c -lcrypto
gcc -o aes_128_cbc ch3/aes_128_cbc.c -lcrypto
gcc -o ssl_client ch9/ssl_client.c -lssl -lcrypto
gcc -o ssl_server ch9/ssl_server.c -lssl -lcrypto
```


## OpenSSL 호환성

`ch2`, `ch3`, `ch4/rsatest.c`, `ch4/rsa_des_crc.c`, `ch5`, `ch7`, `ch8`, `ch9`의 예제는 OpenSSL **0.9.8 ~ 1.0.2** 시절의 API 관례로 작성되어 있으며, 아래와 같은 근거로 유추할 수 있습니다.

| 증거 | 위치 | 의미 |
| --- | --- | --- |
| `RSA_generate_key(...)` | `ch2/rsagenkey.c`, `ch4/rsatest.c`, `ch5/rsa_sha1_sign_test.c` | `RSA_generate_key_ex()`로 대체되기 전 API. 1.1.0에서 완전히 제거됨 → 1.0.x 이하 |
| `EVP_CIPHER_CTX ctx;` (스택 구조체 선언) | `ch3/aes_128_cbc.c`, `ch4/rsa_des_crc.c` | `EVP_CIPHER_CTX`가 1.1.0부터 opaque 타입이 되어 반드시 `EVP_CIPHER_CTX_new()`로 힙 할당해야 함. 스택 선언이 가능한 건 1.0.x 이하 |
| `EVP_MD_CTX ctx;` + `EVP_MD_CTX_init/cleanup` | `ch5/rsa_sha1_sign_test.c`, `ch7/hash_sign.c` | 동일하게 1.1.0 이후 opaque화(`EVP_MD_CTX_new/free`)됨 |
| `EVP_CIPHER_CTX_cleanup()` | 위 동일 | 1.1.0에서 `EVP_CIPHER_CTX_reset()`으로 대체(구 함수는 매크로로만 남음) |
| `SSLv23_client_method()` / `SSLv23_server_method()` | `ch9/ssl_client.c`, `ch9/ssl_server.c` | 1.1.0부터 `TLS_method()` 권장, `SSLv23_*`는 레거시 이름 |
| `SSL_library_init()` / `SSL_load_error_strings()` 명시적 호출 | 위 동일 | 1.1.0부터 라이브러리가 자동 초기화되어 이 호출들이 사실상 불필요(no-op 매크로)해짐. 명시적으로 호출한다는 건 1.0.x 관례 |
| `DES_set_key`, `DES_ncbc_encrypt`, `const_DES_cblock` | `ch8/client0.c`, `ch8/server0.c` | 저수준 DES API를 직접 사용하는 방식은 구식 예제에 전형적 |

이 파일들은 `RSA_generate_key` 등 1.1.0에서 완전히 제거된 API를 사용하므로 **OpenSSL 1.1.0 이상에서는 컴파일이 되지 않으며**, 빌드하려면 OpenSSL 1.0.2 계열(또는 호환 레이어)이 필요합니다.

## 참고

- 예제 코드는 학습 목적으로 작성되었으며, 일부 API(`RSA_generate_key`, `DES` 등)는 최신 OpenSSL 버전에서 사용이 권장되지 않거나 제거될 수 있습니다.
- 실무 환경에서는 최신 권장 알고리즘과 API(`EVP` 인터페이스 등)를 사용하시기 바랍니다.
