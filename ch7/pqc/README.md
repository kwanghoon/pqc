# ch7 PQC 전환: hash_sign.c → pqc_hash_sign.c

[pqc_hash_sign.c](pqc_hash_sign.c)는 [../hash_sign.c](../hash_sign.c)의 RSA + SHA-1 파일 서명을 ML-DSA-65 + SHA-512 서명(HashML-DSA)으로 대체한 예제다. 전환에 필요한 부분만 바꾸고 나머지 구조는 원본과 같게 유지했다.

## 원본과 같은 부분

- `main()`과 `provideSubdir()`는 두 파일에서 완전히 같다. 함수 순서와 이름(`hashNsign`, `verify`, `provideSubdir`), `BUFFSZ`, `FNSZ`, 출력 메시지, 상단 주석 형식, `static` 미사용도 같다.
- `fread` 루프로 파일을 `BUFFSZ`(1024바이트) 단위로 읽으며 `Init` → `Update` 루프 → `Final` 순서로 처리한다. 파일 전체를 메모리에 올리지 않는다.
- 서명은 `<dir>/.hash/<파일명>.sig`에 저장한다. 사용법: `-i <개인키 파일> <dir>`(서명), `-c <공개키 파일> <dir>`(검증).
- `assert` 대신 명시적 `if` 검사와 `goto done` 정리 코드로 처리한다. `hashNsign`, `verify`, `provideSubdir`는 성공 시 1, 실패 시 0을 반환한다. `main()`은 모두 성공이면 0, 하나라도 실패하면 1을 반환한다.

## 전환 때문에 달라진 부분

| 항목 | 원본 | 전환본 |
|---|---|---|
| 해시 | `EVP_SignInit_ex(EVP_sha1())`, `EVP_SignUpdate` | `EVP_DigestInit_ex(EVP_sha512())`, `EVP_DigestUpdate` (루프는 그대로) |
| 서명 | `EVP_SignFinal` | `EVP_DigestFinal_ex`로 다이제스트를 구한 뒤 `signHashed()`가 ML-DSA-65로 서명 |
| 검증 | `EVP_VerifyUpdate`, `EVP_VerifyFinal` | `EVP_DigestUpdate` 후 `verifyHashed()` |
| 키 읽기 | `PEM_read_RSAPrivateKey`/`PEM_read_RSAPublicKey` + `EVP_PKEY_set1_RSA` | `PEM_read_PrivateKey`/`PEM_read_PUBKEY` (`EVP_PKEY` 직접 사용) |
| 알고리즘 확인 | 없음 | `EVP_PKEY_is_a(pkey, "ML-DSA-65")` (RSA 키가 들어오면 거부) |
| 서명 버퍼 | `SIGNSZ 1024`, `unsigned int` | `SIGNSZ 4096`, `size_t` (ML-DSA-65 서명은 3309바이트) |
| 컨텍스트 | `EVP_MD_CTX ctx`, `EVP_MD_CTX_init/cleanup` | `EVP_MD_CTX_new/free` |
| 헤더 | `openssl/rsa.h` | `openssl/params.h`, `openssl/core_names.h` |
| 추가 함수 | | `buildHashMsg()`, `signHashed()`, `verifyHashed()` |

## HashML-DSA 구성

ML-DSA는 스트리밍 API(`EVP_DigestSignUpdate` 등)를 지원하지 않는다. OpenSSL 3.5.8에서 호출하면 `provider signature not supported`로 실패한다. 그래서 파일은 SHA-512로 스트리밍 해시하고, 그 다이제스트에 대해 ML-DSA 서명을 한 번만 호출한다. ML-DSA 서명 자체는 스트리밍이 아니고, 스트리밍되는 것은 해시 계산이다.

서명 대상은 FIPS 204 Algorithm 4의 메시지 M'다.

```text
M' = 0x01 || len(ctx) || ctx || OID(SHA-512) || SHA-512(파일)
```

`ctx`는 비어 있고(`len(ctx)` = 0), OID는 `2.16.840.1.101.3.4.2.3`이다. M'는 77바이트다.

OpenSSL은 Pre-hash ML-DSA(HashML-DSA)를 지원하지 않는다. 3.5.8 및 현재 master 문서가 그렇게 명시하며, "Pre-hash 인코딩을 외부에서 한 뒤 메시지를 인코딩하지 않는 옵션을 선택하라"고 안내한다. 그래서 `buildHashMsg()`로 M'를 직접 만들고, `signHashed()`와 `verifyHashed()`에서 `message-encoding`을 0으로 지정한 `EVP_DigestSign`/`EVP_DigestVerify`로 M'를 그대로 서명한다.

주의:

- 서명이 파일 자체가 아니라 SHA-512 다이제스트를 담은 M'에 대한 것이므로 일반 ML-DSA 서명과 다르다.
- 같은 OpenSSL 3.5.8에서 서명, 검증, 변조 검출을 확인했다. 다른 HashML-DSA 구현과의 상호 운용은 검증하지 못했다.
- OpenSSL FIPS provider에서는 `message-encoding` = 0이면 FIPS 승인 표시(indicator)가 0이 된다.

## 키 파일

ML-DSA 키가 필요하므로 기존 RSA 키(`../privKey.pem`, `../pubKey.pem`)는 쓸 수 없다. 테스트용 키 `mldsa_priv.pem`, `mldsa_pub.pem`이 이 디렉터리에 있다. 프로그램은 이 파일을 읽기만 하고 만들지 않는다. 다시 만들려면 다음과 같이 한다.

```bash
$OPENSSL358/bin/openssl genpkey -algorithm ML-DSA-65 -out mldsa_priv.pem
$OPENSSL358/bin/openssl pkey -in mldsa_priv.pem -pubout -out mldsa_pub.pem
```

## 빌드 및 실행 방법

이 디렉터리의 Makefile은 OpenSSL 3.5.8로 `pqc_hash_sign`을 빌드하고 실행한다. 기본 설치 경로는 `$(HOME)/pqc/openssl-3.5.8/install`이며 `OPENSSL358`로 변경할 수 있다. `lib64`와 `lib` 중 존재하는 라이브러리 디렉터리를 자동으로 선택한다.

```bash
make OPENSSL358=/path/to/openssl-3.5.8/install
```

`sampledir`를 복사한 `pqc-hash-sign-test`에 서명하고 검증한 뒤, `file0.txt`를 변조해 검증이 실패하는지까지 확인한다. 상위 디렉터리의 [build.sh](../build.sh)는 RSA 원본과 이 예제를 차례로 실행한다. 직접 실행하려면 다음과 같이 한다.

```bash
gcc -o pqc_hash_sign pqc_hash_sign.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lcrypto
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH
./pqc_hash_sign -i mldsa_priv.pem sampledir   # 서명
./pqc_hash_sign -c mldsa_pub.pem  sampledir   # 검증
```
