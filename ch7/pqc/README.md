# ch7 PQC 전환: hash_sign.c → pqc_hash_sign.c

[../hash_sign.c](../hash_sign.c)(RSA + SHA-1 서명)를 ML-DSA-65 서명으로 전환한 예제 [pqc_hash_sign.c](pqc_hash_sign.c)이다.

## 변경 내용

| 항목 | 원본 | 전환본 |
|---|---|---|
| 서명 알고리즘 | RSA + SHA-1 | ML-DSA-65 (별도 해시 선택 없음) |
| 개인키 읽기 | `PEM_read_RSAPrivateKey` | `PEM_read_PrivateKey` + `EVP_PKEY_is_a("ML-DSA-65")` |
| 공개키 읽기 | `PEM_read_RSAPublicKey` | `PEM_read_PUBKEY` (SubjectPublicKeyInfo) |
| 서명/검증 | `EVP_SignInit/Update/Final` (스트리밍) | `EVP_DigestSign` / `EVP_DigestVerify` (일괄 처리) |
| 서명 크기 | 128바이트 (RSA-1024) | 3309바이트 (동적 할당) |

ML-DSA는 스트리밍 해싱을 지원하지 않으므로 파일 전체를 메모리에 읽어 한 번에 서명한다. 대용량 파일에는 적합하지 않다.
서명은 `<dir>/.hash/<파일명>.sig`에 저장되며, 검증이 하나라도 실패하면 종료 코드가 1이다.

## 키 파일

ML-DSA 키가 필요하므로 기존 RSA 키(`../privKey.pem`, `../pubKey.pem`)는 쓸 수 없다. 테스트용 키 `mldsa_priv.pem`, `mldsa_pub.pem`이 이 디렉터리에 있으며 다시 만들려면 다음과 같이 한다.

```bash
$OPENSSL358/bin/openssl genpkey -algorithm ML-DSA-65 -out mldsa_priv.pem
$OPENSSL358/bin/openssl pkey -in mldsa_priv.pem -pubout -out mldsa_pub.pem
```

## 빌드 및 실행 방법

```bash
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
export LD_LIBRARY_PATH=$OPENSSL358/lib64:$LD_LIBRARY_PATH

cd ch7/pqc
gcc -o pqc_hash_sign pqc_hash_sign.c -I$OPENSSL358/include -L$OPENSSL358/lib64 -lcrypto

./pqc_hash_sign -i mldsa_priv.pem sampledir   # 서명
./pqc_hash_sign -c mldsa_pub.pem  sampledir   # 검증
```
