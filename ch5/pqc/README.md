# ch5 PQC 전자서명 예제

[pqc_mldsa_sign_test.c](pqc_mldsa_sign_test.c)는 [../rsa_sha1_sign_test.c](../rsa_sha1_sign_test.c)의 RSA + SHA-1 전자서명을 ML-DSA-65 서명으로 대체한 예제다. RSA API와 SHA-1은 사용하지 않는다.

- `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)`로 키 쌍을 생성한다.
- `EVP_DigestSign()`으로 메시지를 서명하고 `EVP_DigestVerify()`로 검증한다.
- ML-DSA는 메시지를 직접 서명하므로 해시 알고리즘을 지정하지 않는다. 이 때문에 원본의 `Update`/`Final` 방식 대신 한 번에 서명하는 API를 쓴다.
- 서명 길이는 고정 버퍼가 아니라 `EVP_DigestSign()`이 알려주는 크기로 할당한다(ML-DSA-65 서명은 3309바이트).
- 정상 서명이면 종료 코드 0, 검증에 실패하면 1을 반환한다. 원본은 항상 1을 반환했다.

## 빌드 및 실행

```sh
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
cd /home/khchoi/work/pqc/ch5/pqc

gcc -o pqc_mldsa_sign_test pqc_mldsa_sign_test.c \
    -I"$OPENSSL358/include" -L"$OPENSSL358/lib64" -lcrypto

export LD_LIBRARY_PATH="$OPENSSL358/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./pqc_mldsa_sign_test
```

`Signature is verified to be clear.`가 출력되면 검증에 성공한 것이다. 서명 변조 시 실패하는 경우를 시험하려면 `main()`의 주석 처리된 변조 테스트를 활성화한다.
