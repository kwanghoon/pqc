# ch7 빌드 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o hash_sign ./ch7/hash_sign.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```


```
./hash_sign -i ./ch7/privKey.pem ./ch7/sampledir
```

지정한 디렉토리의 각 파일들의 해쉬를 만들어 .hash 디렉토리에 저장

```
./hash_sign -c ./ch7/pubKey.pem ./ch7/sampledir
```

.hash 디렉토리에 저장된 해쉬와 디렉토리의 각 파일들의 해쉬를 비교