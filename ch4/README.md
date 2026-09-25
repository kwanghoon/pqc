# ch4 빌드 방법

`$OPENSSL102`은 리포지토리 루트 [README.md](../README.md#openssl-102u-설치-방법)의 안내에 따라 빌드한 OpenSSL 1.0.2u 경로입니다.

```bash
export OPENSSL102=/home/khchoi/work/pqc/openssl-1.0.2u

gcc -o rsatest rsatest.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
gcc -o rsa_des_crc rsa_des_crc.c -I$OPENSSL102/include -L$OPENSSL102 -lcrypto
```

```
export LD_LIBRARY_PATH=$OPENSSL102:$LD_LIBRARY_PATH
./rsatest privKey.pem pubKey.pem ./ch4/foo.txt cl.txt rec.txt
diff ./ch4/foo.txt ./rec.txt 
```

1024-bit RSA와 RSA_PKCS1_OAEP_PADDING을 사용하고 있고,
foo.txt는 최대 86바이트 텍스트임.

암호화된 cl.txt와 다시 푼 dec.txt를 생성. dec.txt와 foo.txt는 동일.

```
export LD_LIBRARY_PATH=$OPENSSL102:$LD_LIBRARY_PATH
./rsa_des_crc ./ch4/pubKey.pem ./ch4/privKey.pem ./ch4/plain.txt cipher.dec plain.txt
diff ./ch4/plain.txt plain.txt
```

pubKey.pem으로 암호화한 전자 봉투(cipher.dec)를 privKey.pem으로 복호화하여 plain.txt에 평문을 기록. ./ch4/plain.txt와 plain.txt는 동일.

 2장 예제에서 PEM_write_RSAPublicKey로 생성한 PKCS#1 형식(BEGIN RSA PUBLIC KEY)입니다. 반면 rsa_des_crc.c:38는 PEM_read_RSA_PUBKEY(X.509 SubjectPublicKeyInfo BEGIN PUBLIC KEY 형식 전용)로 읽고 있어서 포맷 불일치로 파싱에 실패하고 rsaPub가 NULL이 되는 것입니다.

 rsa_des_crc.c:38에서 PEM_read_RSA_PUBKEY를 PEM_read_RSAPublicKey로 변경했음.