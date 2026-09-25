# OpenSSL을 이용한 인증서 관리

## 인증기관 CA의 개인키 및 자기서명 인증서 생성 (루트 인증서 생성)

```
$ $OPENSSL102/apps/openssl genrsa -out CAPriv.pem 1024
Generating RSA private key, 1024 bit long modulus
........................+++++
..........................................+++++
e is 65537 (0x10001)

$ $OPENSSL102/apps/openssl req -new -key CAPriv.pem -out CAReq.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:KR
State or Province Name (full name) [Some-State]:CA-State
Locality Name (eg, city) []:Gwangju
Organization Name (eg, company) [Internet Widgits Pty Ltd]:JNU
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:Gil-Dong
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

$ $OPENSSL102/apps/openssl x509 -req -days 3650 -in CAReq.pem -signkey CAPriv.pem -out CACert.pem
Signature ok
subject=/C=KR/ST=CA-State/L=Gwangju/O=JNU/CN=Gil-Dong
Getting Private key

$ 
```

CAPriv.pem, CAReq.pem, CACert.pem 파일들이 생성됨


루트 공개키 인증서 CACert.pem을 검증하는 예제

```
Alice:
$ $OPENSSL102/apps/openssl verify -CAfile CACert.pem CACert.pem 
```

CACert.pem: OK 메시지를 출력함

x509 명령어의 -fingerprint 옵션으로 20바이트 핑거프린트를 출력

```
$ $OPENSSL102/apps/openssl x509 -noout -in CACert.pem -fingerprint
SHA1 Fingerprint=65:D0:66:B6:88:4E:05:BC:63:50:94:40:5A:2A:23:07:35:19:39:DB
```

## 개인 사용자의 인증서 발급

Alice가 인증서 서명 신청서를 작성하고 공개키 인증서를 생성

```
$ $OPENSSL102/apps/openssl req -new -keyout AlicePriv.pem -subj '/C=KR/ST=CA-State/O=
JNU/CN=Alice' -out AliceReq.pem 
Generating a RSA private key
.................................................................................................................................+++++
......+++++
writing new private key to 'AlicePriv.pem'
Enter PEM pass phrase: Alice is making cert
Verifying - Enter PEM pass phrase: Alice is making cert
-----

$ $OPENSSL102/apps/openssl x509 -req -days 365 -CA CACert.pem -CAkey CAPriv.pem -CAcreateserial -in AliceReq.pem -out AliceCert.pem 
Signature ok
subject=/C=KR/ST=CA-State/O=JNU/CN=Alice
Getting CA Private Key
```

만든 인증서 AliceCert.pem은 루트 인증서 CACert.pem과 함께 Alice에게 전달하고, Alice는 검증

```
$ $OPENSSL102/apps/openssl verify -CAfile CACert.pem CACert.pem
CACert.pem: OK

$ $OPENSSL102/apps/openssl verify -CAfile CACert.pem AliceCert.pem 
AliceCert.pem: OK
```

Bob이 인증서 서명 신청서를 작성하고 공개키 인증서를 생성. 기존의 일련번호 파일을 이용한 인증서 생성.

```
$ $OPENSSL102/apps/openssl req -new -keyout BobPriv.pem -subj '/C=KR/ST=CA-State/O=JN
U/CN=Bob' -out BobReq.pem -nodes 
Generating a RSA private key
.........................................................................................+++++
.....................................................................+++++
writing new private key to 'BobPriv.pem'
-----

$ $OPENSSL102/apps/openssl x509 -req -days 365 -CA CACert.pem -CAkey CAPriv.pem -CAserial CACert.srl -in BobReq.pem -out BobCert.pem
Signature ok
subject=/C=KR/ST=CA-State/O=JNU/CN=Bob
Getting CA Private Key

$ $OPENSSL102/apps/openssl x509 -text -noout -in BobCert.pem
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            b0:4d:9f:d7:48:23:90:1f
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=KR, ST=CA-State, L=Gwangju, O=JNU, CN=Gil-Dong
        Validity
            Not Before: Sep 25 12:58:23 2026 GMT
            Not After : Sep 25 12:58:23 2027 GMT
        Subject: C=KR, ST=CA-State, O=JNU, CN=Bob
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b2:a6:fd:fe:39:20:41:6f:ae:d2:33:e4:d0:ae:
                    6f:55:20:b1:c9:99:84:3a:f1:08:fa:26:9e:fb:57:
                    14:c0:bf:c0:3a:3a:57:11:10:e1:a3:2f:c8:02:3d:
                    3e:c4:02:4c:b0:77:92:3b:ee:f3:63:6c:6b:e4:c2:
                    d8:b7:cd:7c:04:7d:6c:6f:a4:17:5e:e5:b8:fa:93:
                    ce:b6:50:0f:86:a5:98:27:82:95:d4:56:a8:8c:53:
                    ac:57:14:8b:bf:53:ca:8f:d5:c6:31:f6:fe:2e:72:
                    7c:b3:63:d2:17:53:c3:fb:4c:6f:b6:91:0e:d4:03:
                    7f:54:5e:bd:bd:17:30:46:a2:01:31:0f:f1:69:64:
                    54:29:0a:cc:74:1c:99:a2:7a:f9:88:b8:ce:8e:14:
                    93:d9:52:b5:19:bb:58:61:6e:9a:5b:04:17:17:b8:
                    a3:63:20:0d:69:01:7d:31:37:f7:d4:a3:95:54:13:
                    e0:64:48:a4:80:53:dd:a4:1b:b6:51:8a:00:a7:27:
                    3f:43:1c:f6:64:87:14:6a:d0:48:d2:3d:44:34:e1:
                    0d:ff:dd:0a:e3:e4:47:02:35:74:52:77:f3:e4:f1:
                    8f:f8:c5:c4:1e:cb:a3:d2:3f:e3:8a:3c:10:27:f9:
                    0a:b6:9f:66:39:5f:be:e5:77:c1:62:07:6e:14:15:
                    bc:e5
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
         78:7c:79:27:ba:4d:c9:f9:89:d0:fb:83:29:3d:09:b0:dd:74:
         58:d7:28:67:69:ef:43:bd:9e:14:a1:af:f6:af:2a:d1:4c:9f:
         61:0f:e3:9b:ea:66:53:0f:b7:6b:c9:59:af:3e:b7:6a:ea:a3:
         f4:d1:bf:56:94:cb:e5:33:b0:42:2b:53:01:66:3c:d0:a4:59:
         90:68:56:67:8c:f2:9a:5a:bc:31:66:c3:24:b8:40:d9:fe:bc:
         b0:e4:69:6f:73:06:cf:e2:0e:b7:be:eb:3b:54:0e:d5:9d:08:
         09:40:44:9b:c1:f2:d2:c9:a1:a7:9d:06:5d:73:05:4d:94:c0:
         01:1b
```


개인키와 인증서를 이용한 전자 서명 및 검증

```
$ cat test.txt

$ $OPENSSL102/apps/openssl smime -sign -in test.txt -inkey AlicePriv.pem -signer AliceCert.pem -out mail.msg
Enter pass phrase for AlicePriv.pem:Alice is making cert

$ cat mail.msg

$ $OPENSSL102/apps/openssl smime -verify -in mail.msg -signer AliceCert.pem -CAfile CACert.pem -out recover.txt
Verification successful

$ cat recover.txt
```

## 인증서를 이용한 메시지 서명 및 암호화

Alice와 Bob이 각각 상대방의 공개키 인증서 BobCert.pem과 AliceCert.pem을 가지고 있을 때 메시지에 전자 서명을 첨부하고 암호화하여 보내고, 복호화하고 전자 서명을 검증하는 과정

```
$ $OPENSSL102/apps/openssl smime -sign -in test.txt -signer AliceCert.pem -inkey AlicePriv.pem -text -out signed.msg
Enter pass phrase for AlicePriv.pem: Alice is making cert

$ $OPENSSL102/apps/openssl smime -encrypt -in signed.msg -out sien.msg -from Alice -to Bob -subject "Sign and Encryption test" -aes128 BobCert.pem 
```

```
$ $OPENSSL102/apps/openssl smime -decrypt -in sien.msg -out decryp.msg -recip BobCert.pem -inkey BobPriv.pem 

$ $OPENSSL102/apps/openssl smime -verify -in decryp.msg -out verif.txt -signer AliceCert.pem -CAfile CACert.pem 
Verification successful
```