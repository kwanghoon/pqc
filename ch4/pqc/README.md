# ch4 PQC 예제

## ML-KEM 파일 암호화 예제

[pqc_mlkem_file.c](pqc_mlkem_file.c)는 [../rsatest.c](../rsatest.c)의 RSA 공개키 직접 암호화를 양자내성 KEM 기반 봉투 방식으로 바꾼 예제다.

- ML-KEM-768으로 공유 비밀을 캡슐화하고 복원한다.
- 공유 비밀을 AES-256-GCM 키로 사용해 파일을 암호화하고 인증한다.
- `../foo.txt`를 입력으로 읽고 `pqc_mlkem_file.enc` 봉투와 `pqc_mlkem_file.dec` 복호화 결과를 만든다.
- 키 쌍은 실행 중 임시 생성되므로, 생성된 봉투는 같은 실행 중에만 복호화할 수 있다.

## 빌드 및 실행

프로젝트 경로가 `/home/khchoi/work/pqc`이고 OpenSSL 3.5.8이 아래 경로에 설치되어 있는 경우:

```sh
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
cd /home/khchoi/work/pqc/ch4/pqc

gcc -o pqc_mlkem_file pqc_mlkem_file.c \
    -I"$OPENSSL358/include" -L"$OPENSSL358/lib64" -lcrypto

export LD_LIBRARY_PATH="$OPENSSL358/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./pqc_mlkem_file
diff ../foo.txt ./pqc_mlkem_file.dec
```

`diff`에서 출력이 없으면 복호화 결과가 원본과 일치한다. `LD_LIBRARY_PATH`에는 링크 시 사용한 OpenSSL 설치 경로의 `lib64` 디렉터리를 지정한다.

## ML-KEM 전자 봉투 예제

[pqc_mlkem_envelope.c](pqc_mlkem_envelope.c)는 [../rsa_des_crc.c](../rsa_des_crc.c)의 RSA + 3DES 전자 봉투를 ML-KEM-768 + AES-256-GCM 봉투로 대체한 예제다. RSA API는 사용하지 않는다.

- 인자는 원본과 같은 순서이며, 공개키/개인키 파일이 없으면 ML-KEM-768 키 쌍을 생성해 PEM으로 저장한다(개인키는 권한 0600).
- 봉투에는 ML-KEM 암호문, nonce, AES-256-GCM 암호문, 인증 태그가 들어 있고, 헤더도 인증 대상이다.
- 키 파일을 저장하므로 이후 실행에서도 같은 키로 봉투를 열 수 있다.

```sh
export OPENSSL358=/home/khchoi/work/pqc/openssl-3.5.8/install
cd /home/khchoi/work/pqc/ch4/pqc

gcc -o pqc_mlkem_envelope pqc_mlkem_envelope.c \
    -I"$OPENSSL358/include" -L"$OPENSSL358/lib64" -lcrypto

export LD_LIBRARY_PATH="$OPENSSL358/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./pqc_mlkem_envelope mlkem_pub.pem mlkem_priv.pem ../plain.txt envelope.bin plain_out.txt
diff ../plain.txt plain_out.txt
```
