# OpenSSL 3.5.8 설치 방법 (PQC 실습용)

이 문서는 각 장의 `pqc/` 예제를 빌드하기 위한 OpenSSL 3.5.8 설치 방법과 장별 전환 요약을 담고 있습니다. 원본 예제를 위한 OpenSSL 1.0.2u 설치는 [README.md](README.md#openssl-102u-설치-방법)를 참고하십시오.

OpenSSL 3.5 계열은 ML-KEM, ML-DSA, SLH-DSA 등 포스트 양자 암호(PQC) 알고리즘을 기본 제공합니다.
아래는 openssl-3.5.8 소스를 내려받아 프로젝트 내 `install` 디렉터리에 빌드/설치하는 방법입니다.

## 설치

```bash
cd pqc
wget https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz

tar xzf openssl-3.5.8.tar.gz
cd openssl-3.5.8
export OPENSSL358=`pwd`/install
echo $OPENSSL358

./config --prefix=$OPENSSL358 --openssldir=$OPENSSL358/openssl

make
make install
```

## 설치 확인

```bash
export LD_LIBRARY_PATH=$OPENSSL358/lib64
$OPENSSL358/bin/openssl version

OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)
```

설치 경로는 `Makefile`과 `build.sh`에서 `OPENSSL358`로 지정합니다. 기본값은 프로젝트와 같은 위치의 `openssl-3.5.8/install`이며, 라이브러리 디렉터리는 `lib64`가 있으면 `lib64`, 없으면 `lib`를 자동으로 선택합니다.

## 장별 PQC 전환 요약

| 장 | 전환 | 사용 알고리즘과 API | 문서 |
| --- | --- | --- | --- |
| ch2 | 난수와 키 생성 | `RAND_bytes`, `EVP_PKEY_CTX_new_from_name("ML-DSA-65")` | [ch2/pqc](ch2/pqc/README.md) |
| ch3 | 대칭 암호 키 길이 확대 | AES-128-CBC → AES-256-CBC (`EVP_aes_256_cbc`) | [ch3/pqc](ch3/pqc/README.md) |
| ch4 | 전자 봉투 | ML-KEM-768 (`EVP_PKEY_encapsulate`/`decapsulate`) + AES-256-GCM | [ch4/pqc](ch4/pqc/README.md) |
| ch5 | 전자서명 | ML-DSA-65 (`EVP_DigestSign`/`EVP_DigestVerify`, 다이제스트 없음) | [ch5/pqc](ch5/pqc/README.md) |
| ch6 | 인증서 | ML-DSA-65 CA와 서버 인증서 (`openssl genpkey`, `req`, `x509`) | [ch6/README_PQC.md](ch6/README_PQC.md) |
| ch7 | 파일 해시 서명 | SHA-512 스트리밍 해시 + ML-DSA-65 (HashML-DSA 방식, `message-encoding=0`) | [ch7/pqc](ch7/pqc/README.md) |
| ch8 | 사전 공유 키 인증 | AES-256-GCM (랜덤 nonce, 태그 검증) | [ch8/pqc](ch8/pqc/README.md) |
| ch9 | TLS | TLS 1.3, `X25519MLKEM768`/`SecP384r1MLKEM1024`, `mldsa65` 서명, 서버 인증서 검증 | [ch9/pqc](ch9/pqc/README.md) |

## 전환 원칙

- **필수 변경만 수정**: 알고리즘이 바뀌어야 하는 부분(키 생성, 서명, 키 캡슐화, 대칭 암호, 협상 설정)만 바꾸고 나머지(`main` 위치, 함수 이름과 순서, 변수 선언, 출력 문자열)는 원본과 같게 유지합니다. 그래야 원본을 입력받아 전환본을 출력하는 변환 도구의 기준(benchmark)으로 쓸 수 있습니다.
- **오류 처리**: `assert`는 명시적 `if` 검사로 바꾸고, 오류 시 `return 1`, 성공 시 `return 0`으로 통일합니다. 원본과 전환본 양쪽에 같게 적용합니다.
- **파일 준비**: 프로그램이 하지 않던 일은 추가하지 않습니다. 예를 들어 ch4의 ML-KEM 키 쌍은 프로그램이 아니라 `Makefile`이 `openssl genpkey`로 만듭니다.
- **원본 결함 수정**: 결함을 고칠 때는 원본과 전환본에 동일하게 반영하고 각 `pqc/README.md`에 기록합니다. 예: ch4~ch9의 반환값 검사, ch8의 `cipherBSz` 검증과 `labs()`, ch9의 서버 인증서 검증.
- **차이의 구분**: 각 `pqc/README.md`는 "알고리즘 전환에 필요한 차이"와 "원본과 같게 유지한 부분"을 나누어 설명합니다.

## 알려진 한계

- OpenSSL 3.5.8은 HashML-DSA를 명시적으로 지원하지 않습니다. ch7은 SHA-512 사전 해시로 FIPS 204의 HashML-DSA 메시지 M'를 직접 구성해 `message-encoding=0`으로 서명합니다. 다른 구현과의 상호운용성은 검증하지 않았습니다.
- ML-DSA는 스트리밍 서명 API(`EVP_DigestSignUpdate`)를 지원하지 않으므로, ch5는 메시지 전체를 한 번에 서명하고 ch7은 해시를 계산한 뒤 해시를 서명합니다.
- ch8은 사전 공유 키 구조를 유지하므로 키 합의는 포함하지 않습니다(ML-KEM은 ch4, TLS는 ch9 참고). 허용 시간차(2초) 이내의 재전송은 막지 못합니다.
- ch9의 원본은 OpenSSL 1.0.2의 기본 설정에 따라 TLS 1.2와 RSA 키 교환으로 협상하며(`group none`), 전환본은 TLS 1.3과 `X25519MLKEM768`로 협상합니다.
