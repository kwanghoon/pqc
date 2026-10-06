# OpenSSL 3.5.8 설치 방법 (PQC 실습용)

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

./config --prefix=$OPENSSL358 --openssldir=$OPENSSL358

make -j$(nproc)
make install
```

## 설치 확인

```bash
export LD_LIBRARY_PATH=`pwd`/install/lib64; ./install/bin/openssl --version

OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)
```

(`openssl-3.5.8` 디렉터리에서 실행합니다.) 버전 3.5.8이 출력되면 정상 설치된 것입니다.

## 참고

- `LD_LIBRARY_PATH`는 현재 셸에서만 유효하므로, 새 셸에서는 다시 설정해야 합니다.
- 시스템에 따라 라이브러리 경로가 `install/lib64` 대신 `install/lib`일 수 있습니다.

