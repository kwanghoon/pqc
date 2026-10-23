# PQC 전환 계획: ch2 - 난수 생성 및 RSA 키 생성

## 1. 전환 목적

이 장의 예제는 [ch2/mkrand16.c](mkrand16.c)와 [ch2/rsagenkey.c](rsagenkey.c)를 통해 다음을 수행한다.

- `RAND_seed()`와 `RAND_bytes()`로 난수를 생성한다.
- `RSA_generate_key(512, RSA_F4, ...)`로 512비트 RSA 키를 생성한다.
- 생성된 키를 PEM 파일로 저장한다.

이 구조는 현대적 관점에서 보면 양자 컴퓨터에 취약한 키 생성 방식이며, 키 교환/서명/인증서를 양자내성 방식으로 전환할 필요가 있다.

## 원본과 전환본

| 원본 | 전환본 | 변경 내용 |
|---|---|---|
| [mkrand16.c](mkrand16.c) | [pqc/pqc_mkrand16.c](pqc/pqc_mkrand16.c) | PQC 공개키 알고리즘 전환 대상이 아니며, 현재는 `RAND_bytes()` 호출과 동작을 동일하게 유지 |
| [rsagenkey.c](rsagenkey.c) | [pqc/pqc_mldsa_genkey.c](pqc/pqc_mldsa_genkey.c) | RSA-512 키 생성에서 ML-DSA-65 키 생성으로 전환 (`EVP_PKEY_CTX_new_from_name()` 및 `EVP_PKEY_keygen()`); SPKI 공개키와 PKCS#8 개인키를 고정 파일명으로 저장 |

## 2. 현재 취약 암호 사용

- 난수 생성: `RAND_seed()`로 시간 기반 값을 추가 입력하고 OpenSSL RAND API로 난수를 생성
- 키 생성: RSA 512비트
- 공개키/개인키 저장: PEM 형식의 RSA 키

이 구조는 다음 이유로 PQC 전환 대상이다.

- RSA는 쇼어 알고리즘에 취약하다.
- 512비트 RSA는 현대 보안 기준에 비해 매우 약하다.
- RSA 키 유형은 양자 내성 기준을 만족하지 않는다. 시간값을 `RAND_seed()`에 전달하는 기존 코드는 유지되며, 이는 강한 엔트로피 확보를 보장하지 않는다.

## 3. 전환 목표

- 난수 생성: 이 예제에서는 `RAND_bytes()`를 그대로 사용한다. 난수 생성 API는 공개키 PQC 알고리즘이 아니므로 `pqc_mkrand16.c`는 알고리즘 전환본이 아니다.
- 키 생성: 이 예제에서는 서명용 RSA 키를 ML-DSA-65 키로 전환한다. 키 캡슐화가 목적이라면 별도 예제에서 ML-KEM을 사용한다.
- 키 저장: PEM을 사용한다. ML-DSA 공개키는 SPKI 형식, 개인키는 PKCS#8 형식으로 저장한다.

## 4. 5단계 전환 계획

### (1) 알고리즘/매개변수 설정

현재 API 패턴(소스 코드 기준):
- `RAND_seed(seedbuf, 8)`
  - `seedbuf`: 타임스탬프 값을 복사해 만든 128바이트 버퍼의 시작 포인터
  - `8`: 시드에 사용되는 바이트 수, 여기서는 8바이트를 사용
- `RAND_bytes(randbuf, 16)`
  - `randbuf`: 난수 저장 버퍼 포인터
  - `16`: 생성할 난수 바이트 수
- `RSA_generate_key(512, RSA_F4, NULL, NULL)`
  - `512`: RSA 키 비트 길이
  - `RSA_F4`: 공개지수 값으로 65537(= 2^16 + 1) 사용
  - `NULL`: 콜백 함수 포인터
  - `NULL`: 콜백 인자
- `RSAPublicKey_dup(rsaPriv)`
  - `rsaPriv`: 기존 개인키 포인터
  - 역할: 개인키에서 공개키를 복제해서 파일로 저장
- `PEM_write_RSAPublicKey(pubf, rsaPub)`
  - `pubf`: 공개키 파일 포인터
  - `rsaPub`: 공개키 객체 포인터
- `PEM_write_RSAPrivateKey(privf, rsaPriv, NULL, NULL, 0, NULL, NULL)`
  - `privf`: 개인키 파일 포인터
  - `rsaPriv`: 개인키 객체 포인터
  - `NULL, NULL, 0, NULL, NULL`: 암호화 비밀번호/프롬프트 관련 인자, 현재는 사용하지 않음

기존 매개변수-역할 정리:
- `seedbuf`: 난수 시드의 입력값으로 사용되는 임시 데이터
- `8`: 시드 크기(바이트)
- `randbuf`: 생성된 난수 결과 저장 위치
- `16`: 생성할 난수 길이
- `512`: RSA 키의 길이(양자 취약점 때문에 매우 작은 값)
- `RSA_F4`: RSA 공개지수 선택값
- `rsaPriv`: 개인키 객체
- `rsaPub`: 공개키 객체
- `pubf`, `privf`: 키를 파일로 기록하는 목적의 파일 핸들

현재 ML-DSA 전환본의 API 패턴:
- `EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)`으로 기본 libctx에서 ML-DSA-65 키 생성 컨텍스트를 만든다.
- `EVP_PKEY_keygen_init(ctx)`와 `EVP_PKEY_keygen(ctx, &pkey)`로 키 쌍을 생성한다.
- `pkey` 하나에 공개키와 개인키가 함께 표현되므로, RSA의 `RSAPublicKey_dup()`에 해당하는 별도 복제는 필요하지 않다.
- `PEM_write_PUBKEY()`는 공개키를 SubjectPublicKeyInfo(SPKI)로, `PEM_write_PrivateKey()`는 개인키를 PKCS#8로 기록한다.

권장 전환:
- 적용 대상 애플리케이션이 키 교환을 수행하는 경우: `ML-KEM`
- 서명이 필요한 경우: `ML-DSA` 또는 `SLH-DSA`
- 하이브리드 운영이 필요한 경우: 기존 RSA를 유지하되 PQC 알고리즘을 병행 적용

### (2) 키 준비

현재:
- `RSA_generate_key()`로 RSA 키를 생성하고 `RSAPublicKey_dup()`으로 공개키 객체를 복제
- `PEM_write_RSAPublicKey()`, `PEM_write_RSAPrivateKey()`로 파일 저장

전환 후:
- `EVP_PKEY_keygen()`으로 ML-DSA-65 키 쌍 생성
- `PEM_write_PUBKEY()` 및 `PEM_write_PrivateKey()`로 SPKI 공개키와 PKCS#8 개인키를 저장

주의점:
- 파일명은 원본과 동일하게 `pubKey.pem`, `privKey.pem`으로 고정되어 있으며, 실행한 현재 디렉터리에 생성한다.
- 전환본은 파일을 `fopen(..., "w")`로 열며 별도 개인키 권한 설정이나 암호화를 수행하지 않는다.
- RSA PEM과 ML-DSA PEM은 알고리즘 및 인코딩 형식이 다르므로 상호 호환되지 않는다.

### (3) 연산 초기화

현재:
- `rsagenkey.c`는 시간값으로 `RAND_seed()`를 호출한 뒤 RSA 키 생성 API를 사용한다.
- `RSA *` 개인키와 복제한 공개키 객체를 별도로 관리한다.

전환 후:
- ML-DSA-65용 `EVP_PKEY_CTX`를 초기화하고 `EVP_PKEY` 키 객체를 관리한다.
- 전환본은 기존 시간 기반 `RAND_seed()` 흐름을 유지하며 키 생성 컨텍스트에는 기본 libctx(`NULL`)를 사용한다.

설계 포인트:
- 난수 생성과 키 생성은 별도 API 및 정책으로 구분한다.
- `RT`(실시간) 동작 환경에서는 초기화 단계가 재사용 가능한 라이브러리 레이어로 관리되어야 한다.

### (4) 연산 실행

현재:
- 난수 생성
- 키 생성
- 키 파일 저장

전환 후:
- 양자내성 키 생성
- 양자내성 공개키 배포
- 필요 시 연산 시점에 키 교환 또는 서명 생성 수행

실행 단계에서 보장해야 할 것:
- 키 생성 속도와 메모리 사용량 평가
- 트래픽이 많은 서버 환경에서 키 생성 병목 체크
- 기존 애플리케이션과의 호환 경로 설계

### (5) 결과 처리

현재:
- 생성 결과를 파일로 저장하고 종료

전환 후:
- 생성된 공개키를 인증서 또는 배포 매니저에 등록
- 개인키는 보안 저장소에 보관
- 키 버전 관리 및 로테이션 로그 기록

권장 결과 처리:
- 공개키를 CA/인증서 체인과 연결
- 잘못된 키 버전 누락 여부 확인
- 전환 완료 후 회귀 테스트를 통한 키 포맷 호환성 검증

## 5. 적용 우선순위

1. 키 생성 API를 RSA에서 ML-DSA-65 키 생성 API로 교체
2. SPKI 공개키와 PKCS#8 개인키 형식을 사용하는지 확인
3. 애플리케이션이 ML-DSA 공개키·개인키를 받아들이는지 점검
4. 키 파일 권한, 키 로테이션 및 운영 절차를 별도로 정리

## 6. 요약

이 장의 예제는 “키 생성의 가장 기본적인 단계를 구현한 예시”이므로, PQC 전환에서 가장 먼저 적용해야 하는 부분은 키 생성 알고리즘의 전환이다. RSA 512 비트 키는 양자 컴퓨터 공격에 취약하므로, 이 장의 전환은 단순한 라이브러리 변경이 아니라 보안 기저 기술 전체를 재설계하는 작업으로 이해해야 한다.
