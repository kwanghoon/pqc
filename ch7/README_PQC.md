# PQC 전환 계획: ch7 - 파일 무결성 검증 및 전자서명

## 1. 전환 목적

이 장의 예제는 [ch7/hash_sign.c](hash_sign.c)를 통해 파일 무결성을 검증하는 절차를 구현한다.

- 파일을 읽어 해시를 계산한다.
- 개인키로 서명을 생성한다.
- 공개키로 서명 검증을 수행한다.
- `.hash` 디렉터리 안에 서명 파일을 저장한다.

이 구조는 RSA 기반 전자서명과 SHA-1 기반 해시를 사용하므로, 양자 컴퓨터 공격 대비와 해시 안전성 측면에서 전환이 필요하다.

## 원본과 전환본

| 원본 | 전환본 | 변경 내용 |
|---|---|---|
| [hash_sign.c](hash_sign.c) | [pqc/pqc_hash_sign.c](pqc/pqc_hash_sign.c) | RSA + SHA-1 서명 → ML-DSA-65 서명, `EVP_DigestSign`/`EVP_DigestVerify` 사용, 키는 ML-DSA PEM |

실행 방법은 [pqc/README.md](pqc/README.md)를 참고한다.

## 2. 현재 취약 암호 사용

- 키: RSA 개인키/공개키
- 해시: `EVP_sha1()`
- 서명 방법: `EVP_SignInit_ex()`, `EVP_VerifyFinal()`
- 파일 무결성 저장: `.hash/*.sig` 파일

문제점:
- RSA는 양자 공격에 취약하다.
- SHA-1은 안전하지 않은 것으로 인정되며, 파일 무결성 검증이 취약하다.
- 서명 검증의 기준이 고전적인 공개키 구조에 기반하므로, PQC 기반 무결성 보장으로 재설계해야 한다.

## 3. 전환 목표

- 파일 해시와 서명 단계에서 RSA → 양자내성 서명 알고리즘으로 전환
- SHA-1 의존 제거
- 서명 파일 저장 구조를 제어하면서, 인증서/서명 키와 무결성 검증 프로세스를 정비

## 4. 5단계 전환 계획

### (1) 알고리즘/매개변수 설정

현재 API 패턴(소스 코드 기준):
- `RSA *rsaPriv = NULL;` / `RSA *rsaPub = NULL;`
  - `rsaPriv`: 개인키 객체
  - `rsaPub`: 공개키 객체
- `rsaPriv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);`
  - `fp`: 개인키 파일 포인터
  - `NULL, NULL, NULL`: 비밀번호/프롬프트 인자 생략
- `rsaPub = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);`
  - `fp`: 공개키 파일 포인터
- `pkey = EVP_PKEY_new();`
  - `pkey`: OpenSSL 키 객체
- `EVP_PKEY_set1_RSA(pkey, rsaPriv)`
  - `pkey`: 키 객체
  - `rsaPriv`: RSA 개인키
- `EVP_MD_CTX_init(&ctx)`
  - `&ctx`: 해시-서명 컨텍스트 초기화
- `EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)`
  - `EVP_sha1()`: SHA-1 해시 함수 선택
  - `NULL`: 엔진 사용 없음
- `EVP_SignUpdate(&ctx, buff, inLen)`
  - `buff`: 파일 버퍼
  - `inLen`: 읽은 바이트 수
- `EVP_SignFinal(&ctx, sign, &signSize, pkey)`
  - `sign`: 서명 결과 버퍼
  - `&signSize`: 서명 길이 저장 위치
  - `pkey`: 서명 키
- `EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL)`
  - 서명 검증에 사용할 해시 함수 지정
- `EVP_VerifyFinal(&ctx, sign, signSize, pkey)`
  - `sign`: 서명 값
  - `signSize`: 서명 값 길이
  - `pkey`: 검증용 키

기존 매개변수-역할 정리:
- `rsaPriv` / `rsaPub`: RSA 개인키와 공개키 객체
- `pkey`: 서명/검증에 적재되는 OpenSSL 키 객체
- `ctx`: 서명/검증의 상태 저장 컨텍스트
- `EVP_sha1()`: 해시 함수 결정
- `buff` / `inLen`: 파일 내용을 담는 버퍼와 그 길이
- `sign` / `signSize`: 서명 값과 길이

목표 API 패턴(권장):
- `EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA, NULL);`
  - `EVP_PKEY_ML_DSA`: 양자내성 서명 알고리즘 선택
- `EVP_PKEY_sign_init(sctx)`
  - `sctx`: 서명용 컨텍스트
- `EVP_PKEY_sign(sctx, sig, &siglen, msg, msglen, key)`
  - `sig`: 서명 값 저장 버퍼
  - `&siglen`: 서명 길이
  - `msg`: 파일 해시 또는 원문
  - `msglen`: 입력 길이
  - `key`: 개인키
- `EVP_PKEY_verify_init(vctx)`
  - `vctx`: 검증용 컨텍스트
- `EVP_PKEY_verify(vctx, sig, siglen, msg, msglen, pkey)`
  - `pkey`: 검증용 공개키
- `EVP_PKEY_CTX_set_security_bits(sctx, 256)`
  - `256`: 보안 강도

목표 매개변수-역할 정리:
- `EVP_PKEY_ML_DSA`: 서명 알고리즘 선택
- `sctx` / `vctx`: 서명/검증용 컨텍스트
- `sig` / `siglen`: 서명 결과와 길이
- `msg` / `msglen`: 검증 대상 메시지와 길이
- `key` / `pkey`: 개인키와 공개키
- `256`: 보안 강도 값

권장 사항:
- 해당 애플리케이션이 자료 무결성을 검증하는 용도라면 서명 알고리즘을 기본 PQC로 전환한다.
- 기존 서명 검증 기능과 새 기능을 병행 운영할 필요가 있으면 하이브리드 방식 고려를 권장한다.

### (2) 키 준비

현재:
- 개인키/공개키 파일을 읽어 `PEM_read_RSAPrivateKey()`, `PEM_read_RSAPublicKey()`로 로딩
- `EVP_PKEY_set1_RSA()`로 키 설정

전환 후:
- 양자내성 개인키/공개키를 안전하게 생성 및 저장
- 서명 키와 검증 키를 분리하여 보관하고, 공개키를 검증에 사용
- 키 버전(날짜, 알고리즘) 정보를 메타데이터로 함께 보관

중요 포인트:
- 서명 키는 안전한 보관소에서 관리
- 공개키는 검증용으로 배포되고 안전하게 서명 검증에 사용

### (3) 연산 초기화

현재:
- `EVP_MD_CTX_init()`
- `EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)`
- 검증 시 동일 방식으로 초기화

전환 후:
- 양자내성 서명/검증용 초기화 단계 구성
- 해시와 서명/검증 루틴의 연결을 명시적으로 정의
- 파일 전체 검증과 서명 검증이 같은 알고리즘 컨텍스트를 공유하도록 설계

설계 원칙:
- 파일 크기와 서명 크기 제한을 명시적으로 관리
- 서명 컨텍스트 생성 시 생성된 키 체계와 일치하는 알고리즘 사용 여부를 검증

### (4) 연산 실행

현재:
- 파일을 버퍼 단위로 읽어 해시와 서명을 계산
- 서명을 `.sig` 파일로 저장
- 검증 시 파일을 다시 읽어 서명과 비교

전환 후:
- 해시 계산 단계는 PQC 서명에 적합한 표준 해시 체계로 교체
- 서명 생성/검증은 양자내성 알고리즘으로 수행
- 서명 파일에 알고리즘 ID와 키 ID를 포함해 검증 시 사전 검증 가능하게 함

중요 포인트:
- 파일 무결성 검증은 그 자체로 보안 기능이므로, 단순 서명 확인이 아니라 인증과 데이터 정합성까지 함께 고려한다.
- 연산 실행 시 예외 처리: 파일 손상, 알고리즘 불일치, 잘못된 서명 파일 등을 명확히 분리한다.

### (5) 결과 처리

현재:
- `.hash` 디렉터리 하위에 서명 파일 생성
- 검증 결과를 stdout에 출력

전환 후:
- 결과 파일에 서명 체계와 키 버전 정보 포함
- 검증 실패 시 보안 로그 및 경고 이벤트 로그 기록
- 검증 결과를 배포나 운영 자동화 시스템에 연결

권장 사항:
- 서명 검증이 실패했을 때 “원본 파일 변조”와 “잘못된 키”를 구분할 수 있도록 한다.
- 운영 환경에서 PQC 서명 검증이 실패한 건에 대한 재처리 정책을 마련한다.

## 5. 적용 우선순위

1. 서명 알고리즘을 RSA 기반에서 PQC 서명 기반으로 전환
2. SHA-1 의존 제거
3. 서명 파일 저장 구조와 메타데이터 관리 개선
4. 검증 실패 로깅과 운영 절차 정비

## 6. 요약

이 장은 데이터 무결성 검증을 구현하는 예제로, PQC 전환의 핵심 문제는 단순히 서명 알고리즘만 바꾸는 것이 아니라 파일 무결성 절차 전체를 양자내성 방식에 맞게 설계하는 것이다. 따라서 ch7는 “해시 + 서명 + 검증” 흐름이 모두 PQC 기반으로 재구성되어야 하는 대표 사례로 볼 수 있다.
