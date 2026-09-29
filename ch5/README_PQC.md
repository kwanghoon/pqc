# PQC 전환 계획: ch5 - RSA+SHA-1 전자서명

## 1. 전환 목적

이 장의 예제는 [ch5/rsa_sha1_sign_test.c](rsa_sha1_sign_test.c)를 통해 다음을 수행한다.

- RSA 개인키로 전자서명을 생성한다.
- SHA-1 해시를 사용해 서명 메시지를 구성한다.
- 공개키로 서명 검증을 수행한다.

이 구조는 RSA와 SHA-1 조합을 사용하므로 양자적 위협과 해시 안전성 관점에서 전환이 필요하다.

## 2. 현재 취약 암호 사용

- 서명 알고리즘: RSA
- 해시: SHA-1
- 서명 API: `EVP_SignInit_ex()`, `EVP_VerifyInit_ex()`

문제점:
- RSA는 양자 공격에 취약하다.
- SHA-1은 안전하지 않은 것으로 널리 인정된다.
- 전자서명 경로가 고전적 공개키 방식에 의존하고 있어 PQC 전환이 필요하다.

## 3. 전환 목표

- 서명 알고리즘을 ML-DSA 또는 SLH-DSA로 교체
- 해시 알고리즘을 SHA-256 이상 또는 PQC 서명에 맞는 해시 체계로 변경
- 서명 검증 로직을 양자내성 키 집합에 맞게 재설계

## 4. 5단계 전환 계획

### (1) 알고리즘/매개변수 설정

현재 API 패턴(소스 코드 기준):
- `RSA_generate_key(512, RSA_F4, NULL, NULL)`
  - `512`: 서명용 RSA 키 비트 길이
  - `RSA_F4`: 공개지수
  - `NULL`: 콜백 인자 없음
- `EVP_PKEY_new()`
  - 서명 키 객체를 생성하는 함수
- `EVP_PKEY_set1_RSA(pkey, rsaPriv)`
  - `pkey`: 키 객체 포인터
  - `rsaPriv`: RSA 개인키 포인터
- `EVP_MD_CTX_init(&ctx)`
  - `&ctx`: 해시-서명 컨텍스트 초기화
- `EVP_SignInit_ex(&ctx, EVP_sha1(), NULL)`
  - `&ctx`: 서명 컨텍스트
  - `EVP_sha1()`: SHA-1 해시 함수
  - `NULL`: 엔진 없음
- `EVP_SignUpdate(&ctx, plaintext, plsize)`
  - `plaintext`: 서명 대상 메시지 버퍼
  - `plsize`: 메시지 길이
- `EVP_SignFinal(&ctx, sign, signSize, pkey)`
  - `sign`: 서명 결과 저장 버퍼
  - `signSize`: 서명 길이 포인터
  - `pkey`: 서명에 사용할 개인키
- `EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL)`
  - `EVP_sha1()`: 검증에 사용할 해시 함수
- `EVP_VerifyUpdate(&ctx, plaintext, plsize)`
  - 서명 검증 대상 메시지 입력
- `EVP_VerifyFinal(&ctx, sign, signSize, pukey)`
  - `sign`: 서명 값
  - `signSize`: 서명 길이
  - `pukey`: 검증용 공개키

기존 매개변수-역할 정리:
- `512`: RSA 키 길이
- `RSA_F4`: 공개 지수
- `pkey` / `pukey`: 서명용 키 객체
- `rsaPriv` / `rsaPub`: 개인키/공개키 객체
- `ctx`: 서명/검증 상태를 유지하는 컨텍스트
- `EVP_sha1()`: 해시 함수 선택
- `plaintext` / `sign`: 서명 생성과 검증 대상 메시지와 결과값
- `plsize` / `signSize`: 메시지 길이와 서명 길이

목표 API 패턴(권장):
- `EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA, NULL);`
  - `EVP_PKEY_ML_DSA`: 양자내성 서명 알고리즘
- `EVP_PKEY_sign_init(sctx)`
  - `sctx`: 서명용 컨텍스트
- `EVP_PKEY_sign(sctx, sig, &siglen, msg, msglen, key)`
  - `sig`: 서명 결과 버퍼
  - `&siglen`: 서명 길이
  - `msg`: 서명 대상 메시지
  - `msglen`: 메시지 길이
  - `key`: 개인키
- `EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA, NULL);`
  - 검증용 컨텍스트
- `EVP_PKEY_verify_init(vctx)`
  - `vctx`: 검증용 컨텍스트
- `EVP_PKEY_verify(vctx, sig, siglen, msg, msglen, pkey)`
  - `pkey`: 공개키
  - `msg` / `msglen`: 검증 대상 값
  - `sig` / `siglen`: 서명 값과 길이
- `EVP_PKEY_CTX_set_security_bits(sctx, 256)`
  - `256`: 보안 강도 지정

목표 매개변수-역할 정리:
- `EVP_PKEY_ML_DSA`: 서명 알고리즘 선택
- `sctx` / `vctx`: 서명 및 검증 시간의 컨텍스트
- `sig` / `siglen`: 서명 값과 길이
- `msg` / `msglen`: 서명 대상 메시지와 길이
- `key` / `pkey`: 서명용 개인키와 검증용 공개키
- `256`: 보안 강도

권장 구성:
- 서명이 필요한 애플리케이션은 양자내성 서명 알고리즘을 기본으로 사용
- 기존 RSA 서명 검증 코드와 병행 운영이 필요하면 하이브리드 모드 고려

### (2) 키 준비

현재:
- 서명용 RSA 개인키 생성
- 공개키 복사 및 `EVP_PKEY_set1_RSA()`로 설정

전환 후:
- 양자내성 개인키/공개키 생성
- PEM/PKCS#8 또는 표준 포맷으로 저장
- 인증서와 서명 키를 분리하여 관리

중요사항:
- 서명 키와 암호화 키를 동일 계열로 묶지 않는다.
- 서명 키의 보관/재사용 전략을 명시한다.

### (3) 연산 초기화

현재:
- `EVP_MD_CTX_init()`
- `EVP_SignInit_ex()`
- `EVP_VerifyInit_ex()`

전환 후:
- 서명 컨텍스트와 검증 컨텍스트를 양자내성 알고리즘에 맞게 초기화
- 서명 키와 공개키를 각각의 컨텍스트에 적재

포인트:
- 서명/검증 순서를 인프라 레벨에서 통일
- 서명 알고리즘 선택이 애플리케이션 설정에서 일관되게 유지되도록 함

### (4) 연산 실행

현재:
- 평문을 해시하고 서명 생성
- 동일한 평문과 서명을 검증

전환 후:
- 양자내성 서명 생성과 검증을 같은 라이브러리/엔진에서 수행
- 메시지 전체 또는 메시지 해시 기반의 서명 체계 유지

검증 필요 항목:
- 메시지 길이 제한
- 서명 크기 및 인코딩 규격
- 비정상 입력에 대한 검증 실패 처리

### (5) 결과 처리

현재:
- 서명 값 출력
- 서명 검증 성공/실패 출력

전환 후:
- 서명 데이터에 알고리즘 식별 포함
- 검증 결과 로그와 감사 기록 유지
- 키 회전과 서명 검증 정책 반영

권장 사항:
- 서명 결과의 비정상 길이나 포맷 오류를 예외로 처리
- 이전 서명과 새 서명 사이의 호환성 정책을 문서화

## 5. 적용 우선순위

1. 서명 알고리즘을 RSA에서 PQC 서명 알고리즘으로 교체
2. SHA-1 의존 제거
3. 공개키와 개인키 저장 포맷 검토
4. 서명 검증 에러 처리와 키 로테이션 정책 정리

## 6. 요약

이 장은 전자서명 예제 중 가장 직접적으로 PQC 전환이 필요한 사례다. 서명 자체는 보안의 핵심 기능이므로, RSA + SHA-1 구조를 양자내성 서명으로 교체하는 것은 보안 아키텍처 변경이자, 운영 정책 변경으로 간주해야 한다.
