# PQC 전환 계획: ch3 - AES-128-CBC 파일 암호화/복호화

## 1. 전환 목적

이 장의 예제는 [ch3/aes_128_cbc.c](aes_128_cbc.c)의 파일 암호화/복호화를 다룬다.

- 랜덤 키와 IV를 생성한다.
- `EVP_aes_128_cbc()`로 파일을 암호화한다.
- 동일한 키와 IV를 사용해 복호화한다.

이 패턴은 “암호화 자체는 동작하지만, 키와 IV의 배포·관리 방식이 취약하다”는 점에서 PQC 전환 대상이 된다. AES는 Grover 공격 대비 상대적으로 강하나, 키 분배와 보호 구조는 양자 내성 관점에서 재설계가 필요하다.

## 원본과 전환본

| 원본 | 전환본 | 변경 내용 |
|---|---|---|
| [aes_128_cbc.c](aes_128_cbc.c) | [pqc/pqc_aes_256_cbc.c](pqc/pqc_aes_256_cbc.c) | AES-128-CBC → AES-256-CBC, OpenSSL 3.x 컨텍스트 API(`EVP_CIPHER_CTX_new/free`, `EVP_Encrypt*`/`EVP_Decrypt*`) |

## 2. 현재 취약 암호 사용

- 대칭키: AES-128-CBC
- 키 생성: `RAND_bytes()` 기반 임의 키
- IV: `RAND_bytes()`로 직접 생성
- 키/IV 취급: 동일 파일/프로그램 내부에서 생성 후 사용

문제점:
- 키 교환 경로가 정의되어 있지 않다.
- 키와 IV가 파일/메모리에 함께 존재할 수 있어 노출 위험이 있다.
- 전자봉투(암호문+키 배포) 구조가 없다.

## 3. 전환 목표

- 키 배포 구조를 양자내성 KEM으로 전환
- 대칭 암호는 AES-256-GCM 또는 AES-256-CTR로 강화
- IV 사용 방식을 정규화하고 nonce 재사용 방지
- 파일 암호화는 수신자와의 안전한 키 합의 구조를 갖추도록 변경

## 4. 5단계 전환 계획

### (1) 알고리즘/매개변수 설정

현재 API 패턴(소스 코드 기준):
- `RAND_bytes(mykey, 16)`
  - `mykey`: 대칭키 저장 버퍼
  - `16`: 키 길이(128비트)
- `RAND_bytes(iv, 16)`
  - `iv`: 초기화 벡터(IV) 저장 버퍼
  - `16`: IV 길이(128비트)
- `EVP_CIPHER_CTX_init(&ctx)`
  - `&ctx`: 초기화할 OpenSSL 암호 컨텍스트 포인터
- `EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_ENCRYPT)`
  - `&ctx`: 암호화 컨텍스트
  - `EVP_aes_128_cbc()`: AES-128-CBC 알고리즘 선택
  - `NULL`: 엔진 지정 없음
  - `key`: 암호화 키 포인터
  - `iv`: IV 포인터
  - `AES_ENCRYPT`: 암호화 모드
- `EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, AES_DECRYPT)`
  - `&ctx`: 복호화 컨텍스트
  - `EVP_aes_128_cbc()`: 암호화 알고리즘 선택
  - `key`: 동일 키 사용
  - `iv`: 동일 IV 사용
  - `AES_DECRYPT`: 복호화 모드
- `EVP_CipherUpdate(&ctx, cipherbuff, &out_len, plainbuff, in_len)`
  - `&ctx`: 동작 중인 컨텍스트
  - `cipherbuff`: 출력 버퍼
  - `&out_len`: 출력 길이 저장 주소
  - `plainbuff`: 입력 평문 버퍼
  - `in_len`: 입력 크기
- `EVP_CipherFinal_ex(&ctx, cipherbuff, &out_len)`
  - `&ctx`: 최종 블록 처리용 컨텍스트
  - `cipherbuff`: 최종 출력 버퍼
  - `&out_len`: 최종 출력 길이
- `EVP_CIPHER_CTX_cleanup(&ctx)`
  - `&ctx`: 정리할 컨텍스트

기존 매개변수-역할 정리:
- `mykey`: 대칭 암호 키, 16바이트 길이
- `iv`: CBC 모드의 초기화 벡터, 16바이트 길이
- `ctx`: 암호화/복호화 상태 저장 객체
- `key`: 현재 암호화 키 포인터
- `iv`: 현재 IV 포인터
- `AES_ENCRYPT` / `AES_DECRYPT`: 동작 모드
- `plainbuff` / `cipherbuff`: 입력-출력 버퍼
- `in_len` / `out_len`: 입력 및 출력 길이

목표 API 패턴(권장):
- `EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_KEM, NULL);`
  - `EVP_PKEY_ML_KEM`: 양자내성 키 교환 알고리즘
  - `NULL`: 엔진 없음
- `EVP_PKEY_encapsulate_init(kctx)`
  - `kctx`: 키 캡슐화 컨텍스트
- `EVP_PKEY encapsulate(kctx, out, &outlen, pubkey)`
  - `out`: 캡슐화된 세션 키 버퍼
  - `&outlen`: 세션 키 길이
  - `pubkey`: 수신자 공개키
- `EVP_CIPHER_CTX_init(&dem_ctx)`
  - `&dem_ctx`: DEM(대칭암호) 컨텍스트
- `EVP_EncryptInit_ex(&dem_ctx, EVP_aes_256_gcm(), NULL, session_key, iv)`
  - `EVP_aes_256_gcm()`: AES-256-GCM 선택
  - `session_key`: KEM으로 전달된 세션 키
  - `iv`: nonce/IV
- `EVP_EncryptUpdate(&dem_ctx, outbuf, &outlen, inbuf, inlen)`
  - `outbuf`: 암호문 출력 버퍼
  - `inbuf`: 평문 입력 버퍼
- `EVP_EncryptFinal_ex(&dem_ctx, outbuf + outlen, &final_len)`
  - 최종 블록 처리 및 인증 태그 생성

목표 매개변수-역할 정리:
- `EVP_PKEY_ML_KEM`: 양자내성 키 교환 알고리즘 식별자
- `kctx`: 키 캡슐화/복호화용 컨텍스트
- `out`: 생성된 세션 키 또는 캡슐화 결과
- `outlen`: 결과 길이
- `pubkey`: 수신자 공개키
- `session_key`: KEM으로 생성된 대칭 세션 키
- `iv`: IV 또는 nonce
- `dem_ctx`: 대칭 암호 연산 컨텍스트
- `EVP_aes_256_gcm()`: 인증 가능한 안전한 대칭 알고리즘

권장 전환 구조:
- 키 교환과 암호화가 분리된 KEM + DEM 구조
- 대칭키는 KEM으로 전달되고, 실제 데이터는 DEM에서 암호화

### (2) 키 준비

현재:
- `mykey`와 `iv`를 동일 프로그램에서 생성
- 파일 암호화/복호화에 동일 키와 IV 사용

전환 후:
- 키는 외부 배포 채널을 통해 안전하게 전달
- IV/nonce는 매 암호문마다 독립적으로 생성
- 키 저장은 안전한 키 저장소, HSM, 또는 보호된 애플리케이션 보관소 사용

필수 사항:
- 암호화 키와 서명 키를 분리
- 키 식별자와 생성 시각을 기록
- 키 로테이션 정책 수립

### (3) 연산 초기화

현재:
- `EVP_CIPHER_CTX_init()`
- `EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), ..., key, iv, AES_ENCRYPT)`
- 암호화/복호화 함수를 별도로 호출

전환 후:
- KEM으로 키를 합의한 뒤 DEM용 컨텍스트를 초기화
- GCM/CTR용 상태를 별도 관리
- 인증 태그 검증 로직을 함께 구성

중요 포인트:
- CBC는 패딩 문제와 IV 재사용 위험이 있어 현대 구현에서는 GCM이 더 안전한 선택이다.
- 암호화와 복호화 컨텍스트를 일관되게 유지해야 한다.

### (4) 연산 실행

현재:
- 파일을 `MAXBUFF` 단위로 읽어 암호화
- 암호문을 파일로 출력
- 동일 방식으로 복호화

전환 후:
- KEM으로 공유한 세션 키를 기반으로 파일 암호화
- `EVP_EncryptUpdate()`/`EVP_DecryptUpdate()`를 사용해 연속 처리
- 인증 태그 검증을 마지막 단계에서 수행

주의:
- 무결성을 보장하지 않는 CBC 방식은 재전송/변조 탐지에 약하다.
- PQC 전환에서는 대칭 암호화 단계에서 인증을 추가하는 것이 표준이다.

### (5) 결과 처리

현재:
- `foo.enc`와 `foo.dec` 파일을 출력

전환 후:
- 암호문의 메타데이터(알고리즘, 키 ID, nonce, 인증 태그) 포함
- 복호화 실패 시 명확한 에러 처리
- 원문 파일 무결성 보장 로깅

권장 전환 결과:
- 파일 암호문에는 대칭 알고리즘 식별자와 키 ID가 포함되어야 한다.
- 복호화 시 알고리즘과 키 버전을 검증한다.

## 5. 적용 우선순위

1. 파일 암호화의 키 분배 구조를 KEM 기반으로 전환
2. CBC에서 GCM/CTR 중심 구조로 이동
3. IV/nonce를 매번 독립적으로 생성하도록 변경
4. 키 로테이션과 파일 복호화 실패 처리를 개선

## 6. 요약

이 장은 단순 암호화 예제이지만, 실제 전환 관점에서는 가장 큰 문제는 “키를 어떻게 안전하게 나누고 관리할 것인가”이다. 따라서 ch3는 AES 자체보다도 키 합의와 보호 구조를 바꾸는 전환이 핵심이며, PQC 환경에서는 KEM + DEM 방식으로 전환하는 것이 가장 자연스러운 설계이다.
