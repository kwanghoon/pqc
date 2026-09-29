# PQC 비교 문서: ssl_client.c/server.c vs pqc_ssl_client.c/pqc_ssl_server.c

## 목적

이 문서는 [../ssl_client.c](../ssl_client.c), [../ssl_server.c](../ssl_server.c)와 [pqc_ssl_client.c](pqc_ssl_client.c), [pqc_ssl_server.c](pqc_ssl_server.c)의 차이를 비교한다.

- 원본 동작 유지: TLS 연결과 HTTP 통신
- TLS 정책 강화: TLS 1.2+ 및 AES-256 기반 스위트 사용
- OpenSSL 3.x API로 정리
- 불필요한 기능 추가 없이 비교에 집중

## 비교용 diff

```diff
--- a/ch9/ssl_client.c
+++ b/ch9/pqc/pqc_ssl_client.c
@@
-    meth = SSLv23_client_method();
+    meth = TLS_client_method();
+    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
+    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
+    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
+    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:secp256r1");
```

## 변경 포인트

- 구식 `SSLv23_*` 메서드를 `TLS_*_method()`로 전환했다.
- TLS 1.2 이상을 보장하고, TLS 1.3의 AES-256 기반 스위트를 명시했다.
- 키 교환 그룹 목록을 최신형 그룹으로 정리했다.
- 세션 동작은 그대로 유지: 연결 → 핸드셰이크 → HTTP 요청 → 응답 수신.

## 결론

이 문서는 기존 TLS 예제의 동작을 유지하면서, OpenSSL 3.5.8 환경에서 보안 정책을 더 강하게 정리한 버전이다.
