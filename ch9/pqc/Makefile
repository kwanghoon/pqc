CC = gcc
OPENSSL358 ?= $(HOME)/pqc/openssl-3.5.8/install
OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL358)/lib64),$(OPENSSL358)/lib64,$(OPENSSL358)/lib)
TEST_DIR ?= pqc-tls-test

CPPFLAGS += -I$(OPENSSL358)/include
LDFLAGS += -L$(OPENSSL_LIBDIR)
LDLIBS += -lssl -lcrypto

OSSL = $(OPENSSL358)/bin/openssl
export LD_LIBRARY_PATH := $(OPENSSL_LIBDIR)$(if $(LD_LIBRARY_PATH),:$(LD_LIBRARY_PATH))

.PHONY: all run clean
.ONESHELL:
.SHELLFLAGS = -ec

all: run

# $(TEST_DIR)에 ML-DSA-65 CA와 CN=localhost 서버 인증서를 새로 발급한 뒤 다음을 확인한다.
#  1) 서버와 클라이언트가 TLS 1.3과 하이브리드 ML-KEM 그룹으로 연결한다.
#  2) 다른 CA로 검증하는 클라이언트는 서버 인증서를 거부한다.
#  3) 서버는 ML-DSA-65가 아닌(RSA) 키를 거부한다.
# 서버는 연결 하나를 처리하고 종료하므로 시험마다 새로 띄운다.
run: pqc_ssl_client pqc_ssl_server
	@rm -rf "$(TEST_DIR)"; mkdir -p "$(TEST_DIR)/other" "$(TEST_DIR)/rsa"
	cd "$(TEST_DIR)"
	gen_ca() {
	    $(OSSL) genpkey -algorithm ML-DSA-65 -out CAPriv.pem
	    $(OSSL) req -x509 -new -key CAPriv.pem -subj "/C=KR/O=PQC Test/CN=$$1" -days 365 -out CACert.pem
	}
	gen_ca "PQC Test CA" >/dev/null 2>&1
	$(OSSL) genpkey -algorithm ML-DSA-65 -out BobPriv.pem
	$(OSSL) req -new -key BobPriv.pem -subj "/C=KR/O=PQC Test/CN=localhost" -out BobReq.pem
	$(OSSL) x509 -req -in BobReq.pem -CA CACert.pem -CAkey CAPriv.pem \
	    -CAcreateserial -days 365 -out BobCert.pem >/dev/null 2>&1
	(cd other && gen_ca "Other CA" >/dev/null 2>&1)
	(cd rsa && $(OSSL) req -x509 -newkey rsa:2048 -nodes -keyout BobPriv.pem \
	    -subj "/CN=localhost" -days 365 -out BobCert.pem >/dev/null 2>&1)
	spid=
	trap 'kill $$spid 2>/dev/null || true' EXIT
	echo "../pqc_ssl_server &"
	../pqc_ssl_server > server.log 2>&1 &
	spid=$$!
	sleep 1
	echo "../pqc_ssl_client"
	../pqc_ssl_client | tee client.log
	wait $$spid
	grep -q "Negotiated: TLSv1.3, group .*MLKEM" client.log
	grep -q "Connection Established" client.log
	echo "(cd other && ../../pqc_ssl_client)   # 다른 CA: 실패해야 함"
	../pqc_ssl_server > server.log 2>&1 &
	spid=$$!
	sleep 1
	if (cd other && ../../pqc_ssl_client); then
	    echo "untrusted server certificate was accepted"; exit 1
	fi
	wait $$spid || true
	echo "(cd rsa && ../../pqc_ssl_server)   # RSA 키: 거부되어야 함"
	if (cd rsa && ../../pqc_ssl_server); then
	    echo "RSA key was accepted"; exit 1
	fi

pqc_ssl_client: pqc_ssl_client.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

pqc_ssl_server: pqc_ssl_server.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf pqc_ssl_client pqc_ssl_server pqc-tls-test
