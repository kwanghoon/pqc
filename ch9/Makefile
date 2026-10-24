CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install
TEST_DIR ?= tls-test

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lssl -lcrypto -ldl -lpthread

OSSL = $(OPENSSL102)/bin/openssl

.PHONY: all run clean
.ONESHELL:
.SHELLFLAGS = -ec

all: run

# $(TEST_DIR)에 CA와 CN=localhost 서버 인증서(RSA)를 새로 발급한 뒤 다음을 확인한다.
#  1) 서버와 클라이언트가 TLS 연결에 성공한다.
#  2) 다른 CA로 검증하는 클라이언트는 서버 인증서를 거부한다.
# 서버는 연결 하나를 처리하고 종료하므로 시험마다 새로 띄운다.
run: ssl_client ssl_server
	@rm -rf "$(TEST_DIR)"; mkdir -p "$(TEST_DIR)/other"
	cd "$(TEST_DIR)"
	gen_ca() {
	    $(OSSL) genrsa -out CAPriv.pem 2048
	    $(OSSL) req -new -key CAPriv.pem -subj "/C=KR/O=Test/CN=$$1" -out CAReq.pem
	    $(OSSL) x509 -req -days 365 -in CAReq.pem -signkey CAPriv.pem -out CACert.pem
	}
	gen_ca "Test CA" >/dev/null 2>&1
	$(OSSL) genrsa -out BobPriv.pem 2048 >/dev/null 2>&1
	$(OSSL) req -new -key BobPriv.pem -subj "/C=KR/O=Test/CN=localhost" -out BobReq.pem
	$(OSSL) x509 -req -days 365 -in BobReq.pem -CA CACert.pem -CAkey CAPriv.pem \
	    -CAcreateserial -out BobCert.pem >/dev/null 2>&1
	(cd other && gen_ca "Other CA" >/dev/null 2>&1)
	spid=
	trap 'kill $$spid 2>/dev/null || true' EXIT
	echo "../ssl_server &"
	../ssl_server > server.log 2>&1 &
	spid=$$!
	sleep 1
	echo "../ssl_client"
	../ssl_client | tee client.log
	wait $$spid
	grep -q "Connection Established" client.log
	echo "(cd other && ../../ssl_client)   # 다른 CA: 실패해야 함"
	../ssl_server > server.log 2>&1 &
	spid=$$!
	sleep 1
	if (cd other && ../../ssl_client); then
	    echo "untrusted server certificate was accepted"; exit 1
	fi
	wait $$spid || true

ssl_client: ssl_client.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

ssl_server: ssl_server.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf ssl_client ssl_server tls-test
