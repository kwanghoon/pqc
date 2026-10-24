CC = gcc
OPENSSL358 ?= $(HOME)/pqc/openssl-3.5.8/install
OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL358)/lib64),$(OPENSSL358)/lib64,$(OPENSSL358)/lib)
WRONG_DIR ?= pqc-wrong-key-test

CPPFLAGS += -I$(OPENSSL358)/include
LDFLAGS += -L$(OPENSSL_LIBDIR)
LDLIBS += -lcrypto

RUN = LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}"

.PHONY: all run clean

all: run

# 서버를 백그라운드로 실행하고 클라이언트 두 개를 실행한 뒤 서버를 종료한다.
# 두 번째 클라이언트는 다른 키를 쓰므로 authentication fails.가 나와야 한다.
run: pqc_client0 pqc_server0
	@rm -rf "$(WRONG_DIR)"; mkdir "$(WRONG_DIR)"; head -c 32 /dev/urandom > "$(WRONG_DIR)/symmKey.sec"
	@$(RUN) ./pqc_server0 & pid=$$!; \
	trap 'kill $$pid 2>/dev/null' EXIT; \
	sleep 1; \
	echo "./pqc_client0"; \
	out=$$($(RUN) ./pqc_client0); echo "$$out"; \
	test "$$out" = "connected." || { echo "pqc_client0 failed"; exit 1; }; \
	echo "(cd $(WRONG_DIR) && ../pqc_client0)   # 다른 키: 실패해야 함"; \
	out=$$(cd "$(WRONG_DIR)" && $(RUN) ../pqc_client0); echo "$$out"; \
	test "$$out" = "authentication fails." || { echo "wrong key was not rejected"; exit 1; }

pqc_client0: pqc_client0.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

pqc_server0: pqc_server0.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf pqc_client0 pqc_server0 pqc-wrong-key-test
