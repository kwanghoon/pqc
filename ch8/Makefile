CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install
WRONG_DIR ?= wrong-key-test

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lcrypto

RUN = LD_LIBRARY_PATH="$(OPENSSL102)/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}"

.PHONY: all run clean

all: run

# 서버를 백그라운드로 실행하고 클라이언트 두 개를 실행한 뒤 서버를 종료한다.
# 두 번째 클라이언트는 다른 키를 쓰므로 authentication fails.가 나와야 한다.
run: client0 server0
	@rm -rf "$(WRONG_DIR)"; mkdir "$(WRONG_DIR)"; printf 'wrongkey' > "$(WRONG_DIR)/symmKey.sec"
	@$(RUN) ./server0 & pid=$$!; \
	trap 'kill $$pid 2>/dev/null' EXIT; \
	sleep 1; \
	echo "./client0"; \
	out=$$($(RUN) ./client0); echo "$$out"; \
	test "$$out" = "connected." || { echo "client0 failed"; exit 1; }; \
	echo "(cd $(WRONG_DIR) && ../client0)   # 다른 키: 실패해야 함"; \
	out=$$(cd "$(WRONG_DIR)" && $(RUN) ../client0); echo "$$out"; \
	test "$$out" = "authentication fails." || { echo "wrong key was not rejected"; exit 1; }

client0: client0.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

server0: server0.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf client0 server0 wrong-key-test
