CC = gcc
OPENSSL102 ?= $(HOME)/pqc/openssl-1.0.2u/install
PRIVATE_KEY ?= privKey.pem
PUBLIC_KEY ?= pubKey.pem
SAMPLE_DIR ?= sampledir
TEST_DIR ?= hash-sign-test

CPPFLAGS += -I$(OPENSSL102)/include
LDFLAGS += -L$(OPENSSL102)/lib
LDLIBS += -lcrypto

RUN = LD_LIBRARY_PATH="$(OPENSSL102)/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}"

.PHONY: all run clean

all: run

# 샘플 디렉터리를 복사해서 서명하므로 sampledir의 .hash 파일은 바뀌지 않는다.
# 마지막 단계는 파일을 변조했을 때 검증이 실패하는지 확인한다.
run: hash_sign
	@rm -rf "$(TEST_DIR)"
	@cp -r "$(SAMPLE_DIR)" "$(TEST_DIR)"
	@rm -rf "$(TEST_DIR)/.hash"
	@printf './hash_sign -i "%s" "%s"\n' "$(PRIVATE_KEY)" "$(TEST_DIR)"
	@$(RUN) ./hash_sign -i "$(PRIVATE_KEY)" "$(TEST_DIR)"
	@printf './hash_sign -c "%s" "%s"\n' "$(PUBLIC_KEY)" "$(TEST_DIR)"
	@$(RUN) ./hash_sign -c "$(PUBLIC_KEY)" "$(TEST_DIR)"
	@echo tampered >> "$(TEST_DIR)/file0.txt"
	@printf './hash_sign -c "%s" "%s"   # file0.txt 변조 후 실패해야 함\n' "$(PUBLIC_KEY)" "$(TEST_DIR)"
	@if $(RUN) ./hash_sign -c "$(PUBLIC_KEY)" "$(TEST_DIR)"; then \
	    echo "tampered file was not detected"; exit 1; \
	fi

hash_sign: hash_sign.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf hash_sign hash-sign-test
