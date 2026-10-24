CC = gcc
OPENSSL358 ?= $(HOME)/pqc/openssl-3.5.8/install
OPENSSL_LIBDIR ?= $(if $(wildcard $(OPENSSL358)/lib64),$(OPENSSL358)/lib64,$(OPENSSL358)/lib)
PRIVATE_KEY ?= mldsa_priv.pem
PUBLIC_KEY ?= mldsa_pub.pem
SAMPLE_DIR ?= sampledir
TEST_DIR ?= pqc-hash-sign-test

CPPFLAGS += -I$(OPENSSL358)/include
LDFLAGS += -L$(OPENSSL_LIBDIR)
LDLIBS += -lcrypto

RUN = LD_LIBRARY_PATH="$(OPENSSL_LIBDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}"

.PHONY: all run clean

all: run

# 샘플 디렉터리를 복사해서 서명하므로 sampledir의 .hash 파일은 바뀌지 않는다.
# 마지막 단계는 파일을 변조했을 때 검증이 실패하는지 확인한다.
run: pqc_hash_sign
	@rm -rf "$(TEST_DIR)"
	@cp -r "$(SAMPLE_DIR)" "$(TEST_DIR)"
	@rm -rf "$(TEST_DIR)/.hash"
	@printf './pqc_hash_sign -i "%s" "%s"\n' "$(PRIVATE_KEY)" "$(TEST_DIR)"
	@$(RUN) ./pqc_hash_sign -i "$(PRIVATE_KEY)" "$(TEST_DIR)"
	@printf './pqc_hash_sign -c "%s" "%s"\n' "$(PUBLIC_KEY)" "$(TEST_DIR)"
	@$(RUN) ./pqc_hash_sign -c "$(PUBLIC_KEY)" "$(TEST_DIR)"
	@echo tampered >> "$(TEST_DIR)/file0.txt"
	@printf './pqc_hash_sign -c "%s" "%s"   # file0.txt 변조 후 실패해야 함\n' "$(PUBLIC_KEY)" "$(TEST_DIR)"
	@if $(RUN) ./pqc_hash_sign -c "$(PUBLIC_KEY)" "$(TEST_DIR)"; then \
	    echo "tampered file was not detected"; exit 1; \
	fi

pqc_hash_sign: pqc_hash_sign.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -rf pqc_hash_sign pqc-hash-sign-test
