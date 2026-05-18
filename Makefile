# CITS3007 Phase 2 — Reproduction Package Makefile
# Target: Group 40
#
# How to use:
#   1. Unzip Group 40's phase 1 source into a folder called `target/`
#      (so you end up with target/bun_parse.c, target/main.c, etc.)
#   2. Run:  make reproduce
#
# That will build the parser with ASan + UBSan, generate the fixture files,
# run each one, and print [PASS] or [FAIL] for each finding.

CC            = gcc
CUSTOM_CFLAGS = -std=c11 -fsanitize=address,undefined -fno-omit-frame-pointer -g -O2

PARSER        = ./bun_parser_asan
TARGET_DIR    = target

.PHONY: all reproduce rebuild_target gen_fixtures clean

all: reproduce

# step 1: build the target parser with sanitizers
rebuild_target:
	@echo "==> Building group-40 parser with ASan + UBSan..."
	@test -d $(TARGET_DIR) || \
	    (echo "ERROR: $(TARGET_DIR)/ not found. Unzip group-40 source there first." && exit 1)
	cd $(TARGET_DIR) && make CFLAGS="$(CUSTOM_CFLAGS)" all
	cp $(TARGET_DIR)/bun_parser $(PARSER)
	@echo "    Built: $(PARSER)"

# step 2: generate the crafted .bun fixture files
gen_fixtures:
	@echo "==> Generating fixture files..."
	python3 gen_fixtures.py
	@echo "    Done."

# step 3: run all findings and report results
reproduce: rebuild_target gen_fixtures
	@echo ""
	@echo "================================================================="
	@echo " CITS3007 Phase 2 — Reproduction Tests (target: Group 40)"
	@echo "================================================================="
	@PASS=0; FAIL=0; \
	\
	echo ""; \
	echo "-----------------------------------------------------------------"; \
	echo " F-01  u64 overflow lets bad data_offset bypass bounds check"; \
	echo "       (Spec §9.5 — asset data must lie within the data section)"; \
	echo "-----------------------------------------------------------------"; \
	echo " Input: tests/fixtures/f01_data_overflow.bun"; \
	$(PARSER) tests/fixtures/f01_data_overflow.bun 2>/dev/null; \
	CODE=$$?; \
	echo " Exit code: $$CODE  (expected: 1 = BUN_MALFORMED)"; \
	if [ $$CODE -eq 0 ]; then \
	    echo " RESULT: [FAIL] Finding F-01 TRIGGERED — parser exited BUN_OK (0) for a malformed file"; \
	    FAIL=$$((FAIL+1)); \
	elif [ $$CODE -eq 1 ]; then \
	    echo " RESULT: [PASS] Finding F-01 not triggered (parser correctly returned BUN_MALFORMED)"; \
	    PASS=$$((PASS+1)); \
	else \
	    echo " RESULT: [FAIL] Unexpected exit code $$CODE (expected 1)"; \
	    FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "-----------------------------------------------------------------"; \
	echo " F-02  RLE size mismatch returns wrong exit code (3 not 1)"; \
	echo "       (Spec §5.1 note 4 — size mismatch must return BUN_MALFORMED)"; \
	echo "-----------------------------------------------------------------"; \
	echo " Input: tests/fixtures/f02_rle_mismatch.bun"; \
	$(PARSER) tests/fixtures/f02_rle_mismatch.bun 2>/dev/null; \
	CODE=$$?; \
	echo " Exit code: $$CODE  (expected: 1 = BUN_MALFORMED, actual bug: 3 = BUN_ERR_IO)"; \
	if [ $$CODE -eq 3 ]; then \
	    echo " RESULT: [FAIL] Finding F-02 TRIGGERED — parser returned BUN_ERR_IO (3) instead of BUN_MALFORMED (1)"; \
	    FAIL=$$((FAIL+1)); \
	elif [ $$CODE -eq 1 ]; then \
	    echo " RESULT: [PASS] Finding F-02 not triggered (parser correctly returned BUN_MALFORMED)"; \
	    PASS=$$((PASS+1)); \
	else \
	    echo " RESULT: [FAIL] Unexpected exit code $$CODE (expected 1)"; \
	    FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "-----------------------------------------------------------------"; \
	echo " F-03  data section overlapping header not detected"; \
	echo "       (Spec §9.3 — no two sections may overlap, header included)"; \
	echo "-----------------------------------------------------------------"; \
	echo " Input: tests/fixtures/f03_header_overlap.bun"; \
	$(PARSER) tests/fixtures/f03_header_overlap.bun 2>/dev/null; \
	CODE=$$?; \
	echo " Exit code: $$CODE  (expected: 1 = BUN_MALFORMED)"; \
	if [ $$CODE -eq 0 ]; then \
	    echo " RESULT: [FAIL] Finding F-03 TRIGGERED — parser exited BUN_OK (0) for a file with data section overlapping the header"; \
	    FAIL=$$((FAIL+1)); \
	elif [ $$CODE -eq 1 ]; then \
	    echo " RESULT: [PASS] Finding F-03 not triggered (parser correctly returned BUN_MALFORMED)"; \
	    PASS=$$((PASS+1)); \
	else \
	    echo " RESULT: [FAIL] Unexpected exit code $$CODE (expected 1)"; \
	    FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "================================================================="; \
	echo " Summary: $$FAIL finding(s) triggered, $$PASS passed"; \
	echo "================================================================="; \
	exit $$FAIL

clean:
	-rm -f $(PARSER)
	-rm -f tests/fixtures/f01_data_overflow.bun \
	        tests/fixtures/f02_rle_mismatch.bun \
	        tests/fixtures/f03_header_overlap.bun
	-cd $(TARGET_DIR) && make clean 2>/dev/null; true
