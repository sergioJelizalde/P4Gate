# SPDX-License-Identifier: BSD-3-Clause
# P4Gate on the BlueField-3 (DPDK): parse, registers, LLR, small forest, gate, boosted trees only for DEFER.   make ; sudo ./build/p4gate_nic -l 0-3 -a <pci> -- --gate score --ts hw --out nic_only
APP = p4gate_nic
SRCS-y := main.c
PKGCONF ?= pkg-config
MCPU ?=

ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 -std=gnu11 -DALLOW_EXPERIMENTAL_API $(MCPU) $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lm
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lm

build/$(APP)-shared: $(SRCS-y) core.h gate.h rf_model.h gbt_model.h p4gate_llr.h p4gate_consts.h Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) core.h gate.h rf_model.h gbt_model.h p4gate_llr.h p4gate_consts.h Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true
