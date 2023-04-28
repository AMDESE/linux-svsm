# SPDX-License-Identifier: MIT

OBJCOPY		= objcopy

SVSM_BIN	:= svsm.bin
CPL0_BIN	:= cpl0.bin
CPL3_BIN	:= cpl3.bin

CPL0_ELF	:= cpl0/$(CPL0_BIN).elf
CPL3_ELF	:= cpl3/$(CPL3_BIN).elf

FEATURES	:= ""

## Memory layout
SVSM_GPA	:= 0x8000000000
SVSM_MEM	:= 0x10000000

.PHONY: all cpl0 cpl3 doc prereq clean superclean

all: .prereq $(SVSM_BIN)

doc: .prereq
	$(MAKE) -C cpl0 $@
	$(MAKE) -C cpl3 $@

$(SVSM_BIN): $(CPL0_BIN) $(CPL3_BIN)
	cat $(CPL0_BIN) $(CPL3_BIN) > $@
	chmod +x svsm.bin

$(CPL0_BIN): $(CPL3_BIN) cpl0
	objcopy -g -O binary $(CPL0_ELF) $@

cpl0:
	$(eval CPL3_SIZE := $(shell stat -c %s $(CPL3_BIN)))

ifeq ($(strip $(FEATURES)),)
	$(MAKE) -C cpl0 SVSM_GPA=$(SVSM_GPA) SVSM_MEM=$(SVSM_MEM) \
		CPL3_SIZE=$(CPL3_SIZE) all FEATURES=$(FEATURES)
else

	$(MAKE) -C cpl0 SVSM_GPA=$(SVSM_GPA) SVSM_MEM=$(SVSM_MEM) \
		CPL3_SIZE=$(CPL3_SIZE) all
endif

$(CPL3_BIN): cpl3
	objcopy -g -O binary $(CPL3_ELF) $@

cpl3:
ifeq ($(strip $(FEATURES)),)
	$(MAKE) -C cpl3 all FEATURES=$(FEATURES)
else
	$(MAKE) -C cpl3 all
endif

prereq: .prereq

.prereq:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	source $(HOME)/.cargo/env
	echo "source $(HOME)/.cargo/env" >> ~/.bashrc
	rustup component add rust-src
	rustup component add llvm-tools-preview
	cargo install xargo
	cargo install bootimage
	touch .prereq

clean:
	$(MAKE) -C cpl0 $@
	$(MAKE) -C cpl3 $@
	rm -f $(SVSM_BIN) $(CPL0_BIN) $(CPL3_BIN)

superclean: clean
	rm -f .prereq
