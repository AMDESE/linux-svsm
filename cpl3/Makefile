# SPDX-License-Identifier: MIT

GCC		= gcc

SHELL		:= /bin/bash

A_FLAGS		:= -D__ASSEMBLY__ -I../include

C_FLAGS		:= -g -O2 -I../include
C_FLAGS		+= -m64 -march=x86-64 -mno-sse2
C_FLAGS		+= -fno-stack-protector
C_FLAGS		+= -ffreestanding
C_FLAGS		+= -Wall -Wstrict-prototypes -Wno-address-of-packed-member

LD_SCRIPT	:= src/start/cpl3.lds

LD_FLAGS	:= -m64
LD_FLAGS	+= -nostdlib
LD_FLAGS	+= -Wl,-T$(LD_SCRIPT) -Wl,--build-id=none

LDS_FLAGS	+= -DSVSM_GPA="$(SVSM_GPA)"
LDS_FLAGS	+= -DSVSM_MEM="$(SVSM_MEM)"

TARGET_DIR	:= target
TARGET		:= $(TARGET_DIR)/svsm-target/debug

OBJS		:= src/start/start.o
OBJS		+= $(TARGET)/libsvsm_cpl3.a

ELF_FILE	:= cpl3.bin.elf

FEATURES	:= ""

.PHONY: all doc clean

all: $(ELF_FILE)

doc:
	cargo doc --open

$(ELF_FILE): $(OBJS) $(LD_SCRIPT)
	$(GCC) $(LD_FLAGS) -o $@ $(OBJS)

%.a: src/*.rs
	@xargo build --features $(FEATURES)

%.o: %.S ../include/svsm.h
	$(GCC) $(C_FLAGS) $(LDS_FLAGS) $(A_FLAGS) -c -o $@ $<

%.lds: %.lds.S ../include/svsm.h
	$(GCC) $(A_FLAGS) $(LDS_FLAGS) -E -P -o $@ $<

clean:
	@xargo clean 
	rm -f $(ELF_FILE) $(OBJS) $(LD_SCRIPT)
	rm -rf $(TARGET_DIR)
