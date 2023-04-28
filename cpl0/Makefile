# SPDX-License-Identifier: MIT

GCC		= gcc

SHELL		:= /bin/bash

A_FLAGS		:= -D__ASSEMBLY__ -I../include

C_FLAGS		:= -g -O2 -I../include
C_FLAGS		+= -m64 -march=x86-64 -mno-sse2
C_FLAGS		+= -fno-stack-protector
C_FLAGS		+= -ffreestanding
C_FLAGS		+= -Wall -Wstrict-prototypes -Wno-address-of-packed-member

LD_SCRIPT	:= src/start/cpl0.lds

LD_FLAGS	:= -m64
LD_FLAGS	+= -nostdlib
LD_FLAGS	+= -Wl,-T$(LD_SCRIPT) -Wl,--build-id=none

LDS_FLAGS	:= -DSVSM_GPA="$(SVSM_GPA)"
LDS_FLAGS	+= -DSVSM_MEM="$(SVSM_MEM)"
LDS_FLAGS	+= -DCPL3_SIZE="$(CPL3_SIZE)"

TARGET_DIR	:= target
TARGET		:= $(TARGET_DIR)/svsm-target/debug

OBJS		:= src/start/start.o
OBJS		+= src/cpu/syscall.o
OBJS		+= $(TARGET)/libsvsm_cpl0.a

ELF_FILE	:= cpl0.bin.elf

EXT_LIBS := external/libcrt/libcrt.a
EXT_LIBS += external/openssl/libcrypto.a

.PHONY: all doc prereq clean clean_all superclean libcrt libcrypto

all: .prereq libcrt libcrypto cpl0.bin

doc: .prereq
	cargo doc --open

external/libcrt/libcrt.a: libcrt

libcrt:
	$(MAKE) -C external/libcrt

external/openssl/libcrypto.a: libcrypto

libcrypto: external/openssl/Makefile libcrt
	$(MAKE) -C external/openssl -j$$(nproc)

cpl0.bin: cpl0.bin.elf
	objcopy -g -O binary $< $@

# "-Wl,-u,malloc" prevents the linker from removing the wrapper.rs symbols
cpl0.bin.elf: $(EXT_LIBS) $(OBJS) $(LD_SCRIPT)
	$(GCC) $(LD_FLAGS) -o $@ $(OBJS) -Wl,-u,malloc -Wl,--start-group $(EXT_LIBS) -Wl,--end-group

%.a: src/*.rs src/cpu/*.rs src/mem/*.rs src/protocols/*.rs src/util/*.rs
ifeq ($(strip $(FEATURES)),)
	@xargo build
else
	@xargo build --features $(FEATURES)
endif

%.o: %.S ../include/svsm.h
	$(GCC) $(C_FLAGS) $(LDS_FLAGS) $(A_FLAGS) -c -o $@ $<

%.lds: %.lds.S ../include/svsm.h
	$(GCC) $(A_FLAGS) $(LDS_FLAGS) -E -P -o $@ $<

test:
ifeq ($(strip $(FEATURES)),)
	cargo test --target=x86_64-unknown-linux-gnu -Z build-std
else
	cargo test --features $(FEATURES) --target=x86_64-unknown-linux-gnu -Z build-std
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

external/openssl/Makefile:
	git submodule update --init
	(cd external/openssl && git checkout OpenSSL_1_1_1q  && \
		./Configure \
			--config=../openssl_svsm.conf \
			SVSM \
			no-afalgeng \
			no-async \
			no-autoerrinit \
			no-autoload-config \
			no-bf \
			no-blake2 \
			no-capieng \
			no-cast \
			no-chacha \
			no-cms \
			no-ct \
			no-deprecated \
			no-des \
			no-dgram \
			no-dsa \
			no-dynamic-engine \
			no-ec2m \
			no-engine \
			no-err \
			no-filenames \
			no-gost \
			no-hw \
			no-idea \
			no-md4 \
			no-mdc2 \
			no-pic \
			no-ocb \
			no-poly1305 \
			no-posix-io \
			no-rc2 \
			no-rc4 \
			no-rfc3779 \
			no-rmd160 \
			no-scrypt \
			no-seed \
			no-sock \
			no-srp \
			no-ssl \
			no-stdio \
			no-threads \
			no-ts \
			no-whirlpool \
			no-shared \
			no-sse2 \
			no-ui-console \
			no-asm \
			--with-rand-seed=none \
			-I../libcrt/include \
			-Wl,rpath=../libcrt -lcrt )

clean:
	@xargo clean 
	rm -f cpl0.bin cpl0.bin.elf $(OBJS)
	rm -rf $(TARGET_DIR)
	rm -f $(LD_SCRIPT)

clean_all: clean
	$(MAKE) -C external/libcrt clean
	$(MAKE) -C external/openssl clean

superclean: clean_all
	rm -f .prereq

