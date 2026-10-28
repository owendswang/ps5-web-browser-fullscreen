# SPDX-License-Identifier: GPL-3.0-or-later
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
SDK_GOALS := $(if $(MAKECMDGOALS),$(filter-out clean profile-tool opcodes jsc-hook,$(MAKECMDGOALS)),all)
ifneq ($(strip $(SDK_GOALS)),)
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

CFLAGS := -Wall -Wextra -O2 -g -DEXPORT_FIXED_PROFILE=0
HOST_CC ?= cc
HEADERS := $(wildcard src/*.h)
SOURCES := src/main.c src/hbc_patch.c
LIBS := -lSceUserService -lSceSystemService
TEST_FLAGS := -Isrc -DFULLSCREEN_SAFE_SCAN=1 -DTEST_HERMES_EXPORT=0 -DTEST_HBC_EXPORT=0 -DTEST_HBC_LIVE_PLAN=1
TEST_ELFS := web-browser-fullscreen-test.elf web-browser-restore-test.elf web-browser-inspect-test.elf

.PHONY: all inspect test profile-tool opcodes jsc-hook clean
all: web-browser-fullscreen.elf web-browser-restore.elf

web-browser-fullscreen.elf: $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LIBS)

web-browser-restore.elf: $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) -DRESTORE=1 -o $@ $(SOURCES) $(LIBS)

inspect: web-browser-inspect.elf
web-browser-inspect.elf: $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) -DLOCATE_ONLY=1 -o $@ $(SOURCES) $(LIBS)

test: $(TEST_ELFS)

web-browser-fullscreen-test.elf: $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(TEST_FLAGS) -o $@ $(SOURCES) $(LIBS)

web-browser-restore-test.elf: $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(TEST_FLAGS) -DRESTORE=1 -o $@ $(SOURCES) $(LIBS)

web-browser-inspect-test.elf: $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(TEST_FLAGS) -DLOCATE_ONLY=1 -o $@ $(SOURCES) $(LIBS)

profile-tool: src/profile_tool.c $(HEADERS)
	$(HOST_CC) -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O2 -Isrc src/profile_tool.c -o profile-tool

opcodes:
	HOST_CC='$(HOST_CC)' python3 src/generate_opcodes.py

jsc-hook:
	python3 src/generate_jsc_hook.py

clean:
	$(RM) web-browser-fullscreen.elf web-browser-restore.elf web-browser-inspect.elf $(TEST_ELFS) profile-tool
