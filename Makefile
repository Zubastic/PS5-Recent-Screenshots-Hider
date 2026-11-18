# recent-screenshots-hider - resident PS5 payload that hides the
# home-screen "Recent Capture" card by re-pointing the
# RecentCaptureService call
# sites (addActionCard/updateActionCard -> removeActionCard) in the
# NPXS40003 (rnps-control-center) Hermes bytecode inside SceShellUI,
# repairs leftovers of the retired patches (gate byte + card type
# string), and
# handles SceShellUI restarts (sysctl find_pid + kqueue NOTE_EXEC
# watch on SceSysCore.elf).

SHELL := /bin/sh

ifeq ($(strip $(PS5_PAYLOAD_SDK)),)
$(error PS5_PAYLOAD_SDK is required, e.g. export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := recent-screenshots-hider.elf

BUILD_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

OBJS := $(patsubst %.c,build/%.o,src/main.c)

# flags proven to compile this payload (procio.h included) cleanly.
# NO -std=c11: __STRICT_ANSI__ hides the __error() declaration
# behind the SDK's errno.h while the errno macro itself stays visible.
CFLAGS := -Os -Wall -Wextra
CFLAGS += -ffunction-sections -fdata-sections -flto
CFLAGS += -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
CFLAGS += -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=700 -ferror-limit=200
CFLAGS += -DRSH_VERSION=\"$(BUILD_VERSION)\"

LDFLAGS := -Wl,--gc-sections -flto
LDADD := -lkernel -lSceNotification -lpthread

all: $(BIN)

build/src/%.o: src/%.c src/procio.h Makefile
	mkdir -p $(dir $@)
	"$(CC)" $(CFLAGS) -c $< -o $@

$(BIN): $(OBJS) Makefile
	"$(CC)" $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)
	"$(STRIP)" --strip-all $@

clean:
	rm -rf build $(BIN)

.PHONY: all clean
