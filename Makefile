# viy build helper — builds librax (from the vendored rax submodule) and the viy
# plugin, staging both artifacts into ./build, and can deploy them into IDA.
#
#   make                 # build librax + viy into ./build
#   make install         # deploy into $PLUGIN_DIR (or the per-user IDA plugins dir)
#   make install-app     # deploy into $IDABIN/plugins
#   make clean
#
# Required env:
#   IDASDK   path to the IDA SDK (for building the plugin)
# Optional env:
#   IDABIN         IDA install dir (for `make install-app`)
#   IDAUSR         per-user IDA root (first entry; used by `make install`)
#   PLUGIN_DIR     explicit user-plugin destination for `make install`
#   IDA_CMAKE_DIR  ida-cmake checkout (or set it in the environment)
#   BUILD_DIR      output dir (default: build)
#   DEBUG=1        Debug build

BUILD_DIR ?= build
DEBUG     ?= 0
CMAKE_FLAGS ?=
RAX_DIR   := $(CURDIR)/vendor/rax
RAX_TARGET_DIR := $(RAX_DIR)/target/release

ifeq ($(DEBUG),1)
BUILD_TYPE := Debug
else
BUILD_TYPE := Release
endif

# Platform artifact names.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
RAX_LIB := librax.dylib
VIY_LIB := viy.dylib
else
RAX_LIB := librax.so
VIY_LIB := viy.so
endif

IDA_CMAKE_FLAG := $(if $(IDA_CMAKE_DIR),-DIDA_CMAKE_DIR=$(IDA_CMAKE_DIR),)

# Per-user IDA directory — where user plugins live (no write access to the IDA
# install needed, survives IDA upgrades). Honors $IDAUSR (first of its ':'-list),
# else the platform default (~/.idapro on macOS/Linux). Override with PLUGIN_DIR.
ifeq ($(strip $(IDAUSR)),)
IDA_USER_DIR := $(HOME)/.idapro
else
IDA_USER_DIR := $(firstword $(subst :, ,$(IDAUSR)))
endif
PLUGIN_DIR ?= $(IDA_USER_DIR)/plugins

.PHONY: all build rax viy configure test test-ida install install-app submodules clean distclean help

all: build

## build: librax + viy, both staged into $(BUILD_DIR)
build: rax viy

## submodules: ensure the vendored rax is present
submodules:
	@test -f "$(RAX_DIR)/capi/include/rax.h" || git submodule update --init --depth 1 vendor/rax

## rax: build librax via cargo and stage it into $(BUILD_DIR)
rax: submodules
	cargo build -p rax-capi --release --manifest-path "$(RAX_DIR)/Cargo.toml"
	@mkdir -p "$(BUILD_DIR)"
	cp "$(RAX_TARGET_DIR)/$(RAX_LIB)" "$(BUILD_DIR)/$(RAX_LIB)"
	@echo "staged $(BUILD_DIR)/$(RAX_LIB)"

## configure: run CMake for the plugin (needs $IDASDK)
configure: submodules
	@test -n "$(IDASDK)" || { echo "error: set IDASDK=/path/to/ida-sdk"; exit 1; }
	cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(IDA_CMAKE_FLAG) $(CMAKE_FLAGS)

## viy: build the plugin into $(BUILD_DIR)
viy: configure
	cmake --build "$(BUILD_DIR)" --parallel
	@echo "staged $(BUILD_DIR)/$(VIY_LIB)"

## test: rax C-ABI tests plus all IDA-free viy CTest targets
test: build
	cargo test -p rax-capi --manifest-path "$(RAX_DIR)/Cargo.toml"
	ctest --test-dir "$(BUILD_DIR)" --output-on-failure

## test-ida: licensed real-IDAT evidence persistence/corruption recovery test
test-ida: build
	BUILD_DIR="$(abspath $(BUILD_DIR))" tests/run_ida_evidence_persistence.sh

# viy.dylib goes directly in plugins/ (IDA loads it); librax.dylib goes in a
# plugins/viy/ subdir so IDA does NOT try to load it as a plugin. The loader
# finds it there (companion_dir search).
define install_to
	mkdir -p "$(1)/viy"
	cp "$(BUILD_DIR)/$(VIY_LIB)" "$(1)/$(VIY_LIB)"
	cp "$(BUILD_DIR)/$(RAX_LIB)" "$(1)/viy/$(RAX_LIB)"
	rm -f "$(1)/$(RAX_LIB)"   # remove any librax left in plugins/ by an older install
	@echo "installed $(VIY_LIB) -> $(1) ; $(RAX_LIB) -> $(1)/viy"
endef

## install: deploy into the user IDA plugins dir (~/.idapro/plugins by default)
install: build
	$(call install_to,$(PLUGIN_DIR))

## install-app: deploy into the IDA *install* dir instead ($IDABIN/plugins)
install-app: build
	@test -n "$(IDABIN)" || { echo "error: set IDABIN=/path/to/ida"; exit 1; }
	$(call install_to,$(IDABIN)/plugins)

## clean: remove the build directory
clean:
	rm -rf "$(BUILD_DIR)"

## distclean: also clean the rax cargo target
distclean: clean
	-cargo clean --manifest-path "$(RAX_DIR)/Cargo.toml"

help:
	@echo "viy build helper"
	@echo "  make               build librax + viy into ./$(BUILD_DIR)"
	@echo "  make rax           build + stage librax only"
	@echo "  make viy           build + stage the plugin only"
	@echo "  make install       deploy viy + librax into $(PLUGIN_DIR)"
	@echo "  make install-app   deploy into the IDA install dir (\$$IDABIN/plugins)"
	@echo "  make test          run rax ABI and IDA-free viy tests"
	@echo "  make test-ida      run the licensed real-IDAT recovery integration test"
	@echo "  make clean         remove ./$(BUILD_DIR)"
	@echo ""
	@echo "Env: IDASDK (required to build), IDAUSR or PLUGIN_DIR (install location),"
	@echo "     IDABIN (for install-app), IDA_CMAKE_DIR, BUILD_DIR (default build), DEBUG=1"
