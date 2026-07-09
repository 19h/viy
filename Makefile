# viy build helper — builds librax (from the vendored rax submodule) and the viy
# plugin, staging both artifacts into ./build, and can deploy them into IDA.
#
#   make                 # build librax + viy into ./build
#   make install         # deploy build/viy.* and build/librax.* into $IDABIN/plugins
#   make clean
#
# Required env:
#   IDASDK   path to the IDA SDK (for building the plugin)
# Optional env:
#   IDABIN         IDA install dir (for `make install`)
#   IDA_CMAKE_DIR  ida-cmake checkout (else the CMakeLists default is used)
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

.PHONY: all build rax viy configure install install-ida-folder submodules clean distclean help

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

## install: deploy the plugin AND librax into $IDABIN/plugins (librax next to viy)
install: build
	@test -n "$(IDABIN)" || { echo "error: set IDABIN=/path/to/ida"; exit 1; }
	mkdir -p "$(IDABIN)/plugins"
	cp "$(BUILD_DIR)/$(VIY_LIB)" "$(IDABIN)/plugins/$(VIY_LIB)"
	cp "$(BUILD_DIR)/$(RAX_LIB)" "$(IDABIN)/plugins/$(RAX_LIB)"
	@echo "installed $(VIY_LIB) + $(RAX_LIB) -> $(IDABIN)/plugins"

## install-ida-folder: deploy viy into plugins/ but librax into the IDA folder
install-ida-folder: build
	@test -n "$(IDABIN)" || { echo "error: set IDABIN=/path/to/ida"; exit 1; }
	mkdir -p "$(IDABIN)/plugins"
	cp "$(BUILD_DIR)/$(VIY_LIB)" "$(IDABIN)/plugins/$(VIY_LIB)"
	cp "$(BUILD_DIR)/$(RAX_LIB)" "$(IDABIN)/$(RAX_LIB)"
	@echo "installed $(VIY_LIB) -> $(IDABIN)/plugins ; $(RAX_LIB) -> $(IDABIN)"

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
	@echo "  make install       deploy viy + librax into \$$IDABIN/plugins"
	@echo "  make install-ida-folder  deploy viy into plugins/, librax into the IDA folder"
	@echo "  make clean         remove ./$(BUILD_DIR)"
	@echo ""
	@echo "Env: IDASDK (required to build the plugin), IDABIN (for install),"
	@echo "     IDA_CMAKE_DIR, BUILD_DIR (default build), DEBUG=1"
