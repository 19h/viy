# ============================================================================
# viy — an IDA plugin that emulates analyzed bytes with rax and recovers the
# cross-references the main analysis missed (indirect calls/jumps, jump-table
# targets, computed data accesses).
#
# rax is pulled in HEADER-ONLY (rax.h, for typedefs/constants). librax is NOT
# linked; it is dlopen'd at runtime by src/rax_loader.cpp. This keeps the plugin
# always-loadable: when librax is absent, viy is a silent no-op.
#
# Build:
#   export IDASDK=/path/to/ida-sdk           # required
#   export IDABIN=/path/to/ida               # optional (plugin install dir)
#   cmake -S . -B build \
#     -DIDA_CMAKE_DIR=/path/to/ida-cmake \    # kvasir's ida-cmake checkout
#     -DRAX_CAPI_DIR=/path/to/rax/capi        # contains include/rax.h
#   cmake --build build
# ============================================================================
cmake_minimum_required(VERSION 3.27)
project(viy CXX)

# --- Locate ida-cmake (bootstrap.cmake + idasdkConfig.cmake live here) --------
if(NOT IDA_CMAKE_DIR)
  if(DEFINED ENV{IDA_CMAKE_DIR})
    set(IDA_CMAKE_DIR "$ENV{IDA_CMAKE_DIR}")
  else()
    set(IDA_CMAKE_DIR "/Users/int/hexrays/kvasir/ida-cmake")
  endif()
endif()
if(NOT EXISTS "${IDA_CMAKE_DIR}/bootstrap.cmake")
  message(FATAL_ERROR
    "ida-cmake not found at '${IDA_CMAKE_DIR}'. "
    "Set -DIDA_CMAKE_DIR=/path/to/ida-cmake (kvasir's checkout).")
endif()

include("${IDA_CMAKE_DIR}/bootstrap.cmake")  # validates $IDASDK, sets CMAKE_PREFIX_PATH
find_package(idasdk REQUIRED)                 # -> idasdk::plugin + ida_add_plugin()

# --- rax C API: header only (dlopen'd at runtime, never linked) ---------------
set(RAX_CAPI_DIR "/Users/int/dev/rax/capi" CACHE PATH "rax capi dir (contains include/rax.h)")
if(NOT EXISTS "${RAX_CAPI_DIR}/include/rax.h")
  message(FATAL_ERROR
    "rax.h not found under '${RAX_CAPI_DIR}/include'. "
    "Set -DRAX_CAPI_DIR=/path/to/rax/capi.")
endif()

# --- The plugin ---------------------------------------------------------------
# ida_add_plugin (kvasir/ida-cmake): positional NAME, links idasdk::plugin
# (brings __IDP__, __EA64__, C++17, PIC, libida), strips the "lib" prefix, and
# installs to ${IDA_PLUGIN_DIR}. Output: viy.dylib / viy.so / viy.dll.
ida_add_plugin(viy
  SOURCES
    src/viy.cpp
    src/rax_loader.cpp
    src/viy_config.cpp
    src/program_model.cpp
    src/emu_driver.cpp
    src/ref_discovery.cpp
    src/static_decoder.cpp
  INCLUDES
    "${RAX_CAPI_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# dlopen/dlsym for the runtime librax loader (empty on macOS, -ldl on Linux).
target_link_libraries(viy PRIVATE ${CMAKE_DL_LIBS})

message(STATUS "viy: IDASDK=$ENV{IDASDK}  ida-cmake=${IDA_CMAKE_DIR}  rax=${RAX_CAPI_DIR}/include (header-only)")
