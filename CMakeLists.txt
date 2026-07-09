# ============================================================================
# viy — an IDA plugin that emulates analyzed bytes with rax and recovers the
# cross-references the main analysis missed (indirect calls/jumps, jump-table
# targets, computed data accesses).
#
# rax is pulled in HEADER-ONLY (rax.h, for typedefs/constants). librax is NOT
# linked; it is dlopen'd at runtime by src/rax_loader.cpp. This keeps the plugin
# always-loadable: when librax is absent, IDA-native and deobfuscation evidence
# providers remain available.
#
# Build:
#   export IDASDK=/path/to/ida-sdk           # required
#   export IDABIN=/path/to/ida               # optional (plugin install dir)
#   cmake -S . -B build \
#     -DIDA_CMAKE_DIR=/path/to/ida-cmake \
#     -DRAX_CAPI_DIR=/path/to/rax/capi        # contains include/rax.h
#   cmake --build build
# ============================================================================
cmake_minimum_required(VERSION 3.27)
project(viy CXX)

include(CTest)
option(VIY_TEST_SANITIZERS "Build pure viy tests with ASan and UBSan" OFF)
option(VIY_TEST_STRICT_WARNINGS "Treat warnings in IDA-free test targets as errors" ON)
option(VIY_IDA_INTEGRATION_TESTS "Enable licensed real-IDAT integration tests" OFF)
set(VIY_IDAT "" CACHE FILEPATH
    "Path to the IDA text-mode executable used by integration tests")

# --- Locate ida-cmake (bootstrap.cmake + idasdkConfig.cmake live here) --------
if(NOT IDA_CMAKE_DIR)
  if(DEFINED ENV{IDA_CMAKE_DIR})
    set(IDA_CMAKE_DIR "$ENV{IDA_CMAKE_DIR}")
  endif()
endif()
if(NOT IDA_CMAKE_DIR)
  message(FATAL_ERROR
    "ida-cmake location is required. Set -DIDA_CMAKE_DIR=/path/to/ida-cmake "
    "or export IDA_CMAKE_DIR.")
endif()
if(NOT EXISTS "${IDA_CMAKE_DIR}/bootstrap.cmake")
  message(FATAL_ERROR
    "ida-cmake not found at '${IDA_CMAKE_DIR}'. "
    "Set -DIDA_CMAKE_DIR=/path/to/ida-cmake or export IDA_CMAKE_DIR.")
endif()

include("${IDA_CMAKE_DIR}/bootstrap.cmake")  # validates $IDASDK, sets CMAKE_PREFIX_PATH
find_package(idasdk REQUIRED)                 # -> idasdk::plugin + ida_add_plugin()
find_package(Threads REQUIRED)

function(viy_harden_test_target target)
  if(VIY_TEST_STRICT_WARNINGS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror -Wno-cpp)
  endif()
endfunction()

# --- rax C API: header only (dlopen'd at runtime, never linked) ---------------
# Defaults to the vendored submodule (vendor/rax). librax itself is built
# separately (see the Makefile / `cargo build -p rax-capi`); viy only needs the
# header here.
set(RAX_CAPI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/capi" CACHE PATH "rax capi dir (contains include/rax.h)")
if(NOT EXISTS "${RAX_CAPI_DIR}/include/rax.h")
  message(FATAL_ERROR
    "rax.h not found under '${RAX_CAPI_DIR}/include'. "
    "Did you clone submodules? (git submodule update --init) "
    "or set -DRAX_CAPI_DIR=/path/to/rax/capi.")
endif()

# --- The plugin ---------------------------------------------------------------
# ida_add_plugin: positional NAME, links idasdk::plugin
# (brings __IDP__, __EA64__, C++17, PIC, libida), strips the "lib" prefix, and
# installs to ${IDA_PLUGIN_DIR}. Output: viy.dylib / viy.so / viy.dll.
ida_add_plugin(viy
  SOURCES
    src/viy.cpp
    src/rax_loader.cpp
    src/viy_config.cpp
    src/program_model.cpp
    src/program_model_core.cpp
    src/abi_policy.cpp
    src/emu_driver.cpp
    src/emulation_workers.cpp
    src/emulation_rax_executor.cpp
    src/entry_state.cpp
    src/call_summary.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp
    src/evidence_lifecycle.cpp
    src/ida_evidence_store.cpp
    src/evidence_bridge.cpp
    src/evidence_apply_policy.cpp
    src/evidence_apply.cpp
    src/decoder_core.cpp
    src/decoder_audit.cpp
    src/smir_analysis.cpp
    src/hexrays_bridge.cpp
    src/native_analysis.cpp
    src/deobf_analysis_core.cpp
    src/deobf_analysis_store.cpp
    src/deobf_analysis.cpp
    src/runtime_enrich_core.cpp
    src/runtime_enrich.cpp
    src/ref_discovery.cpp
    src/static_decoder.cpp
    src/enrich.cpp
    src/advanced.cpp
  INCLUDES
    "${RAX_CAPI_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# dlopen/dlsym for the runtime librax loader (empty on macOS, -ldl on Linux).
target_link_libraries(viy PRIVATE ${CMAKE_DL_LIBS} Threads::Threads)

if(BUILD_TESTING)
  add_executable(viy_evidence_tests
    tests/evidence_store_test.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp)
  target_include_directories(viy_evidence_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_evidence_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_evidence_tests)

  add_executable(viy_evidence_lifecycle_tests
    tests/evidence_lifecycle_test.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp
    src/evidence_lifecycle.cpp)
  target_include_directories(viy_evidence_lifecycle_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_evidence_lifecycle_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_evidence_lifecycle_tests)

  add_executable(viy_evidence_apply_policy_tests
    tests/evidence_apply_policy_test.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp
    src/evidence_apply_policy.cpp)
  target_include_directories(viy_evidence_apply_policy_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_evidence_apply_policy_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_evidence_apply_policy_tests)

  add_executable(viy_config_tests
    tests/viy_config_test.cpp
    src/viy_config.cpp)
  target_include_directories(viy_config_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_config_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_config_tests)

  add_executable(viy_emulation_worker_tests
    tests/emulation_workers_test.cpp
    src/emulation_workers.cpp)
  target_include_directories(viy_emulation_worker_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${RAX_CAPI_DIR}/include")
  target_compile_features(viy_emulation_worker_tests PRIVATE cxx_std_17)
  target_link_libraries(viy_emulation_worker_tests PRIVATE Threads::Threads)
  viy_harden_test_target(viy_emulation_worker_tests)

  add_executable(viy_emu_evidence_tests
    tests/emu_evidence_test.cpp
    src/abi_policy.cpp
    src/emu_driver.cpp
    src/program_model_core.cpp
    src/rax_loader.cpp
    src/evidence_bridge.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp)
  target_include_directories(viy_emu_evidence_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${RAX_CAPI_DIR}/include")
  target_compile_features(viy_emu_evidence_tests PRIVATE cxx_std_17)
  target_link_libraries(viy_emu_evidence_tests PRIVATE ${CMAKE_DL_LIBS})
  viy_harden_test_target(viy_emu_evidence_tests)

  add_executable(viy_abi_policy_tests
    tests/abi_policy_test.cpp
    src/abi_policy.cpp
    src/program_model_core.cpp)
  target_include_directories(viy_abi_policy_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${RAX_CAPI_DIR}/include")
  target_compile_features(viy_abi_policy_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_abi_policy_tests)

  add_executable(viy_program_model_tests
    tests/program_model_test.cpp
    src/program_model_core.cpp)
  target_include_directories(viy_program_model_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_program_model_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_program_model_tests)

  add_executable(viy_hexrays_bridge_tests
    tests/hexrays_bridge_test.cpp
    src/hexrays_bridge.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp)
  target_include_directories(viy_hexrays_bridge_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_hexrays_bridge_tests PRIVATE cxx_std_17)
  target_compile_definitions(viy_hexrays_bridge_tests PRIVATE VIY_WITH_HEXRAYS_SDK=0)
  viy_harden_test_target(viy_hexrays_bridge_tests)

  add_executable(viy_smir_analysis_tests
    tests/smir_analysis_test.cpp
    src/smir_analysis.cpp
    src/program_model_core.cpp
    src/rax_loader.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp)
  target_include_directories(viy_smir_analysis_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${RAX_CAPI_DIR}/include")
  target_compile_features(viy_smir_analysis_tests PRIVATE cxx_std_17)
  target_link_libraries(viy_smir_analysis_tests PRIVATE ${CMAKE_DL_LIBS})
  viy_harden_test_target(viy_smir_analysis_tests)

  add_executable(viy_decoder_core_tests
    tests/decoder_core_test.cpp
    src/decoder_core.cpp
    src/rax_loader.cpp)
  target_include_directories(viy_decoder_core_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${RAX_CAPI_DIR}/include")
  target_compile_features(viy_decoder_core_tests PRIVATE cxx_std_17)
  target_link_libraries(viy_decoder_core_tests PRIVATE ${CMAKE_DL_LIBS})
  viy_harden_test_target(viy_decoder_core_tests)

  add_executable(viy_deobf_analysis_tests
    tests/deobf_analysis_test.cpp
    src/analysis_facts.cpp
    src/evidence_store.cpp
    src/deobf_analysis_core.cpp
    src/deobf_analysis_store.cpp)
  target_include_directories(viy_deobf_analysis_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(viy_deobf_analysis_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_deobf_analysis_tests)

  add_executable(viy_runtime_enrich_core_tests
    tests/runtime_enrich_core_test.cpp
    src/runtime_enrich_core.cpp)
  target_include_directories(viy_runtime_enrich_core_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${RAX_CAPI_DIR}/include")
  target_compile_features(viy_runtime_enrich_core_tests PRIVATE cxx_std_17)
  viy_harden_test_target(viy_runtime_enrich_core_tests)

  if(VIY_TEST_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(viy_evidence_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_evidence_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_evidence_lifecycle_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_evidence_lifecycle_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_evidence_apply_policy_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_evidence_apply_policy_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_config_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_config_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_emulation_worker_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_emulation_worker_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_emu_evidence_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_emu_evidence_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_abi_policy_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_abi_policy_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_program_model_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_program_model_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_hexrays_bridge_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_hexrays_bridge_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_smir_analysis_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_smir_analysis_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_decoder_core_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_decoder_core_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_deobf_analysis_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_deobf_analysis_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(viy_runtime_enrich_core_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(viy_runtime_enrich_core_tests PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
  endif()
  add_test(NAME viy.evidence COMMAND viy_evidence_tests)
  add_test(NAME viy.evidence_lifecycle COMMAND viy_evidence_lifecycle_tests)
  add_test(NAME viy.evidence_apply_policy COMMAND viy_evidence_apply_policy_tests)
  add_test(NAME viy.config COMMAND viy_config_tests)
  add_test(NAME viy.emulation_workers COMMAND viy_emulation_worker_tests)
  add_test(NAME viy.emu_evidence COMMAND viy_emu_evidence_tests)
  add_test(NAME viy.abi_policy COMMAND viy_abi_policy_tests)
  add_test(NAME viy.program_model COMMAND viy_program_model_tests)
  add_test(NAME viy.hexrays_bridge COMMAND viy_hexrays_bridge_tests)
  add_test(NAME viy.smir_analysis COMMAND viy_smir_analysis_tests)
  add_test(NAME viy.decoder_core COMMAND viy_decoder_core_tests)
  add_test(NAME viy.deobf_analysis COMMAND viy_deobf_analysis_tests)
  add_test(NAME viy.runtime_enrich_core COMMAND viy_runtime_enrich_core_tests)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.dylib")
    set_tests_properties(viy.emu_evidence PROPERTIES ENVIRONMENT
      "VIY_RAX_PATH=${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.dylib;VIY_REQUIRE_RAX_TESTS=1")
  elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.so")
    set_tests_properties(viy.emu_evidence PROPERTIES ENVIRONMENT
      "VIY_RAX_PATH=${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.so;VIY_REQUIRE_RAX_TESTS=1")
  endif()
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.dylib")
    set_tests_properties(viy.smir_analysis PROPERTIES ENVIRONMENT
      "VIY_RAX_PATH=${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.dylib;VIY_REQUIRE_RAX_TESTS=1")
  elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.so")
    set_tests_properties(viy.smir_analysis PROPERTIES ENVIRONMENT
      "VIY_RAX_PATH=${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.so;VIY_REQUIRE_RAX_TESTS=1")
  else()
    set_tests_properties(viy.smir_analysis PROPERTIES SKIP_RETURN_CODE 77)
  endif()
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.dylib")
    set_tests_properties(viy.decoder_core PROPERTIES ENVIRONMENT
      "VIY_RAX_PATH=${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.dylib;VIY_REQUIRE_RAX_TESTS=1")
  elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.so")
    set_tests_properties(viy.decoder_core PROPERTIES ENVIRONMENT
      "VIY_RAX_PATH=${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax/target/release/librax.so;VIY_REQUIRE_RAX_TESTS=1")
  else()
    set_tests_properties(viy.decoder_core PROPERTIES SKIP_RETURN_CODE 77)
  endif()
  if(VIY_IDA_INTEGRATION_TESTS)
    if(NOT VIY_IDAT)
      message(FATAL_ERROR
        "VIY_IDA_INTEGRATION_TESTS=ON requires -DVIY_IDAT=/path/to/idat")
    endif()
    if(NOT EXISTS "${VIY_IDAT}")
      message(FATAL_ERROR "VIY_IDA_INTEGRATION_TESTS=ON but VIY_IDAT does not exist: ${VIY_IDAT}")
    endif()
    add_test(NAME viy.ida_evidence_persistence
      COMMAND "${CMAKE_COMMAND}" -E env
        "IDAT=${VIY_IDAT}"
        "BUILD_DIR=${CMAKE_BINARY_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_ida_evidence_persistence.sh")
    set_tests_properties(viy.ida_evidence_persistence PROPERTIES
      TIMEOUT 180 LABELS "ida;integration;persistence" RUN_SERIAL TRUE)
    add_test(NAME viy.ida_hexrays_bridge
      COMMAND "${CMAKE_COMMAND}" -E env
        "IDAT=${VIY_IDAT}"
        "BUILD_DIR=${CMAKE_BINARY_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_ida_hexrays_bridge.sh")
    set_tests_properties(viy.ida_hexrays_bridge PROPERTIES
      TIMEOUT 60 LABELS "ida;integration;hexrays" RUN_SERIAL TRUE)
  endif()
endif()

# Emit the plugin into the build tree (the Makefile stages librax next to it).
# This overrides ida_add_plugin's default of installing straight into
# IDA_PLUGIN_DIR; use `make install` (or the install target) to deploy.
set_target_properties(viy PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

message(STATUS "viy: IDASDK=$ENV{IDASDK}  ida-cmake=${IDA_CMAKE_DIR}  rax=${RAX_CAPI_DIR}/include (header-only)")
