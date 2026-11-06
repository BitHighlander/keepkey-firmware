# Explicit research overlay for the same libkkemu FFI lifecycle the Vault uses.
# The normal emulator/device configuration never loads this file.
function(monero_native_emulator_overlay)
  if(NOT KK_EMULATOR OR NOT KK_BUILD_DYLIB OR NOT KK_MONERO_EMULATOR_SELFTEST)
    message(FATAL_ERROR "Monero emulator overlay requires explicit emulator+dylib+selftest")
  endif()
  if(NOT EXISTS "${KK_MONERO_VECTOR_DIR}/interop_vectors.h")
    message(FATAL_ERROR "missing generated public reference fixtures")
  endif()
  target_compile_options(trezorcrypto PRIVATE -UUSE_MONERO -DUSE_MONERO=1)
  target_sources(trezorcrypto PRIVATE
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/xmr.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/serialize.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/base58.c")
  target_sources(kkemulator_dylib PRIVATE
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/interoperability.c"
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/emulator-selftest.c")
  target_include_directories(kkemulator_dylib PRIVATE "${KK_MONERO_VECTOR_DIR}")
  set_source_files_properties(
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/interoperability.c"
    TARGET_DIRECTORY kkemulator_dylib
    PROPERTIES COMPILE_OPTIONS "-UUSE_MONERO;-DUSE_MONERO=1;-DMONERO_ARM=1")
endfunction()
cmake_language(DEFER CALL monero_native_emulator_overlay)
