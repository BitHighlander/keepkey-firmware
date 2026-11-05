# Explicit, unsigned hardware research image. Default builds never load this.
function(monero_hardware_overlay)
  if(NOT KK_MONERO_HARDWARE_SELFTEST)
    message(FATAL_ERROR "hardware-overlay requires explicit selftest selection")
  endif()
  if(NOT EXISTS "${KK_MONERO_VECTOR_DIR}/interop_vectors.h")
    message(FATAL_ERROR "missing reviewed public fixture subset")
  endif()
  target_compile_options(trezorcrypto PRIVATE -UUSE_MONERO -DUSE_MONERO=1)
  target_sources(trezorcrypto PRIVATE
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/xmr.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/serialize.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/base58.c")
  target_sources(firmware.keepkey.elf PRIVATE
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/interoperability.c"
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/hardware-selftest.c"
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/hardware-stack.S")
  target_include_directories(firmware.keepkey.elf PRIVATE "${KK_MONERO_VECTOR_DIR}")
  set_source_files_properties(
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/interoperability.c"
    TARGET_DIRECTORY firmware.keepkey.elf
    PROPERTIES COMPILE_OPTIONS "-UUSE_MONERO;-DUSE_MONERO=1;-DMONERO_ARM=1")
  set_source_files_properties(
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/hardware-selftest.c"
    TARGET_DIRECTORY firmware.keepkey.elf
    PROPERTIES COMPILE_OPTIONS "-DMONERO_HARDWARE_CASE_COUNT=8")
  target_link_options(firmware.keepkey.elf PRIVATE -Wl,--wrap=kk_board_init)
endfunction()
cmake_language(DEFER CALL monero_hardware_overlay)
