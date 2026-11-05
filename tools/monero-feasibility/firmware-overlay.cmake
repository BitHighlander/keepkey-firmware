# Optional research overlay, loaded with CMAKE_PROJECT_KeepKeyFirmware_INCLUDE.
# DEFER requires CMake >= 3.19. Normal firmware configuration never loads this.
function(monero_feasibility_overlay)
  if(NOT KK_MONERO_FEASIBILITY)
    return()
  endif()
  target_compile_options(trezorcrypto PRIVATE -UUSE_MONERO -DUSE_MONERO=1)
  target_sources(trezorcrypto PRIVATE
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/xmr.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/serialize.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/base58.c")
  target_sources(firmware.keepkey.elf PRIVATE
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/probe.c")
  set_source_files_properties(
    "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/probe.c"
    TARGET_DIRECTORY firmware.keepkey.elf
    PROPERTIES COMPILE_OPTIONS "-UUSE_MONERO;-DUSE_MONERO=1")
  # Retain the whole probe call graph without adding a boot-time call.
  target_link_options(firmware.keepkey.elf PRIVATE -Wl,--undefined=monero_probe)
endfunction()
cmake_language(DEFER CALL monero_feasibility_overlay)
