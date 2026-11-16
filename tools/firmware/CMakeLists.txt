if(NOT ${KK_EMULATOR})
  set(sources
      keepkey_main.c
      startup.s
      ../bootloader/bl_mpu.c
      ../bootloader/isr.s
      header.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.ld)

  # Link map for the CI SRAM report/artifact (pairs with the .ld's 16 KiB
  # stack-reserve ASSERT and the -fstack-usage frame report).
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib -Wl,-Map=${CMAKE_BINARY_DIR}/bin/firmware.keepkey.map,--cref")

  # Newlib's snprintf links the float engine (_svfprintf_r, _dtoa_r,
  # soft-double libgcc, malloc): ~22 KB of ROM with no %f user. Resolve every
  # snprintf/vsnprintf in this image to the integer-only sniprintf family
  # (%lld/%llu included). At link time, for the firmware only: kkboard is
  # shared with the bootloader, whose binary must not change.
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -Wl,--defsym=snprintf=sniprintf -Wl,--defsym=vsnprintf=vsniprintf")

  # Link-time optimisation for the firmware image only (see the top-level
  # CMakeLists.txt; off in bootloader-tools builds).
  if(NOT KK_BUILD_BOOTLOADER_TOOLS)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    # Under LTO the -fstack-usage records (.su) are written at link time, into
    # the linker's temp directory. Keep that inside the build tree so the SRAM
    # gate (tools/check_sram_budget.py) still finds them.
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/lto-su)
    set(CMAKE_C_LINK_EXECUTABLE
        "${CMAKE_COMMAND} -E env TMPDIR=${CMAKE_BINARY_DIR}/lto-su ${CMAKE_C_LINK_EXECUTABLE}")
  endif()

  set(LINK_FLAGS
      kkfirmware
      kkboard
      kktransport
      trezorcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

  add_executable(firmware.keepkey.elf ${sources})
  target_link_libraries(firmware.keepkey.elf
      kkfirmware
      kkfirmware.keepkey
      kkboard
      kkboard.keepkey
      kkvariant.keepkey
      kkvariant.salt
      kktransport
      trezorcrypto
      qrcodegenerator
      SecAESSTM32
      kkrand
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET firmware.keepkey.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/firmware.keepkey.elf
          ${CMAKE_BINARY_DIR}/bin/firmware.keepkey.bin)

endif()
