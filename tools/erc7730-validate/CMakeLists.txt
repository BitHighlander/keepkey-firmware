if(${KK_EMULATOR} AND NOT ${KK_BITCOIN_ONLY})
  include_directories(
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  add_executable(erc7730-validate main.c)
  target_link_libraries(erc7730-validate
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
      kkemulator)
endif()
