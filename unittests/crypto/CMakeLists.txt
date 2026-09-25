set(sources
    bip340.cpp
    rand.cpp
    vuln1845.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

add_executable(crypto-unit ${sources})
target_link_libraries(crypto-unit
    gtest_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    kkboard
    qrcodegenerator
    kkrand
    kkemulator
    trezorcrypto
    kktransport)

# Exercise the dormant engine in ordinary full emulator CI, even though this
# foundation does not yet expose Zcash firmware handlers.
if(KK_ZCASH_PRIVACY OR (KK_EMULATOR AND NOT KK_BITCOIN_ONLY))
  add_executable(zcash-crypto-unit
      ../firmware/zcash.cpp
      ${CMAKE_SOURCE_DIR}/lib/firmware/zcash.c)
  target_include_directories(zcash-crypto-unit PRIVATE
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_SOURCE_DIR}/lib/firmware
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/ed25519-donna)
  target_link_libraries(zcash-crypto-unit
      gtest_main
      trezorcrypto
      kkrand)
endif()
