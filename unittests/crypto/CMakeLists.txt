set(sources
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
    kkrand
    kkemulator
    qrcodegenerator
    trezorcrypto
    kktransport)

# The constant-time Pallas implementation, compiled a second time with
# test-only operation counters. Kept out of trezorcrypto so the counters can
# never reach firmware or the normal emulator binary.
if(NOT ${KK_BITCOIN_ONLY})
  add_executable(pallas-ct-unit
      pallas_ct.cpp
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/pallas_ct.c
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/memzero.c)
  target_compile_definitions(pallas-ct-unit PRIVATE PALLAS_CT_TESTING)
  target_include_directories(pallas-ct-unit PRIVATE
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)
  target_link_libraries(pallas-ct-unit gtest_main)
endif()
