set(sources
    rand.cpp
    vuln1845.cpp)

if(NOT "${COIN_SUPPORT}" STREQUAL "BTC")
  list(APPEND sources
    zcash_orchard.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto
    ${CMAKE_SOURCE_DIR}/deps/crypto)

add_executable(crypto-unit ${sources})

set(libraries
  gtest_main
  kkfirmware
  kkfirmware.keepkey
  kkboard
  kkboard.keepkey
  kkvariant.keepkey
  kkboard
  kkemulator
  qrcodegenerator
  kkrand
  trezorcrypto
  kktransport)

if(NOT "${COIN_SUPPORT}" STREQUAL "BTC")
  list(APPEND libraries
    kkvariant.salt
  )
endif()

target_link_libraries(crypto-unit
  ${libraries}
  )
