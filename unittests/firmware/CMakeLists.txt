set(sources
    coins.cpp
    cosmos.cpp
    eos.cpp
    ethereum.cpp
    nano.cpp
    recovery.cpp
    signed_metadata.cpp
    ripple.cpp
    storage.cpp
    usb_rx.cpp
    u2f.cpp)

# Coin/token unit tests exercise handlers that are compiled out of the
# bitcoin-only firmware, so they only build against a full-feature image.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      binance.cpp
      eip712.cpp
      mayachain.cpp
      osmosis.cpp
      solana.cpp
      thorchain.cpp
      tron.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

add_executable(firmware-unit ${sources})
target_link_libraries(firmware-unit
    gmock_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    kkboard
    kkrand
    kkemulator
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kktransport)
