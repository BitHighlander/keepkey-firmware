# Every .cpp in this directory belongs here. thorchain.cpp and mayachain.cpp
# existed on disk since 2019/2021 but were never listed, so nothing in them
# ever compiled -- including the memo-disclosure regression added by this
# release. A test that is not built is not a test.
set(sources
    binance.cpp
    coins.cpp
    confirm_test_utils.cpp
    cosmos.cpp
    eos.cpp
    ethereum.cpp
    fsm.cpp
    mayachain.cpp
    osmosis.cpp
    nano.cpp
    dice.cpp
    recovery.cpp
    rng_health.cpp
    setup_ceremony.cpp
    ripple.cpp
    signing.cpp
    solana.cpp
    storage.cpp
    test_board.cpp
    thorchain.cpp
    transaction.cpp
    usb_rx.cpp
    u2f.cpp)

# Suites for the coin engines the bitcoin-only image compiles out. Building
# them against that image fails at the first reference to an absent symbol
# (ethereum_address_checksum, tokenByTicker, ...), so they follow their
# subjects out of the build. coins.cpp is here because it asserts the
# multi-chain coin AND token table, not just the Bitcoin rows.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      binance.cpp
      coins.cpp
      cosmos.cpp
      eos.cpp
      ethereum.cpp
      nano.cpp
      ripple.cpp
      solana.cpp)
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
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kkemulator
    kktransport)
