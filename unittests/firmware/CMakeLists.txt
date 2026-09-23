set(sources
    nanopb_bounds.cpp
    authenticator.cpp
    confirm_test_utils.cpp
    fsm.cpp
    dice.cpp
    recovery.cpp
    recovery_review_probe.c
    review_handlers.cpp
    rng_health.cpp
    setup_ceremony.cpp
    signing.cpp
    storage.cpp
    storage_cipher_probe.c
    storage_passphrase.cpp
    test_board.cpp
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
      eos_authorization.cpp
      eos_authorization_probe.c
      ethereum.cpp
      review_integer.cpp
      mayachain.cpp
      nano.cpp
      osmosis.cpp
      ripple.cpp
      signed_metadata.cpp
      tron.cpp
      solana.cpp
      thorchain.cpp)
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

# Compile and exercise the dormant Zcash address display without enabling
# Zcash signing handlers in the foundation firmware.
if(NOT KK_BITCOIN_ONLY)
  add_executable(zcash-display-unit
      zcash_display.cpp zcash_display_confirm_probe.c zcash_display_layout_probe.c
      confirm_test_utils.cpp test_board.cpp)
  get_target_property(FIRMWARE_TEST_LIBS firmware-unit LINK_LIBRARIES)
  target_link_libraries(zcash-display-unit ${FIRMWARE_TEST_LIBS})
endif()
