set(sources
    nanopb_bounds.cpp
    confirm_test_utils.cpp
    fsm.cpp
    dice.cpp
    recovery.cpp
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
      eip712.cpp
      eos.cpp
      eos_authorization.cpp
      eos_authorization_probe.c
      ethereum.cpp
      eip712_stream.cpp
      mayachain.cpp
      nano.cpp
      osmosis.cpp
      ripple.cpp
      signed_metadata.cpp
      erc7730_abi.cpp
      erc7730_abi_stream.cpp
      erc7730_catalog.cpp
      erc7730_condition.cpp
      erc7730_format.cpp
      erc7730_program.cpp
      erc7730_tx.cpp
      erc7730_workflow.cpp
      solana.cpp
      thorchain.cpp
      tron.cpp)
endif()

if(${KK_ZCASH_PRIVACY})
  list(APPEND sources zcash.cpp)
endif()

# This legacy fixture initializes and mutates persistent emulator flash. Keep
# it last so its process-global storage/session state cannot contaminate UI and
# transport tests that rely on a pristine confirmation harness.
list(APPEND sources authenticator.cpp)

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
