# Only tests that build against BOTH firmware variants belong here. The
# multi-chain suites are appended below under NOT KK_BITCOIN_ONLY -- the merge
# had leaked eight of them (binance, coins, cosmos, eos, ethereum, nano, ripple,
# solana) into this unconditional list as well, so the bitcoin-only build
# compiled them anyway and died on ethereum_address_checksum, which is compiled
# out of that image. recovery.cpp was also listed twice.
set(sources
    app_confirm.cpp
    block13_confirmation.cpp
    block13_entropy.cpp
    block13_progress.cpp
    nanopb_bounds.cpp
    authenticator.cpp
    confirm_test_utils.cpp
    crypto_cleanup.cpp
    fsm.cpp
    dice.cpp
    recovery.cpp
    recovery_review_probe.c
    review_handlers.cpp
    rng_health.cpp
    setup_ceremony.cpp
    reset_policy_probe.c
    signing.cpp
    storage.cpp
    storage_cipher_probe.c
    storage_passphrase.cpp
    test_board.cpp
    transaction.cpp
    usb_rx.cpp
    messages_probe.c
    usb_callbacks.cpp
    u2f.cpp
    ctap2.cpp
    ctap2_cbor.cpp
    seed_display.cpp)

# Coin/token unit tests exercise handlers/helpers that are compiled out of the
# bitcoin-only firmware; they only build against a full-feature firmware.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      coins.cpp
      cosmos.cpp
      eip712.cpp
      eos.cpp
      eos_authorization.cpp
      eos_authorization_probe.c
      ethereum.cpp
      hive_transfer.cpp
      eip712_stream.cpp
      liquidity_key_probe.c
      review_integer.cpp
      mayachain.cpp
      nano.cpp
      osmosis.cpp
      ripple.cpp
      signed_metadata.cpp
      uniswap_ur.cpp
      erc7730_abi.cpp
      erc7730_abi_stream.cpp
      erc7730_catalog.cpp
      erc7730_condition.cpp
      erc7730_field.cpp
      erc7730_format.cpp
      erc7730_program.cpp
      erc7730_tx.cpp
      erc7730_workflow.cpp
      solana.cpp
      thorchain.cpp
      tron.cpp
      clearsign_root.cpp
      hive.cpp
      contact_book.cpp)
else()
  list(APPEND sources bitcoin_only.cpp)
endif()

# zcash.cpp exercises the Orchard engine (lib/firmware/zcash.c), which is only
# compiled into kkfirmware when the privacy flag is on.
if(${KK_ZCASH_PRIVACY})
  list(APPEND sources zcash.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)

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
