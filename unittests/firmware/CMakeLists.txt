set(sources
    authenticator.cpp
    app_confirm.cpp
    coins.cpp
    binance.cpp
    cosmos.cpp
    dice.cpp
    eos.cpp
    eip712.cpp
    ethereum.cpp
    hive.cpp
    mayachain.cpp
    nano.cpp
    osmosis.cpp
    recovery.cpp
    signed_metadata.cpp
    ripple.cpp
    solana.cpp
    storage.cpp
    usb_rx.cpp
    thorchain.cpp
    tron.cpp
    u2f.cpp)

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
    kkemulator
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kktransport)
