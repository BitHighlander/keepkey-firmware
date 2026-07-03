set(sources
    coins.cpp
    cosmos.cpp
    eos.cpp
    ethereum.cpp
    # mayachain.cpp  # disabled: stale since 50164a2e added denom param to
    # mayachain_signTxUpdateMsgSend; mayachain.cpp:58 still calls it 2-arg.
    # Needs call + expected-signature update before re-enabling.
    nano.cpp
    recovery.cpp
    ripple.cpp
    signed_metadata.cpp
    solana.cpp
    storage.cpp
    thorchain.cpp
    tron.cpp
    usb_rx.cpp
    u2f.cpp
    zcash.cpp)

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
    kkemulator
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kktransport)
