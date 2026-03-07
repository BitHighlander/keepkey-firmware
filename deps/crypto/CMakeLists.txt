set(sources
    bip39.c
    bip39_english.c
    hmac.c
    hmac_drbg.c
    sha2.c
    base32.c
    hasher.c
    rand.c
    rc4.c
    blake256.c
    cash_addr.c
    curves.c
    rfc6979.c
    ed25519-donna/curve25519-donna-scalarmult-base.c
    ed25519-donna/ed25519-donna-32bit-tables.c
    ed25519-donna/ed25519.c
    ed25519-donna/curve25519-donna-helpers.c
    ed25519-donna/ed25519-blake2b.c
    ed25519-donna/ed25519-keccak.c
    ed25519-donna/ed25519-sha3.c
    ed25519-donna/ed25519-donna-basepoint-table.c
    ed25519-donna/modm-donna-32bit.c
    ed25519-donna/curve25519-donna-32bit.c
    ed25519-donna/ed25519-donna-impl-base.c
    nem.c
    nano.c
    secp256k1.c
    bignum.c
    segwit_addr.c
    ripemd160.c
    groestl.c
    nist256p1.c
    memzero.c
    blake2b.c
    script.c
    bip32.c
    address.c
    blake2s.c
    sha3.c
    base58.c
    ecdsa.c
    pbkdf2.c
    aes/aeskey.c
    aes/aescrypt.c
    aes/aes_modes.c
    aes/aestab.c)


include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})


add_library(trezorcrypto ${sources})
