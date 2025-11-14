# BTC core crypto — always compiled
set(base_sources
    hw-crypto/crypto/bip39.c
    hw-crypto/crypto/bip39_english.c
    hw-crypto/crypto/hmac.c
    hw-crypto/crypto/hmac_drbg.c
    hw-crypto/crypto/sha2.c
    hw-crypto/crypto/base32.c
    hw-crypto/crypto/hasher.c
    hw-crypto/crypto/rand.c
    hw-crypto/crypto/rc4.c
    hw-crypto/crypto/blake256.c
    hw-crypto/crypto/cash_addr.c
    hw-crypto/crypto/curves.c
    hw-crypto/crypto/rfc6979.c
    hw-crypto/crypto/secp256k1.c
    hw-crypto/crypto/bignum.c
    hw-crypto/crypto/segwit_addr.c
    hw-crypto/crypto/ripemd160.c
    hw-crypto/crypto/memzero.c
    hw-crypto/crypto/blake2b.c
    hw-crypto/crypto/script.c
    hw-crypto/crypto/bip32.c
    hw-crypto/crypto/address.c
    hw-crypto/crypto/blake2s.c
    hw-crypto/crypto/base58.c
    hw-crypto/crypto/ecdsa.c
    hw-crypto/crypto/pbkdf2.c
    hw-crypto/crypto/aes/aeskey.c
    hw-crypto/crypto/aes/aescrypt.c
    hw-crypto/crypto/aes/aes_modes.c
    hw-crypto/crypto/aes/aestab.c
    hw-crypto/crypto/groestl.c
    hw-crypto/crypto/sha3.c
    hw-crypto/crypto/nist256p1.c
    hw-crypto/crypto/ed25519-donna/curve25519-donna-scalarmult-base.c
    hw-crypto/crypto/ed25519-donna/ed25519-donna-32bit-tables.c
    hw-crypto/crypto/ed25519-donna/ed25519.c
    hw-crypto/crypto/ed25519-donna/curve25519-donna-helpers.c
    hw-crypto/crypto/ed25519-donna/ed25519-blake2b.c
    hw-crypto/crypto/ed25519-donna/ed25519-keccak.c
    hw-crypto/crypto/ed25519-donna/ed25519-sha3.c
    hw-crypto/crypto/ed25519-donna/ed25519-donna-basepoint-table.c
    hw-crypto/crypto/ed25519-donna/modm-donna-32bit.c
    hw-crypto/crypto/ed25519-donna/curve25519-donna-32bit.c
    hw-crypto/crypto/ed25519-donna/ed25519-donna-impl-base.c)

# Altcoin crypto — skipped in BTC-only builds
set(altcoin_sources
    hw-crypto/crypto/nem.c
    hw-crypto/crypto/nano.c)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/hw-crypto/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/hw-crypto/
  ${CMAKE_CURRENT_SOURCE_DIR}/hw-crypto/crypto/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})

if(KK_BITCOIN_ONLY)
    set(sources ${base_sources})
else()
    set(sources ${base_sources} ${altcoin_sources})
endif()

add_library(trezorcrypto ${sources})
