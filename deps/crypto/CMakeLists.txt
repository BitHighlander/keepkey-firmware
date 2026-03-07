set(sources
    crypto/bip39.c
    crypto/bip39_english.c
    crypto/hmac.c
    crypto/hmac_drbg.c
    crypto/sha2.c
    crypto/base32.c
    crypto/hasher.c
    #crypto/tools/bip39bruteforce.c
    #crypto/tools/mktable.c
    #crypto/tools/xpubaddrgen.c
    crypto/rand.c
    crypto/rc4.c
    crypto/blake256.c
    crypto/cash_addr.c
    crypto/curves.c
    crypto/rfc6979.c
    crypto/ed25519-donna/curve25519-donna-scalarmult-base.c
    crypto/ed25519-donna/ed25519-donna-32bit-tables.c
    crypto/ed25519-donna/ed25519.c
    crypto/ed25519-donna/curve25519-donna-helpers.c
    crypto/ed25519-donna/ed25519-blake2b.c
    crypto/ed25519-donna/ed25519-keccak.c
    crypto/ed25519-donna/ed25519-sha3.c
    crypto/ed25519-donna/ed25519-donna-basepoint-table.c
    crypto/ed25519-donna/modm-donna-32bit.c
    crypto/ed25519-donna/curve25519-donna-32bit.c
    crypto/ed25519-donna/ed25519-donna-impl-base.c
    crypto/nem.c
    crypto/nano.c
    #crypto/tests/test_check.c
    #crypto/tests/test_openssl.c
    #crypto/tests/test_speed.c
    crypto/secp256k1.c
    crypto/bignum.c
    crypto/segwit_addr.c
    crypto/ripemd160.c
    crypto/groestl.c
    crypto/nist256p1.c
    #crypto/monero/serialize.c
    #crypto/monero/range_proof.c
    #crypto/monero/xmr.c
    #crypto/monero/base58.c
    crypto/memzero.c
    crypto/blake2b.c
    crypto/script.c
    crypto/bip32.c
    crypto/address.c
    crypto/blake2s.c
    crypto/sha3.c
    crypto/base58.c
    crypto/ecdsa.c
    crypto/pbkdf2.c
    crypto/aes/aeskey.c
    crypto/aes/aescrypt.c
    crypto/aes/aes_modes.c
    #crypto/aes/aestst.c
    crypto/aes/aestab.c)

    # Clang 5.0 in the docker image (kktech/firmware:v7) is missing
    # <xmmintrin.h>, which breaks these. Until they're needed, we'll just elide
    # them.
    #crypto/chacha20poly1305/chacha_merged.c
    #crypto/chacha20poly1305/rfc7539.c
    #crypto/chacha20poly1305/poly1305-donna.c
    #crypto/chacha20poly1305/chacha20poly1305.c


include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})


add_library(trezorcrypto ${sources})
