set(sources
    bip39.c
    bip39_english.c
    hmac.c
    hmac_drbg.c
    sha2.c
    base32.c
    hasher.c
    #tools/bip39bruteforce.c
    #tools/mktable.c
    #tools/xpubaddrgen.c
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
    #tests/test_check.c
    #tests/test_openssl.c
    #tests/test_speed.c
    secp256k1.c
    bignum.c
    segwit_addr.c
    ripemd160.c
    groestl.c
    nist256p1.c
    #monero/serialize.c
    #monero/range_proof.c
    #monero/xmr.c
    #monero/base58.c
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
    #aes/aestst.c
    aes/aestab.c)

    # Clang 5.0 in the docker image (kktech/firmware:v7) is missing
    # <xmmintrin.h>, which breaks these. Until they're needed, we'll just elide
    # them.
    #chacha20poly1305/chacha_merged.c
    #chacha20poly1305/rfc7539.c
    #chacha20poly1305/poly1305-donna.c
    #chacha20poly1305/chacha20poly1305.c


include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})


add_library(trezorcrypto ${sources})
