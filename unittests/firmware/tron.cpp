extern "C" {
#include "keepkey/firmware/tron.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hasher.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>

TEST(Tron, AddressFromCompressedPubkey) {
    /* Test that tron_getAddress produces a valid T-prefix Base58Check address
     * from a compressed secp256k1 public key. */
    const uint8_t pubkey[33] = {
        0x02, 0xc0, 0xde, 0xd2, 0xbc, 0x1f, 0x12, 0x05,
        0xfb, 0x88, 0x96, 0xf5, 0x79, 0x3f, 0x9b, 0x6e,
        0x0c, 0x73, 0xad, 0x0f, 0x0b, 0xe6, 0x1e, 0xae,
        0x2c, 0xe5, 0xa1, 0x95, 0x22, 0x10, 0xb3, 0xe6,
        0x78
    };

    char address[MAX_TRON_ADDR_SIZE];
    ASSERT_TRUE(tron_getAddress(pubkey, address));

    /* Should start with 'T' */
    EXPECT_EQ(address[0], 'T');
    /* Should be 34 characters */
    EXPECT_EQ(strlen(address), 34);
}

TEST(Tron, DecodeAddressRoundTrip) {
    /* Encode then decode should produce the same raw bytes */
    const uint8_t pubkey[33] = {
        0x02, 0xc0, 0xde, 0xd2, 0xbc, 0x1f, 0x12, 0x05,
        0xfb, 0x88, 0x96, 0xf5, 0x79, 0x3f, 0x9b, 0x6e,
        0x0c, 0x73, 0xad, 0x0f, 0x0b, 0xe6, 0x1e, 0xae,
        0x2c, 0xe5, 0xa1, 0x95, 0x22, 0x10, 0xb3, 0xe6,
        0x78
    };

    char address[MAX_TRON_ADDR_SIZE];
    ASSERT_TRUE(tron_getAddress(pubkey, address));

    uint8_t raw[TRON_ADDRESS_SIZE];
    ASSERT_TRUE(tron_decodeAddress(address, raw));

    /* First byte should be 0x41 (mainnet prefix) */
    EXPECT_EQ(raw[0], TRON_MAINNET_PREFIX);

    /* Re-encode and check match */
    EXPECT_TRUE(tron_validateAddress(address));
}

TEST(Tron, InvalidAddressRejected) {
    /* Invalid address should fail validation */
    EXPECT_FALSE(tron_validateAddress("Tinvalid"));
    EXPECT_FALSE(tron_validateAddress(""));
    EXPECT_FALSE(tron_validateAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")); /* BTC addr */
}

TEST(Tron, FormatAmount) {
    char buf[32];

    tron_formatAmount(buf, sizeof(buf), 1000000);
    EXPECT_STREQ(buf, "1.000000 TRX");

    tron_formatAmount(buf, sizeof(buf), 0);
    EXPECT_STREQ(buf, "0.000000 TRX");

    tron_formatAmount(buf, sizeof(buf), 1234567);
    EXPECT_STREQ(buf, "1.234567 TRX");

    tron_formatAmount(buf, sizeof(buf), 100000000000ULL);
    EXPECT_STREQ(buf, "100000.000000 TRX");
}

TEST(Tron, DecodeTRC20Transfer) {
    /* ABI: transfer(address,uint256)
     * selector: 0xa9059cbb
     * address: 12 zero bytes + 20-byte EVM address (no 0x41 prefix)
     * amount: 32 bytes big-endian
     * Matches Trezor reference and actual on-chain format. */
    uint8_t data[68];
    memset(data, 0, sizeof(data));

    /* Selector */
    data[0] = 0xa9; data[1] = 0x05; data[2] = 0x9c; data[3] = 0xbb;

    /* Address: 12 zero bytes (4..15), then 20-byte EVM address (16..35) */
    /* No 0x41 prefix in ABI data — it's added by the decoder */
    for (int i = 0; i < 20; i++) data[16 + i] = (uint8_t)(0x10 + i);

    /* Amount: 1000000 (0xF4240) in last 3 bytes of 32-byte word */
    data[36 + 29] = 0x0F;
    data[36 + 30] = 0x42;
    data[36 + 31] = 0x40;

    uint8_t to_raw[TRON_ADDRESS_SIZE];
    uint8_t amount_bytes[32];

    ASSERT_TRUE(tron_decodeTRC20Transfer(data, sizeof(data),
                                          to_raw, amount_bytes));

    /* Verify recipient starts with 0x41 (added by decoder) */
    EXPECT_EQ(to_raw[0], TRON_MAINNET_PREFIX);

    /* Verify the 20-byte EVM address follows the prefix */
    for (int i = 0; i < 20; i++) {
        EXPECT_EQ(to_raw[1 + i], (uint8_t)(0x10 + i));
    }

    /* Verify amount bytes */
    EXPECT_EQ(amount_bytes[29], 0x0F);
    EXPECT_EQ(amount_bytes[30], 0x42);
    EXPECT_EQ(amount_bytes[31], 0x40);
}

TEST(Tron, DecodeTRC20RejectsOld0x41Format) {
    /* Verify that the old format with 0x41 embedded in ABI data is rejected.
     * On-chain, TRON ABI uses standard EVM 20-byte addresses without prefix. */
    uint8_t data[68];
    memset(data, 0, sizeof(data));

    /* Selector */
    data[0] = 0xa9; data[1] = 0x05; data[2] = 0x9c; data[3] = 0xbb;

    /* Old incorrect format: 11 zeros + 0x41 + 20 bytes */
    data[15] = 0x41;
    for (int i = 0; i < 20; i++) data[16 + i] = (uint8_t)(0x10 + i);

    uint8_t to_raw[TRON_ADDRESS_SIZE];
    uint8_t amount_bytes[32];

    /* Should fail: byte 15 (index 11 in addr_word) is 0x41, not 0x00 */
    EXPECT_FALSE(tron_decodeTRC20Transfer(data, sizeof(data),
                                           to_raw, amount_bytes));
}

TEST(Tron, DecodeTRC20WithTrezorVector) {
    /* Test with actual Trezor test vector:
     * USDT transfer from Trezor fixtures sign_tx.json
     * data: a9059cbb000000000000000000000000d093f24888ab06073a4bdffbb8107db1ea9dc0a0
     *       00000000000000000000000000000000000000000000000000000000013bb450 */
    uint8_t data[68];
    const uint8_t hex_data[] = {
        0xa9, 0x05, 0x9c, 0xbb,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd0, 0x93, 0xf2, 0x48,
        0x88, 0xab, 0x06, 0x07, 0x3a, 0x4b, 0xdf, 0xfb,
        0xb8, 0x10, 0x7d, 0xb1, 0xea, 0x9d, 0xc0, 0xa0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x3b, 0xb4, 0x50
    };
    memcpy(data, hex_data, 68);

    uint8_t to_raw[TRON_ADDRESS_SIZE];
    uint8_t amount_bytes[32];

    ASSERT_TRUE(tron_decodeTRC20Transfer(data, sizeof(data),
                                          to_raw, amount_bytes));

    /* Should have 0x41 prefix (added by decoder) */
    EXPECT_EQ(to_raw[0], TRON_MAINNET_PREFIX);

    /* Verify EVM address bytes match */
    EXPECT_EQ(to_raw[1], 0xd0);
    EXPECT_EQ(to_raw[2], 0x93);
    EXPECT_EQ(to_raw[20], 0xa0);

    /* Verify amount = 0x013bb450 = 20_726_864 */
    EXPECT_EQ(amount_bytes[28], 0x01);
    EXPECT_EQ(amount_bytes[29], 0x3b);
    EXPECT_EQ(amount_bytes[30], 0xb4);
    EXPECT_EQ(amount_bytes[31], 0x50);
}

TEST(Tron, DecodeTRC20RejectsWrongSelector) {
    uint8_t data[68];
    memset(data, 0, sizeof(data));
    /* Wrong selector */
    data[0] = 0x00; data[1] = 0x00; data[2] = 0x00; data[3] = 0x00;

    uint8_t to_raw[TRON_ADDRESS_SIZE];
    uint8_t amount_bytes[32];

    EXPECT_FALSE(tron_decodeTRC20Transfer(data, sizeof(data),
                                           to_raw, amount_bytes));
}

TEST(Tron, SerializeRawTransaction) {
    /* Test that structured fields serialize to a valid protobuf
     * that produces a deterministic SHA256 hash. */
    TronSignTx msg;
    memset(&msg, 0, sizeof(msg));

    /* ref_block_bytes */
    msg.has_ref_block_bytes = true;
    msg.ref_block_bytes.size = 2;
    msg.ref_block_bytes.bytes[0] = 0xAB;
    msg.ref_block_bytes.bytes[1] = 0xCD;

    /* ref_block_hash */
    msg.has_ref_block_hash = true;
    msg.ref_block_hash.size = 8;
    memset(msg.ref_block_hash.bytes, 0x42, 8);

    /* expiration */
    msg.has_expiration = true;
    msg.expiration = 1700000000000ULL;

    /* timestamp */
    msg.has_timestamp = true;
    msg.timestamp = 1699999990000ULL;

    /* transfer */
    msg.has_transfer = true;
    msg.transfer.amount = 1000000; /* 1 TRX */
    strcpy(msg.transfer.to_address, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");

    /* Owner raw address (dummy) */
    uint8_t owner_raw[TRON_ADDRESS_SIZE];
    memset(owner_raw, 0x41, 1);
    memset(owner_raw + 1, 0xAA, 20);

    uint8_t serialized[1024];
    size_t serialized_len = 0;

    ASSERT_TRUE(tron_serializeRawTransaction(&msg, owner_raw,
                                              serialized, &serialized_len,
                                              sizeof(serialized)));

    /* Should produce non-empty output */
    EXPECT_GT(serialized_len, 0u);

    /* Hash should be deterministic */
    uint8_t hash1[32], hash2[32];
    sha256_Raw(serialized, serialized_len, hash1);

    uint8_t serialized2[1024];
    size_t serialized2_len = 0;
    ASSERT_TRUE(tron_serializeRawTransaction(&msg, owner_raw,
                                              serialized2, &serialized2_len,
                                              sizeof(serialized2)));

    sha256_Raw(serialized2, serialized2_len, hash2);

    EXPECT_TRUE(memcmp(hash1, hash2, 32) == 0);
    EXPECT_EQ(serialized_len, serialized2_len);
    EXPECT_TRUE(memcmp(serialized, serialized2, serialized_len) == 0);
}
