extern "C" {
#include "keepkey/firmware/ton.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>

TEST(Ton, ParseDestinationBounceable) {
    /* EQD... style bounceable address (48 chars base64) */
    /* Test with a known TON address */
    /* UQBv... = non-bounceable, EQBv... = bounceable */
    /* We'll construct a synthetic valid address for testing */

    /* Construct: flag(0x11) + workchain(0x00) + hash(32 bytes) + CRC16(2 bytes) */
    uint8_t raw[36];
    raw[0] = 0x11; /* bounceable, mainnet */
    raw[1] = 0x00; /* workchain 0 */
    memset(raw + 2, 0xAB, 32); /* dummy hash */

    /* Compute CRC16 */
    uint16_t crc = 0;
    for (int i = 0; i < 34; i++) {
        crc ^= (uint16_t)raw[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }
    raw[34] = (crc >> 8) & 0xFF;
    raw[35] = crc & 0xFF;

    /* Base64 encode */
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char encoded[49];
    int pos = 0;
    for (int i = 0; i < 36; i += 3) {
        uint32_t triple = ((uint32_t)raw[i] << 16);
        if (i + 1 < 36) triple |= ((uint32_t)raw[i+1] << 8);
        if (i + 2 < 36) triple |= raw[i+2];

        encoded[pos++] = b64[(triple >> 18) & 0x3F];
        encoded[pos++] = b64[(triple >> 12) & 0x3F];
        encoded[pos++] = (i + 1 < 36) ? b64[(triple >> 6) & 0x3F] : '=';
        encoded[pos++] = (i + 2 < 36) ? b64[triple & 0x3F] : '=';
    }
    encoded[48] = '\0';

    TonParsedAddress parsed;
    ASSERT_TRUE(ton_parseDestination(encoded, &parsed));

    EXPECT_EQ(parsed.workchain, 0);
    EXPECT_TRUE(parsed.bounceable);
    EXPECT_FALSE(parsed.testnet);

    /* Verify hash */
    uint8_t expected_hash[32];
    memset(expected_hash, 0xAB, 32);
    EXPECT_TRUE(memcmp(parsed.hash, expected_hash, 32) == 0);
}

TEST(Ton, ParseDestinationInvalidCRC) {
    /* Same as above but corrupt the CRC */
    uint8_t raw[36];
    raw[0] = 0x11;
    raw[1] = 0x00;
    memset(raw + 2, 0xAB, 32);
    raw[34] = 0xFF; /* wrong CRC */
    raw[35] = 0xFF;

    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char encoded[49];
    int pos = 0;
    for (int i = 0; i < 36; i += 3) {
        uint32_t triple = ((uint32_t)raw[i] << 16);
        if (i + 1 < 36) triple |= ((uint32_t)raw[i+1] << 8);
        if (i + 2 < 36) triple |= raw[i+2];

        encoded[pos++] = b64[(triple >> 18) & 0x3F];
        encoded[pos++] = b64[(triple >> 12) & 0x3F];
        encoded[pos++] = (i + 1 < 36) ? b64[(triple >> 6) & 0x3F] : '=';
        encoded[pos++] = (i + 2 < 36) ? b64[triple & 0x3F] : '=';
    }
    encoded[48] = '\0';

    TonParsedAddress parsed;
    EXPECT_FALSE(ton_parseDestination(encoded, &parsed));
}

TEST(Ton, BitBuffer) {
    TonBitBuffer bb;
    ton_initBitBuffer(&bb);

    /* Write 8 bits = 0xFF */
    ton_writeBits(&bb, 0xFF, 8);
    EXPECT_EQ(bb.bit_len, 8);
    EXPECT_EQ(bb.data[0], 0xFF);

    /* Write 4 bits = 0x5 (0101) */
    ton_writeBits(&bb, 0x5, 4);
    EXPECT_EQ(bb.bit_len, 12);
    EXPECT_EQ(bb.data[1], 0x50); /* 0101_0000 */
}

TEST(Ton, CellHashDeterministic) {
    /* Build a simple cell and verify hash is deterministic */
    TonCell cell;
    memset(&cell, 0, sizeof(cell));
    ton_initBitBuffer(&cell.bits);

    /* Write some test data */
    ton_writeBits(&cell.bits, 0xDEADBEEF, 32);

    uint8_t hash1[TON_CELL_HASH_SIZE];
    uint8_t hash2[TON_CELL_HASH_SIZE];

    ASSERT_TRUE(ton_cellHash(&cell, hash1));
    ASSERT_TRUE(ton_cellHash(&cell, hash2));

    EXPECT_TRUE(memcmp(hash1, hash2, TON_CELL_HASH_SIZE) == 0);
}

TEST(Ton, BuildInternalMessage) {
    TonParsedAddress dest;
    dest.workchain = 0;
    dest.bounceable = true;
    dest.testnet = false;
    memset(dest.hash, 0xBB, 32);

    TonCell cell;
    ASSERT_TRUE(ton_buildInternalMessage(&dest, 1000000000ULL, true,
                                          NULL, &cell));

    /* Cell should have some bits written */
    EXPECT_GT(cell.bits.bit_len, 0);

    /* Should be hashable */
    uint8_t hash[TON_CELL_HASH_SIZE];
    ASSERT_TRUE(ton_cellHash(&cell, hash));
}

TEST(Ton, BuildSigningMessage) {
    TonParsedAddress dest;
    dest.workchain = 0;
    dest.bounceable = true;
    dest.testnet = false;
    memset(dest.hash, 0xCC, 32);

    TonCell internal_msg;
    ASSERT_TRUE(ton_buildInternalMessage(&dest, 500000000ULL, true,
                                          "test", &internal_msg));

    TonCell signing_msg;
    ASSERT_TRUE(ton_buildSigningMessage(TON_V4R2_WALLET_ID, 1700000000,
                                         1, 0, 3, &internal_msg,
                                         &signing_msg));

    /* Signing message should have exactly 1 ref */
    EXPECT_EQ(signing_msg.ref_count, 1);

    /* Should have bits: wallet_id(32) + expire(32) + seqno(32) + op(8) + mode(8) = 112 */
    EXPECT_EQ(signing_msg.bits.bit_len, 112);

    /* Hash should be deterministic */
    uint8_t hash1[TON_CELL_HASH_SIZE];
    uint8_t hash2[TON_CELL_HASH_SIZE];
    ASSERT_TRUE(ton_cellHash(&signing_msg, hash1));
    ASSERT_TRUE(ton_cellHash(&signing_msg, hash2));
    EXPECT_TRUE(memcmp(hash1, hash2, TON_CELL_HASH_SIZE) == 0);
}

TEST(Ton, FormatAmount) {
    char buf[32];

    ton_formatAmount(buf, sizeof(buf), 1000000000ULL);
    EXPECT_STREQ(buf, "1.000000000 TON");

    ton_formatAmount(buf, sizeof(buf), 0);
    EXPECT_STREQ(buf, "0.000000000 TON");

    ton_formatAmount(buf, sizeof(buf), 1500000000ULL);
    EXPECT_STREQ(buf, "1.500000000 TON");
}
