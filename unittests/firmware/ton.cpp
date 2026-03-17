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

TEST(Ton, ParseDestinationNonBounceable) {
    /* 0x51 = non-bounceable, mainnet (bit 6 set) */
    uint8_t raw[36];
    raw[0] = 0x51;
    raw[1] = 0x00;
    memset(raw + 2, 0xCC, 32);

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
    EXPECT_FALSE(parsed.bounceable);
    EXPECT_FALSE(parsed.testnet);
}

TEST(Ton, ParseDestinationBounceableTestnet) {
    /* 0x91 = bounceable, testnet */
    uint8_t raw[36];
    raw[0] = 0x91;
    raw[1] = 0x00;
    memset(raw + 2, 0xDD, 32);

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
    EXPECT_TRUE(parsed.bounceable);
    EXPECT_TRUE(parsed.testnet);
}


TEST(Ton, CellHashLeafRegression) {
    /* Regression baseline: leaf cell with 32 bits of 0xDEADBEEF, no refs.
     * Expected hash computed independently (Python SHA256 of d1=0x00, d2=0x08,
     * data=DEADBEEF). Cross-verified against Keystone/tonutils d2 formula:
     * d2 = data.len()*2 - (!full_bytes) which equals floor(bit_len/8)*2
     * for byte-aligned cells. */
    TonCell cell;
    memset(&cell, 0, sizeof(cell));
    ton_initBitBuffer(&cell.bits);
    ton_writeBits(&cell.bits, 0xDEADBEEF, 32);

    uint8_t hash[TON_CELL_HASH_SIZE];
    ASSERT_TRUE(ton_cellHash(&cell, hash));

    static const uint8_t expected[TON_CELL_HASH_SIZE] = {
        0x27, 0x09, 0x06, 0xfd, 0x17, 0x1b, 0x9c, 0x43,
        0xf3, 0x7a, 0x35, 0x30, 0x59, 0xa7, 0x3f, 0xbc,
        0x02, 0xe0, 0x56, 0x81, 0x88, 0xec, 0x30, 0x18,
        0x6a, 0xf8, 0x46, 0xca, 0xef, 0xd0, 0x9b, 0x8c
    };
    EXPECT_TRUE(memcmp(hash, expected, TON_CELL_HASH_SIZE) == 0)
        << "Leaf cell hash does not match independently computed reference";
}

TEST(Ton, CellHashSigningMsgRegression) {
    /* End-to-end regression: build an internal message (workchain 0,
     * hash = all zeros, 1 TON, bounce, no comment), wrap it in a v4r2
     * signing message (wallet_id=698983191, expire=1700000000, seqno=1,
     * op=0, mode=3), and verify the final cell hash matches the
     * independently computed reference value. */
    TonParsedAddress dest;
    dest.workchain = 0;
    dest.bounceable = true;
    dest.testnet = false;
    memset(dest.hash, 0x00, 32);

    TonCell internal_msg;
    ASSERT_TRUE(ton_buildInternalMessage(&dest, 1000000000ULL, true,
                                          NULL, &internal_msg));
    EXPECT_EQ(internal_msg.bits.bit_len, 416);

    /* Verify internal message hash */
    uint8_t im_hash[TON_CELL_HASH_SIZE];
    ASSERT_TRUE(ton_cellHash(&internal_msg, im_hash));

    static const uint8_t expected_im[TON_CELL_HASH_SIZE] = {
        0x1f, 0x22, 0x89, 0xad, 0x76, 0x1a, 0x5a, 0x99,
        0xfb, 0x0d, 0x60, 0xde, 0x51, 0x69, 0x0a, 0x48,
        0x00, 0x80, 0x85, 0x15, 0x7f, 0xda, 0x2d, 0x7b,
        0xeb, 0xe7, 0x19, 0x46, 0x08, 0xe2, 0xba, 0x93
    };
    EXPECT_TRUE(memcmp(im_hash, expected_im, TON_CELL_HASH_SIZE) == 0)
        << "Internal message hash does not match reference";

    /* Build signing message and verify final hash */
    TonCell signing_msg;
    ASSERT_TRUE(ton_buildSigningMessage(TON_V4R2_WALLET_ID, 1700000000,
                                         1, 0, 3, &internal_msg,
                                         &signing_msg));
    EXPECT_EQ(signing_msg.bits.bit_len, 112);

    uint8_t sm_hash[TON_CELL_HASH_SIZE];
    ASSERT_TRUE(ton_cellHash(&signing_msg, sm_hash));

    static const uint8_t expected_sm[TON_CELL_HASH_SIZE] = {
        0xf6, 0x59, 0x60, 0x04, 0x24, 0xea, 0x2e, 0x47,
        0x16, 0x9c, 0x35, 0x0d, 0xf2, 0xaf, 0x81, 0x7c,
        0x78, 0xd0, 0xc5, 0xfc, 0xed, 0x52, 0xc3, 0x49,
        0x6c, 0x30, 0x63, 0x19, 0xa0, 0x06, 0xd2, 0x5c
    };
    EXPECT_TRUE(memcmp(sm_hash, expected_sm, TON_CELL_HASH_SIZE) == 0)
        << "Signing message hash does not match reference";
}

TEST(Ton, WriteBitsOverflow) {
    TonBitBuffer bb;
    ton_initBitBuffer(&bb);

    for (int i = 0; i < 128; i++) {
        ASSERT_TRUE(ton_writeBits(&bb, 0xFF, 8));
    }
    EXPECT_FALSE(ton_writeBits(&bb, 1, 1));
}
