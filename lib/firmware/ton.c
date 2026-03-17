/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/ton.h"

#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Base64 decoding (for TON user-friendly addresses)                  */
/* ------------------------------------------------------------------ */

static const int8_t b64_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

static int base64_decode(const char *src, size_t src_len,
                         uint8_t *out, size_t max_out) {
    if (src_len % 4 != 0) return -1;
    size_t out_len = (src_len / 4) * 3;

    /* Account for padding */
    if (src_len > 0 && src[src_len - 1] == '=') out_len--;
    if (src_len > 1 && src[src_len - 2] == '=') out_len--;

    if (out_len > max_out) return -1;

    size_t j = 0;
    for (size_t i = 0; i < src_len; i += 4) {
        uint8_t a = (uint8_t)src[i];
        uint8_t b = (uint8_t)src[i + 1];
        uint8_t c = (uint8_t)src[i + 2];
        uint8_t d = (uint8_t)src[i + 3];

        int8_t va = b64_table[a];
        int8_t vb = b64_table[b];
        int8_t vc = (src[i + 2] == '=') ? 0 : b64_table[c];
        int8_t vd = (src[i + 3] == '=') ? 0 : b64_table[d];

        if (va < 0 || vb < 0 || (src[i+2] != '=' && vc < 0) ||
            (src[i+3] != '=' && vd < 0)) {
            return -1;
        }

        uint32_t triple = ((uint32_t)va << 18) | ((uint32_t)vb << 12) |
                           ((uint32_t)vc << 6) | (uint32_t)vd;

        if (j < out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) out[j++] = triple & 0xFF;
    }

    return (int)out_len;
}

/* ------------------------------------------------------------------ */
/*  Address parsing                                                    */
/* ------------------------------------------------------------------ */

/* CRC16-XMODEM for TON address checksum */
static uint16_t crc16_xmodem(const uint8_t *data, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }
    return crc;
}

bool ton_parseDestination(const char *address, TonParsedAddress *parsed) {
    size_t alen = strlen(address);

    /* User-friendly format: 48 chars base64 → 36 bytes
     * [1 flag][1 workchain][32 hash][2 CRC16] */
    if (alen != 48) return false;

    /* Handle URL-safe base64: replace - with + and _ with / */
    char safe[49];
    memcpy(safe, address, alen);
    safe[alen] = '\0';
    for (size_t i = 0; i < alen; i++) {
        if (safe[i] == '-') safe[i] = '+';
        else if (safe[i] == '_') safe[i] = '/';
    }

    uint8_t decoded[36];
    int dlen = base64_decode(safe, alen, decoded, sizeof(decoded));
    if (dlen != 36) return false;

    /* Verify CRC16 */
    uint16_t crc = crc16_xmodem(decoded, 34);
    uint16_t expected = ((uint16_t)decoded[34] << 8) | decoded[35];
    if (crc != expected) return false;

    /* Parse flags */
    uint8_t flags = decoded[0];
    parsed->bounceable = (flags & 0x11) == 0x11;
    parsed->testnet = (flags & 0x80) != 0;

    /* Workchain (signed byte) */
    parsed->workchain = (int8_t)decoded[1];

    /* 32-byte hash */
    memcpy(parsed->hash, decoded + 2, 32);

    return true;
}

/* ------------------------------------------------------------------ */
/*  Bit buffer for cell construction                                   */
/* ------------------------------------------------------------------ */

void ton_initBitBuffer(TonBitBuffer *bb) {
    memset(bb->data, 0, sizeof(bb->data));
    bb->bit_len = 0;
}

void ton_writeBits(TonBitBuffer *bb, uint64_t value, uint8_t bits) {
    for (int i = bits - 1; i >= 0; i--) {
        uint16_t byte_idx = bb->bit_len / 8;
        uint8_t bit_idx = 7 - (bb->bit_len % 8);
        if (byte_idx >= sizeof(bb->data)) return; /* overflow guard */

        if ((value >> i) & 1) {
            bb->data[byte_idx] |= (1 << bit_idx);
        }
        bb->bit_len++;
    }
}

void ton_writeBytes(TonBitBuffer *bb, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ton_writeBits(bb, data[i], 8);
    }
}

/* ------------------------------------------------------------------ */
/*  Cell hashing (TVM cell representation → SHA256)                    */
/* ------------------------------------------------------------------ */

bool ton_cellHash(const TonCell *cell, uint8_t hash_out[TON_CELL_HASH_SIZE]) {
    /*
     * Cell representation for hashing (standard cell, no exotic):
     *   d1 = refs_count + (has_bits ? 0 : 0) + level*32 (we use level 0)
     *   d2 = ceil(bit_len / 8) * 2 + (bit_len % 8 != 0 ? 1 : 0)
     *        actually: d2 = floor(bit_len/8)*2 + ceil(bit_len%8 ? 1 : 0)
     *
     * Standard formula:
     *   d1 = ref_count (low 3 bits) | (exotic << 3) | (level << 5)
     *   d2 = (bit_len / 8) * 2 + ((bit_len % 8) ? 1 : 0)
     *        but byte count uses ceiling: ceil(bit_len / 8)
     *   data bytes = ceil(bit_len / 8), with padding bit if not byte-aligned
     *   then for each ref: 2 bytes depth (big-endian), then hash (32 bytes)
     *   wait — depth comes first for ALL refs, then hashes for ALL refs
     */

    SHA256_CTX ctx;
    sha256_Init(&ctx);

    /* d1: refs_descriptor */
    uint8_t d1 = cell->ref_count;  /* level 0, not exotic */
    sha256_Update(&ctx, &d1, 1);

    /* d2: bits_descriptor */
    uint16_t byte_len = (cell->bits.bit_len + 7) / 8;
    uint8_t d2_val = (uint8_t)(byte_len * 2);
    if (cell->bits.bit_len % 8 != 0) {
        d2_val--; /* incomplete byte: floor(bit_len/8)*2 + 1 */
    }
    /* Actually the standard formula is:
     * d2 = ceil(bit_len / 8) * 2
     * if bit_len % 8 != 0, we need the padding bit set
     * Let me use the standard: d2 = floor(bit_len/8)*2 + (bit_len%8 ? 1 : 0) */
    d2_val = (uint8_t)((cell->bits.bit_len / 8) * 2 +
                       (cell->bits.bit_len % 8 ? 1 : 0));
    sha256_Update(&ctx, &d2_val, 1);

    /* Data bytes: ceil(bit_len / 8) */
    uint8_t data_copy[128];
    memcpy(data_copy, cell->bits.data, byte_len);

    /* If not byte-aligned, add completion tag: set bit after last data bit,
     * clear remaining bits */
    if (cell->bits.bit_len % 8 != 0) {
        uint8_t last_byte_idx = (uint8_t)(cell->bits.bit_len / 8);
        uint8_t used_bits = cell->bits.bit_len % 8;
        /* Set the completion bit */
        data_copy[last_byte_idx] |= (1 << (7 - used_bits));
        /* Clear remaining bits after completion bit */
        uint8_t mask = (uint8_t)(0xFF << (7 - used_bits));
        data_copy[last_byte_idx] &= mask;
    }

    sha256_Update(&ctx, data_copy, byte_len);

    /* Depths for each ref (2 bytes big-endian) */
    for (uint8_t i = 0; i < cell->ref_count; i++) {
        uint8_t depth_be[2];
        depth_be[0] = (cell->ref_depths[i] >> 8) & 0xFF;
        depth_be[1] = cell->ref_depths[i] & 0xFF;
        sha256_Update(&ctx, depth_be, 2);
    }

    /* Hashes for each ref (32 bytes each) */
    for (uint8_t i = 0; i < cell->ref_count; i++) {
        sha256_Update(&ctx, cell->ref_hashes[i], TON_CELL_HASH_SIZE);
    }

    sha256_Final(&ctx, hash_out);
    return true;
}

/* ------------------------------------------------------------------ */
/*  Build internal message cell                                        */
/* ------------------------------------------------------------------ */

/* Write variable-length nanoTON amount in "coins" format */
static void ton_writeCoins(TonBitBuffer *bb, uint64_t amount) {
    if (amount == 0) {
        ton_writeBits(bb, 0, 4); /* len = 0 nibble */
        return;
    }

    /* Count bytes needed */
    uint8_t bytes[8];
    int nbytes = 0;
    uint64_t tmp = amount;
    while (tmp > 0) {
        bytes[nbytes++] = (uint8_t)(tmp & 0xFF);
        tmp >>= 8;
    }

    /* Write length nibble (number of bytes) */
    ton_writeBits(bb, (uint64_t)nbytes, 4);

    /* Write bytes big-endian */
    for (int i = nbytes - 1; i >= 0; i--) {
        ton_writeBits(bb, bytes[i], 8);
    }
}

bool ton_buildInternalMessage(const TonParsedAddress *dest,
                              uint64_t amount,
                              bool bounce,
                              const char *comment,
                              TonCell *cell_out) {
    memset(cell_out, 0, sizeof(*cell_out));
    TonBitBuffer *bb = &cell_out->bits;
    ton_initBitBuffer(bb);

    /*
     * Internal message structure:
     *   int_msg_info$0 = 0 (1 bit)
     *   ihr_disabled:1 = 1
     *   bounce:1
     *   bounced:1 = 0
     *   src:MsgAddressExt = addr_none$00 (2 bits)
     *   dest:MsgAddressInt = addr_std$10 (2 bits) + anycast:0 (1 bit) +
     *        workchain_id:int8 (8 bits) + address:bits256 (256 bits)
     *   value:CurrencyCollection = coins + other_currencies:0 (1 bit)
     *   ihr_fee:Coins = 0 (4 bits)
     *   fwd_fee:Coins = 0 (4 bits)
     *   created_lt:uint64 = 0 (64 bits)
     *   created_at:uint32 = 0 (32 bits)
     *   init:Maybe = 0 (1 bit)
     *   body:Either = 0 (inline, 1 bit) or 1 (ref)
     */

    /* int_msg_info$0 */
    ton_writeBits(bb, 0, 1);

    /* ihr_disabled = 1 */
    ton_writeBits(bb, 1, 1);

    /* bounce */
    ton_writeBits(bb, bounce ? 1 : 0, 1);

    /* bounced = 0 */
    ton_writeBits(bb, 0, 1);

    /* src = addr_none$00 */
    ton_writeBits(bb, 0, 2);

    /* dest = addr_std$10 + anycast:0 */
    ton_writeBits(bb, 0b100, 3); /* 10 + 0 */

    /* workchain_id: int8 */
    ton_writeBits(bb, (uint64_t)(uint8_t)dest->workchain, 8);

    /* address: bits256 */
    ton_writeBytes(bb, dest->hash, 32);

    /* value: amount in coins + no other currencies */
    ton_writeCoins(bb, amount);
    ton_writeBits(bb, 0, 1); /* empty ExtraCurrencyCollection */

    /* ihr_fee = 0 coins */
    ton_writeCoins(bb, 0);

    /* fwd_fee = 0 coins */
    ton_writeCoins(bb, 0);

    /* created_lt = 0 */
    ton_writeBits(bb, 0, 64);

    /* created_at = 0 */
    ton_writeBits(bb, 0, 32);

    /* init: Maybe = 0 (no StateInit) */
    ton_writeBits(bb, 0, 1);

    /* body: if comment exists, use inline text
     * For simple transfers with short comments, inline the body */
    if (comment && comment[0] != '\0') {
        size_t clen = strlen(comment);
        /* Check if comment fits inline (with 32-bit zero prefix for text op) */
        uint16_t body_bits = 32 + (uint16_t)(clen * 8);
        if (bb->bit_len + 1 + body_bits <= TON_MAX_CELL_BITS) {
            ton_writeBits(bb, 0, 1); /* inline body */
            ton_writeBits(bb, 0, 32); /* op = 0 (text comment) */
            ton_writeBytes(bb, (const uint8_t *)comment, clen);
        } else {
            /* Comment too long for inline — put in ref cell */
            ton_writeBits(bb, 1, 1); /* body in ref */

            /* Build body cell */
            TonCell body_cell;
            memset(&body_cell, 0, sizeof(body_cell));
            ton_initBitBuffer(&body_cell.bits);
            ton_writeBits(&body_cell.bits, 0, 32); /* op = 0 */
            ton_writeBytes(&body_cell.bits, (const uint8_t *)comment, clen);

            /* Hash body cell and store as ref */
            uint8_t body_hash[TON_CELL_HASH_SIZE];
            if (!ton_cellHash(&body_cell, body_hash)) return false;

            memcpy(cell_out->ref_hashes[cell_out->ref_count], body_hash,
                   TON_CELL_HASH_SIZE);
            cell_out->ref_depths[cell_out->ref_count] = 0;
            cell_out->ref_count++;
        }
    } else {
        /* No body */
        ton_writeBits(bb, 0, 1); /* inline empty body */
    }

    return true;
}

/* ------------------------------------------------------------------ */
/*  Build v4r2 signing message                                         */
/* ------------------------------------------------------------------ */

bool ton_buildSigningMessage(uint32_t wallet_id,
                             uint32_t expire_at,
                             uint32_t seqno,
                             uint8_t op,
                             uint8_t mode,
                             const TonCell *internal_msg,
                             TonCell *cell_out) {
    memset(cell_out, 0, sizeof(*cell_out));
    TonBitBuffer *bb = &cell_out->bits;
    ton_initBitBuffer(bb);

    /*
     * v4r2 signing message:
     *   wallet_id: uint32 (32 bits)
     *   valid_until: uint32 (32 bits)
     *   seqno: uint32 (32 bits)
     *   op: uint8 (8 bits) — 0 for simple send
     *   mode: uint8 (8 bits) — send mode
     *   ref → internal message cell
     */

    ton_writeBits(bb, wallet_id, 32);
    ton_writeBits(bb, expire_at, 32);
    ton_writeBits(bb, seqno, 32);
    ton_writeBits(bb, op, 8);
    ton_writeBits(bb, mode, 8);

    /* Add internal message as ref */
    uint8_t msg_hash[TON_CELL_HASH_SIZE];
    if (!ton_cellHash(internal_msg, msg_hash)) return false;

    memcpy(cell_out->ref_hashes[0], msg_hash, TON_CELL_HASH_SIZE);

    /* Compute depth of internal msg: its depth + 1 */
    uint16_t msg_depth = 0;
    for (uint8_t i = 0; i < internal_msg->ref_count; i++) {
        if (internal_msg->ref_depths[i] + 1 > msg_depth) {
            msg_depth = internal_msg->ref_depths[i] + 1;
        }
    }
    cell_out->ref_depths[0] = msg_depth;
    cell_out->ref_count = 1;

    return true;
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

void ton_formatAmount(char *buf, size_t len, uint64_t nanoton) {
    uint64_t whole = nanoton / 1000000000ULL;
    uint64_t frac  = nanoton % 1000000000ULL;
    snprintf(buf, len, "%llu.%09llu TON",
             (unsigned long long)whole, (unsigned long long)frac);
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool ton_signTx(const HDNode *node, const TonSignTx *msg, TonSignedTx *resp) {
    uint8_t hash[32];

    bool is_structured = msg->has_destination && msg->has_ton_amount &&
                         msg->has_seqno;
    bool is_legacy = msg->has_raw_tx && msg->raw_tx.size > 0;

    if (is_structured) {
        /* Structured mode: reconstruct v4r2 signing message */

        /* Parse destination address */
        TonParsedAddress dest;
        if (!ton_parseDestination(msg->destination, &dest)) {
            return false;
        }

        /* Build internal message */
        TonCell internal_msg;
        bool bounce = msg->has_bounce ? msg->bounce : true;
        const char *comment = (msg->has_comment && msg->comment[0]) ?
                              msg->comment : NULL;

        if (!ton_buildInternalMessage(&dest, msg->ton_amount, bounce,
                                      comment, &internal_msg)) {
            return false;
        }

        /* Build signing message */
        uint32_t wallet_id = TON_V4R2_WALLET_ID;
        uint32_t expire_at = msg->has_expire_at ? msg->expire_at : 0;
        uint8_t mode = msg->has_mode ? (uint8_t)msg->mode : 3;

        TonCell signing_msg;
        if (!ton_buildSigningMessage(wallet_id, expire_at, msg->seqno,
                                     0, mode, &internal_msg,
                                     &signing_msg)) {
            return false;
        }

        /* Hash the signing message cell */
        if (!ton_cellHash(&signing_msg, hash)) {
            return false;
        }

        /* Return cell hash for verification */
        resp->has_cell_hash = true;
        resp->cell_hash.size = TON_CELL_HASH_SIZE;
        memcpy(resp->cell_hash.bytes, hash, TON_CELL_HASH_SIZE);

    } else if (is_legacy) {
        /* Legacy mode: hash raw_tx directly */
        sha256_Raw(msg->raw_tx.bytes, msg->raw_tx.size, hash);
    } else {
        return false;
    }

    /* Ed25519 sign */
    uint8_t sig[64];
    ed25519_sign(hash, 32, node->private_key, node->public_key + 1, sig);

    resp->has_signature = true;
    resp->signature.size = 64;
    memcpy(resp->signature.bytes, sig, 64);

    return true;
}
