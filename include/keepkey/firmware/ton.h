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

#ifndef KEEPKEY_FIRMWARE_TON_H
#define KEEPKEY_FIRMWARE_TON_H

#include "trezor/crypto/bip32.h"
#include "messages-ton.pb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TON_DECIMALS 9
#define TON_V4R2_WALLET_ID 698983191  /* 0x29a9a317 */

/* Cell representation: bits + refs → SHA256 = cell hash */
#define TON_MAX_CELL_BITS  1023
#define TON_MAX_CELL_REFS  4
#define TON_CELL_HASH_SIZE 32

/* Address parsing result */
typedef struct {
    int8_t workchain;
    uint8_t hash[32];
    bool bounceable;
    bool testnet;
} TonParsedAddress;

/* Bit-buffer for cell construction */
typedef struct {
    uint8_t data[128];  /* max 1023 bits = 128 bytes */
    uint16_t bit_len;
} TonBitBuffer;

/* Cell structure for SHA256 hashing */
typedef struct {
    TonBitBuffer bits;
    uint8_t ref_hashes[TON_MAX_CELL_REFS][TON_CELL_HASH_SIZE];
    uint8_t ref_count;
    uint16_t ref_depths[TON_MAX_CELL_REFS];
} TonCell;

/* Address functions */
bool ton_parseDestination(const char *address, TonParsedAddress *parsed);

/* Cell construction */
void ton_initBitBuffer(TonBitBuffer *bb);
void ton_writeBits(TonBitBuffer *bb, uint64_t value, uint8_t bits);
void ton_writeBytes(TonBitBuffer *bb, const uint8_t *data, size_t len);

/* Cell hashing (SHA256 of cell representation) */
bool ton_cellHash(const TonCell *cell, uint8_t hash_out[TON_CELL_HASH_SIZE]);

/* Build internal message cell for TON transfer */
bool ton_buildInternalMessage(const TonParsedAddress *dest,
                              uint64_t amount,
                              bool bounce,
                              const char *comment,
                              TonCell *cell_out);

/* Build v4r2 signing message (outer cell) */
bool ton_buildSigningMessage(uint32_t wallet_id,
                             uint32_t expire_at,
                             uint32_t seqno,
                             uint8_t op,
                             uint8_t mode,
                             const TonCell *internal_msg,
                             TonCell *cell_out);

/* Formatting */
void ton_formatAmount(char *buf, size_t len, uint64_t nanoton);

/* Sign transaction (structured or raw) */
bool ton_signTx(const HDNode *node, const TonSignTx *msg, TonSignedTx *resp);

#endif /* KEEPKEY_FIRMWARE_TON_H */
