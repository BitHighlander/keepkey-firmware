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

#ifndef KEEPKEY_FIRMWARE_SOLANA_H
#define KEEPKEY_FIRMWARE_SOLANA_H

#include "trezor/crypto/bip32.h"
#include "messages-solana.pb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SOL_DECIMALS 9
#define SOL_PUBKEY_SIZE 32
#define SOL_SIG_SIZE 64

/* Well-known program IDs */
extern const uint8_t SOL_SYSTEM_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_TOKEN_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_STAKE_PROGRAM[SOL_PUBKEY_SIZE];

/* Instruction types recognized by the parser */
typedef enum {
    SOL_INSTR_SYSTEM_TRANSFER,
    SOL_INSTR_SYSTEM_CREATE_ACCOUNT,
    SOL_INSTR_TOKEN_TRANSFER,
    SOL_INSTR_TOKEN_TRANSFER_CHECKED,
    SOL_INSTR_TOKEN_APPROVE,
    SOL_INSTR_STAKE_DELEGATE,
    SOL_INSTR_STAKE_WITHDRAW,
    SOL_INSTR_UNKNOWN,
} SolanaInstrType;

/* Parsed instruction */
typedef struct {
    SolanaInstrType type;
    uint8_t program_id[SOL_PUBKEY_SIZE];
    /* Decoded fields (filled based on type) */
    uint8_t from[SOL_PUBKEY_SIZE];
    uint8_t to[SOL_PUBKEY_SIZE];
    uint64_t amount;
    uint64_t lamports;
    /* For token transfers */
    uint8_t mint[SOL_PUBKEY_SIZE];
    bool has_mint;
} SolanaParsedInstruction;

/* Parsed transaction header */
typedef struct {
    uint8_t num_required_sigs;
    uint8_t num_readonly_signed;
    uint8_t num_readonly_unsigned;
    uint8_t num_accounts;
    uint8_t accounts[32][SOL_PUBKEY_SIZE]; /* max 32 account keys */
    uint8_t recent_blockhash[SOL_PUBKEY_SIZE];
    uint8_t num_instructions;
    SolanaParsedInstruction instructions[8]; /* max 8 instructions */
} SolanaParsedTx;

/* Firmware review result for a Solana message */
typedef enum {
    SOL_TX_REVIEW_MALFORMED = 0,
    SOL_TX_REVIEW_OPAQUE,
    SOL_TX_REVIEW_VERIFIED,
} SolanaTxReview;

/* Inspect a raw Solana transaction and classify it for signing UX */
SolanaTxReview solana_inspectTx(const uint8_t *raw, size_t raw_len,
                                SolanaParsedTx *tx);

/* Parse a raw Solana transaction */
bool solana_parseTx(const uint8_t *raw, size_t raw_len, SolanaParsedTx *tx);

/* Format SOL amount */
void solana_formatAmount(char *buf, size_t len, uint64_t lamports);

/* Format token amount with decimals */
void solana_formatTokenAmount(char *buf, size_t len, uint64_t amount,
                              const char *symbol, uint8_t decimals);

/* Look up token info from the host-provided list */
const SolanaTokenInfo *solana_findTokenInfo(const SolanaSignTx *msg,
                                            const uint8_t mint[SOL_PUBKEY_SIZE]);

/* Sign transaction */
bool solana_signTx(const HDNode *node, const SolanaSignTx *msg,
                   SolanaSignedTx *resp);

#endif /* KEEPKEY_FIRMWARE_SOLANA_H */
