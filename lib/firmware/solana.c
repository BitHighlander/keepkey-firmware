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

#include "keepkey/firmware/solana.h"

#include "trezor/crypto/memzero.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Well-known program IDs                                             */
/* ------------------------------------------------------------------ */

/* 11111111111111111111111111111111 */
const uint8_t SOL_SYSTEM_PROGRAM[SOL_PUBKEY_SIZE] = {0};

/* TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA */
const uint8_t SOL_TOKEN_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
};

/* Stake11111111111111111111111111111111111111 */
const uint8_t SOL_STAKE_PROGRAM[SOL_PUBKEY_SIZE] = {
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
    0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
    0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00
};

/* ------------------------------------------------------------------ */
/*  Compact-u16 decoder (Solana transaction format)                    */
/* ------------------------------------------------------------------ */

static int read_compact_u16(const uint8_t *data, size_t len, uint16_t *out) {
    if (len < 1) return -1;

    if (data[0] < 0x80) {
        *out = data[0];
        return 1;
    }

    if (len < 2) return -1;
    if (data[1] < 0x80) {
        *out = (uint16_t)((data[0] & 0x7F) | ((uint16_t)data[1] << 7));
        return 2;
    }

    if (len < 3) return -1;
    /* Third byte uses bits 14-15, so only values 0-3 are valid
     * (max compact-u16 value is 0xFFFF = 65535). */
    if (data[2] > 3) return -1;
    *out = (uint16_t)((data[0] & 0x7F) | ((data[1] & 0x7F) << 7) |
                       ((uint16_t)data[2] << 14));
    return 3;
}

static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  Transaction parser                                                 */
/* ------------------------------------------------------------------ */

bool solana_parseTx(const uint8_t *raw, size_t raw_len, SolanaParsedTx *tx) {
    memset(tx, 0, sizeof(*tx));
    size_t pos = 0;

    /* Header: num_required_sigs, num_readonly_signed, num_readonly_unsigned */
    if (raw_len < 3) return false;
    tx->num_required_sigs = raw[pos++];
    tx->num_readonly_signed = raw[pos++];
    tx->num_readonly_unsigned = raw[pos++];

    /* Account keys count (compact-u16) */
    uint16_t num_accounts;
    int n = read_compact_u16(raw + pos, raw_len - pos, &num_accounts);
    if (n < 0) return false;
    pos += n;

    if (num_accounts > 32) return false;
    tx->num_accounts = (uint8_t)num_accounts;

    /* Read account keys */
    for (uint16_t i = 0; i < num_accounts; i++) {
        if (pos + SOL_PUBKEY_SIZE > raw_len) return false;
        memcpy(tx->accounts[i], raw + pos, SOL_PUBKEY_SIZE);
        pos += SOL_PUBKEY_SIZE;
    }

    /* Recent blockhash */
    if (pos + SOL_PUBKEY_SIZE > raw_len) return false;
    memcpy(tx->recent_blockhash, raw + pos, SOL_PUBKEY_SIZE);
    pos += SOL_PUBKEY_SIZE;

    /* Instructions count (compact-u16) */
    uint16_t num_instructions;
    n = read_compact_u16(raw + pos, raw_len - pos, &num_instructions);
    if (n < 0) return false;
    pos += n;

    if (num_instructions > 8) {
        /* Too many instructions to parse — reject so the caller falls
         * back to the blind-sign warning path rather than silently
         * signing instructions the user never saw on-screen. */
        return false;
    }
    tx->num_instructions = (uint8_t)num_instructions;

    /* Parse each instruction */
    for (uint16_t i = 0; i < num_instructions; i++) {
        /* Program ID index */
        if (pos >= raw_len) return false;
        uint8_t program_idx = raw[pos++];
        if (program_idx >= num_accounts) return false;

        /* Account indices */
        uint16_t num_acct_indices;
        n = read_compact_u16(raw + pos, raw_len - pos, &num_acct_indices);
        if (n < 0) return false;
        pos += n;

        if (pos + num_acct_indices > raw_len) return false;

        const uint8_t *acct_indices = raw + pos;
        pos += num_acct_indices;

        /* Bounds-check every account index before we use them */
        for (uint16_t j = 0; j < num_acct_indices; j++) {
            if (acct_indices[j] >= num_accounts) return false;
        }

        /* Instruction data */
        uint16_t data_len;
        n = read_compact_u16(raw + pos, raw_len - pos, &data_len);
        if (n < 0) return false;
        pos += n;

        if (pos + data_len > raw_len) return false;
        const uint8_t *instr_data = raw + pos;
        pos += data_len;

        SolanaParsedInstruction *pi = &tx->instructions[i];
        memcpy(pi->program_id, tx->accounts[program_idx], SOL_PUBKEY_SIZE);

        /* Classify and decode */
        if (memcmp(pi->program_id, SOL_SYSTEM_PROGRAM,
                   SOL_PUBKEY_SIZE) == 0) {
            /* System program */
            if (data_len >= 12) {
                uint32_t instr_type = read_le32(instr_data);
                if (instr_type == 2) {
                    /* Transfer */
                    pi->type = SOL_INSTR_SYSTEM_TRANSFER;
                    pi->lamports = read_le64(instr_data + 4);
                    if (num_acct_indices >= 2) {
                        memcpy(pi->from, tx->accounts[acct_indices[0]],
                               SOL_PUBKEY_SIZE);
                        memcpy(pi->to, tx->accounts[acct_indices[1]],
                               SOL_PUBKEY_SIZE);
                    }
                } else if (instr_type == 0) {
                    /* CreateAccount */
                    pi->type = SOL_INSTR_SYSTEM_CREATE_ACCOUNT;
                    pi->lamports = read_le64(instr_data + 4);
                    if (num_acct_indices >= 2) {
                        memcpy(pi->from, tx->accounts[acct_indices[0]],
                               SOL_PUBKEY_SIZE);
                        memcpy(pi->to, tx->accounts[acct_indices[1]],
                               SOL_PUBKEY_SIZE);
                    }
                } else {
                    pi->type = SOL_INSTR_UNKNOWN;
                }
            } else {
                pi->type = SOL_INSTR_UNKNOWN;
            }
        } else if (memcmp(pi->program_id, SOL_TOKEN_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            /* SPL Token program */
            if (data_len >= 1) {
                uint8_t token_instr = instr_data[0];
                if (token_instr == 3 && data_len >= 9) {
                    /* Transfer */
                    pi->type = SOL_INSTR_TOKEN_TRANSFER;
                    pi->amount = read_le64(instr_data + 1);
                    if (num_acct_indices >= 3) {
                        memcpy(pi->from, tx->accounts[acct_indices[0]],
                               SOL_PUBKEY_SIZE);
                        memcpy(pi->to, tx->accounts[acct_indices[1]],
                               SOL_PUBKEY_SIZE);
                    }
                } else if (token_instr == 12 && data_len >= 9) {
                    /* TransferChecked */
                    pi->type = SOL_INSTR_TOKEN_TRANSFER_CHECKED;
                    pi->amount = read_le64(instr_data + 1);
                    if (num_acct_indices >= 4) {
                        memcpy(pi->from, tx->accounts[acct_indices[0]],
                               SOL_PUBKEY_SIZE);
                        memcpy(pi->mint, tx->accounts[acct_indices[1]],
                               SOL_PUBKEY_SIZE);
                        pi->has_mint = true;
                        memcpy(pi->to, tx->accounts[acct_indices[2]],
                               SOL_PUBKEY_SIZE);
                    }
                } else if (token_instr == 4 && data_len >= 9) {
                    /* Approve */
                    pi->type = SOL_INSTR_TOKEN_APPROVE;
                    pi->amount = read_le64(instr_data + 1);
                    if (num_acct_indices >= 2) {
                        memcpy(pi->from, tx->accounts[acct_indices[0]],
                               SOL_PUBKEY_SIZE);
                        memcpy(pi->to, tx->accounts[acct_indices[1]],
                               SOL_PUBKEY_SIZE);
                    }
                } else {
                    pi->type = SOL_INSTR_UNKNOWN;
                }
            } else {
                pi->type = SOL_INSTR_UNKNOWN;
            }
        } else if (memcmp(pi->program_id, SOL_STAKE_PROGRAM,
                          SOL_PUBKEY_SIZE) == 0) {
            if (data_len >= 4) {
                uint32_t stake_instr = read_le32(instr_data);
                if (stake_instr == 2) {
                    pi->type = SOL_INSTR_STAKE_DELEGATE;
                } else if (stake_instr == 4 && data_len >= 12) {
                    pi->type = SOL_INSTR_STAKE_WITHDRAW;
                    pi->lamports = read_le64(instr_data + 4);
                } else {
                    pi->type = SOL_INSTR_UNKNOWN;
                }
            } else {
                pi->type = SOL_INSTR_UNKNOWN;
            }
        } else {
            pi->type = SOL_INSTR_UNKNOWN;
        }
    }

    /* Reject if there are unconsumed bytes — prevents hidden trailing data */
    if (pos != raw_len) return false;

    return true;
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

void solana_formatAmount(char *buf, size_t len, uint64_t lamports) {
    uint64_t whole = lamports / 1000000000ULL;
    uint64_t frac  = lamports % 1000000000ULL;
    snprintf(buf, len, "%llu.%09llu SOL",
             (unsigned long long)whole, (unsigned long long)frac);
}

void solana_formatTokenAmount(char *buf, size_t len, uint64_t amount,
                              const char *symbol, uint8_t decimals) {
    if (decimals == 0 || decimals > 18) {
        snprintf(buf, len, "%llu %s", (unsigned long long)amount, symbol);
        return;
    }

    uint64_t divisor = 1;
    for (uint8_t i = 0; i < decimals; i++) divisor *= 10;

    uint64_t whole = amount / divisor;
    uint64_t frac  = amount % divisor;

    /* Format with appropriate decimal places (max 9 shown) */
    uint8_t show_dec = decimals > 9 ? 9 : decimals;
    uint64_t show_div = 1;
    for (uint8_t i = 0; i < show_dec; i++) show_div *= 10;
    uint64_t show_frac = frac;
    if (decimals > 9) {
        for (uint8_t i = 0; i < decimals - 9; i++) show_frac /= 10;
    }

    char fmt[32];
    snprintf(fmt, sizeof(fmt), "%%llu.%%0%dllu %%s", show_dec);
    snprintf(buf, len, fmt, (unsigned long long)whole,
             (unsigned long long)show_frac, symbol);
}

const SolanaTokenInfo *solana_findTokenInfo(const SolanaSignTx *msg,
                                            const uint8_t mint[SOL_PUBKEY_SIZE]) {
    for (size_t i = 0; i < msg->token_info_count; i++) {
        if (msg->token_info[i].has_mint &&
            msg->token_info[i].mint.size == SOL_PUBKEY_SIZE &&
            memcmp(msg->token_info[i].mint.bytes, mint, SOL_PUBKEY_SIZE) == 0) {
            return &msg->token_info[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool solana_signTx(const HDNode *node, const SolanaSignTx *msg,
                   SolanaSignedTx *resp) {
    if (!msg->has_raw_tx || msg->raw_tx.size == 0) return false;

    /* Ed25519 sign the raw transaction message directly
     * (Solana signs the serialized message, not a hash of it) */
    uint8_t sig[SOL_SIG_SIZE];
    ed25519_sign(msg->raw_tx.bytes, msg->raw_tx.size,
                 node->private_key, node->public_key + 1, sig);

    resp->has_signature = true;
    resp->signature.size = SOL_SIG_SIZE;
    memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

    return true;
}
