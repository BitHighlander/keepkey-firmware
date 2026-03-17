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

#include "keepkey/firmware/tron.h"
#include "tron_tokens.h"

#include "trezor/crypto/base58.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hasher.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Protobuf encoding helpers                                         */
/* ------------------------------------------------------------------ */

static size_t pb_encode_varint(uint8_t *buf, uint64_t value) {
    size_t pos = 0;
    while (value >= 0x80) {
        buf[pos++] = (uint8_t)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    buf[pos++] = (uint8_t)(value & 0x7F);
    return pos;
}

static size_t pb_write_tag(uint8_t *buf, uint32_t field, uint32_t wire) {
    return pb_encode_varint(buf, ((uint64_t)field << 3) | wire);
}

static size_t pb_write_bytes(uint8_t *buf, uint32_t field,
                             const uint8_t *data, size_t len) {
    size_t pos = 0;
    pos += pb_write_tag(buf + pos, field, 2);
    pos += pb_encode_varint(buf + pos, len);
    memcpy(buf + pos, data, len);
    return pos + len;
}

static size_t pb_write_varint_field(uint8_t *buf, uint32_t field,
                                    uint64_t value) {
    size_t pos = 0;
    pos += pb_write_tag(buf + pos, field, 0);
    pos += pb_encode_varint(buf + pos, value);
    return pos;
}

/* ------------------------------------------------------------------ */
/*  Address functions                                                  */
/* ------------------------------------------------------------------ */

bool tron_getAddress(const uint8_t public_key[33],
                     char address[MAX_TRON_ADDR_SIZE]) {
    /* Decompress to 65-byte uncompressed key */
    uint8_t uncompressed[65];
    if (ecdsa_uncompress_pubkey(&secp256k1, public_key, uncompressed) == 0) {
        return false;
    }

    /* Keccak256 of the 64-byte coordinate part (skip 0x04 prefix) */
    uint8_t hash[32];
    keccak_256(uncompressed + 1, 64, hash);

    /* Raw address = 0x41 prefix + last 20 bytes of hash */
    uint8_t raw[TRON_ADDRESS_SIZE];
    raw[0] = TRON_MAINNET_PREFIX;
    memcpy(raw + 1, hash + 12, 20);

    /* Base58Check encode */
    size_t addr_len = MAX_TRON_ADDR_SIZE;
    if (base58_encode_check(raw, TRON_ADDRESS_SIZE, HASHER_SHA2D,
                            address, addr_len) == 0) {
        return false;
    }

    return true;
}

bool tron_decodeAddress(const char *address,
                        uint8_t raw_address[TRON_ADDRESS_SIZE]) {
    uint8_t decoded[25]; /* 21 raw + 4 checksum */
    if (base58_decode_check(address, HASHER_SHA2D, decoded, sizeof(decoded))
        != TRON_ADDRESS_SIZE) {
        return false;
    }
    if (decoded[0] != TRON_MAINNET_PREFIX) {
        return false;
    }
    memcpy(raw_address, decoded, TRON_ADDRESS_SIZE);
    return true;
}

bool tron_validateAddress(const char *address) {
    uint8_t raw[TRON_ADDRESS_SIZE];
    return tron_decodeAddress(address, raw);
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

void tron_formatAmount(char *buf, size_t len, uint64_t amount) {
    uint64_t whole = amount / 1000000ULL;
    uint64_t frac  = amount % 1000000ULL;
    snprintf(buf, len, "%llu.%06llu TRX",
             (unsigned long long)whole, (unsigned long long)frac);
}

static void tron_formatTokenAmount(char *buf, size_t len,
                                   const uint8_t amount_bytes[32],
                                   const TronToken *token) {
    /* Extract the amount from big-endian 32-byte word.
     * For display we only handle amounts that fit in uint64. */
    uint64_t val = 0;
    bool overflow = false;
    for (int i = 0; i < 32; i++) {
        if (i < 24 && amount_bytes[i] != 0) {
            overflow = true;
            break;
        }
        if (i >= 24) {
            val = (val << 8) | amount_bytes[i];
        }
    }

    if (overflow) {
        snprintf(buf, len, "large amount %s", token->symbol);
        return;
    }

    if (token->decimals == 6) {
        uint64_t whole = val / 1000000ULL;
        uint64_t frac  = val % 1000000ULL;
        snprintf(buf, len, "%llu.%06llu %s",
                 (unsigned long long)whole, (unsigned long long)frac,
                 token->symbol);
    } else if (token->decimals == 18) {
        /* Show integer part only for 18-decimal tokens on small display */
        uint64_t whole = val / 1000000000000000000ULL;
        snprintf(buf, len, "%llu %s", (unsigned long long)whole,
                 token->symbol);
    } else if (token->decimals == 8) {
        uint64_t whole = val / 100000000ULL;
        uint64_t frac  = val % 100000000ULL;
        snprintf(buf, len, "%llu.%08llu %s",
                 (unsigned long long)whole, (unsigned long long)frac,
                 token->symbol);
    } else {
        snprintf(buf, len, "%llu (raw) %s", (unsigned long long)val,
                 token->symbol);
    }
}

/* ------------------------------------------------------------------ */
/*  TRC-20 ABI decoding                                                */
/* ------------------------------------------------------------------ */

bool tron_decodeTRC20Transfer(const uint8_t *data, size_t data_len,
                              uint8_t to_raw[TRON_ADDRESS_SIZE],
                              uint8_t amount_bytes[32]) {
    /* transfer(address,uint256) = 4 + 32 + 32 = 68 bytes */
    if (data_len < 68) return false;

    /* Check selector 0xa9059cbb */
    if (data[0] != 0xa9 || data[1] != 0x05 ||
        data[2] != 0x9c || data[3] != 0xbb) {
        return false;
    }

    /* Address is in bytes 4..35 — last 20 bytes are the address,
     * first 11 bytes of the 32-byte word must be zero,
     * byte 12 (index 15) is the 0x41 TRON prefix. */
    const uint8_t *addr_word = data + 4;
    for (int i = 0; i < 11; i++) {
        if (addr_word[i] != 0) return false;
    }

    /* The 21-byte raw TRON address starts at offset 11 in the word */
    to_raw[0] = TRON_MAINNET_PREFIX;
    memcpy(to_raw + 1, addr_word + 12, 20);

    /* Amount is bytes 36..67 */
    memcpy(amount_bytes, data + 36, 32);

    return true;
}

/* ------------------------------------------------------------------ */
/*  Serialization: reconstruct raw_data from structured fields         */
/* ------------------------------------------------------------------ */

static bool tron_serializeTransferContract(
    const TronTransferContract *tc,
    const uint8_t *owner_raw,
    uint8_t *buf, size_t *len, size_t max_len) {
    size_t pos = 0;

    /* Inner contract: TransferContract protobuf
     * field 1: owner_address (bytes, 21)
     * field 2: to_address (bytes, 21)
     * field 3: amount (int64)
     */
    uint8_t inner[128];
    size_t inner_pos = 0;

    /* owner_address (field 1) */
    inner_pos += pb_write_bytes(inner + inner_pos, 1,
                                owner_raw, TRON_ADDRESS_SIZE);

    /* to_address (field 2) — decode from Base58 */
    uint8_t to_raw[TRON_ADDRESS_SIZE];
    if (!tron_decodeAddress(tc->to_address, to_raw)) return false;
    inner_pos += pb_write_bytes(inner + inner_pos, 2,
                                to_raw, TRON_ADDRESS_SIZE);

    /* amount (field 3) */
    inner_pos += pb_write_varint_field(inner + inner_pos, 3, tc->amount);

    /* Outer Contract wrapper:
     * field 1: type (enum ContractType = 1 for TransferContract)
     * field 2: parameter (Any { type_url, value })
     */
    uint8_t param[256];
    size_t param_pos = 0;

    /* parameter.type_url (field 1, string) */
    param_pos += pb_write_bytes(param + param_pos, 1,
                                (const uint8_t *)TRON_CONTRACT_TRANSFER,
                                strlen(TRON_CONTRACT_TRANSFER));

    /* parameter.value (field 2, bytes) */
    param_pos += pb_write_bytes(param + param_pos, 2, inner, inner_pos);

    /* Contract.type (field 1, varint = 1) */
    pos += pb_write_varint_field(buf + pos, 1, 1);

    /* Contract.parameter (field 2, nested message) */
    pos += pb_write_bytes(buf + pos, 2, param, param_pos);

    if (pos > max_len) return false;
    *len = pos;
    return true;
}

static bool tron_serializeTriggerSmartContract(
    const TronTriggerSmartContract *tsc,
    const uint8_t *owner_raw,
    uint8_t *buf, size_t *len, size_t max_len) {
    size_t pos = 0;

    /* Inner: TriggerSmartContract protobuf
     * field 1: owner_address (bytes)
     * field 2: contract_address (bytes)
     * field 3: call_value (int64, optional)
     * field 4: data (bytes)
     */
    uint8_t inner[768];
    size_t inner_pos = 0;

    /* owner_address (field 1) */
    inner_pos += pb_write_bytes(inner + inner_pos, 1,
                                owner_raw, TRON_ADDRESS_SIZE);

    /* contract_address (field 2) */
    uint8_t contract_raw[TRON_ADDRESS_SIZE];
    if (!tron_decodeAddress(tsc->contract_address, contract_raw)) return false;
    inner_pos += pb_write_bytes(inner + inner_pos, 2,
                                contract_raw, TRON_ADDRESS_SIZE);

    /* call_value (field 3) */
    if (tsc->has_call_value && tsc->call_value > 0) {
        inner_pos += pb_write_varint_field(inner + inner_pos, 3,
                                           tsc->call_value);
    }

    /* data (field 4) */
    if (tsc->data.size > 0) {
        inner_pos += pb_write_bytes(inner + inner_pos, 4,
                                    tsc->data.bytes, tsc->data.size);
    }

    /* Outer wrapper */
    uint8_t param[900];
    size_t param_pos = 0;

    param_pos += pb_write_bytes(param + param_pos, 1,
                                (const uint8_t *)TRON_CONTRACT_TRIGGER_SMART,
                                strlen(TRON_CONTRACT_TRIGGER_SMART));
    param_pos += pb_write_bytes(param + param_pos, 2, inner, inner_pos);

    /* Contract.type = 31 (TriggerSmartContract) */
    pos += pb_write_varint_field(buf + pos, 1, 31);
    pos += pb_write_bytes(buf + pos, 2, param, param_pos);

    if (pos > max_len) return false;
    *len = pos;
    return true;
}

bool tron_serializeRawTransaction(const TronSignTx *msg,
                                  const uint8_t *owner_raw,
                                  uint8_t *out, size_t *out_len,
                                  size_t max_len) {
    size_t pos = 0;

    /*
     * Tron Transaction.raw protobuf field numbers:
     *  1: ref_block_bytes (bytes)
     *  4: ref_block_hash (bytes)   — note: field 4, not 3!
     *  8: expiration (int64)
     * 11: contract (repeated Contract, nested)
     * 14: timestamp (int64)
     * 18: fee_limit (int64, optional)
     */

    /* Field 1: ref_block_bytes */
    if (msg->has_ref_block_bytes && msg->ref_block_bytes.size == 2) {
        pos += pb_write_bytes(out + pos, 1,
                              msg->ref_block_bytes.bytes,
                              msg->ref_block_bytes.size);
    } else {
        return false;
    }

    /* Field 4: ref_block_hash */
    if (msg->has_ref_block_hash && msg->ref_block_hash.size == 8) {
        pos += pb_write_bytes(out + pos, 4,
                              msg->ref_block_hash.bytes,
                              msg->ref_block_hash.size);
    } else {
        return false;
    }

    /* Field 8: expiration */
    if (msg->has_expiration) {
        pos += pb_write_varint_field(out + pos, 8, msg->expiration);
    } else {
        return false;
    }

    /* Field 11: contract (nested message) */
    uint8_t contract_buf[1024];
    size_t contract_len = 0;

    if (msg->has_transfer) {
        if (!tron_serializeTransferContract(&msg->transfer, owner_raw,
                                            contract_buf, &contract_len,
                                            sizeof(contract_buf))) {
            return false;
        }
    } else if (msg->has_trigger_smart) {
        if (!tron_serializeTriggerSmartContract(&msg->trigger_smart, owner_raw,
                                                contract_buf, &contract_len,
                                                sizeof(contract_buf))) {
            return false;
        }
    } else {
        return false;
    }

    pos += pb_write_bytes(out + pos, 11, contract_buf, contract_len);

    /* Field 14: timestamp */
    if (msg->has_timestamp) {
        pos += pb_write_varint_field(out + pos, 14, msg->timestamp);
    }

    /* Field 18: fee_limit */
    if (msg->has_fee_limit && msg->fee_limit > 0) {
        pos += pb_write_varint_field(out + pos, 18, msg->fee_limit);
    }

    if (pos > max_len) return false;
    *out_len = pos;
    return true;
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp) {
    uint8_t hash[32];

    if (msg->has_transfer || msg->has_trigger_smart) {
        /* Structured mode: reconstruct-then-sign */
        /* Get owner address raw bytes from pubkey */
        uint8_t uncompressed[65];
        if (ecdsa_uncompress_pubkey(&secp256k1, node->public_key,
                                    uncompressed) == 0) {
            return false;
        }
        uint8_t keccak[32];
        keccak_256(uncompressed + 1, 64, keccak);

        uint8_t owner_raw[TRON_ADDRESS_SIZE];
        owner_raw[0] = TRON_MAINNET_PREFIX;
        memcpy(owner_raw + 1, keccak + 12, 20);

        uint8_t serialized[1024];
        size_t serialized_len = 0;

        if (!tron_serializeRawTransaction(msg, owner_raw,
                                          serialized, &serialized_len,
                                          sizeof(serialized))) {
            return false;
        }

        /* Hash the reconstructed raw_data */
        sha256_Raw(serialized, serialized_len, hash);

        /* Return serialized_tx for host verification */
        resp->has_serialized_tx = true;
        resp->serialized_tx.size = serialized_len;
        memcpy(resp->serialized_tx.bytes, serialized, serialized_len);

    } else if (msg->has_raw_data && msg->raw_data.size > 0) {
        /* Legacy mode: blind-sign the host-supplied raw_data */
        sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);
    } else {
        return false;
    }

    /* ECDSA sign the digest */
    uint8_t sig[64];
    uint8_t pby;
    if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                          sig, &pby, NULL) != 0) {
        return false;
    }

    /* Tron signature format: r(32) + s(32) + v(1) where v = recovery_id */
    resp->has_signature = true;
    resp->signature.size = TRON_SIGNATURE_SIZE;
    memcpy(resp->signature.bytes, sig, 64);
    resp->signature.bytes[64] = pby;

    return true;
}
