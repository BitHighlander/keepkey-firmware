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
/*  Protobuf encoding helpers — bounded-write variants                 */
/*                                                                     */
/*  Every helper checks remaining capacity BEFORE writing.  On failure */
/*  the buffer is left unchanged and the function returns false.       */
/* ------------------------------------------------------------------ */

/* Compute the encoded size of a varint without writing anything. */
static size_t pb_varint_size(uint64_t value) {
    size_t n = 1;
    while (value >= 0x80) {
        n++;
        value >>= 7;
    }
    return n;
}

/* Encode a varint into buf, checking capacity first.
 * Returns true on success, advances *pos. */
static bool pb_encode_varint_safe(uint8_t *buf, size_t *pos, size_t max_len,
                                  uint64_t value) {
    size_t need = pb_varint_size(value);
    if (*pos + need > max_len) return false;
    while (value >= 0x80) {
        buf[(*pos)++] = (uint8_t)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    buf[(*pos)++] = (uint8_t)(value & 0x7F);
    return true;
}

/* Write a protobuf tag (field number + wire type). */
static bool pb_write_tag_safe(uint8_t *buf, size_t *pos, size_t max_len,
                              uint32_t field, uint32_t wire) {
    return pb_encode_varint_safe(buf, pos, max_len,
                                 ((uint64_t)field << 3) | wire);
}

/* Write a length-delimited field (wire type 2): tag + length + data.
 * Checks total space needed BEFORE touching the buffer. */
static bool pb_write_bytes_safe(uint8_t *buf, size_t *pos, size_t max_len,
                                uint32_t field,
                                const uint8_t *data, size_t len) {
    size_t tag_size = pb_varint_size(((uint64_t)field << 3) | 2);
    size_t len_size = pb_varint_size((uint64_t)len);
    if (*pos + tag_size + len_size + len > max_len) return false;

    if (!pb_write_tag_safe(buf, pos, max_len, field, 2)) return false;
    if (!pb_encode_varint_safe(buf, pos, max_len, (uint64_t)len)) return false;
    memcpy(buf + *pos, data, len);
    *pos += len;
    return true;
}

/* Write a varint field (wire type 0): tag + varint value.
 * Checks total space needed BEFORE touching the buffer. */
static bool pb_write_varint_field_safe(uint8_t *buf, size_t *pos,
                                       size_t max_len,
                                       uint32_t field, uint64_t value) {
    size_t tag_size = pb_varint_size(((uint64_t)field << 3) | 0);
    size_t val_size = pb_varint_size(value);
    if (*pos + tag_size + val_size > max_len) return false;

    if (!pb_write_tag_safe(buf, pos, max_len, field, 0)) return false;
    if (!pb_encode_varint_safe(buf, pos, max_len, value)) return false;
    return true;
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

    /* HIGH-1: Validate the TRON mainnet prefix byte (0x41) */
    if (addr_word[11] != TRON_MAINNET_PREFIX) return false;

    /* The 21-byte raw TRON address starts at offset 11 in the word */
    memcpy(to_raw, addr_word + 11, TRON_ADDRESS_SIZE);

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

    uint8_t inner[128];
    size_t inner_pos = 0;

    if (!pb_write_bytes_safe(inner, &inner_pos, sizeof(inner), 1,
                             owner_raw, TRON_ADDRESS_SIZE))
        return false;

    uint8_t to_raw[TRON_ADDRESS_SIZE];
    if (!tron_decodeAddress(tc->to_address, to_raw)) return false;
    if (!pb_write_bytes_safe(inner, &inner_pos, sizeof(inner), 2,
                             to_raw, TRON_ADDRESS_SIZE))
        return false;

    if (!pb_write_varint_field_safe(inner, &inner_pos, sizeof(inner),
                                    3, tc->amount))
        return false;

    uint8_t param[256];
    size_t param_pos = 0;

    if (!pb_write_bytes_safe(param, &param_pos, sizeof(param), 1,
                             (const uint8_t *)TRON_CONTRACT_TRANSFER,
                             strlen(TRON_CONTRACT_TRANSFER)))
        return false;

    if (!pb_write_bytes_safe(param, &param_pos, sizeof(param), 2,
                             inner, inner_pos))
        return false;

    size_t pos = 0;

    if (!pb_write_varint_field_safe(buf, &pos, max_len, 1, 1))
        return false;

    if (!pb_write_bytes_safe(buf, &pos, max_len, 2, param, param_pos))
        return false;

    *len = pos;
    return true;
}


static bool tron_serializeTriggerSmartContract(
    const TronTriggerSmartContract *tsc,
    const uint8_t *owner_raw,
    uint8_t *buf, size_t *len, size_t max_len) {

    uint8_t inner[768];
    size_t inner_pos = 0;

    if (!pb_write_bytes_safe(inner, &inner_pos, sizeof(inner), 1,
                             owner_raw, TRON_ADDRESS_SIZE))
        return false;

    uint8_t contract_raw[TRON_ADDRESS_SIZE];
    if (!tron_decodeAddress(tsc->contract_address, contract_raw)) return false;
    if (!pb_write_bytes_safe(inner, &inner_pos, sizeof(inner), 2,
                             contract_raw, TRON_ADDRESS_SIZE))
        return false;

    if (tsc->has_call_value && tsc->call_value > 0) {
        if (!pb_write_varint_field_safe(inner, &inner_pos, sizeof(inner),
                                        3, tsc->call_value))
            return false;
    }

    if (tsc->data.size > 0) {
        if (!pb_write_bytes_safe(inner, &inner_pos, sizeof(inner), 4,
                                 tsc->data.bytes, tsc->data.size))
            return false;
    }

    uint8_t param[900];
    size_t param_pos = 0;

    if (!pb_write_bytes_safe(param, &param_pos, sizeof(param), 1,
                             (const uint8_t *)TRON_CONTRACT_TRIGGER_SMART,
                             strlen(TRON_CONTRACT_TRIGGER_SMART)))
        return false;
    if (!pb_write_bytes_safe(param, &param_pos, sizeof(param), 2,
                             inner, inner_pos))
        return false;

    size_t pos = 0;

    if (!pb_write_varint_field_safe(buf, &pos, max_len, 1, 31))
        return false;
    if (!pb_write_bytes_safe(buf, &pos, max_len, 2, param, param_pos))
        return false;

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
        if (!pb_write_bytes_safe(out, &pos, max_len, 1,
                                 msg->ref_block_bytes.bytes,
                                 msg->ref_block_bytes.size))
            return false;
    } else {
        return false;
    }

    /* Field 4: ref_block_hash */
    if (msg->has_ref_block_hash && msg->ref_block_hash.size == 8) {
        if (!pb_write_bytes_safe(out, &pos, max_len, 4,
                                 msg->ref_block_hash.bytes,
                                 msg->ref_block_hash.size))
            return false;
    } else {
        return false;
    }

    /* Field 8: expiration */
    if (msg->has_expiration) {
        if (!pb_write_varint_field_safe(out, &pos, max_len, 8,
                                        msg->expiration))
            return false;
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

    if (!pb_write_bytes_safe(out, &pos, max_len, 11,
                             contract_buf, contract_len))
        return false;

    /* Field 14: timestamp */
    if (msg->has_timestamp) {
        if (!pb_write_varint_field_safe(out, &pos, max_len, 14,
                                        msg->timestamp))
            return false;
    }

    /* Field 18: fee_limit */
    if (msg->has_fee_limit && msg->fee_limit > 0) {
        if (!pb_write_varint_field_safe(out, &pos, max_len, 18,
                                        msg->fee_limit))
            return false;
    }

    *out_len = pos;
    return true;
}

/* ------------------------------------------------------------------ */
/*  Signing                                                            */
/* ------------------------------------------------------------------ */

bool tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp) {
    uint8_t hash[32];
    uint8_t sig[64];
    uint8_t pby = 0;
    bool ok = false;

    memzero(hash, sizeof(hash));
    memzero(sig, sizeof(sig));

    if (msg->has_transfer || msg->has_trigger_smart) {
        /* Structured mode: reconstruct-then-sign */
        uint8_t uncompressed[65];
        if (ecdsa_uncompress_pubkey(&secp256k1, node->public_key,
                                    uncompressed) == 0) {
            goto cleanup;
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
            memzero(keccak, sizeof(keccak));
            memzero(owner_raw, sizeof(owner_raw));
            goto cleanup;
        }

        sha256_Raw(serialized, serialized_len, hash);

        resp->has_serialized_tx = true;
        resp->serialized_tx.size = serialized_len;
        memcpy(resp->serialized_tx.bytes, serialized, serialized_len);

        memzero(keccak, sizeof(keccak));
        memzero(owner_raw, sizeof(owner_raw));

    } else if (msg->has_raw_data && msg->raw_data.size > 0) {
        sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);
    } else {
        goto cleanup;
    }

    if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                          sig, &pby, NULL) != 0) {
        goto cleanup;
    }

    resp->has_signature = true;
    resp->signature.size = TRON_SIGNATURE_SIZE;
    memcpy(resp->signature.bytes, sig, 64);
    resp->signature.bytes[64] = pby;

    ok = true;

cleanup:
    memzero(hash, sizeof(hash));
    memzero(sig, sizeof(sig));
    return ok;
}
