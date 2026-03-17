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

#ifndef KEEPKEY_FIRMWARE_TRON_H
#define KEEPKEY_FIRMWARE_TRON_H

#include "trezor/crypto/bip32.h"
#include "messages-tron.pb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRON_DECIMALS 6
#define TRON_ADDRESS_SIZE 21
#define MAX_TRON_ADDR_SIZE 35
#define TRON_MAINNET_PREFIX 0x41
#define TRON_SIGNATURE_SIZE 65

/* Protobuf contract type URLs */
#define TRON_CONTRACT_TRANSFER \
    "type.googleapis.com/protocol.TransferContract"
#define TRON_CONTRACT_TRIGGER_SMART \
    "type.googleapis.com/protocol.TriggerSmartContract"

/* TRC-20 ABI selector: transfer(address,uint256) */
#define TRC20_TRANSFER_SELECTOR 0xa9059cbb

/* Address derivation */
bool tron_getAddress(const uint8_t public_key[33],
                     char address[MAX_TRON_ADDR_SIZE]);

bool tron_decodeAddress(const char *address,
                        uint8_t raw_address[TRON_ADDRESS_SIZE]);

bool tron_validateAddress(const char *address);

/* Formatting */
void tron_formatAmount(char *buf, size_t len, uint64_t amount);

/* Reconstruct-then-sign: serialize raw_data from structured fields */
bool tron_serializeRawTransaction(const TronSignTx *msg,
                                  const uint8_t *owner_raw,
                                  uint8_t *out, size_t *out_len,
                                  size_t max_len);

/* TRC-20 ABI decoding */
bool tron_decodeTRC20Transfer(const uint8_t *data, size_t data_len,
                              uint8_t to_raw[TRON_ADDRESS_SIZE],
                              uint8_t amount_bytes[32]);

/* Sign transaction (structured or raw) */
bool tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp);

#endif /* KEEPKEY_FIRMWARE_TRON_H */
