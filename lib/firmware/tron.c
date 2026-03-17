/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

#include "keepkey/crypto/curves.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha3.h"

#include <string.h>

#define TRON_ADDRESS_PREFIX 0x41  // Mainnet addresses start with 'T'

/**
 * Generate TRON address from secp256k1 public key
 * TRON uses Keccak256(uncompressed_pubkey) and takes last 20 bytes,
 * then prepends 0x41 and Base58Check encodes it
 */
bool tron_getAddress(const uint8_t public_key[33], char *address,
                     size_t address_len) {
  if (address_len < TRON_ADDRESS_MAX_LEN) {
    return false;
  }

  uint8_t uncompressed_pubkey[65];
  uint8_t hash[32];
  uint8_t addr_bytes[21];

  // Uncompress the public key
  if (!ecdsa_uncompress_pubkey(&secp256k1, public_key, uncompressed_pubkey)) {
    return false;
  }

  // Keccak256 hash of uncompressed public key (skip first 0x04 byte)
  keccak_256(uncompressed_pubkey + 1, 64, hash);

  // Take last 20 bytes of hash and prepend TRON prefix byte
  addr_bytes[0] = TRON_ADDRESS_PREFIX;
  memcpy(addr_bytes + 1, hash + 12, 20);

  // Base58Check encode with double SHA256
  if (!base58_encode_check(addr_bytes, 21, HASHER_SHA2D, address,
                           address_len)) {
    return false;
  }

  // Clean up sensitive data
  memzero(uncompressed_pubkey, sizeof(uncompressed_pubkey));
  memzero(hash, sizeof(hash));

  return true;
}

/**
 * Format TRON amount (SUN) for display
 * 1 TRX = 1,000,000 SUN
 */
void tron_formatAmount(char *buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TRX", TRON_DECIMALS, 0, false, buf, len);
}

/*
 * Minimal protobuf wire-format parser for TRON TransferContract.
 *
 * TRON Transaction.raw layout (protobuf):
 *   field 11 (contract, repeated message) → Contract {
 *     field 1 (type, enum): ContractType  (1 = TransferContract)
 *     field 2 (parameter, Any message) → google.protobuf.Any {
 *       field 1 (type_url, string)
 *       field 2 (value, bytes) → serialized TransferContract {
 *         field 1 (owner_address, bytes): 21 bytes
 *         field 2 (to_address, bytes):    21 bytes
 *         field 3 (amount, int64):        varint
 *       }
 *     }
 *   }
 */

// Read a protobuf varint, return bytes consumed (0 on error)
static size_t pb_read_varint(const uint8_t *buf, size_t len, uint64_t *val) {
  *val = 0;
  size_t i = 0;
  unsigned shift = 0;
  while (i < len && shift < 64) {
    uint64_t byte = buf[i];
    *val |= (byte & 0x7F) << shift;
    shift += 7;
    i++;
    if (!(byte & 0x80)) return i;
  }
  return 0;  // malformed
}

// Skip a protobuf field given its wire type (0=varint, 2=length-delimited, etc)
static size_t pb_skip_field(const uint8_t *buf, size_t len, unsigned wire_type) {
  if (wire_type == 0) {  // varint
    uint64_t dummy;
    return pb_read_varint(buf, len, &dummy);
  } else if (wire_type == 2) {  // length-delimited
    uint64_t flen;
    size_t n = pb_read_varint(buf, len, &flen);
    if (n == 0 || n + flen > len) return 0;
    return n + (size_t)flen;
  } else if (wire_type == 5) {  // 32-bit
    return len >= 4 ? 4 : 0;
  } else if (wire_type == 1) {  // 64-bit
    return len >= 8 ? 8 : 0;
  }
  return 0;
}

// Find a length-delimited field by field number in a protobuf message.
// Returns pointer to the field data and sets *out_len. NULL if not found.
static const uint8_t *pb_find_bytes(const uint8_t *buf, size_t len,
                                    unsigned field_num, size_t *out_len) {
  size_t pos = 0;
  while (pos < len) {
    uint64_t tag;
    size_t n = pb_read_varint(buf + pos, len - pos, &tag);
    if (n == 0) return NULL;
    pos += n;
    unsigned fn = (unsigned)(tag >> 3);
    unsigned wt = (unsigned)(tag & 7);
    if (fn == field_num && wt == 2) {
      uint64_t flen;
      n = pb_read_varint(buf + pos, len - pos, &flen);
      if (n == 0 || pos + n + flen > len) return NULL;
      *out_len = (size_t)flen;
      return buf + pos + n;
    }
    n = pb_skip_field(buf + pos, len - pos, wt);
    if (n == 0) return NULL;
    pos += n;
  }
  return NULL;
}

// Find a varint field by field number. Returns true if found.
static bool pb_find_varint(const uint8_t *buf, size_t len,
                           unsigned field_num, uint64_t *val) {
  size_t pos = 0;
  while (pos < len) {
    uint64_t tag;
    size_t n = pb_read_varint(buf + pos, len - pos, &tag);
    if (n == 0) return false;
    pos += n;
    unsigned fn = (unsigned)(tag >> 3);
    unsigned wt = (unsigned)(tag & 7);
    if (fn == field_num && wt == 0) {
      n = pb_read_varint(buf + pos, len - pos, val);
      return n > 0;
    }
    n = pb_skip_field(buf + pos, len - pos, wt);
    if (n == 0) return false;
    pos += n;
  }
  return false;
}

// Count occurrences of a length-delimited field in a protobuf message.
static unsigned pb_count_field(const uint8_t *buf, size_t len,
                               unsigned field_num) {
  unsigned count = 0;
  size_t pos = 0;
  while (pos < len) {
    uint64_t tag;
    size_t n = pb_read_varint(buf + pos, len - pos, &tag);
    if (n == 0) break;
    pos += n;
    unsigned fn = (unsigned)(tag >> 3);
    unsigned wt = (unsigned)(tag & 7);
    if (fn == field_num && wt == 2) count++;
    n = pb_skip_field(buf + pos, len - pos, wt);
    if (n == 0) break;
    pos += n;
  }
  return count;
}

bool tron_parseTransfer(const uint8_t *raw_data, size_t raw_data_len,
                        TronParsedTransfer *out) {
  memset(out, 0, sizeof(*out));

  // Reject if there are multiple contract entries (repeated field 11).
  // A malicious payload could hide extra contracts after a benign transfer.
  if (pb_count_field(raw_data, raw_data_len, 11) != 1) return false;

  // Find the single contract entry
  size_t contract_len = 0;
  const uint8_t *contract = pb_find_bytes(raw_data, raw_data_len, 11,
                                          &contract_len);
  if (!contract) return false;

  // Check contract type (field 1): must be 1 (TransferContract)
  uint64_t contract_type = 0;
  if (!pb_find_varint(contract, contract_len, 1, &contract_type)) return false;
  if (contract_type != 1) return false;  // not a simple transfer

  // Find parameter (field 2) = google.protobuf.Any
  size_t any_len = 0;
  const uint8_t *any = pb_find_bytes(contract, contract_len, 2, &any_len);
  if (!any) return false;

  // Find value (field 2 inside Any) = serialized TransferContract
  size_t tc_len = 0;
  const uint8_t *tc = pb_find_bytes(any, any_len, 2, &tc_len);
  if (!tc) return false;

  // Parse TransferContract: field 2 = to_address (bytes, 21)
  size_t addr_len = 0;
  const uint8_t *to_addr = pb_find_bytes(tc, tc_len, 2, &addr_len);
  if (!to_addr || addr_len != 21) return false;
  memcpy(out->to_address, to_addr, 21);

  // Parse TransferContract: field 3 = amount (varint, signed zigzag or plain)
  uint64_t amount_raw = 0;
  if (!pb_find_varint(tc, tc_len, 3, &amount_raw)) return false;
  out->amount = (int64_t)amount_raw;

  out->valid = true;
  return true;
}

/**
 * Sign a TRON transaction with secp256k1
 */
bool tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  // Verify we have raw transaction data
  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    return false;
  }

  // Get the curve for secp256k1
  const curve_info *curve = get_curve_by_name(SECP256K1_NAME);
  if (!curve) {
    return false;
  }

  // Hash the transaction with SHA256
  uint8_t hash[32];
  sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);

  // Sign with secp256k1 (recoverable signature: 65 bytes including recovery
  // ID)
  uint8_t sig[65];
  uint8_t pby;

  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, &pby,
                        NULL) != 0) {
    memzero(hash, sizeof(hash));
    return false;
  }

  // Convert to recoverable signature format (r + s + recovery_id)
  // The recovery ID allows recovering the public key from the signature
  sig[64] = pby;

  // Copy signature to response (65 bytes)
  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  // Clean up sensitive data
  memzero(hash, sizeof(hash));
  memzero(sig, sizeof(sig));

  return true;
}
