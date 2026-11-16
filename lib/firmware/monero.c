/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

/* Monero wallet keys and addresses, ported from the emulator research
 * (tools/monero-feasibility/commands) and checked against Monero Core
 * fixtures in unittests/firmware/monero.cpp. */

#include "keepkey/firmware/monero.h"

#include <string.h>

#include "keepkey/firmware/monero/crypto.h"
#include "monero_internal.h"
#include "trezor/crypto/hasher.h"
#include "trezor/crypto/memzero.h"

bool monero_path_valid(const uint32_t* path, size_t count) {
  return path && count == 3 && path[0] == (0x80000000u | 44u) &&
         path[1] == (0x80000000u | 128u) && (path[2] & 0x80000000u) != 0;
}

const char* monero_network_name(uint32_t network) {
  static const char* const names[] = {"Mainnet", "Testnet", "Stagenet"};
  return network < 3 ? names[network] : NULL;
}

/* Unlike xmr_hash_to_scalar, scrub the hash state: inputs here are secret. */
void monero_hash_scalar(bignum256modm out, const uint8_t* input, size_t size) {
  Hasher hasher = {0};
  uint8_t hash[32] = {0};
  hasher_Init(&hasher, HASHER_SHA3K);
  hasher_Update(&hasher, input, size);
  hasher_Final(&hasher, hash);
  expand256_modm(out, hash, sizeof(hash));
  memzero(hash, sizeof(hash));
  memzero(&hasher, sizeof(hasher));
}

bool monero_wallet_secrets(const uint8_t node_key[32], bignum256modm spend,
                           bignum256modm view) {
  uint8_t spend_bytes[32] = {0};
  /* Trezor convention: reduce the SLIP-10 node key directly. */
  expand256_modm(spend, node_key, 32);
  contract256_modm(spend_bytes, spend);
  monero_hash_scalar(view, spend_bytes, sizeof(spend_bytes));
  memzero(spend_bytes, sizeof(spend_bytes));
  if (iszero256_modm(spend) || iszero256_modm(view)) {
    memzero(spend, sizeof(bignum256modm));
    memzero(view, sizeof(bignum256modm));
    return false;
  }
  return true;
}

void monero_subaddress_scalar(bignum256modm out, const bignum256modm view,
                              uint32_t major, uint32_t minor) {
  uint8_t data[48] = {'S', 'u', 'b', 'A', 'd', 'd', 'r', 0};
  contract256_modm(data + 8, view);
  for (unsigned i = 0; i < 4; ++i) {
    data[40 + i] = (uint8_t)(major >> (8 * i));
    data[44 + i] = (uint8_t)(minor >> (8 * i));
  }
  monero_hash_scalar(out, data, sizeof(data));
  memzero(data, sizeof(data));
}

/* Reject noncanonical encodings, identity and torsion before multiplying a
 * public input by a wallet or transaction secret. */
bool monero_decode_public(ge25519* point, const uint8_t encoded[32]) {
  static const uint8_t identity[32] = {1};
  static const uint8_t order_bytes[32] = {
      0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
      0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
  struct {
    ge25519 check;
    bignum256modm order;
    uint8_t canonical[32];
  } tmp = {0};
  bool ok = false;
  ge25519_set_neutral(point);
  if (!xmr_point_load_canonical(point, encoded) ||
      !memcmp(encoded, identity, 32))
    goto done;
  expand_raw256_modm(tmp.order, order_bytes);
  ge25519_scalarmult(&tmp.check, point, tmp.order);
  ge25519_pack(tmp.canonical, &tmp.check);
  ok = memcmp(tmp.canonical, identity, 32) == 0;
done:
  memzero(&tmp, sizeof(tmp));
  return ok;
}

bool monero_address_keys(const bignum256modm spend, const bignum256modm view,
                         uint32_t major, uint32_t minor, uint8_t keys[64]) {
  struct {
    bignum256modm sub;
    ge25519 B, D, C;
  } scratch = {0};
  static const uint8_t neutral[32] = {1};

  /* B = bG. A subaddress has D = B + mG and C = aD; the primary address
   * has D = B and C = aG. */
  ge25519_scalarmult_base_wrapper(&scratch.B, spend);
  if (major != 0 || minor != 0) {
    monero_subaddress_scalar(scratch.sub, view, major, minor);
    ge25519_scalarmult_base_wrapper(&scratch.D, scratch.sub);
    ge25519_add(&scratch.D, &scratch.D, &scratch.B, 0);
    ge25519_scalarmult(&scratch.C, &scratch.D, view);
  } else {
    ge25519_copy(&scratch.D, &scratch.B);
    ge25519_scalarmult_base_wrapper(&scratch.C, view);
  }
  ge25519_pack(keys, &scratch.D);
  ge25519_pack(keys + 32, &scratch.C);
  memzero(&scratch, sizeof(scratch));
  if (!memcmp(keys, neutral, 32) || !memcmp(keys + 32, neutral, 32)) {
    memzero(keys, 64);
    return false;
  }
  return true;
}

bool monero_encode_address(uint32_t network, MoneroAddressKind kind,
                           const uint8_t keys[64], const uint8_t* payment_id,
                           char* address, size_t capacity) {
  static const uint8_t prefixes[3][3] = {
      {18, 53, 24}, {42, 63, 36}, {19, 54, 25}};
  /* prefix | keys | payment id | Keccak checksum. Built here in a fixed
   * buffer: trezor-crypto's xmr_base58_addr_encode_check() sizes its copy
   * with a variable-length array, which the SRAM gate cannot bound. Every
   * prefix is below 128, so its varint is the byte itself. */
  uint8_t data[1 + 72 + HASHER_DIGEST_LENGTH] = {0};
  const bool integrated = kind == MONERO_ADDRESS_INTEGRATED;
  const size_t size = 1u + (integrated ? 72u : 64u);
  const size_t length = integrated ? 106u : MONERO_ADDRESS_LENGTH;
  if (!address || capacity <= length) return false;
  memzero(address, capacity);
  if (network >= 3 || (unsigned)kind >= 3 || !keys ||
      (integrated && !payment_id))
    return false;
  data[0] = prefixes[kind][network];
  memcpy(data + 1, keys, 64);
  if (integrated) memcpy(data + 65, payment_id, 8);
  hasher_Raw(HASHER_SHA3K, data, size, data + size);
  size_t written = capacity;
  if (!xmr_base58_encode(address, &written, data, size + 4) ||
      written != length) {
    memzero(address, capacity);
    return false;
  }
  address[length] = '\0';
  return true;
}

bool monero_get_address(const uint8_t node_key[32], uint32_t network,
                        uint32_t major, uint32_t minor,
                        char address[MONERO_ADDRESS_CAPACITY]) {
  struct {
    bignum256modm spend, view;
    uint8_t public_keys[64];
  } scratch = {0};
  bool ok = false;
  const bool is_subaddress = major != 0 || minor != 0;

  if (!address) goto cleanup;
  memzero(address, MONERO_ADDRESS_CAPACITY);
  if (!node_key || network >= 3) goto cleanup;
  if (!monero_wallet_secrets(node_key, scratch.spend, scratch.view))
    goto cleanup;
  if (!monero_address_keys(scratch.spend, scratch.view, major, minor,
                           scratch.public_keys))
    goto cleanup;
  ok = monero_encode_address(
      network,
      is_subaddress ? MONERO_ADDRESS_SUBADDRESS : MONERO_ADDRESS_STANDARD,
      scratch.public_keys, NULL, address, MONERO_ADDRESS_CAPACITY);

cleanup:
  memzero(&scratch, sizeof(scratch));
  if (!ok && address) memzero(address, MONERO_ADDRESS_CAPACITY);
  return ok;
}

bool monero_get_watch_key(const uint8_t node_key[32], uint32_t network,
                          uint32_t major, uint8_t view_key[32],
                          char address[MONERO_ADDRESS_CAPACITY]) {
  bignum256modm spend = {0}, view = {0};
  bool ok = false;
  if (view_key) memzero(view_key, 32);
  if (!node_key || !view_key || !address) goto cleanup;
  if (!monero_get_address(node_key, network, major, 0, address)) goto cleanup;
  if (!monero_wallet_secrets(node_key, spend, view)) goto cleanup;
  contract256_modm(view_key, view);
  ok = true;
cleanup:
  memzero(spend, sizeof(spend));
  memzero(view, sizeof(view));
  if (!ok) {
    if (view_key) memzero(view_key, 32);
    if (address) memzero(address, MONERO_ADDRESS_CAPACITY);
  }
  return ok;
}
