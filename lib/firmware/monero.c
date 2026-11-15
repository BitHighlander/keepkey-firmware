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

#include "monero_internal.h"
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

bool monero_get_address(const uint8_t node_key[32], uint32_t network,
                        uint32_t major, uint32_t minor,
                        char address[MONERO_ADDRESS_CAPACITY]) {
  struct {
    bignum256modm spend, view, sub;
    ge25519 B, D, C;
    uint8_t public_keys[64];
  } scratch = {0};
  bool ok = false;
  const bool is_subaddress = major != 0 || minor != 0;
  static const uint8_t base_prefix[] = {18, 53, 24};
  static const uint8_t sub_prefix[] = {42, 63, 36};
  static const uint8_t neutral[32] = {1};

  if (!address) goto cleanup;
  memzero(address, MONERO_ADDRESS_CAPACITY);
  if (!node_key || network >= 3) goto cleanup;
  if (!monero_wallet_secrets(node_key, scratch.spend, scratch.view))
    goto cleanup;

  /* B = bG. A subaddress has D = B + mG and C = aD; the primary address
   * has D = B and C = aG. */
  ge25519_scalarmult_base_wrapper(&scratch.B, scratch.spend);
  if (is_subaddress) {
    monero_subaddress_scalar(scratch.sub, scratch.view, major, minor);
    ge25519_scalarmult_base_wrapper(&scratch.D, scratch.sub);
    ge25519_add(&scratch.D, &scratch.D, &scratch.B, 0);
    ge25519_scalarmult(&scratch.C, &scratch.D, scratch.view);
  } else {
    ge25519_copy(&scratch.D, &scratch.B);
    ge25519_scalarmult_base_wrapper(&scratch.C, scratch.view);
  }
  ge25519_pack(scratch.public_keys, &scratch.D);
  ge25519_pack(scratch.public_keys + 32, &scratch.C);
  if (!memcmp(scratch.public_keys, neutral, 32) ||
      !memcmp(scratch.public_keys + 32, neutral, 32))
    goto cleanup;
  const uint8_t prefix =
      is_subaddress ? sub_prefix[network] : base_prefix[network];
  const int written = xmr_base58_addr_encode_check(
      prefix, scratch.public_keys, sizeof(scratch.public_keys), address,
      MONERO_ADDRESS_CAPACITY);
  if (written != (int)MONERO_ADDRESS_LENGTH) goto cleanup;
  address[MONERO_ADDRESS_LENGTH] = '\0';
  ok = true;

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
