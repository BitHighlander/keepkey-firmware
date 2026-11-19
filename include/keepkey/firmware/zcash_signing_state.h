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

#ifndef KEEPKEY_FIRMWARE_ZCASH_SIGNING_STATE_H
#define KEEPKEY_FIRMWARE_ZCASH_SIGNING_STATE_H

/* The Zcash shielded signing session, used only by fsm_msg_zcash.h. It is a
 * header so that the shared signing-session arena can size its union. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/zcash.h"
#include "messages-zcash.pb.h"
#include "trezor/crypto/blake2b.h"

#define ZCASH_MAX_ACTIONS 16
#define ZCASH_MAX_TRANSPARENT_INPUTS 8
#define ZCASH_MAX_TRANSPARENT_OUTPUTS 8
#define ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY 128

typedef struct {
  bool received;
  uint8_t prevout_txid[32];
  uint32_t prevout_index;
  uint32_t sequence;
  uint64_t amount;
  uint8_t script_pubkey[ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY];
  size_t script_pubkey_size;
  uint32_t address_n[8];
  uint32_t address_n_count;
} ZcashTransparentInputState;

typedef struct {
  bool received;
  uint64_t amount;
  uint8_t script_pubkey[ZCASH_MAX_TRANSPARENT_SCRIPT_PUBKEY];
  size_t script_pubkey_size;
} ZcashTransparentOutputState;

/* Zcash shielded signing state. It lives in the shared signing-session
 * arena (signing_session.h), owned by SIGNING_SESSION_ZCASH. */
typedef struct {
  bool active;
  uint32_t account;
  uint32_t n_actions;
  uint32_t current_action;
  uint64_t fee;
  uint32_t branch_id;
  ZcashOrchardKeys keys;
  /* The account's internal-scope (change) ivk, and the value of the outputs
   * proven to pay it: shown once, at the final gate. */
  uint8_t ivk_internal[32];
  uint64_t change_value;
  uint8_t header_digest[32];
  uint8_t sighash[32];
  bool transaction_v6;
  /* The pool of the actions being streamed. A crossing transaction (ZIP 318)
   * streams n_orchard_actions Orchard actions, then the Ironwood ones. */
  bool is_ironwood;
  uint32_t n_orchard_actions;
  uint8_t orchard_component_digest[32];
  uint8_t ironwood_component_digest[32];
  /* Set only at the final gate, from device-computed digests. */
  bool has_device_sighash;
  /* Phase 2b: incremental orchard digest verification */
  bool verify_orchard_digest;
  BLAKE2B_CTX compact_ctx;
  BLAKE2B_CTX memos_ctx;
  BLAKE2B_CTX noncompact_ctx;
  /* Per bundle, indexed by pool (0 Orchard, 1 Ironwood). */
  uint8_t expected_bundle_digest[2][32];
  uint8_t bundle_flags[2];
  int64_t bundle_value_balance[2];
  uint8_t orchard_anchor[32];
  /* One slot per REAL spend; dummies are never signed here. While streaming a
   * slot holds alpha || rk, at the final gate the 64-byte signature. */
  uint8_t signatures[ZCASH_MAX_ACTIONS][64];
  uint32_t signature_count;
  /* Phase 3: transparent shielding state */
  bool has_expected_transparent_digest;
  uint8_t expected_transparent_digest[32];
  bool transparent_digest_verified;
  uint32_t n_transparent_outputs;
  uint32_t current_transparent_output;
  uint32_t n_transparent_inputs;
  uint32_t current_transparent_input;
  ZcashTransparentOutputState
      transparent_outputs[ZCASH_MAX_TRANSPARENT_OUTPUTS];
  ZcashTransparentInputState transparent_inputs[ZCASH_MAX_TRANSPARENT_INPUTS];
  /* Deferred transparent ECDSA sigs — buffered until Orchard/fee final gate */
  bool has_pending_transparent;
  ZcashTransparentSigned pending_transparent;
} ZcashSigningState;

#endif
