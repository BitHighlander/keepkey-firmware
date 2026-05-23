/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "keepkey/firmware/hive.h"

#include "trezor/crypto/base58.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#include <string.h>
#include <stdint.h>

// ── STM public key encoding ───────────────────────────────────────────────

bool hive_getPublicKey(const uint8_t public_key[33], char *out, size_t out_len) {
  const size_t prefix_len = strlen(HIVE_PUBKEY_PREFIX);
  if (out_len < prefix_len + 1) return false;
  strlcpy(out, HIVE_PUBKEY_PREFIX, out_len);
  // Graphene uses RIPEMD checksum (not SHA256d) for public key encoding
  return base58_encode_check(public_key, 33, HASHER_RIPEMD,
                             out + prefix_len, out_len - prefix_len);
}

// ── SLIP-0048 multi-role key derivation ───────────────────────────────────

bool hive_getPublicKeys(const HDNode *root, uint32_t account_index,
                        char *owner_out,   size_t owner_len,
                        char *active_out,  size_t active_len,
                        char *memo_out,    size_t memo_len,
                        char *posting_out, size_t posting_len) {
  const uint32_t roles[4] = {
    HIVE_ROLE_OWNER,
    HIVE_ROLE_ACTIVE,
    HIVE_ROLE_MEMO,
    HIVE_ROLE_POSTING,
  };
  char *outs[4] = { owner_out, active_out, memo_out, posting_out };
  size_t lens[4] = { owner_len, active_len, memo_len, posting_len };

  for (int i = 0; i < 4; i++) {
    HDNode node;
    memcpy(&node, root, sizeof(HDNode));

    // m/48'/13'/role'/account_index'/0'
    if (hdnode_private_ckd(&node, HIVE_SLIP48_PURPOSE) != 0) goto fail;
    if (hdnode_private_ckd(&node, HIVE_SLIP48_NETWORK)  != 0) goto fail;
    if (hdnode_private_ckd(&node, roles[i])              != 0) goto fail;
    if (hdnode_private_ckd(&node, account_index | 0x80000000u) != 0) goto fail;
    if (hdnode_private_ckd(&node, 0x80000000u)           != 0) goto fail;

    hdnode_fill_public_key(&node);
    if (!hive_getPublicKey(node.public_key, outs[i], lens[i])) goto fail;
    memzero(&node, sizeof(node));
    continue;

  fail:
    memzero(&node, sizeof(node));
    return false;
  }
  return true;
}

// ── Graphene binary serialization helpers ─────────────────────────────────

static void append_u8(uint8_t **buf, const uint8_t *end, uint8_t v) {
  if (*buf < end) { **buf = v; (*buf)++; }
}

static void append_u16_le(uint8_t **buf, const uint8_t *end, uint16_t v) {
  append_u8(buf, end, v & 0xFF);
  append_u8(buf, end, (v >> 8) & 0xFF);
}

static void append_u32_le(uint8_t **buf, const uint8_t *end, uint32_t v) {
  append_u8(buf, end, v & 0xFF);
  append_u8(buf, end, (v >> 8) & 0xFF);
  append_u8(buf, end, (v >> 16) & 0xFF);
  append_u8(buf, end, (v >> 24) & 0xFF);
}

static void append_u64_le(uint8_t **buf, const uint8_t *end, uint64_t v) {
  for (int i = 0; i < 8; i++) { append_u8(buf, end, v & 0xFF); v >>= 8; }
}

static void append_varint(uint8_t **buf, const uint8_t *end, uint64_t v) {
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    if (v) b |= 0x80;
    append_u8(buf, end, b);
  } while (v);
}

static void append_string(uint8_t **buf, const uint8_t *end, const char *s) {
  size_t len = s ? strlen(s) : 0;
  append_varint(buf, end, len);
  for (size_t i = 0; i < len && *buf < end; i++)
    append_u8(buf, end, (uint8_t)s[i]);
}

/*
 * Graphene asset encoding: int64 LE amount + uint8 precision + 7-byte symbol
 * The symbol field is null-padded to exactly 7 bytes.
 */
static void append_asset(uint8_t **buf, const uint8_t *end,
                         uint64_t amount, uint8_t precision, const char *symbol) {
  append_u64_le(buf, end, amount);
  append_u8(buf, end, precision);
  char sym[7] = {0};
  if (symbol) strncpy(sym, symbol, 6);
  for (int i = 0; i < 7 && *buf < end; i++)
    append_u8(buf, end, (uint8_t)sym[i]);
}

/*
 * Graphene authority structure:
 *   weight_threshold (uint32 LE) = 1
 *   num_account_auths (varint)   = 0
 *   num_key_auths (varint)       = 1
 *     public_key (33 bytes compressed)
 *     weight (uint16 LE)         = 1
 *
 * The public key must be provided as 33 raw bytes (not STM-encoded).
 */
static void append_authority(uint8_t **buf, const uint8_t *end,
                             const uint8_t pubkey[33]) {
  append_u32_le(buf, end, 1);  // weight_threshold = 1
  append_varint(buf, end, 0);  // 0 account auths
  append_varint(buf, end, 1);  // 1 key auth
  // Key type prefix: 0x00 = secp256k1 (Graphene convention, 1 byte)
  append_u8(buf, end, 0x00);
  for (int i = 0; i < 33 && *buf < end; i++)
    append_u8(buf, end, pubkey[i]);
  append_u16_le(buf, end, 1);  // weight = 1
}

/*
 * Common transaction header: ref_block_num, ref_block_prefix, expiration,
 * then a varint op count = 1, then the op type varint.
 */
static void append_tx_header(uint8_t **buf, const uint8_t *end,
                             uint16_t ref_block_num, uint32_t ref_block_prefix,
                             uint32_t expiration, uint32_t op_type) {
  append_u16_le(buf, end, ref_block_num);
  append_u32_le(buf, end, ref_block_prefix);
  append_u32_le(buf, end, expiration);
  append_varint(buf, end, 1);         // 1 operation
  append_varint(buf, end, op_type);
}

static void append_tx_footer(uint8_t **buf, const uint8_t *end) {
  append_varint(buf, end, 0);         // 0 extensions
}

/*
 * Sign helper: SHA256(chain_id || serialized_tx) → secp256k1 recoverable sig.
 * Writes 65 bytes into sig[]. Returns true on success.
 */
static bool hive_sign_digest(const HDNode *node, const uint8_t *chain_id,
                             const uint8_t *tx_buf, size_t tx_len,
                             uint8_t sig[65]) {
  SHA256_CTX sha;
  sha256_Init(&sha);
  sha256_Update(&sha, chain_id, HIVE_CHAIN_ID_LEN);
  sha256_Update(&sha, tx_buf, tx_len);
  uint8_t digest[32];
  sha256_Final(&sha, digest);

  uint8_t pby;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, digest,
                        sig + 1, &pby, NULL) != 0) {
    memzero(digest, sizeof(digest));
    return false;
  }
  // Compact signature header: 27 + recovery_id + 4 (compressed key flag)
  sig[0] = 27 + pby + 4;
  memzero(digest, sizeof(digest));
  return true;
}

// ── Transfer (op type 2) ──────────────────────────────────────────────────

static size_t hive_serialize_transfer(const HiveSignTx *msg,
                                      uint8_t *buf, size_t buf_len) {
  uint8_t *p = buf;
  const uint8_t *end = buf + buf_len;

  append_tx_header(&p, end,
                   (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix,
                   msg->expiration,
                   HIVE_OP_TRANSFER);

  append_string(&p, end, msg->has_from ? msg->from : "");
  append_string(&p, end, msg->has_to   ? msg->to   : "");

  const char *sym = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";
  uint8_t prec = (uint8_t)(msg->has_decimals ? msg->decimals : HIVE_DECIMALS);
  append_asset(&p, end, msg->amount, prec, sym);

  append_string(&p, end, msg->has_memo ? msg->memo : "");
  append_tx_footer(&p, end);
  return (size_t)(p - buf);
}

void hive_signTx(const HDNode *node, const HiveSignTx *msg, HiveSignedTx *resp) {
  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_transfer(msg, tx_buf, sizeof(tx_buf));

  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t *chain_id = (msg->has_chain_id &&
                              msg->chain_id.size == HIVE_CHAIN_ID_LEN)
                             ? msg->chain_id.bytes
                             : default_chain_id;

  uint8_t sig[65];
  if (!hive_sign_digest(node, chain_id, tx_buf, tx_len, sig)) {
    memzero(sig, sizeof(sig));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(tx_buf, tx_len);
}

// ── Account create (op type 9) ────────────────────────────────────────────

/*
 * Parse an STM-prefixed base58 public key back to 33 raw bytes.
 * Strips the "STM" prefix and decodes base58check with RIPEMD checksum.
 * Returns true on success.
 */
static bool parse_stm_pubkey(const char *stm_key, uint8_t out[33]) {
  if (!stm_key || strncmp(stm_key, HIVE_PUBKEY_PREFIX, 3) != 0) return false;
  const char *b58 = stm_key + 3;  // skip "STM"
  int decoded_len = base58_decode_check(b58, HASHER_RIPEMD, out, 33);
  return decoded_len == 33;
}

static size_t hive_serialize_account_create(const HiveSignAccountCreate *msg,
                                             uint8_t *buf, size_t buf_len) {
  uint8_t *p = buf;
  const uint8_t *end = buf + buf_len;

  append_tx_header(&p, end,
                   (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix,
                   msg->expiration,
                   HIVE_OP_ACCOUNT_CREATE);

  // fee (asset)
  uint64_t fee = msg->has_fee_amount ? msg->fee_amount : 3000;
  append_asset(&p, end, fee, HIVE_DECIMALS, "HIVE");

  // creator
  append_string(&p, end, msg->has_creator ? msg->creator : "");

  // new_account_name
  append_string(&p, end, msg->has_new_account_name ? msg->new_account_name : "");

  // Parse all four STM public keys to raw bytes
  uint8_t owner_raw[33] = {0}, active_raw[33] = {0};
  uint8_t posting_raw[33] = {0}, memo_raw[33] = {0};

  if (msg->has_owner_key)   parse_stm_pubkey(msg->owner_key,   owner_raw);
  if (msg->has_active_key)  parse_stm_pubkey(msg->active_key,  active_raw);
  if (msg->has_posting_key) parse_stm_pubkey(msg->posting_key, posting_raw);
  if (msg->has_memo_key)    parse_stm_pubkey(msg->memo_key,    memo_raw);

  // owner authority
  append_authority(&p, end, owner_raw);
  // active authority
  append_authority(&p, end, active_raw);
  // posting authority
  append_authority(&p, end, posting_raw);
  // memo_key (raw 33 bytes, no authority wrapper — just key type prefix + key)
  append_u8(&p, end, 0x00);
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  // json_metadata (empty string)
  append_string(&p, end, "");
  append_tx_footer(&p, end);

  memzero(owner_raw, sizeof(owner_raw));
  memzero(active_raw, sizeof(active_raw));
  memzero(posting_raw, sizeof(posting_raw));
  memzero(memo_raw, sizeof(memo_raw));

  return (size_t)(p - buf);
}

void hive_signAccountCreate(const HDNode *node,
                             const HiveSignAccountCreate *msg,
                             HiveSignedAccountCreate *resp) {
  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_account_create(msg, tx_buf, sizeof(tx_buf));

  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t *chain_id = (msg->has_chain_id &&
                              msg->chain_id.size == HIVE_CHAIN_ID_LEN)
                             ? msg->chain_id.bytes
                             : default_chain_id;

  uint8_t sig[65];
  if (!hive_sign_digest(node, chain_id, tx_buf, tx_len, sig)) {
    memzero(sig, sizeof(sig));
    memzero(tx_buf, sizeof(tx_buf));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(tx_buf, tx_len);
}

// ── Account update (op type 10) ───────────────────────────────────────────

static size_t hive_serialize_account_update(const HiveSignAccountUpdate *msg,
                                             uint8_t *buf, size_t buf_len) {
  uint8_t *p = buf;
  const uint8_t *end = buf + buf_len;

  append_tx_header(&p, end,
                   (uint16_t)(msg->ref_block_num & 0xFFFF),
                   msg->ref_block_prefix,
                   msg->expiration,
                   HIVE_OP_ACCOUNT_UPDATE);

  // account name
  append_string(&p, end, msg->has_account ? msg->account : "");

  // Parse all four new public keys
  uint8_t owner_raw[33] = {0}, active_raw[33] = {0};
  uint8_t posting_raw[33] = {0}, memo_raw[33] = {0};

  if (msg->has_new_owner_key)   parse_stm_pubkey(msg->new_owner_key,   owner_raw);
  if (msg->has_new_active_key)  parse_stm_pubkey(msg->new_active_key,  active_raw);
  if (msg->has_new_posting_key) parse_stm_pubkey(msg->new_posting_key, posting_raw);
  if (msg->has_new_memo_key)    parse_stm_pubkey(msg->new_memo_key,    memo_raw);

  /*
   * account_update optional fields use a Graphene "optional" wrapper:
   *   present: 0x01 + authority bytes
   *   absent:  0x00
   * We always include all four — this replaces all authorities.
   */
  append_u8(&p, end, 0x01);  // owner present
  append_authority(&p, end, owner_raw);
  append_u8(&p, end, 0x01);  // active present
  append_authority(&p, end, active_raw);
  append_u8(&p, end, 0x01);  // posting present
  append_authority(&p, end, posting_raw);

  // memo_key (raw, always present in account_update)
  append_u8(&p, end, 0x00);
  for (int i = 0; i < 33 && p < end; i++) append_u8(&p, end, memo_raw[i]);

  // json_metadata (empty)
  append_string(&p, end, "");
  append_tx_footer(&p, end);

  memzero(owner_raw, sizeof(owner_raw));
  memzero(active_raw, sizeof(active_raw));
  memzero(posting_raw, sizeof(posting_raw));
  memzero(memo_raw, sizeof(memo_raw));

  return (size_t)(p - buf);
}

void hive_signAccountUpdate(const HDNode *node,
                             const HiveSignAccountUpdate *msg,
                             HiveSignedAccountUpdate *resp) {
  uint8_t tx_buf[512];
  size_t tx_len = hive_serialize_account_update(msg, tx_buf, sizeof(tx_buf));

  const uint8_t default_chain_id[32] = HIVE_CHAIN_ID;
  const uint8_t *chain_id = (msg->has_chain_id &&
                              msg->chain_id.size == HIVE_CHAIN_ID_LEN)
                             ? msg->chain_id.bytes
                             : default_chain_id;

  uint8_t sig[65];
  if (!hive_sign_digest(node, chain_id, tx_buf, tx_len, sig)) {
    memzero(sig, sizeof(sig));
    memzero(tx_buf, sizeof(tx_buf));
    return;
  }

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = tx_len;
  memcpy(resp->serialized_tx.bytes, tx_buf, tx_len);

  memzero(sig, sizeof(sig));
  memzero(tx_buf, tx_len);
}
