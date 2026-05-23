#ifndef KEEPKEY_FIRMWARE_HIVE_H
#define KEEPKEY_FIRMWARE_HIVE_H

#include "trezor/crypto/bip32.h"
#include "messages-hive.pb.h"

// ── Hive mainnet chain ID ─────────────────────────────────────────────────
#define HIVE_CHAIN_ID \
  "\xbe\xea\xb0\xde\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00"
#define HIVE_CHAIN_ID_LEN 32

// ── STM public key prefix (Hive inherited from Steem / Graphene) ──────────
#define HIVE_PUBKEY_PREFIX "STM"

// ── SLIP-0048 derivation constants (all hardened) ─────────────────────────
// Path: m/48'/13'/role'/account_index'/0'
#define HIVE_SLIP48_PURPOSE  (0x80000030u)  // 48'
#define HIVE_SLIP48_NETWORK  (0x8000000Du)  // 13' — Hive SLIP-0048 network ID
#define HIVE_ROLE_OWNER      (0x80000000u)  // 0'  — account recovery, authority changes
#define HIVE_ROLE_ACTIVE     (0x80000001u)  // 1'  — transfers, staking
#define HIVE_ROLE_MEMO       (0x80000003u)  // 3'  — memo field encryption
#define HIVE_ROLE_POSTING    (0x80000004u)  // 4'  — votes, posts, follows

// ── Graphene operation type IDs ───────────────────────────────────────────
#define HIVE_OP_TRANSFER        2
#define HIVE_OP_ACCOUNT_CREATE  9
#define HIVE_OP_ACCOUNT_UPDATE  10

// ── Protocol limits ───────────────────────────────────────────────────────
#define HIVE_MAX_ACCOUNT_LEN 16   // max Hive username length
#define HIVE_DECIMALS        3    // HIVE and HBD both use 3 decimal places

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Encode a 33-byte compressed public key in Hive/Steem STM-prefix base58 format.
 * Uses RIPEMD checksum (Graphene convention, not SHA256d).
 */
bool hive_getPublicKey(const uint8_t public_key[33], char *out, size_t out_len);

/**
 * Derive all four SLIP-0048 role keys for a given account index and encode
 * each as an STM-prefixed string. All output buffers must be >= 64 bytes.
 * Returns false if any derivation or encoding step fails.
 */
bool hive_getPublicKeys(const HDNode *root, uint32_t account_index,
                        char *owner_out,   size_t owner_len,
                        char *active_out,  size_t active_len,
                        char *memo_out,    size_t memo_len,
                        char *posting_out, size_t posting_len);

/**
 * Sign a Hive transfer transaction (op type 2).
 */
void hive_signTx(const HDNode *node, const HiveSignTx *msg, HiveSignedTx *resp);

/**
 * Sign a Hive account_create transaction (op type 9).
 * All four role public keys are embedded as authorities.
 * Device must display the new account name for user confirmation.
 */
void hive_signAccountCreate(const HDNode *node,
                            const HiveSignAccountCreate *msg,
                            HiveSignedAccountCreate *resp);

/**
 * Sign a Hive account_update transaction (op type 10).
 * Replaces all authorities with new KeepKey-derived keys.
 */
void hive_signAccountUpdate(const HDNode *node,
                            const HiveSignAccountUpdate *msg,
                            HiveSignedAccountUpdate *resp);

#endif  // KEEPKEY_FIRMWARE_HIVE_H
