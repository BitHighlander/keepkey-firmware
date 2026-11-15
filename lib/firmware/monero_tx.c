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

/* Monero streamed transaction signing. See keepkey/firmware/monero_tx.h for
 * the protocol and the key schedule. The transaction is built as Monero Core
 * v0.18.5.4 builds it (construct_tx_with_tx_key, genRctSimple,
 * get_pre_mlsag_hash, device_default); the unit tests check the assembled
 * transactions with Core itself. */

#include "keepkey/firmware/monero_tx.h"

#include <string.h>

#include "keepkey/board/timer.h"
#include "keepkey/firmware/signing_session.h"
#include "monero_internal.h"
#include "trezor/crypto/chacha20poly1305/rfc7539.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha3.h"

enum {
  STEP_INPUT = 1, /* set_input x n */
  STEP_VINI,      /* input_vini x n, then all_inputs_set */
  STEP_OUTPUT,    /* set_output x 2, then all_out_set */
  STEP_SIGN,      /* sign_input x n */
  STEP_FINAL,
};

#define TX_OUT_BYTES 35u
#define EXTRA_BYTES 44u /* 01 R | 02 09 01 encrypted payment ID */
#define DEST_BYTES 73u  /* le64 amount | spend | view | flags */
#define VINI_MIN_BYTES 35u
#define VINI_MAX_BYTES 200u
#define CLSAG_PLAIN_BYTES ((MONERO_TX_RING_SIZE + 2u) * 32u)

typedef struct {
  uint32_t started;
  uint8_t step;
  uint8_t n_inputs;
  uint8_t in_pos, vini_pos, out_pos, sign_pos;
  uint8_t out_self[MONERO_TX_OUTPUTS]; /* own address: derive with a*R */
  uint32_t account;
  uint64_t fee, sum_in, sum_out;
  uint64_t seen;                       /* plan indices with a vini accepted */
  uint8_t order[MONERO_TX_MAX_INPUTS]; /* plan index at each sorted position */
  bignum256modm spend, view;
  uint8_t master[32], mac_key[32], open_key[32];
  bignum256modm sum_pseudo, sum_out_mask;
  uint8_t out_mask[MONERO_TX_OUTPUTS][32];
  uint64_t out_amount[MONERO_TX_OUTPUTS];
  uint8_t out_commit[MONERO_TX_OUTPUTS][32];
  uint8_t extra[EXTRA_BYTES];
  uint8_t last_ki[32];
  uint8_t bp_hash[32];
  uint8_t message[32];
  SHA3_CTX prefix;   /* running tx prefix hash */
  SHA3_CTX rct_base; /* running rctSigBase hash */
} TxSession;

_Static_assert(sizeof(TxSession) <= MONERO_SESSION_BYTES,
               "signing session exceeds the Monero arena share");
_Static_assert(MONERO_TX_MAX_INPUTS <= 64, "seen is a 64-bit set");
_Static_assert(MONERO_TX_BPP_SCRATCH_BYTES <= XMR_FRAME_ARENA_FLOOR_BYTES &&
                   MONERO_TX_CLSAG_SCRATCH_BYTES <= XMR_FRAME_ARENA_FLOOR_BYTES,
               "proving scratch must fit the frame arena");
_Static_assert(sizeof(((MoneroTxSetInputAck*)0)->vini.bytes) >= VINI_MAX_BYTES,
               "vini does not fit its field");
_Static_assert(sizeof(((MoneroTxSetOutputAck*)0)->bp_plus.bytes) >=
                   XMR_BPP_SERIALIZED_MAX,
               "range proof does not fit its field");
_Static_assert(sizeof(((MoneroTxSignInputAck*)0)->clsag_enc.bytes) >=
                   CLSAG_PLAIN_BYTES + 16u,
               "encrypted CLSAG does not fit its field");

typedef struct {
  xmr_clsag_workspace ws;
  uint8_t P[MONERO_TX_RING_SIZE][32];
  uint8_t C[MONERO_TX_RING_SIZE][32];
} ClsagScratch;
_Static_assert(sizeof(ClsagScratch) == MONERO_TX_CLSAG_SCRATCH_BYTES,
               "update MONERO_TX_CLSAG_SCRATCH_BYTES");

/* The proof's A, A1, B, r1, s1, d1 and the signature's s, c1, D are hashed
 * and sealed as one run of bytes. */
#define BPP_KEYS_OFFSET offsetof(xmr_bpp_proof, A)
_Static_assert(offsetof(xmr_bpp_proof, d1) == BPP_KEYS_OFFSET + 5u * 32u,
               "BP+ proof keys are not contiguous");
_Static_assert(offsetof(xmr_clsag_sig, s) == 0 &&
                   offsetof(xmr_clsag_sig, c1) == MONERO_TX_RING_SIZE * 32u &&
                   offsetof(xmr_clsag_sig, D) ==
                       (MONERO_TX_RING_SIZE + 1u) * 32u,
               "CLSAG signature fields are not contiguous");

const char* monero_tx_result_text(MoneroTxResult result) {
  switch (result) {
    case MONERO_TX_OK:
      return "OK";
    case MONERO_TX_ERR_STEP:
      return "Monero signing step out of order";
    case MONERO_TX_ERR_EXPIRED:
      return "Monero signing session expired";
    case MONERO_TX_ERR_REQUEST:
      return "Invalid Monero signing request";
    case MONERO_TX_ERR_OUTPUT_COUNT:
      return "Monero: only transactions with exactly 2 outputs are supported";
    case MONERO_TX_ERR_RING_SIZE:
      return "Monero ring size must be 16";
    case MONERO_TX_ERR_HARD_FORK:
      return "Monero hard fork must be 16 or later";
    case MONERO_TX_ERR_RCT_TYPE:
      return "Monero: only CLSAG with Bulletproofs+ is supported";
    case MONERO_TX_ERR_INPUT_COUNT:
      return "Monero: 1 to 64 inputs are supported";
    case MONERO_TX_ERR_PAYMENT_ID:
      return "Monero payment ID must be 8 bytes for one integrated address";
    case MONERO_TX_ERR_INTEGRATED:
      return "Monero: only one integrated destination is supported";
    case MONERO_TX_ERR_POINT:
      return "Invalid Monero public key";
    case MONERO_TX_ERR_SCALAR:
      return "Invalid Monero scalar";
    case MONERO_TX_ERR_CHANGE:
      return "Monero change must return to this wallet";
    case MONERO_TX_ERR_AMOUNT:
      return "Monero amount overflow";
    case MONERO_TX_ERR_RING:
      return "Monero ring must be 16 sorted, distinct members";
    case MONERO_TX_ERR_NOT_OWNED:
      return "Monero input does not belong to this wallet";
    case MONERO_TX_ERR_COMMITMENT:
      return "Monero input amount does not match its commitment";
    case MONERO_TX_ERR_MAC:
      return "Monero signing state was changed or replayed";
    case MONERO_TX_ERR_ORDER:
      return "Monero inputs out of key-image order";
    case MONERO_TX_ERR_BALANCE:
      return "Monero inputs do not equal outputs plus fee";
    case MONERO_TX_ERR_APPROVAL:
      return "Monero transaction changed after review";
    case MONERO_TX_ERR_PROOF:
      return "Monero proving failed or was cancelled";
    case MONERO_TX_ERR_INTERNAL:
    default:
      return "Monero signing failed";
  }
}

/* ------------------------------------------------------------ primitives */

static void put_le32(uint8_t* out, uint32_t v) {
  for (unsigned i = 0; i < 4; ++i) out[i] = (uint8_t)(v >> (8 * i));
}

static void put_le64(uint8_t* out, uint64_t v) {
  for (unsigned i = 0; i < 8; ++i) out[i] = (uint8_t)(v >> (8 * i));
}

static bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; ++i) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

static bool add_u64(uint64_t* sum, uint64_t v) {
  if (v > UINT64_MAX - *sum) return false;
  *sum += v;
  return true;
}

static void hash_varint(SHA3_CTX* ctx, uint64_t v) {
  uint8_t buf[10];
  const int n = xmr_write_varint(buf, sizeof(buf), v);
  keccak_Update(ctx, buf, (size_t)n);
}

/* out = Keccak(pad16(label) || K || le32(index)). */
static void kdf(uint8_t out[32], const uint8_t master[32], const char* label,
                uint32_t index) {
  uint8_t data[16 + 32 + 4] = {0};
  memcpy(data, label, strlen(label));
  memcpy(data + 16, master, 32);
  put_le32(data + 48, index);
  keccak_256(data, sizeof(data), out);
  memzero(data, sizeof(data));
}

static void kdf_scalar(bignum256modm out, const uint8_t master[32],
                       const char* label, uint32_t index) {
  uint8_t h[32];
  kdf(h, master, label, index);
  expand256_modm(out, h, sizeof(h));
  memzero(h, sizeof(h));
}

/* The MAC over host-held state: purpose and slot index are inside it, so
 * one item never verifies in another role or slot. */
static void mac(uint8_t out[32], const TxSession* s, const char* purpose,
                uint32_t index, const uint8_t* data, size_t size) {
  HMAC_SHA256_CTX ctx;
  uint8_t head[16] = {0};
  memcpy(head, purpose, strlen(purpose));
  put_le32(head + 12, index);
  hmac_sha256_Init(&ctx, s->mac_key, 32);
  hmac_sha256_Update(&ctx, head, sizeof(head));
  hmac_sha256_Update(&ctx, data, (uint32_t)size);
  hmac_sha256_Final(&ctx, out);
  memzero(&ctx, sizeof(ctx));
}

static bool mac_matches(const TxSession* s, const char* purpose, uint32_t index,
                        const uint8_t* data, size_t size,
                        const uint8_t expected[32]) {
  uint8_t tag[32];
  mac(tag, s, purpose, index, data, size);
  const bool ok = ct_equal(tag, expected, 32);
  memzero(tag, sizeof(tag));
  return ok;
}

static void dest_encode(uint8_t out[DEST_BYTES],
                        const MoneroTxDestination* dst) {
  put_le64(out, dst->amount);
  memcpy(out + 8, dst->spend_public_key.bytes, 32);
  memcpy(out + 40, dst->view_public_key.bytes, 32);
  out[72] = (uint8_t)((dst->has_is_subaddress && dst->is_subaddress ? 1u : 0u) |
                      (dst->has_is_integrated && dst->is_integrated ? 2u : 0u));
}

static bool dest_well_formed(const MoneroTxDestination* dst) {
  return dst->has_amount && dst->has_spend_public_key &&
         dst->spend_public_key.size == 32 && dst->has_view_public_key &&
         dst->view_public_key.size == 32;
}

/* -------------------------------------------------------------- session */

static TxSession* session(void) {
  return (TxSession*)signing_session_get(SIGNING_SESSION_MONERO_TX);
}

bool monero_tx_active(void) {
  const TxSession* s = session();
  if (s && (uint32_t)(getSysTime() - s->started) > MONERO_TX_SESSION_MS)
    monero_session_abort();
  return session() != NULL;
}

/* The session if it is live and in `step`; otherwise NULL and the reason. */
static TxSession* session_in(uint8_t step, MoneroTxResult* why) {
  const bool had = session() != NULL;
  if (!monero_tx_active()) {
    *why = had ? MONERO_TX_ERR_EXPIRED : MONERO_TX_ERR_STEP;
    return NULL;
  }
  TxSession* s = session();
  if (s->step != step) {
    *why = MONERO_TX_ERR_STEP;
    return NULL;
  }
  return s;
}

bool monero_tx_progress(uint32_t* inputs, uint32_t* signed_inputs) {
  const TxSession* s = session();
  if (!s) return false;
  if (inputs) *inputs = s->n_inputs;
  if (signed_inputs) *signed_inputs = s->sign_pos;
  return true;
}

bool monero_tx_next_output_proves(void) {
  const TxSession* s = session();
  return s && s->step == STEP_OUTPUT && s->out_pos == MONERO_TX_OUTPUTS - 1u;
}

/* ----------------------------------------------------------------- plan */

typedef struct {
  uint8_t own[64];      /* the wallet's (account, 0) spend and view keys */
  uint8_t change_index; /* the one output classified as change */
  bool self[MONERO_TX_OUTPUTS];
  bool tx_key_on_spend; /* R = r*D: the one recipient is a subaddress */
  uint8_t tx_key_base[32];
  uint8_t pid_view[32]; /* view key the payment ID is encrypted to */
  uint8_t digest[32];
} TxPlan;

/* Everything that needs no key. */
static MoneroTxResult plan_check(const MoneroTxInitRequest* m) {
  if (!m || !monero_path_valid(m->address_n, m->address_n_count) ||
      !monero_network_name(m->has_network_type ? (uint32_t)m->network_type
                                               : 0u) ||
      !m->has_tsx_data)
    return MONERO_TX_ERR_REQUEST;
  const MoneroTxData* t = &m->tsx_data;
  if (t->outputs_count != MONERO_TX_OUTPUTS) return MONERO_TX_ERR_OUTPUT_COUNT;
  if (!t->has_ring_size || t->ring_size != MONERO_TX_RING_SIZE)
    return MONERO_TX_ERR_RING_SIZE;
  if (!t->has_hard_fork || t->hard_fork < 16) return MONERO_TX_ERR_HARD_FORK;
  if (!t->has_bp_version || t->bp_version != 4) return MONERO_TX_ERR_RCT_TYPE;
  if (!t->has_num_inputs || t->num_inputs < 1 ||
      t->num_inputs > MONERO_TX_MAX_INPUTS)
    return MONERO_TX_ERR_INPUT_COUNT;
  if (!t->has_fee) return MONERO_TX_ERR_REQUEST;
  if (t->has_payment_id && t->payment_id.size != 8)
    return MONERO_TX_ERR_PAYMENT_ID;

  unsigned integrated = 0;
  uint64_t sum = t->fee;
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j) {
    const MoneroTxDestination* d = &t->outputs[j];
    if (!dest_well_formed(d)) return MONERO_TX_ERR_REQUEST;
    if (d->has_is_integrated && d->is_integrated) {
      /* An integrated address is a standard address plus a payment ID. */
      if (d->amount == 0 || (d->has_is_subaddress && d->is_subaddress))
        return MONERO_TX_ERR_REQUEST;
      ++integrated;
    }
    if (!add_u64(&sum, d->amount)) return MONERO_TX_ERR_AMOUNT;
  }
  if (integrated > 1) return MONERO_TX_ERR_INTEGRATED;
  if ((integrated == 1) != t->has_payment_id) return MONERO_TX_ERR_PAYMENT_ID;

  const MoneroTxChange* c = &t->change_dts;
  if (!t->has_change_dts || !c->has_amount || !c->has_spend_public_key ||
      c->spend_public_key.size != 32 || !c->has_view_public_key ||
      c->view_public_key.size != 32 ||
      (c->has_major ? c->major : 0u) != (t->has_account ? t->account : 0u) ||
      (c->has_minor && c->minor != 0))
    return MONERO_TX_ERR_CHANGE;
  return MONERO_TX_OK;
}

/* Classifies the outputs with the wallet's own keys. The change output is
 * the one that pays the device-derived (account, 0) address the declared
 * change amount; the other one is a recipient, whatever the host calls it.
 * Derivation follows Core: every output to the own address uses a*R, and the
 * own address is left out when Core counts destinations. */
static MoneroTxResult plan_build(const bignum256modm spend,
                                 const bignum256modm view,
                                 const MoneroTxInitRequest* m, TxPlan* plan) {
  ge25519 point;
  uint8_t field[DEST_BYTES];
  SHA3_CTX hash;
  memzero(plan, sizeof(*plan));
  MoneroTxResult result = plan_check(m);
  if (result != MONERO_TX_OK) return result;
  const MoneroTxData* t = &m->tsx_data;
  const uint32_t account = t->has_account ? t->account : 0u;

  if (!monero_address_keys(spend, view, account, 0, plan->own))
    return MONERO_TX_ERR_INTERNAL;
  if (memcmp(t->change_dts.spend_public_key.bytes, plan->own, 32) ||
      memcmp(t->change_dts.view_public_key.bytes, plan->own + 32, 32))
    return MONERO_TX_ERR_CHANGE;

  int change = -1;
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j) {
    const MoneroTxDestination* d = &t->outputs[j];
    if (!monero_decode_public(&point, d->spend_public_key.bytes) ||
        !monero_decode_public(&point, d->view_public_key.bytes))
      return MONERO_TX_ERR_POINT;
    plan->self[j] = !memcmp(d->spend_public_key.bytes, plan->own, 32) &&
                    !memcmp(d->view_public_key.bytes, plan->own + 32, 32);
    const bool integrated = d->has_is_integrated && d->is_integrated;
    /* The device knows what kind of address its own one is. */
    if (plan->self[j] &&
        (d->has_is_subaddress && d->is_subaddress) != (account != 0))
      return MONERO_TX_ERR_REQUEST;
    if (change < 0 && plan->self[j] && !integrated &&
        d->amount == t->change_dts.amount)
      change = (int)j;
  }
  if (change < 0) return MONERO_TX_ERR_CHANGE;
  plan->change_index = (uint8_t)change;

  /* Core's classify_addresses and get_destination_view_key_pub for one
   * recipient plus change. */
  const unsigned other = 1u - plan->change_index;
  const MoneroTxDestination* recipient = &t->outputs[other];
  if (!plan->self[other] && recipient->has_is_subaddress &&
      recipient->is_subaddress) {
    plan->tx_key_on_spend = true;
    memcpy(plan->tx_key_base, recipient->spend_public_key.bytes, 32);
  }
  if (!plan->self[other] && recipient->amount != 0)
    memcpy(plan->pid_view, recipient->view_public_key.bytes, 32);
  else
    memcpy(plan->pid_view, plan->own + 32, 32);

  /* T: the device's canonical encoding of what is reviewed. */
  static const char domain[16] = "KKXMR-init-v1";
  keccak_256_Init(&hash);
  keccak_Update(&hash, (const uint8_t*)domain, sizeof(domain));
  for (unsigned i = 0; i < 3; ++i) {
    put_le32(field, m->address_n[i]);
    keccak_Update(&hash, field, 4);
  }
  const uint32_t words[] = {
      m->has_network_type ? (uint32_t)m->network_type : 0u,
      account,
      t->num_inputs,
      t->ring_size,
      t->hard_fork,
      t->bp_version,
      plan->change_index,
      t->has_payment_id ? 1u : 0u};
  for (unsigned i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
    put_le32(field, words[i]);
    keccak_Update(&hash, field, 4);
  }
  const uint64_t wide[] = {t->fee, t->has_unlock_time ? t->unlock_time : 0u,
                           t->change_dts.amount};
  for (unsigned i = 0; i < sizeof(wide) / sizeof(wide[0]); ++i) {
    put_le64(field, wide[i]);
    keccak_Update(&hash, field, 8);
  }
  memzero(field, 8);
  if (t->has_payment_id) memcpy(field, t->payment_id.bytes, 8);
  keccak_Update(&hash, field, 8);
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j) {
    dest_encode(field, &t->outputs[j]);
    keccak_Update(&hash, field, DEST_BYTES);
  }
  keccak_Update(&hash, plan->own, sizeof(plan->own));
  keccak_Final(&hash, plan->digest);
  return MONERO_TX_OK;
}

MoneroTxResult monero_tx_review(const uint8_t node_key[32],
                                const MoneroTxInitRequest* request,
                                MoneroTxReview* review) {
  bignum256modm spend = {0}, view = {0};
  TxPlan plan;
  MoneroTxResult result = MONERO_TX_ERR_INTERNAL;
  if (!review) return result;
  memzero(review, sizeof(*review));
  if (!node_key || !monero_wallet_secrets(node_key, spend, view)) goto done;
  result = plan_build(spend, view, request, &plan);
  if (result != MONERO_TX_OK) goto done;

  const MoneroTxData* t = &request->tsx_data;
  review->network =
      request->has_network_type ? (uint32_t)request->network_type : 0u;
  review->account = t->has_account ? t->account : 0u;
  review->num_inputs = t->num_inputs;
  review->fee = t->fee;
  review->unlock_time = t->has_unlock_time ? t->unlock_time : 0u;
  review->has_payment_id = t->has_payment_id;
  if (t->has_payment_id) memcpy(review->payment_id, t->payment_id.bytes, 8);
  review->total = t->fee;
  result = MONERO_TX_ERR_INTERNAL;
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j) {
    const MoneroTxDestination* d = &t->outputs[j];
    MoneroTxReviewOutput* o = &review->outputs[j];
    uint8_t keys[64];
    o->amount = d->amount;
    o->is_change = j == plan.change_index;
    o->is_integrated = d->has_is_integrated && d->is_integrated;
    o->is_subaddress = d->has_is_subaddress && d->is_subaddress;
    /* plan_check bounded the sum of every output and the fee. */
    if (!o->is_change) review->total += d->amount;
    memcpy(keys, d->spend_public_key.bytes, 32);
    memcpy(keys + 32, d->view_public_key.bytes, 32);
    const MoneroAddressKind kind = o->is_integrated ? MONERO_ADDRESS_INTEGRATED
                                   : o->is_subaddress
                                       ? MONERO_ADDRESS_SUBADDRESS
                                       : MONERO_ADDRESS_STANDARD;
    if (!monero_encode_address(review->network, kind, keys, review->payment_id,
                               o->address, sizeof(o->address)))
      goto done;
  }
  memcpy(review->digest, plan.digest, 32);
  result = MONERO_TX_OK;
done:
  memzero(spend, sizeof(spend));
  memzero(view, sizeof(view));
  memzero(&plan, sizeof(plan));
  if (result != MONERO_TX_OK) memzero(review, sizeof(*review));
  return result;
}

/* ---------------------------------------------------------------- begin */

/* R and the encrypted payment ID, then the tx extra Core would write:
 * 01 R | 02 09 01 pid. Core adds the dummy (zero) payment ID itself when a
 * two-output transaction has none. */
static bool build_extra(TxSession* s, const TxPlan* plan,
                        const uint8_t* payment_id) {
  struct {
    bignum256modm r;
    ge25519 point, product;
    uint8_t data[33], hash[32];
  } tmp = {0};
  bool ok = false;
  kdf_scalar(tmp.r, s->master, "KKXMR-r", 0);
  if (iszero256_modm(tmp.r)) goto done;
  s->extra[0] = 0x01;
  if (plan->tx_key_on_spend) {
    if (!monero_decode_public(&tmp.point, plan->tx_key_base)) goto done;
    ge25519_scalarmult(&tmp.product, &tmp.point, tmp.r);
  } else {
    ge25519_scalarmult_base_wrapper(&tmp.product, tmp.r);
  }
  ge25519_pack(s->extra + 1, &tmp.product);

  if (!monero_decode_public(&tmp.point, plan->pid_view)) goto done;
  xmr_generate_key_derivation(&tmp.product, &tmp.point, tmp.r);
  ge25519_pack(tmp.data, &tmp.product);
  tmp.data[32] = 0x8d; /* HASH_KEY_ENCRYPTED_PAYMENT_ID */
  keccak_256(tmp.data, sizeof(tmp.data), tmp.hash);
  s->extra[33] = 0x02; /* nonce */
  s->extra[34] = 0x09;
  s->extra[35] = 0x01; /* encrypted payment ID */
  for (unsigned i = 0; i < 8; ++i)
    s->extra[36 + i] =
        (uint8_t)((payment_id ? payment_id[i] : 0) ^ tmp.hash[i]);
  ok = true;
done:
  memzero(&tmp, sizeof(tmp));
  return ok;
}

MoneroTxResult monero_tx_begin(const uint8_t node_key[32],
                               const MoneroTxInitRequest* request,
                               const uint8_t approved_digest[32],
                               MoneroTxInitAck* ack) {
  bignum256modm spend = {0}, view = {0};
  uint8_t spend_bytes[32] = {0}, field[DEST_BYTES];
  TxPlan plan;
  TxSession* s = NULL;
  MoneroTxResult result = MONERO_TX_ERR_INTERNAL;

  monero_session_abort();
  if (ack) memzero(ack, sizeof(*ack));
  if (!node_key || !approved_digest || !ack ||
      !monero_wallet_secrets(node_key, spend, view))
    goto done;
  result = plan_build(spend, view, request, &plan);
  if (result != MONERO_TX_OK) goto done;
  result = MONERO_TX_ERR_APPROVAL;
  if (!ct_equal(plan.digest, approved_digest, 32)) goto done;

  result = MONERO_TX_ERR_INTERNAL;
  s = signing_session_claim(SIGNING_SESSION_MONERO_TX);
  if (!s) goto done;
  const MoneroTxData* t = &request->tsx_data;
  /* K: hedged with the spend key and the reviewed plan, so even a repeated
   * RNG output gives a different K for a different plan. */
  contract256_modm(spend_bytes, spend);
  result = MONERO_TX_ERR_PROOF;
  if (!xmr_hedge_key(s->master, "KKXMR-K", spend_bytes, sizeof(spend_bytes),
                     plan.digest, sizeof(plan.digest)))
    goto done;
  result = MONERO_TX_ERR_INTERNAL;
  kdf(s->mac_key, s->master, "KKXMR-mac", 0);
  kdf(s->open_key, s->master, "KKXMR-open", 0);
  memcpy(s->spend, spend, sizeof(bignum256modm));
  memcpy(s->view, view, sizeof(bignum256modm));
  s->account = t->has_account ? t->account : 0u;
  s->n_inputs = (uint8_t)t->num_inputs;
  s->fee = t->fee;
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j)
    s->out_self[j] = plan.self[j];
  if (!build_extra(s, &plan, t->has_payment_id ? t->payment_id.bytes : NULL))
    goto done;

  /* tx prefix: version 2, unlock time, then the inputs. */
  keccak_256_Init(&s->prefix);
  hash_varint(&s->prefix, 2);
  hash_varint(&s->prefix, t->has_unlock_time ? t->unlock_time : 0u);
  hash_varint(&s->prefix, s->n_inputs);
  /* rctSigBase: type, fee, then the encrypted amounts and commitments. */
  keccak_256_Init(&s->rct_base);
  field[0] = MONERO_TX_RCT_TYPE;
  keccak_Update(&s->rct_base, field, 1);
  hash_varint(&s->rct_base, s->fee);

  ack->dst_hmacs_count = MONERO_TX_OUTPUTS;
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j) {
    dest_encode(field, &t->outputs[j]);
    mac(ack->dst_hmacs[j].bytes, s, "txdest", j, field, DEST_BYTES);
    ack->dst_hmacs[j].size = 32;
  }
  ack->has_rsig_mode = true;
  ack->rsig_mode = 0;
  s->step = STEP_INPUT;
  s->started = getSysTime();
  result = MONERO_TX_OK;
done:
  memzero(spend, sizeof(spend));
  memzero(view, sizeof(view));
  memzero(spend_bytes, sizeof(spend_bytes));
  memzero(&plan, sizeof(plan));
  if (result != MONERO_TX_OK) {
    if (ack) memzero(ack, sizeof(*ack));
    monero_session_abort();
  }
  return result;
}

/* --------------------------------------------------------------- inputs */

typedef struct {
  bignum256modm secret; /* x: one-time spend key of the real output */
  bignum256modm mask;   /* its commitment mask */
  uint64_t amount;
  uint8_t real_index;
  uint8_t vini[VINI_MAX_BYTES]; /* 02 | 00 | count | offsets | key image */
  size_t vini_size;
} TxInput;

/* Checks one source entry and opens it: proves the real member is this
 * wallet's (x*G == P), that amount and mask open its commitment, and builds
 * the txin_to_key with the key image I = x*Hp(P). */
static MoneroTxResult input_open(const TxSession* s,
                                 const MoneroTxSourceEntry* src,
                                 bool check_decoys, TxInput* in) {
  struct {
    ge25519 tx, derivation, point;
    bignum256modm scalar, sub;
    uint8_t encoded[42], check[32];
  } tmp = {0};
  MoneroTxResult result = MONERO_TX_ERR_RING;
  memzero(in, sizeof(*in));

  if (src->ring_count != MONERO_TX_RING_SIZE || !src->has_real_index ||
      src->real_index >= MONERO_TX_RING_SIZE)
    goto done;
  for (unsigned i = 0; i < MONERO_TX_RING_SIZE; ++i) {
    const MoneroTxRingMember* member = &src->ring[i];
    if (!member->has_global_index || !member->has_dest ||
        member->dest.size != 32 || !member->has_commitment ||
        member->commitment.size != 32 ||
        (i && member->global_index <= src->ring[i - 1].global_index))
      goto done;
  }
  result = MONERO_TX_ERR_REQUEST;
  if (!src->has_real_out_tx_key || src->real_out_tx_key.size != 32 ||
      (src->has_real_out_additional_key &&
       src->real_out_additional_key.size != 32) ||
      !src->has_real_output_in_tx_index || !src->has_amount || !src->has_mask ||
      src->mask.size != 32 || src->has_sub_major != src->has_sub_minor ||
      (src->has_sub_major && src->sub_major != s->account))
    goto done;
  result = MONERO_TX_ERR_SCALAR;
  expand256_modm(in->mask, src->mask.bytes, 32);
  contract256_modm(tmp.check, in->mask);
  if (memcmp(tmp.check, src->mask.bytes, 32)) goto done;

  if (check_decoys) {
    result = MONERO_TX_ERR_POINT;
    for (unsigned i = 0; i < MONERO_TX_RING_SIZE; ++i) {
      const uint8_t* keys[2] = {src->ring[i].dest.bytes,
                                src->ring[i].commitment.bytes};
      for (unsigned k = 0; k < 2; ++k) {
        if (!xmr_point_load_canonical(&tmp.point, keys[k])) goto done;
      }
    }
  }

  const MoneroTxRingMember* real = &src->ring[src->real_index];
  const uint32_t minor = src->has_sub_minor ? src->sub_minor : 0u;
  /* The output was derived from R or from its additional key. Both are
   * multiplied by the view key, so both must be clean points first. */
  const unsigned alternatives = src->has_real_out_additional_key ? 2u : 1u;
  bool owned = false;
  for (unsigned alternative = 0; alternative < alternatives; ++alternative) {
    const uint8_t* tx = alternative ? src->real_out_additional_key.bytes
                                    : src->real_out_tx_key.bytes;
    result = MONERO_TX_ERR_POINT;
    if (!monero_decode_public(&tmp.tx, tx)) goto done;
    if (owned) continue;
    xmr_generate_key_derivation(&tmp.derivation, &tmp.tx, s->view);
    ge25519_pack(tmp.encoded, &tmp.derivation);
    const int n =
        xmr_write_varint(tmp.encoded + 32, 10, src->real_output_in_tx_index);
    monero_hash_scalar(tmp.scalar, tmp.encoded, 32u + (size_t)n);
    add256_modm(in->secret, tmp.scalar, s->spend);
    if (s->account || minor) {
      monero_subaddress_scalar(tmp.sub, s->view, s->account, minor);
      add256_modm(in->secret, in->secret, tmp.sub);
    }
    ge25519_scalarmult_base_wrapper(&tmp.point, in->secret);
    ge25519_pack(tmp.check, &tmp.point);
    owned = memcmp(tmp.check, real->dest.bytes, 32) == 0;
  }
  result = MONERO_TX_ERR_NOT_OWNED;
  if (!owned) goto done;

  result = MONERO_TX_ERR_COMMITMENT;
  xmr_gen_c(&tmp.point, in->mask, src->amount);
  ge25519_pack(tmp.check, &tmp.point);
  if (memcmp(tmp.check, real->commitment.bytes, 32)) goto done;

  /* vini: txin_to_key with amount 0 and offsets relative to the previous. */
  uint8_t* p = in->vini;
  *p++ = 0x02;
  *p++ = 0x00;
  *p++ = (uint8_t)MONERO_TX_RING_SIZE;
  uint64_t previous = 0;
  for (unsigned i = 0; i < MONERO_TX_RING_SIZE; ++i) {
    p += xmr_write_varint(p, 10, src->ring[i].global_index - previous);
    previous = src->ring[i].global_index;
  }
  xmr_hash_to_ec(&tmp.point, real->dest.bytes, 32);
  ge25519_scalarmult(&tmp.derivation, &tmp.point, in->secret);
  ge25519_pack(p, &tmp.derivation);
  in->vini_size = (size_t)(p - in->vini) + 32u;
  in->amount = src->amount;
  in->real_index = (uint8_t)src->real_index;
  result = MONERO_TX_OK;
done:
  memzero(&tmp, sizeof(tmp));
  if (result != MONERO_TX_OK) memzero(in, sizeof(*in));
  return result;
}

/* out = mask*G + amount*H, packed. */
static void commit(uint8_t out[32], const bignum256modm mask, uint64_t amount) {
  ge25519 point;
  xmr_gen_c(&point, mask, amount);
  ge25519_pack(out, &point);
  memzero(&point, sizeof(point));
}

MoneroTxResult monero_tx_set_input(const MoneroTxSetInputRequest* request,
                                   MoneroTxSetInputAck* ack) {
  TxInput in;
  bignum256modm pseudo = {0};
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_INPUT, &result);
  memzero(&in, sizeof(in));
  if (ack) memzero(ack, sizeof(*ack));
  if (!s) goto fail;
  result = MONERO_TX_ERR_REQUEST;
  if (!request || !ack || !request->has_src) goto fail;
  result = input_open(s, &request->src, true, &in);
  if (result != MONERO_TX_OK) goto fail;
  result = MONERO_TX_ERR_AMOUNT;
  if (!add_u64(&s->sum_in, in.amount)) goto fail;

  const uint32_t index = s->in_pos;
  kdf_scalar(pseudo, s->master, "KKXMR-pa", index);
  commit(ack->pseudo_out.bytes, pseudo, in.amount);
  add256_modm(s->sum_pseudo, s->sum_pseudo, pseudo);
  ack->has_pseudo_out = true;
  ack->pseudo_out.size = 32;
  ack->has_pseudo_out_hmac = true;
  ack->pseudo_out_hmac.size = 32;
  mac(ack->pseudo_out_hmac.bytes, s, "txin-comm", index, ack->pseudo_out.bytes,
      32);
  ack->has_vini = true;
  ack->vini.size = (pb_size_t)in.vini_size;
  memcpy(ack->vini.bytes, in.vini, in.vini_size);
  ack->has_vini_hmac = true;
  ack->vini_hmac.size = 32;
  mac(ack->vini_hmac.bytes, s, "txin", index, in.vini, in.vini_size);
  if (++s->in_pos == s->n_inputs) s->step = STEP_VINI;
  memzero(&in, sizeof(in));
  memzero(pseudo, sizeof(pseudo));
  return MONERO_TX_OK;
fail:
  memzero(&in, sizeof(in));
  memzero(pseudo, sizeof(pseudo));
  if (ack) memzero(ack, sizeof(*ack));
  monero_session_abort();
  return result;
}

MoneroTxResult monero_tx_input_vini(const MoneroTxInputViniRequest* request) {
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_VINI, &result);
  if (!s) goto fail;
  result = MONERO_TX_ERR_STEP;
  if (s->vini_pos >= s->n_inputs) goto fail;
  result = MONERO_TX_ERR_REQUEST;
  if (!request || !request->has_vini || request->vini.size < VINI_MIN_BYTES ||
      request->vini.size > VINI_MAX_BYTES || !request->has_vini_hmac ||
      request->vini_hmac.size != 32 || !request->has_orig_idx)
    goto fail;
  result = MONERO_TX_ERR_ORDER;
  if (request->orig_idx >= s->n_inputs || (s->seen >> request->orig_idx) & 1u)
    goto fail;
  result = MONERO_TX_ERR_MAC;
  if (!mac_matches(s, "txin", request->orig_idx, request->vini.bytes,
                   request->vini.size, request->vini_hmac.bytes))
    goto fail;
  /* Core sorts inputs by key image, largest first. Strictly decreasing
   * also means no key image appears twice. */
  const uint8_t* key_image = request->vini.bytes + request->vini.size - 32u;
  result = MONERO_TX_ERR_ORDER;
  if (s->vini_pos && memcmp(s->last_ki, key_image, 32) <= 0) goto fail;
  memcpy(s->last_ki, key_image, 32);
  keccak_Update(&s->prefix, request->vini.bytes, request->vini.size);
  s->seen |= (uint64_t)1 << request->orig_idx;
  s->order[s->vini_pos++] = (uint8_t)request->orig_idx;
  return MONERO_TX_OK;
fail:
  monero_session_abort();
  return result;
}

MoneroTxResult monero_tx_all_inputs_set(void) {
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_VINI, &result);
  if (!s || s->vini_pos != s->n_inputs) {
    if (s) result = MONERO_TX_ERR_STEP;
    monero_session_abort();
    return result;
  }
  hash_varint(&s->prefix, MONERO_TX_OUTPUTS);
  s->step = STEP_OUTPUT;
  return MONERO_TX_OK;
}

/* -------------------------------------------------------------- outputs */

static bool bpp_matches_commitments(const xmr_bpp_proof* proof,
                                    const TxSession* s) {
  ge25519 v, c;
  uint8_t packed[32];
  bool ok = proof->n_outputs == MONERO_TX_OUTPUTS;
  for (unsigned j = 0; ok && j < MONERO_TX_OUTPUTS; ++j) {
    ok = ge25519_unpack_vartime(&v, proof->V[j]) != 0;
    if (!ok) break;
    ge25519_mul8(&c, &v);
    ge25519_pack(packed, &c);
    ok = ct_equal(packed, s->out_commit[j], 32);
  }
  return ok;
}

MoneroTxResult monero_tx_set_output(const MoneroTxSetOutputRequest* request,
                                    MoneroTxSetOutputAck* ack, void* scratch,
                                    size_t scratch_size,
                                    xmr_progress_fn progress,
                                    void* progress_ctx) {
  struct {
    ge25519 point, derivation;
    bignum256modm scalar, mask;
    uint8_t encoded[8 + 32 + 10], amount_key[15 + 32], hash[32];
    uint8_t field[DEST_BYTES];
    xmr_bpp_proof proof;
  } tmp;
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_OUTPUT, &result);
  memzero(&tmp, sizeof(tmp));
  if (ack) memzero(ack, sizeof(*ack));
  if (!s) goto fail;
  result = MONERO_TX_ERR_STEP;
  if (s->out_pos >= MONERO_TX_OUTPUTS) goto fail;
  result = MONERO_TX_ERR_REQUEST;
  if (!request || !ack || !request->has_dst ||
      !dest_well_formed(&request->dst) || !request->has_dst_hmac ||
      request->dst_hmac.size != 32)
    goto fail;
  const unsigned j = s->out_pos;
  const bool proves = j == MONERO_TX_OUTPUTS - 1u;
  result = MONERO_TX_ERR_INTERNAL;
  if (proves && (!scratch || scratch_size < MONERO_TX_BPP_SCRATCH_BYTES ||
                 ((uintptr_t)scratch % XMR_WORKSPACE_ALIGN) != 0))
    goto fail;
  const MoneroTxDestination* dst = &request->dst;
  dest_encode(tmp.field, dst);
  result = MONERO_TX_ERR_MAC;
  if (!mac_matches(s, "txdest", j, tmp.field, DEST_BYTES,
                   request->dst_hmac.bytes))
    goto fail;

  /* derivation: a*R for the wallet's own address, r*A for a recipient. */
  result = MONERO_TX_ERR_POINT;
  if (s->out_self[j]) {
    if (!monero_decode_public(&tmp.point, s->extra + 1)) goto fail;
    xmr_generate_key_derivation(&tmp.derivation, &tmp.point, s->view);
  } else {
    if (!monero_decode_public(&tmp.point, dst->view_public_key.bytes))
      goto fail;
    kdf_scalar(tmp.scalar, s->master, "KKXMR-r", 0);
    xmr_generate_key_derivation(&tmp.derivation, &tmp.point, tmp.scalar);
  }
  /* encoded = "view_tag" | derivation | varint(j) */
  memcpy(tmp.encoded, "view_tag", 8);
  ge25519_pack(tmp.encoded + 8, &tmp.derivation);
  const size_t index_size = (size_t)xmr_write_varint(tmp.encoded + 40, 10, j);
  keccak_256(tmp.encoded, 40u + index_size, tmp.hash);
  const uint8_t view_tag = tmp.hash[0];
  /* amount key = Hs(derivation | varint(j)); P = amount_key*G + B */
  monero_hash_scalar(tmp.scalar, tmp.encoded + 8, 32u + index_size);
  memcpy(tmp.amount_key, "commitment_mask", 15);
  contract256_modm(tmp.amount_key + 15, tmp.scalar);
  if (!monero_decode_public(&tmp.point, dst->spend_public_key.bytes)) goto fail;
  ge25519_scalarmult_base_wrapper(&tmp.derivation, tmp.scalar);
  ge25519_add(&tmp.point, &tmp.point, &tmp.derivation, 0);

  ack->has_tx_out = true;
  ack->tx_out.size = TX_OUT_BYTES;
  ack->tx_out.bytes[0] = 0x00; /* amount */
  ack->tx_out.bytes[1] = 0x03; /* txout_to_tagged_key */
  ge25519_pack(ack->tx_out.bytes + 2, &tmp.point);
  ack->tx_out.bytes[34] = view_tag;

  /* mask = Hs("commitment_mask" | amount key); C = mask*G + amount*H;
   * encrypted amount = amount ^ Keccak("amount" | amount key)[0..8). */
  monero_hash_scalar(tmp.mask, tmp.amount_key, sizeof(tmp.amount_key));
  contract256_modm(s->out_mask[j], tmp.mask);
  s->out_amount[j] = dst->amount;
  commit(s->out_commit[j], tmp.mask, dst->amount);
  add256_modm(s->sum_out_mask, s->sum_out_mask, tmp.mask);
  result = MONERO_TX_ERR_AMOUNT;
  if (!add_u64(&s->sum_out, dst->amount)) goto fail;
  memcpy(tmp.amount_key + 9, "amount", 6);
  keccak_256(tmp.amount_key + 9, 6u + 32u, tmp.hash);
  ack->has_ecdh_info = true;
  ack->ecdh_info.size = 8;
  put_le64(ack->ecdh_info.bytes, dst->amount);
  for (unsigned i = 0; i < 8; ++i) ack->ecdh_info.bytes[i] ^= tmp.hash[i];
  ack->has_out_pk = true;
  ack->out_pk.size = 64;
  memcpy(ack->out_pk.bytes, ack->tx_out.bytes + 2, 32);
  memcpy(ack->out_pk.bytes + 32, s->out_commit[j], 32);

  keccak_Update(&s->prefix, ack->tx_out.bytes, TX_OUT_BYTES);
  keccak_Update(&s->rct_base, ack->ecdh_info.bytes, 8);

  if (proves) {
    /* The long step. The amounts and masks are the session's; the prover
     * holds no other secret across its progress callback, and after an
     * aborted callback neither it nor this function touches scratch. */
    result = MONERO_TX_ERR_PROOF;
    if (!xmr_bpp_prove(&tmp.proof, s->out_amount,
                       (const uint8_t (*)[32])s->out_mask, MONERO_TX_OUTPUTS,
                       (xmr_bpp_workspace*)scratch, progress, progress_ctx))
      goto fail;
    /* A callback that let a session-ending message through must have
     * returned false; never continue on a session that is gone. */
    if (session() != s || s->step != STEP_OUTPUT) goto fail;
    result = MONERO_TX_ERR_INTERNAL;
    size_t written = 0;
    if (!bpp_matches_commitments(&tmp.proof, s) ||
        !xmr_bpp_serialize(&tmp.proof, ack->bp_plus.bytes,
                           sizeof(ack->bp_plus.bytes), &written))
      goto fail;
    ack->has_bp_plus = true;
    ack->bp_plus.size = (pb_size_t)written;
    /* Third part of the CLSAG message: the proof's keys, no counts. */
    SHA3_CTX hash;
    keccak_256_Init(&hash);
    keccak_Update(&hash, (const uint8_t*)&tmp.proof + BPP_KEYS_OFFSET,
                  6u * 32u);
    keccak_Update(&hash, (const uint8_t*)tmp.proof.L, tmp.proof.n_rounds * 32u);
    keccak_Update(&hash, (const uint8_t*)tmp.proof.R, tmp.proof.n_rounds * 32u);
    keccak_Final(&hash, s->bp_hash);
    /* Only the sum of the masks is needed from here on. */
    memzero(s->out_mask, sizeof(s->out_mask));
    memzero(s->out_amount, sizeof(s->out_amount));
  }
  ++s->out_pos;
  memzero(&tmp, sizeof(tmp));
  return MONERO_TX_OK;
fail:
  memzero(&tmp, sizeof(tmp));
  if (ack) memzero(ack, sizeof(*ack));
  monero_session_abort();
  return result;
}

MoneroTxResult monero_tx_all_out_set(MoneroTxAllOutSetAck* ack) {
  uint8_t hashes[96];
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_OUTPUT, &result);
  if (ack) memzero(ack, sizeof(*ack));
  if (!s) goto fail;
  result = MONERO_TX_ERR_STEP;
  if (!ack || s->out_pos != MONERO_TX_OUTPUTS) goto fail;
  /* No signature exists yet: the fee the user approved must be exactly
   * what the inputs leave after the outputs. */
  uint64_t spent = s->sum_out;
  result = MONERO_TX_ERR_BALANCE;
  if (!add_u64(&spent, s->fee) || spent != s->sum_in) goto fail;

  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j)
    keccak_Update(&s->rct_base, s->out_commit[j], 32);
  hash_varint(&s->prefix, EXTRA_BYTES);
  keccak_Update(&s->prefix, s->extra, EXTRA_BYTES);
  /* CLSAG message = Keccak(prefix hash | rctSigBase hash | proof hash). */
  keccak_Final(&s->prefix, hashes);
  keccak_Final(&s->rct_base, hashes + 32);
  memcpy(hashes + 64, s->bp_hash, 32);
  keccak_256(hashes, sizeof(hashes), s->message);

  ack->has_extra = true;
  ack->extra.size = EXTRA_BYTES;
  memcpy(ack->extra.bytes, s->extra, EXTRA_BYTES);
  ack->has_tx_prefix_hash = true;
  ack->tx_prefix_hash.size = 32;
  memcpy(ack->tx_prefix_hash.bytes, hashes, 32);
  ack->has_fee = true;
  ack->fee = s->fee;
  ack->has_rct_type = true;
  ack->rct_type = MONERO_TX_RCT_TYPE;
  ack->has_full_message_hash = true;
  ack->full_message_hash.size = 32;
  memcpy(ack->full_message_hash.bytes, s->message, 32);
  s->step = STEP_SIGN;
  return MONERO_TX_OK;
fail:
  if (ack) memzero(ack, sizeof(*ack));
  monero_session_abort();
  return result;
}

/* -------------------------------------------------------------- signing */

MoneroTxResult monero_tx_sign_input(const MoneroTxSignInputRequest* request,
                                    MoneroTxSignInputAck* ack, void* scratch,
                                    size_t scratch_size,
                                    xmr_progress_fn progress,
                                    void* progress_ctx) {
  struct {
    TxInput in;
    bignum256modm pseudo, delta;
    uint8_t secret[32], offset_secret[32], pseudo_out[32], nonce[12];
    xmr_clsag_sig sig;
    chacha20poly1305_ctx cipher;
  } tmp;
  ClsagScratch* work = (ClsagScratch*)scratch;
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_SIGN, &result);
  memzero(&tmp, sizeof(tmp));
  if (ack) memzero(ack, sizeof(*ack));
  if (!s) goto fail;
  result = MONERO_TX_ERR_STEP;
  if (s->sign_pos >= s->n_inputs) goto fail;
  result = MONERO_TX_ERR_REQUEST;
  if (!request || !ack || !request->has_src || !request->has_vini ||
      request->vini.size < VINI_MIN_BYTES ||
      request->vini.size > VINI_MAX_BYTES || !request->has_vini_hmac ||
      request->vini_hmac.size != 32 || !request->has_pseudo_out ||
      request->pseudo_out.size != 32 || !request->has_pseudo_out_hmac ||
      request->pseudo_out_hmac.size != 32 || !request->has_orig_idx)
    goto fail;
  result = MONERO_TX_ERR_INTERNAL;
  if (!scratch || scratch_size < MONERO_TX_CLSAG_SCRATCH_BYTES ||
      ((uintptr_t)scratch % XMR_WORKSPACE_ALIGN) != 0)
    goto fail;
  /* Same order as the vini: the prefix hash already fixed it. */
  const uint32_t position = s->sign_pos;
  const uint32_t index = request->orig_idx;
  result = MONERO_TX_ERR_ORDER;
  if (index != s->order[position]) goto fail;
  result = MONERO_TX_ERR_MAC;
  if (!mac_matches(s, "txin", index, request->vini.bytes, request->vini.size,
                   request->vini_hmac.bytes) ||
      !mac_matches(s, "txin-comm", index, request->pseudo_out.bytes, 32,
                   request->pseudo_out_hmac.bytes))
    goto fail;

  /* Open the source again and require the very input that was MAC'd: the
   * same ring offsets and key image, and the same amount (the pseudo-output
   * commits to it under a mask only the device knows). */
  result = input_open(s, &request->src, false, &tmp.in);
  if (result != MONERO_TX_OK) goto fail;
  result = MONERO_TX_ERR_MAC;
  if (tmp.in.vini_size != request->vini.size ||
      !ct_equal(tmp.in.vini, request->vini.bytes, tmp.in.vini_size))
    goto fail;
  kdf_scalar(tmp.pseudo, s->master, "KKXMR-pa", index);
  commit(tmp.pseudo_out, tmp.pseudo, tmp.in.amount);
  if (!ct_equal(tmp.pseudo_out, request->pseudo_out.bytes, 32)) goto fail;
  if (position + 1u == s->n_inputs) {
    /* Last input: move its mask so the pseudo-output masks sum to the
     * output masks, as the RingCT balance needs. */
    sub256_modm(tmp.delta, s->sum_out_mask, s->sum_pseudo);
    add256_modm(tmp.pseudo, tmp.pseudo, tmp.delta);
    commit(tmp.pseudo_out, tmp.pseudo, tmp.in.amount);
  }
  /* z: the real commitment minus the pseudo-output is z*G. */
  sub256_modm(tmp.delta, tmp.in.mask, tmp.pseudo);
  contract256_modm(tmp.offset_secret, tmp.delta);
  contract256_modm(tmp.secret, tmp.in.secret);

  for (unsigned i = 0; i < MONERO_TX_RING_SIZE; ++i) {
    memcpy(work->P[i], request->src.ring[i].dest.bytes, 32);
    memcpy(work->C[i], request->src.ring[i].commitment.bytes, 32);
  }
  /* One CLSAG per input per session: the position only moves forward, and
   * any failure ends the session. After an aborted callback neither the
   * signer nor this function touches scratch (the ring copies included). */
  result = MONERO_TX_ERR_PROOF;
  if (!xmr_clsag_sign(&tmp.sig, s->message, (const uint8_t (*)[32])work->P,
                      (const uint8_t (*)[32])work->C, tmp.pseudo_out,
                      MONERO_TX_RING_SIZE, tmp.in.real_index, tmp.secret,
                      tmp.offset_secret, &work->ws, progress, progress_ctx))
    goto fail;
  if (session() != s || s->step != STEP_SIGN) goto fail;
  result = MONERO_TX_ERR_INTERNAL;
  if (!ct_equal(tmp.sig.I, tmp.in.vini + tmp.in.vini_size - 32u, 32)) goto fail;

  /* s[16] | c1 | D, sealed until final releases Kopen. The nonce is the
   * position, used once per session key. */
  put_le32(tmp.nonce, position);
  rfc7539_init(&tmp.cipher, s->open_key, tmp.nonce);
  chacha20poly1305_encrypt(&tmp.cipher, (const uint8_t*)&tmp.sig,
                           ack->clsag_enc.bytes, CLSAG_PLAIN_BYTES);
  rfc7539_finish(&tmp.cipher, 0, CLSAG_PLAIN_BYTES,
                 ack->clsag_enc.bytes + CLSAG_PLAIN_BYTES);
  ack->has_clsag_enc = true;
  ack->clsag_enc.size = CLSAG_PLAIN_BYTES + 16u;
  ack->has_pseudo_out = true;
  ack->pseudo_out.size = 32;
  memcpy(ack->pseudo_out.bytes, tmp.pseudo_out, 32);
  if (++s->sign_pos == s->n_inputs) s->step = STEP_FINAL;
  memzero(&tmp, sizeof(tmp));
  return MONERO_TX_OK;
fail:
  memzero(&tmp, sizeof(tmp));
  if (ack) memzero(ack, sizeof(*ack));
  monero_session_abort();
  return result;
}

MoneroTxResult monero_tx_final(MoneroTxFinalAck* ack) {
  MoneroTxResult result = MONERO_TX_ERR_STEP;
  TxSession* s = session_in(STEP_FINAL, &result);
  if (ack) memzero(ack, sizeof(*ack));
  if (s && ack) {
    ack->has_opening_key = true;
    ack->opening_key.size = 32;
    memcpy(ack->opening_key.bytes, s->open_key, 32);
    result = MONERO_TX_OK;
  } else if (s) {
    result = MONERO_TX_ERR_REQUEST;
  }
  monero_session_abort();
  return result;
}
