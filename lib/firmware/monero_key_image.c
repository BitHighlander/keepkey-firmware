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

/* Key-image sync (Trezor's wire protocol), ported from the emulator research
 * (tools/monero-feasibility/commands/key-image.c). The wallet sends the
 * outputs it believes it owns; for each the device proves ownership, computes
 * the key image and a one-member ring signature over it, and returns both
 * encrypted. Only the final, correctly bound transcript releases the key.
 * Legacy/CLSAG key images (Keccak, fromfe, mul8), not FCMP++. */

#include <string.h>

#include "keepkey/board/timer.h"
#include "keepkey/firmware/monero.h"
#include "keepkey/firmware/monero_tx.h"
#include "keepkey/firmware/signing_session.h"
#include "keepkey/rand/rng_health.h"
#include "monero_internal.h"
#include "trezor/crypto/chacha20poly1305/rfc7539.h"
#include "trezor/crypto/memzero.h"

#define KEY_IMAGE_SESSION_MS 120000u
#define KEY_IMAGE_MAX_SUBADDRESSES 32u

typedef struct {
  uint32_t started;
  uint32_t count, processed;
  bignum256modm spend, view;
  uint8_t expected[32], encryption_key[32];
  Hasher transcript;
  uint32_t sub_count;
  struct {
    uint32_t major, minor;
  } subs[KEY_IMAGE_MAX_SUBADDRESSES];
} KeyImageSession;

_Static_assert(sizeof(KeyImageSession) <= MONERO_SESSION_BYTES,
               "key-image session exceeds the Monero arena share");

static KeyImageSession* session(void) {
  return (KeyImageSession*)signing_session_get(
      SIGNING_SESSION_MONERO_KEY_IMAGE);
}

void monero_session_abort(void) {
  signing_session_release(SIGNING_SESSION_MONERO_KEY_IMAGE);
  signing_session_release(SIGNING_SESSION_MONERO_TX);
}

bool monero_key_image_active(void) {
  const KeyImageSession* s = session();
  return s && (uint32_t)(getSysTime() - s->started) <= KEY_IMAGE_SESSION_MS;
}

/* Handler/dispatch safe point. Activity predicates never revoke a handler's
 * retained arena pointer; continuations clean up before using one. */
void monero_session_expire(void) {
  if ((signing_session_owner() == SIGNING_SESSION_MONERO_KEY_IMAGE &&
       !monero_key_image_active()) ||
      (signing_session_owner() == SIGNING_SESSION_MONERO_TX &&
       !monero_tx_active()))
    monero_session_abort();
}

bool monero_key_image_begin(const uint8_t node_key[32],
                            const MoneroKeyImageExportInitRequest* request) {
  monero_session_abort();
  if (!node_key || !request || !request->has_num || !request->num ||
      request->num > MONERO_KEY_IMAGE_MAX_OUTPUTS || !request->has_hash ||
      request->hash.size != 32 || request->subs_count > 4 ||
      (request->has_network_type && request->network_type > 2))
    return false;
  KeyImageSession* s =
      signing_session_prepare(SIGNING_SESSION_MONERO_KEY_IMAGE);
  if (!s) return false;
  for (pb_size_t i = 0; i < request->subs_count; ++i) {
    const MoneroSubAddressIndicesList* list = &request->subs[i];
    if (!list->has_account || !list->minor_indices_count ||
        list->minor_indices_count > 8)
      goto failure;
    for (pb_size_t j = 0; j < list->minor_indices_count; ++j) {
      if (s->sub_count >= KEY_IMAGE_MAX_SUBADDRESSES) goto failure;
      s->subs[s->sub_count].major = list->account;
      s->subs[s->sub_count++].minor = list->minor_indices[j];
    }
  }
  if (!monero_wallet_secrets(node_key, s->spend, s->view) ||
      !random_buffer_checked(s->encryption_key, sizeof(s->encryption_key)))
    goto failure;
  memcpy(s->expected, request->hash.bytes, 32);
  s->count = (uint32_t)request->num;
  hasher_Init(&s->transcript, HASHER_SHA3K);
  s->started = getSysTime();
  signing_session_publish(SIGNING_SESSION_MONERO_KEY_IMAGE);
  return true;
failure:
  monero_session_abort();
  return false;
}

/* Finds the one-time secret x of `td` and checks x*G == out_key. */
static bool owned_output(const KeyImageSession* s,
                         const MoneroTransferDetails* td, bignum256modm secret,
                         ge25519* output) {
  struct {
    ge25519 tx, derivation, calculated;
    bignum256modm deriv_scalar, sub;
    uint8_t encoded[42];
  } tmp = {0};
  bool ok = false;
  if (!td->has_out_key || td->out_key.size != 32 || !td->has_tx_pub_key ||
      td->tx_pub_key.size != 32 || !td->has_internal_output_index ||
      td->internal_output_index > UINT32_MAX ||
      td->additional_tx_pub_keys_count > 16 ||
      (td->additional_tx_pub_keys_count > 1 &&
       td->internal_output_index >= td->additional_tx_pub_keys_count) ||
      td->has_sub_addr_major != td->has_sub_addr_minor ||
      !monero_decode_public(output, td->out_key.bytes) ||
      !monero_decode_public(&tmp.tx, td->tx_pub_key.bytes))
    goto done;
  for (pb_size_t i = 0; i < td->additional_tx_pub_keys_count; ++i)
    if (td->additional_tx_pub_keys[i].size != 32 ||
        !monero_decode_public(&tmp.tx, td->additional_tx_pub_keys[i].bytes))
      goto done;
  /* The output may be derived from R or from its additional key. */
  const unsigned derivations = td->additional_tx_pub_keys_count ? 2u : 1u;
  for (unsigned alternative = 0; alternative < derivations; ++alternative) {
    const uint8_t* tx = td->tx_pub_key.bytes;
    if (alternative) {
      const uint64_t index =
          td->additional_tx_pub_keys_count == 1 ? 0 : td->internal_output_index;
      tx = td->additional_tx_pub_keys[index].bytes;
    }
    if (!monero_decode_public(&tmp.tx, tx)) goto done;
    xmr_generate_key_derivation(&tmp.derivation, &tmp.tx, s->view);
    ge25519_pack(tmp.encoded, &tmp.derivation);
    const int n =
        xmr_write_varint(tmp.encoded + 32, 10, td->internal_output_index);
    if (n <= 0 || n > 10) goto done;
    monero_hash_scalar(tmp.deriv_scalar, tmp.encoded, 32u + (size_t)n);
    const unsigned candidates = td->has_sub_addr_major ? 1u : s->sub_count + 1u;
    for (unsigned i = 0; i < candidates; ++i) {
      uint32_t major = 0, minor = 0;
      if (td->has_sub_addr_major) {
        major = td->sub_addr_major;
        minor = td->sub_addr_minor;
      } else if (i) {
        major = s->subs[i - 1].major;
        minor = s->subs[i - 1].minor;
      }
      add256_modm(secret, tmp.deriv_scalar, s->spend);
      if (major || minor) {
        monero_subaddress_scalar(tmp.sub, s->view, major, minor);
        add256_modm(secret, secret, tmp.sub);
      }
      ge25519_scalarmult_base_wrapper(&tmp.calculated, secret);
      ge25519_pack(tmp.encoded, &tmp.calculated);
      if (!memcmp(tmp.encoded, td->out_key.bytes, 32)) {
        ok = true;
        goto done;
      }
    }
  }
done:
  memzero(&tmp, sizeof(tmp));
  if (!ok) memzero(secret, sizeof(bignum256modm));
  return ok;
}

/* Hedged nonce: k = Hs(domain || x || I || P || rng32). A weak RNG that
 * still passes its health checks cannot repeat k for different outputs. */
static bool hedged_nonce(bignum256modm nonce, const bignum256modm secret,
                         const uint8_t image[32], const uint8_t output[32]) {
  static const char domain[] = "KKXMR-ki-proof";
  uint8_t data[sizeof(domain) + 32 * 4] = {0};
  bool ok = false;
  memcpy(data, domain, sizeof(domain));
  uint8_t* p = data + sizeof(domain);
  contract256_modm(p, secret);
  memcpy(p + 32, image, 32);
  memcpy(p + 64, output, 32);
  if (random_buffer_checked(p + 96, 32)) {
    monero_hash_scalar(nonce, data, sizeof(data));
    ok = !iszero256_modm(nonce);
  }
  memzero(data, sizeof(data));
  if (!ok) memzero(nonce, sizeof(bignum256modm));
  return ok;
}

static bool export_one(KeyImageSession* s, const MoneroTransferDetails* td,
                       MoneroExportedKeyImage* exported) {
  struct {
    ge25519 output, image, hp, L, R;
    bignum256modm secret, nonce, challenge, response;
    uint8_t plaintext[96], transcript[96], td_hash[32], varint[10];
    Hasher hash;
    chacha20poly1305_ctx cipher;
  } tmp = {0};
  bool ok = false;
  if (!owned_output(s, td, tmp.secret, &tmp.output)) goto done;
  /* I = x * Hp(P). Then Core's one-member ring signature over I:
   * c = Hs(I || kG || kHp(P)), r = k - cx. */
  xmr_hash_to_ec(&tmp.hp, td->out_key.bytes, 32);
  ge25519_scalarmult(&tmp.image, &tmp.hp, tmp.secret);
  ge25519_pack(tmp.plaintext, &tmp.image);
  if (!hedged_nonce(tmp.nonce, tmp.secret, tmp.plaintext, td->out_key.bytes))
    goto done;
  ge25519_scalarmult_base_wrapper(&tmp.L, tmp.nonce);
  ge25519_scalarmult(&tmp.R, &tmp.hp, tmp.nonce);
  memcpy(tmp.transcript, tmp.plaintext, 32);
  ge25519_pack(tmp.transcript + 32, &tmp.L);
  ge25519_pack(tmp.transcript + 64, &tmp.R);
  monero_hash_scalar(tmp.challenge, tmp.transcript, sizeof(tmp.transcript));
  mulsub256_modm(tmp.response, tmp.challenge, tmp.secret, tmp.nonce);
  contract256_modm(tmp.plaintext + 32, tmp.challenge);
  contract256_modm(tmp.plaintext + 64, tmp.response);
  exported->has_iv = true;
  exported->iv.size = 12;
  exported->has_blob = true;
  exported->blob.size = 112;
  if (!random_buffer_checked(exported->iv.bytes, 12)) goto done;
  rfc7539_init(&tmp.cipher, s->encryption_key, exported->iv.bytes);
  chacha20poly1305_encrypt(&tmp.cipher, tmp.plaintext, exported->blob.bytes,
                           sizeof(tmp.plaintext));
  rfc7539_finish(&tmp.cipher, 0, sizeof(tmp.plaintext),
                 exported->blob.bytes + 96);
  /* Transcript item: Keccak(P || R || additional keys || varint(index)). */
  hasher_Init(&tmp.hash, HASHER_SHA3K);
  hasher_Update(&tmp.hash, td->out_key.bytes, 32);
  hasher_Update(&tmp.hash, td->tx_pub_key.bytes, 32);
  for (pb_size_t i = 0; i < td->additional_tx_pub_keys_count; ++i)
    hasher_Update(&tmp.hash, td->additional_tx_pub_keys[i].bytes, 32);
  const int n = xmr_write_varint(tmp.varint, sizeof(tmp.varint),
                                 td->internal_output_index);
  if (n <= 0 || n > 10) goto done;
  hasher_Update(&tmp.hash, tmp.varint, (size_t)n);
  hasher_Final(&tmp.hash, tmp.td_hash);
  hasher_Update(&s->transcript, tmp.td_hash, sizeof(tmp.td_hash));
  ok = true;
done:
  memzero(&tmp, sizeof(tmp));
  if (!ok) memzero(exported, sizeof(*exported));
  return ok;
}

bool monero_key_image_step(const MoneroKeyImageSyncStepRequest* request,
                           MoneroKeyImageSyncStepAck* response,
                           uint32_t* permil) {
  KeyImageSession* s = monero_key_image_active() ? session() : NULL;
  if (!s || !request || !response || !request->tdis_count ||
      request->tdis_count > 4 || request->tdis_count > s->count - s->processed)
    goto failure;
  response->kis_count = 0;
  for (pb_size_t i = 0; i < request->tdis_count; ++i) {
    if (!export_one(s, &request->tdis[i], &response->kis[i])) goto failure;
    ++response->kis_count;
    ++s->processed;
  }
  if (permil) *permil = s->processed * 1000u / s->count;
  return true;
failure:
  if (response) memzero(response, sizeof(*response));
  monero_session_abort();
  return false;
}

bool monero_key_image_finish(uint8_t encryption_key[32]) {
  uint8_t digest[32] = {0};
  KeyImageSession* s = monero_key_image_active() ? session() : NULL;
  bool ok = s && encryption_key && s->processed == s->count;
  if (ok) {
    hasher_Final(&s->transcript, digest);
    ok = memcmp(digest, s->expected, 32) == 0;
  }
  if (ok)
    memcpy(encryption_key, s->encryption_key, 32);
  else if (encryption_key)
    memzero(encryption_key, 32);
  memzero(digest, sizeof(digest));
  monero_session_abort();
  return ok;
}
