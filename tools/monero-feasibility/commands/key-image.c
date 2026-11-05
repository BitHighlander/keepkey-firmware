/* Native-emulator key-image synchronization, using the pinned Trezor wire
 * protocol. Only the final, correctly bound transcript releases the AEAD key.
 * This implementation supports the legacy/CLSAG biased key-image mapping. */
#include "key-image.h"
#if !USE_MONERO
#error "Monero key-image research requires the Monero crypto primitives"
#endif

#include <string.h>
#include "memzero.h"
#include "monero/monero.h"
#include "chacha20poly1305/rfc7539.h"
#include "keepkey/board/timer.h"
#include "keepkey/rand/rng_health.h"

typedef struct {
  bool active;
  uint32_t started;
  uint32_t count, processed;
  bignum256modm spend, view;
  uint8_t expected[32], encryption_key[32];
  Hasher transcript;
  uint32_t sub_count;
  struct { uint32_t major, minor; } subs[32];
} KeyImageSession;

static KeyImageSession CONFIDENTIAL session;
static const uint8_t identity[32] = {1};
static const uint8_t order_bytes[32] = {
  0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
  0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

void monero_key_image_abort(void) { memzero(&session, sizeof(session)); }

bool monero_key_image_active(void) {
  if (session.active && (uint32_t)(getSysTime() - session.started) > 120000u)
    monero_key_image_abort();
  return session.active;
}

bool monero_key_image_state_is_zero(void) {
  const uint8_t* bytes = (const uint8_t*)&session;
  uint8_t aggregate = 0;
  for (size_t i = 0; i < sizeof(session); ++i) aggregate |= bytes[i];
  return aggregate == 0;
}

static void private_hash_scalar(bignum256modm out, const uint8_t* bytes,
                                 size_t size) {
  Hasher hash = {0};
  uint8_t digest[32] = {0};
  hasher_Init(&hash, HASHER_SHA3K);
  hasher_Update(&hash, bytes, size);
  hasher_Final(&hash, digest);
  expand256_modm(out, digest, sizeof(digest));
  memzero(digest, sizeof(digest));
  memzero(&hash, sizeof(hash));
}

static bool random_scalar(bignum256modm out) {
  uint8_t wide[64] = {0};
  bool ok = false;
  for (unsigned tries = 0; tries < 3; ++tries) {
    if (!random_buffer_checked(wide, sizeof(wide))) break;
    expand256_modm(out, wide, sizeof(wide));
    if (!iszero256_modm(out)) { ok = true; break; }
  }
  memzero(wide, sizeof(wide));
  if (!ok) memzero(out, sizeof(bignum256modm));
  return ok;
}

/* Reject noncanonical encodings, identity and torsion before multiplying a
 * public input by a wallet secret. Decode helpers initialize all coordinates. */
static bool decode_public(ge25519* point, const uint8_t encoded[32]) {
  struct { ge25519 check; bignum256modm order; uint8_t canonical[32]; } tmp = {0};
  bool ok = false;
  ge25519_set_neutral(point);
  if (!ge25519_unpack_vartime(point, encoded)) goto done;
  ge25519_pack(tmp.canonical, point);
  if (memcmp(tmp.canonical, encoded, 32) || !memcmp(encoded, identity, 32)) goto done;
  expand_raw256_modm(tmp.order, order_bytes);
  ge25519_scalarmult(&tmp.check, point, tmp.order);
  ge25519_pack(tmp.canonical, &tmp.check);
  ok = memcmp(tmp.canonical, identity, 32) == 0;
done:
  memzero(&tmp, sizeof(tmp));
  return ok;
}

static void subaddress_scalar(bignum256modm out, uint32_t major, uint32_t minor) {
  uint8_t data[48] = {'S','u','b','A','d','d','r',0};
  contract256_modm(data + 8, session.view);
  for (unsigned j = 0; j < 4; ++j) {
    data[40+j] = (uint8_t)(major >> (8*j));
    data[44+j] = (uint8_t)(minor >> (8*j));
  }
  private_hash_scalar(out, data, sizeof(data));
  memzero(data, sizeof(data));
}

bool monero_key_image_begin(const uint8_t node_key[32],
                            const MoneroKeyImageExportInitRequest* request) {
  monero_key_image_abort();
  uint8_t spend_bytes[32] = {0};
  if (!node_key || !request || !request->has_num || !request->num ||
      request->num > MONERO_KEY_IMAGE_MAX_OUTPUTS || !request->has_hash ||
      request->hash.size != 32 ||
      request->subs_count > 4 ||
      (request->has_network_type && request->network_type > 2)) goto failure;
  for (pb_size_t i = 0; i < request->subs_count; ++i) {
    const MoneroSubAddressIndicesList* list = &request->subs[i];
    if (!list->has_account || !list->minor_indices_count || list->minor_indices_count > 8) goto failure;
    for (pb_size_t j = 0; j < list->minor_indices_count; ++j) {
      if (session.sub_count >= 32) goto failure;
      session.subs[session.sub_count].major = list->account;
      session.subs[session.sub_count++].minor = list->minor_indices[j];
    }
  }
  expand256_modm(session.spend, node_key, 32);
  if (iszero256_modm(session.spend)) goto failure;
  contract256_modm(spend_bytes, session.spend);
  private_hash_scalar(session.view, spend_bytes, sizeof(spend_bytes));
  if (iszero256_modm(session.view) ||
      !random_buffer_checked(session.encryption_key, sizeof(session.encryption_key))) goto failure;
  memcpy(session.expected, request->hash.bytes, 32);
  session.count = (uint32_t)request->num;
  hasher_Init(&session.transcript, HASHER_SHA3K);
  session.started = getSysTime();
  session.active = true;
  memzero(spend_bytes, sizeof(spend_bytes));
  return true;
failure:
  memzero(spend_bytes, sizeof(spend_bytes));
  monero_key_image_abort();
  return false;
}

static bool owned_output(const MoneroTransferDetails* td, bignum256modm secret,
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
      !decode_public(output, td->out_key.bytes) ||
      !decode_public(&tmp.tx, td->tx_pub_key.bytes)) goto done;
  for (pb_size_t i = 0; i < td->additional_tx_pub_keys_count; ++i)
    if (td->additional_tx_pub_keys[i].size != 32 ||
        !decode_public(&tmp.tx, td->additional_tx_pub_keys[i].bytes)) goto done;
  unsigned derivations = td->additional_tx_pub_keys_count ? 2u : 1u;
  for (unsigned alternative = 0; alternative < derivations; ++alternative) {
    const uint8_t* tx = td->tx_pub_key.bytes;
    if (alternative) {
      uint64_t index = td->additional_tx_pub_keys_count == 1 ? 0 : td->internal_output_index;
      if (index >= td->additional_tx_pub_keys_count) goto done;
      tx = td->additional_tx_pub_keys[index].bytes;
    }
    if (!decode_public(&tmp.tx, tx)) goto done;
    xmr_generate_key_derivation(&tmp.derivation, &tmp.tx, session.view);
    ge25519_pack(tmp.encoded, &tmp.derivation);
    int n = xmr_write_varint(tmp.encoded + 32, 10, td->internal_output_index);
    if (n <= 0 || n > 10) goto done;
    private_hash_scalar(tmp.deriv_scalar, tmp.encoded, 32u + (size_t)n);
    unsigned candidates = td->has_sub_addr_major ? 1u : session.sub_count + 1u;
    for (unsigned i = 0; i < candidates; ++i) {
      uint32_t major = 0, minor = 0;
      if (td->has_sub_addr_major) { major = td->sub_addr_major; minor = td->sub_addr_minor; }
      else if (i) { major = session.subs[i-1].major; minor = session.subs[i-1].minor; }
      add256_modm(secret, tmp.deriv_scalar, session.spend);
      if (major || minor) {
        subaddress_scalar(tmp.sub, major, minor);
        add256_modm(secret, secret, tmp.sub);
      }
      ge25519_scalarmult_base_wrapper(&tmp.calculated, secret);
      ge25519_pack(tmp.encoded, &tmp.calculated);
      if (!memcmp(tmp.encoded, td->out_key.bytes, 32)) { ok = true; goto done; }
    }
  }
done:
  memzero(&tmp, sizeof(tmp));
  if (!ok) memzero(secret, sizeof(bignum256modm));
  return ok;
}

static bool export_one(const MoneroTransferDetails* td, MoneroExportedKeyImage* exported) {
  struct {
    ge25519 output, image, hp, L, R;
    bignum256modm secret, nonce, challenge, response;
    uint8_t plaintext[96], transcript[96], td_hash[32], varint[10];
    Hasher hash;
    chacha20poly1305_ctx cipher;
  } tmp = {0};
  bool ok = false;
  if (!owned_output(td, tmp.secret, &tmp.output)) goto done;
  xmr_hash_to_ec(&tmp.hp, td->out_key.bytes, 32);
  ge25519_scalarmult(&tmp.image, &tmp.hp, tmp.secret);
  ge25519_pack(tmp.plaintext, &tmp.image);
  if (!random_scalar(tmp.nonce)) goto done;
  ge25519_scalarmult_base_wrapper(&tmp.L, tmp.nonce);
  ge25519_scalarmult(&tmp.R, &tmp.hp, tmp.nonce);
  memcpy(tmp.transcript, tmp.plaintext, 32);
  ge25519_pack(tmp.transcript + 32, &tmp.L);
  ge25519_pack(tmp.transcript + 64, &tmp.R);
  private_hash_scalar(tmp.challenge, tmp.transcript, sizeof(tmp.transcript));
  mulsub256_modm(tmp.response, tmp.challenge, tmp.secret, tmp.nonce);
  contract256_modm(tmp.plaintext + 32, tmp.challenge);
  contract256_modm(tmp.plaintext + 64, tmp.response);
  exported->has_iv = true; exported->iv.size = 12;
  exported->has_blob = true; exported->blob.size = 112;
  if (!random_buffer_checked(exported->iv.bytes, 12)) goto done;
  rfc7539_init(&tmp.cipher, session.encryption_key, exported->iv.bytes);
  chacha20poly1305_encrypt(&tmp.cipher, tmp.plaintext, exported->blob.bytes, sizeof(tmp.plaintext));
  rfc7539_finish(&tmp.cipher, 0, sizeof(tmp.plaintext), exported->blob.bytes + 96);
  hasher_Init(&tmp.hash, HASHER_SHA3K);
  hasher_Update(&tmp.hash, td->out_key.bytes, 32);
  hasher_Update(&tmp.hash, td->tx_pub_key.bytes, 32);
  for (pb_size_t i = 0; i < td->additional_tx_pub_keys_count; ++i)
    hasher_Update(&tmp.hash, td->additional_tx_pub_keys[i].bytes, 32);
  int n = xmr_write_varint(tmp.varint, sizeof(tmp.varint), td->internal_output_index);
  if (n <= 0 || n > 10) goto done;
  hasher_Update(&tmp.hash, tmp.varint, (size_t)n);
  hasher_Final(&tmp.hash, tmp.td_hash);
  hasher_Update(&session.transcript, tmp.td_hash, sizeof(tmp.td_hash));
  ok = true;
done:
  memzero(&tmp, sizeof(tmp));
  if (!ok) memzero(exported, sizeof(*exported));
  return ok;
}

bool monero_key_image_step(const MoneroKeyImageSyncStepRequest* request,
                           MoneroKeyImageSyncStepAck* response) {
  if (!monero_key_image_active() || !request || !response || !request->tdis_count ||
      request->tdis_count > 4 || request->tdis_count > session.count - session.processed) goto failure;
  response->kis_count = 0;
  for (pb_size_t i = 0; i < request->tdis_count; ++i) {
    if (!export_one(&request->tdis[i], &response->kis[i])) goto failure;
    ++response->kis_count;
    ++session.processed;
  }
  return true;
failure:
  if (response) memzero(response, sizeof(*response));
  monero_key_image_abort();
  return false;
}

bool monero_key_image_finish(uint8_t encryption_key[32]) {
  uint8_t digest[32] = {0};
  bool ok = monero_key_image_active() && encryption_key && session.processed == session.count;
  if (ok) {
    hasher_Final(&session.transcript, digest);
    ok = memcmp(digest, session.expected, 32) == 0;
  }
  if (ok) memcpy(encryption_key, session.encryption_key, 32);
  else if (encryption_key) memzero(encryption_key, 32);
  memzero(digest, sizeof(digest));
  monero_key_image_abort();
  return ok;
}
