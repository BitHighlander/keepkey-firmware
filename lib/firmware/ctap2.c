#include "keepkey/firmware/ctap2.h"

#include "keepkey/firmware/ctap2/cbor.h"
#include "keepkey/board/common.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memcmp_s.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/u2f.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/nist256p1.h"
#include "trezor/crypto/rand.h"
#include "trezor/crypto/sha2.h"

#include <string.h>

/* Development AAGUID for KeepKey's built-in authenticator. Production must
 * use the AAGUID recorded in FIDO Metadata Service. */
static const uint8_t KEEPKEY_AAGUID[16] = {
    0x4b, 0x65, 0x65, 0x70, 0x4b, 0x65, 0x79, 0x2d,
    0x80, 0x00, 0x46, 0x49, 0x44, 0x4f, 0x32, 0x00,
};

typedef struct {
  uint8_t private_key[32];
  uint8_t public_key[65];
  bool valid;
} KeyAgreement;

static CONFIDENTIAL KeyAgreement key_agreement;
static CONFIDENTIAL uint8_t pin_token[32];
static bool pin_token_valid;
static uint8_t pin_attempts_since_boot;
static uint32_t reset_deadline;
static uint32_t transport_channel;

typedef struct {
  bool valid;
  bool uv_verified;
  bool up_verified;
  uint8_t count;
  uint8_t next;
  uint32_t deadline;
  uint32_t channel;
  uint8_t slots[PASSKEY_MAX_DISCOVERABLE_CREDENTIALS];
  uint8_t rp_id_hash[32];
  uint8_t client_data_hash[32];
} AssertionSequence;

static AssertionSequence assertion_sequence;

static bool encode_authenticator_data(uint8_t* output, size_t capacity,
                                      size_t* length,
                                      const uint8_t rp_id_hash[32],
                                      uint8_t flags, uint32_t counter,
                                      const uint8_t* credential_id,
                                      const uint8_t public_key[65]);

void ctap2_init(void) {
  reset_deadline = getSysTime() + 10000;
  memzero(pin_token, sizeof(pin_token));
  memzero(&key_agreement, sizeof(key_agreement));
  pin_token_valid = false;
  pin_attempts_since_boot = 0;
  transport_channel = 0;
  memzero(&assertion_sequence, sizeof(assertion_sequence));
}

void ctap2_set_transport_channel(uint32_t channel) {
  transport_channel = channel;
}

static bool map_find(const uint8_t* buffer, size_t length, int64_t wanted,
                     CborValue* value, const uint8_t** slice,
                     size_t* slice_length) {
  CborDecoder decoder;
  CborValue map;
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &map) || map.type != CBOR_TYPE_MAP)
    return false;
  for (uint64_t i = 0; i < map.value; ++i) {
    CborValue key;
    if (!cbor_decode_value(&decoder, &key)) return false;
    int64_t decoded_key;
    if (key.type == CBOR_TYPE_UINT && key.value <= INT64_MAX)
      decoded_key = (int64_t)key.value;
    else if (key.type == CBOR_TYPE_NEGINT && key.value <= INT64_MAX)
      decoded_key = -1 - (int64_t)key.value;
    else
      return false;

    size_t start = decoder.offset;
    if (!cbor_skip_value(&decoder)) return false;
    if (decoded_key == wanted) {
      CborDecoder item;
      cbor_decoder_init(&item, buffer + start, decoder.offset - start);
      if (!cbor_decode_value(&item, value)) return false;
      if (slice != NULL) *slice = buffer + start;
      if (slice_length != NULL) *slice_length = decoder.offset - start;
      return true;
    }
  }
  return false;
}

static bool valid_request_map(const uint8_t* buffer, size_t length) {
  CborDecoder decoder;
  CborValue map;
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &map) || map.type != CBOR_TYPE_MAP)
    return false;
  uint64_t previous = 0;
  bool have_previous = false;
  for (uint64_t i = 0; i < map.value; ++i) {
    CborValue key;
    if (!cbor_decode_value(&decoder, &key) || key.type != CBOR_TYPE_UINT ||
        (have_previous && key.value <= previous) || !cbor_skip_value(&decoder))
      return false;
    previous = key.value;
    have_previous = true;
  }
  return decoder.offset == decoder.length;
}

static bool map_find_text(const uint8_t* buffer, size_t length,
                          const char* wanted, CborValue* value,
                          const uint8_t** slice, size_t* slice_length) {
  CborDecoder decoder;
  CborValue map;
  const size_t wanted_length = strlen(wanted);
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &map) || map.type != CBOR_TYPE_MAP)
    return false;
  for (uint64_t i = 0; i < map.value; ++i) {
    CborValue key;
    if (!cbor_decode_value(&decoder, &key) || key.type != CBOR_TYPE_TEXT)
      return false;
    size_t start = decoder.offset;
    if (!cbor_skip_value(&decoder)) return false;
    if (key.length == wanted_length &&
        memcmp(key.data, wanted, wanted_length) == 0) {
      CborDecoder item;
      cbor_decoder_init(&item, buffer + start, decoder.offset - start);
      if (!cbor_decode_value(&item, value)) return false;
      if (slice != NULL) *slice = buffer + start;
      if (slice_length != NULL) *slice_length = decoder.offset - start;
      return true;
    }
  }
  return false;
}

static bool cbor_bool(const CborValue* value, bool* result) {
  if (value->type != CBOR_TYPE_SIMPLE ||
      (value->value != 20 && value->value != 21))
    return false;
  *result = value->value == 21;
  return true;
}

static bool copy_text(const CborValue* value, char* destination,
                      size_t capacity) {
  if (value->type != CBOR_TYPE_TEXT || value->length == 0 ||
      value->length >= capacity ||
      memchr(value->data, 0, value->length) != NULL)
    return false;
  memcpy(destination, value->data, value->length);
  destination[value->length] = 0;
  return true;
}

static void write_error(uint8_t error, uint8_t* response, size_t* length) {
  response[0] = error;
  *length = 1;
}

static bool encode_cose_public_key(CborEncoder* encoder,
                                   const uint8_t public_key[65]) {
  return cbor_encode_map(encoder, 5) && cbor_encode_int(encoder, 1) &&
         cbor_encode_int(encoder, 2) && cbor_encode_int(encoder, 3) &&
         cbor_encode_int(encoder, -7) && cbor_encode_int(encoder, -1) &&
         cbor_encode_int(encoder, 1) && cbor_encode_int(encoder, -2) &&
         cbor_encode_bytes(encoder, public_key + 1, 32) &&
         cbor_encode_int(encoder, -3) &&
         cbor_encode_bytes(encoder, public_key + 33, 32);
}

static void generate_key_agreement(void) {
  random_buffer(key_agreement.private_key, sizeof(key_agreement.private_key));
  ecdsa_get_public_key65(&nist256p1, key_agreement.private_key,
                         key_agreement.public_key);
  key_agreement.valid = true;
}

static bool decode_cose_public_key(const uint8_t* buffer, size_t length,
                                   uint8_t public_key[65]) {
  CborValue x, y;
  if (!map_find(buffer, length, -2, &x, NULL, NULL) ||
      !map_find(buffer, length, -3, &y, NULL, NULL) ||
      x.type != CBOR_TYPE_BYTES || y.type != CBOR_TYPE_BYTES ||
      x.length != 32 || y.length != 32)
    return false;
  public_key[0] = 0x04;
  memcpy(public_key + 1, x.data, 32);
  memcpy(public_key + 33, y.data, 32);
  return true;
}

static bool shared_secret_from_request(const uint8_t* buffer, size_t length,
                                       uint8_t shared_secret[32]) {
  CborValue value;
  const uint8_t* key_slice;
  size_t key_length;
  uint8_t peer_key[65];
  uint8_t session_key[65];
  if (!key_agreement.valid ||
      !map_find(buffer, length, 3, &value, &key_slice, &key_length) ||
      value.type != CBOR_TYPE_MAP ||
      !decode_cose_public_key(key_slice, key_length, peer_key) ||
      ecdh_multiply(&nist256p1, key_agreement.private_key, peer_key,
                    session_key) != 0)
    return false;
  sha256_Raw(session_key + 1, 32, shared_secret);
  memzero(peer_key, sizeof(peer_key));
  memzero(session_key, sizeof(session_key));
  return true;
}

static void aes256_cbc(bool encrypt, const uint8_t key[32],
                       const uint8_t* input, uint8_t* output, size_t length) {
  uint8_t iv[16] = {0};
  if (encrypt) {
    aes_encrypt_ctx context;
    aes_encrypt_key256(key, &context);
    aes_cbc_encrypt(input, output, length, iv, &context);
    memzero(&context, sizeof(context));
  } else {
    aes_decrypt_ctx context;
    aes_decrypt_key256(key, &context);
    aes_cbc_decrypt(input, output, length, iv, &context);
    memzero(&context, sizeof(context));
  }
}

static void passkey_pin_digest(const uint8_t* pin, size_t pin_length,
                               const uint8_t salt[16], uint8_t digest[32]) {
  uint8_t device_secret[HW_ENTROPY_LEN];
  uint8_t material[16 + 63];
  flash_readHWEntropy(device_secret, sizeof(device_secret));
  memcpy(material, salt, 16);
  memcpy(material + 16, pin, pin_length);
  hmac_sha256(device_secret, sizeof(device_secret), material, 16 + pin_length,
              digest);
  memzero(device_secret, sizeof(device_secret));
  memzero(material, sizeof(material));
}

static bool valid_pin_auth(const uint8_t shared_secret[32],
                           const uint8_t* message, size_t message_length,
                           const CborValue* pin_auth) {
  uint8_t authentication[32];
  if (pin_auth->type != CBOR_TYPE_BYTES || pin_auth->length != 16) return false;
  hmac_sha256(shared_secret, 32, message, message_length, authentication);
  bool valid = memcmp_s(authentication, pin_auth->data, 16) == 0;
  memzero(authentication, sizeof(authentication));
  return valid;
}

static bool request_has_es256(const uint8_t* buffer, size_t length) {
  CborDecoder decoder;
  CborValue array;
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &array) || array.type != CBOR_TYPE_ARRAY)
    return false;
  for (uint64_t i = 0; i < array.value; ++i) {
    const size_t start = decoder.offset;
    if (!cbor_skip_value(&decoder)) return false;
    CborValue alg, type;
    if (map_find_text(buffer + start, decoder.offset - start, "alg", &alg, NULL,
                      NULL) &&
        map_find_text(buffer + start, decoder.offset - start, "type", &type,
                      NULL, NULL) &&
        alg.type == CBOR_TYPE_NEGINT && alg.value == 6 &&
        type.type == CBOR_TYPE_TEXT && type.length == 10 &&
        memcmp(type.data, "public-key", 10) == 0)
      return true; /* -1 - 6 == -7 (ES256) */
  }
  return false;
}

static uint8_t parse_options(const uint8_t* buffer, size_t length,
                             bool make_credential, bool* rk, bool* uv,
                             bool* up) {
  CborDecoder decoder;
  CborValue map;
  *rk = false;
  *uv = false;
  *up = true;
  bool seen_rk = false, seen_uv = false, seen_up = false;
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &map) || map.type != CBOR_TYPE_MAP)
    return CTAP2_ERR_INVALID_CBOR;
  for (uint64_t i = 0; i < map.value; ++i) {
    CborValue key, value;
    if (!cbor_decode_value(&decoder, &key) || key.type != CBOR_TYPE_TEXT)
      return CTAP2_ERR_INVALID_CBOR;
    const size_t value_start = decoder.offset;
    if (!cbor_decode_value(&decoder, &value)) return CTAP2_ERR_INVALID_CBOR;
    bool* destination = NULL;
    bool* seen = NULL;
    if (key.length == 2 && memcmp(key.data, "rk", 2) == 0) {
      if (!make_credential) return CTAP2_ERR_INVALID_OPTION;
      destination = rk;
      seen = &seen_rk;
    } else if (key.length == 2 && memcmp(key.data, "uv", 2) == 0) {
      destination = uv;
      seen = &seen_uv;
    } else if (key.length == 2 && memcmp(key.data, "up", 2) == 0) {
      if (make_credential) return CTAP2_ERR_INVALID_OPTION;
      destination = up;
      seen = &seen_up;
    }
    if (destination != NULL) {
      if (*seen || !cbor_bool(&value, destination))
        return CTAP2_ERR_INVALID_CBOR;
      *seen = true;
    } else if (value.type == CBOR_TYPE_ARRAY || value.type == CBOR_TYPE_MAP) {
      /* The value head was consumed above; skip its children. */
      decoder.offset = value_start;
      if (!cbor_skip_value(&decoder)) return CTAP2_ERR_INVALID_CBOR;
    }
  }
  return CTAP2_OK;
}

static uint8_t verify_pin_uv(const uint8_t* request, size_t request_length,
                             int auth_key, int protocol_key,
                             const uint8_t client_data_hash[32],
                             bool uv_requested, bool require_pin_when_set,
                             bool* verified) {
  CborValue auth, protocol;
  *verified = false;
  bool have_auth =
      map_find(request, request_length, auth_key, &auth, NULL, NULL);
  bool have_protocol =
      map_find(request, request_length, protocol_key, &protocol, NULL, NULL);
  if (!have_auth && !have_protocol) {
    PasskeyStorage storage;
    storage_getPasskeyData(&storage);
    if (storage.pin_set && (uv_requested || require_pin_when_set))
      return CTAP2_ERR_PIN_REQUIRED;
    if (uv_requested) return CTAP2_ERR_PIN_NOT_SET;
    return CTAP2_OK;
  }
  if (!have_auth || !have_protocol || protocol.type != CBOR_TYPE_UINT ||
      protocol.value != 1 || auth.type != CBOR_TYPE_BYTES ||
      auth.length != 16 || !pin_token_valid)
    return CTAP2_ERR_PIN_AUTH_INVALID;
  uint8_t expected[32];
  hmac_sha256(pin_token, sizeof(pin_token), client_data_hash, 32, expected);
  bool matches = memcmp_s(expected, auth.data, 16) == 0;
  memzero(expected, sizeof(expected));
  if (!matches) return CTAP2_ERR_PIN_AUTH_INVALID;
  *verified = true;
  return CTAP2_OK;
}

static bool credential_list_contains(const uint8_t* buffer, size_t length,
                                     const uint8_t rp_id_hash[32],
                                     uint8_t credential_id[64]) {
  CborDecoder decoder;
  CborValue array;
  cbor_decoder_init(&decoder, buffer, length);
  if (!cbor_decode_value(&decoder, &array) || array.type != CBOR_TYPE_ARRAY)
    return false;
  for (uint64_t i = 0; i < array.value; ++i) {
    size_t start = decoder.offset;
    if (!cbor_skip_value(&decoder)) return false;
    CborValue id, type;
    if (map_find_text(buffer + start, decoder.offset - start, "id", &id, NULL,
                      NULL) &&
        map_find_text(buffer + start, decoder.offset - start, "type", &type,
                      NULL, NULL) &&
        id.type == CBOR_TYPE_BYTES && id.length == 64 &&
        type.type == CBOR_TYPE_TEXT && type.length == 10 &&
        memcmp(type.data, "public-key", 10) == 0) {
      uint8_t private_key[32], public_key[65];
      bool valid =
          u2f_load_credential(rp_id_hash, id.data, private_key, public_key);
      memzero(private_key, sizeof(private_key));
      memzero(public_key, sizeof(public_key));
      if (valid) {
        memcpy(credential_id, id.data, 64);
        return true;
      }
    }
  }
  return false;
}

static int store_discoverable_credential(const uint8_t rp_id_hash[32],
                                         const uint8_t* user_id,
                                         size_t user_id_length,
                                         const char* user_name,
                                         const uint8_t credential_id[64]) {
  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  int slot = -1;
  for (size_t i = 0; i < PASSKEY_MAX_DISCOVERABLE_CREDENTIALS; ++i) {
    const PasskeyCredential* candidate = &storage.credentials[i];
    if (candidate->occupied &&
        memcmp(candidate->rp_id_hash, rp_id_hash, 32) == 0 &&
        candidate->user_id_length == user_id_length &&
        memcmp(candidate->user_id, user_id, user_id_length) == 0) {
      slot = (int)i;
      break;
    }
    if (!candidate->occupied && slot < 0) slot = (int)i;
  }
  if (slot < 0) return -1;
  PasskeyCredential* credential = &storage.credentials[slot];
  memzero(credential, sizeof(*credential));
  credential->occupied = 1;
  credential->user_id_length = (uint8_t)user_id_length;
  memcpy(credential->rp_id_hash, rp_id_hash, 32);
  memcpy(credential->credential_id, credential_id, 64);
  memcpy(credential->user_id, user_id, user_id_length);
  strlcpy(credential->user_name, user_name, sizeof(credential->user_name));
  storage_setPasskeyData(&storage);
  return slot;
}

static int find_discoverable_credential(const uint8_t rp_id_hash[32],
                                        PasskeyCredential* credential) {
  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  int count = 0;
  for (size_t i = 0; i < PASSKEY_MAX_DISCOVERABLE_CREDENTIALS; ++i) {
    if (storage.credentials[i].occupied &&
        memcmp(storage.credentials[i].rp_id_hash, rp_id_hash, 32) == 0) {
      if (count == 0) *credential = storage.credentials[i];
      assertion_sequence.slots[count] = (uint8_t)i;
      ++count;
    }
  }
  return count;
}

static void encode_assertion_response(const PasskeyCredential* resident,
                                      const uint8_t rp_id_hash[32],
                                      const uint8_t client_data_hash[32],
                                      bool up_verified, bool uv_verified,
                                      uint8_t number_of_credentials,
                                      uint8_t* response, size_t capacity,
                                      size_t* response_length) {
  uint8_t private_key[32], public_key[65];
  if (!u2f_load_credential(rp_id_hash, resident->credential_id, private_key,
                           public_key)) {
    write_error(CTAP2_ERR_NO_CREDENTIALS, response, response_length);
    return;
  }
  uint8_t auth_data[37], signature_base[69], signature[64], der[72];
  size_t auth_length;
  const uint32_t counter = storage_nextU2FCounter();
  encode_authenticator_data(
      auth_data, sizeof(auth_data), &auth_length, rp_id_hash,
      (up_verified ? 0x01 : 0) | (uv_verified ? 0x04 : 0), counter, NULL, NULL);
  memcpy(signature_base, auth_data, auth_length);
  memcpy(signature_base + auth_length, client_data_hash, 32);
  if (ecdsa_sign(&nist256p1, HASHER_SHA2, private_key, signature_base,
                 sizeof(signature_base), signature, NULL, NULL) != 0) {
    memzero(private_key, sizeof(private_key));
    write_error(CTAP2_ERR_OTHER, response, response_length);
    return;
  }
  const size_t der_length = ecdsa_sig_to_der(signature, der);
  response[0] = CTAP2_OK;
  CborEncoder encoder;
  cbor_encoder_init(&encoder, response + 1, capacity - 1);
  cbor_encode_map(&encoder, number_of_credentials > 1 ? 5 : 4);
  cbor_encode_uint(&encoder, 1);
  cbor_encode_map(&encoder, 2);
  cbor_encode_text(&encoder, "id", 2);
  cbor_encode_bytes(&encoder, resident->credential_id,
                    sizeof(resident->credential_id));
  cbor_encode_text(&encoder, "type", 4);
  cbor_encode_text(&encoder, "public-key", 10);
  cbor_encode_uint(&encoder, 2);
  cbor_encode_bytes(&encoder, auth_data, sizeof(auth_data));
  cbor_encode_uint(&encoder, 3);
  cbor_encode_bytes(&encoder, der, der_length);
  cbor_encode_uint(&encoder, 4);
  cbor_encode_map(&encoder, uv_verified ? 2 : 1);
  cbor_encode_text(&encoder, "id", 2);
  cbor_encode_bytes(&encoder, resident->user_id, resident->user_id_length);
  if (uv_verified) {
    cbor_encode_text(&encoder, "name", 4);
    cbor_encode_text(&encoder, resident->user_name,
                     strnlen(resident->user_name, sizeof(resident->user_name)));
  }
  if (number_of_credentials > 1) {
    cbor_encode_uint(&encoder, 5);
    cbor_encode_uint(&encoder, number_of_credentials);
  }
  const size_t encoded = cbor_encoder_size(&encoder);
  *response_length = encoded == 0 ? 1 : encoded + 1;
  if (encoded == 0) response[0] = CTAP2_ERR_OTHER;
  memzero(private_key, sizeof(private_key));
  memzero(signature_base, sizeof(signature_base));
  memzero(signature, sizeof(signature));
}

static void get_next_assertion(uint8_t* response, size_t capacity,
                               size_t* response_length) {
  if (!assertion_sequence.valid ||
      assertion_sequence.next >= assertion_sequence.count ||
      assertion_sequence.channel != transport_channel ||
      (int32_t)(assertion_sequence.deadline - getSysTime()) <= 0) {
    memzero(&assertion_sequence, sizeof(assertion_sequence));
    write_error(CTAP2_ERR_NOT_ALLOWED, response, response_length);
    return;
  }
  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  const uint8_t slot = assertion_sequence.slots[assertion_sequence.next++];
  if (slot >= PASSKEY_MAX_DISCOVERABLE_CREDENTIALS ||
      !storage.credentials[slot].occupied) {
    memzero(&assertion_sequence, sizeof(assertion_sequence));
    write_error(CTAP2_ERR_NOT_ALLOWED, response, response_length);
    return;
  }
  encode_assertion_response(
      &storage.credentials[slot], assertion_sequence.rp_id_hash,
      assertion_sequence.client_data_hash, assertion_sequence.up_verified,
      assertion_sequence.uv_verified, 0, response, capacity, response_length);
  assertion_sequence.deadline = getSysTime() + 30000;
  if (assertion_sequence.next >= assertion_sequence.count)
    assertion_sequence.valid = false;
}

static bool encode_authenticator_data(uint8_t* output, size_t capacity,
                                      size_t* length,
                                      const uint8_t rp_id_hash[32],
                                      uint8_t flags, uint32_t counter,
                                      const uint8_t* credential_id,
                                      const uint8_t public_key[65]) {
  if (capacity < 37) return false;
  memcpy(output, rp_id_hash, 32);
  output[32] = flags;
  output[33] = (uint8_t)(counter >> 24);
  output[34] = (uint8_t)(counter >> 16);
  output[35] = (uint8_t)(counter >> 8);
  output[36] = (uint8_t)counter;
  *length = 37;
  if (credential_id == NULL) return true;
  if (capacity < *length + 16 + 2 + 64) return false;
  memcpy(output + *length, KEEPKEY_AAGUID, 16);
  *length += 16;
  output[(*length)++] = 0;
  output[(*length)++] = 64;
  memcpy(output + *length, credential_id, 64);
  *length += 64;
  CborEncoder key;
  cbor_encoder_init(&key, output + *length, capacity - *length);
  if (!encode_cose_public_key(&key, public_key)) return false;
  *length += cbor_encoder_size(&key);
  return true;
}

static void make_credential(const uint8_t* request, size_t request_length,
                            uint8_t* response, size_t capacity,
                            size_t* response_length) {
  CborValue client_hash, rp, user, algorithms, value;
  const uint8_t *rp_slice, *user_slice, *algorithm_slice;
  size_t rp_length, user_length, algorithm_length;
  if (!map_find(request, request_length, 1, &client_hash, NULL, NULL) ||
      client_hash.type != CBOR_TYPE_BYTES || client_hash.length != 32 ||
      !map_find(request, request_length, 2, &rp, &rp_slice, &rp_length) ||
      rp.type != CBOR_TYPE_MAP ||
      !map_find(request, request_length, 3, &user, &user_slice, &user_length) ||
      user.type != CBOR_TYPE_MAP ||
      !map_find(request, request_length, 4, &algorithms, &algorithm_slice,
                &algorithm_length) ||
      algorithms.type != CBOR_TYPE_ARRAY) {
    write_error(CTAP2_ERR_MISSING_PARAMETER, response, response_length);
    return;
  }
  if (!request_has_es256(algorithm_slice, algorithm_length)) {
    write_error(CTAP2_ERR_UNSUPPORTED_ALGORITHM, response, response_length);
    return;
  }

  char rp_id[254], user_name[PASSKEY_USER_NAME_MAX];
  if (!map_find_text(rp_slice, rp_length, "id", &value, NULL, NULL) ||
      !copy_text(&value, rp_id, sizeof(rp_id))) {
    write_error(CTAP2_ERR_MISSING_PARAMETER, response, response_length);
    return;
  }
  CborValue user_id;
  if (!map_find_text(user_slice, user_length, "id", &user_id, NULL, NULL) ||
      user_id.type != CBOR_TYPE_BYTES || user_id.length == 0 ||
      user_id.length > PASSKEY_USER_ID_MAX) {
    write_error(CTAP2_ERR_MISSING_PARAMETER, response, response_length);
    return;
  }
  user_name[0] = 0;
  if (map_find_text(user_slice, user_length, "name", &value, NULL, NULL) &&
      value.type == CBOR_TYPE_TEXT) {
    size_t copy = value.length < sizeof(user_name) - 1 ? value.length
                                                       : sizeof(user_name) - 1;
    memcpy(user_name, value.data, copy);
    user_name[copy] = 0;
  }

  bool resident = false, uv_requested = false, ignored_up;
  const uint8_t* options_slice;
  size_t options_length;
  if (map_find(request, request_length, 7, &value, &options_slice,
               &options_length)) {
    uint8_t options_status =
        value.type == CBOR_TYPE_MAP
            ? parse_options(options_slice, options_length, true, &resident,
                            &uv_requested, &ignored_up)
            : CTAP2_ERR_INVALID_CBOR;
    if (options_status != CTAP2_OK) {
      write_error(options_status, response, response_length);
      return;
    }
  }
  bool uv_verified;
  uint8_t uv_status =
      verify_pin_uv(request, request_length, 8, 9, client_hash.data,
                    uv_requested, true, &uv_verified);
  if (uv_status != CTAP2_OK) {
    write_error(uv_status, response, response_length);
    return;
  }

  uint8_t rp_id_hash[32], credential_id[64], private_key[32], public_key[65];
  sha256_Raw((const uint8_t*)rp_id, strlen(rp_id), rp_id_hash);
  const uint8_t* exclude_slice;
  size_t exclude_length;
  if (map_find(request, request_length, 5, &value, &exclude_slice,
               &exclude_length)) {
    if (value.type != CBOR_TYPE_ARRAY) {
      write_error(CTAP2_ERR_INVALID_CBOR, response, response_length);
      return;
    }
    if (credential_list_contains(exclude_slice, exclude_length, rp_id_hash,
                                 credential_id)) {
      if (!ctap2_request_user_presence(rp_id, true)) {
        write_error(ctap2_user_presence_was_cancelled()
                        ? CTAP2_ERR_KEEPALIVE_CANCEL
                        : CTAP2_ERR_USER_ACTION_TIMEOUT,
                    response, response_length);
        return;
      }
      write_error(CTAP2_ERR_CREDENTIAL_EXCLUDED, response, response_length);
      return;
    }
  }
  if (!ctap2_request_user_presence(rp_id, true)) {
    write_error(ctap2_user_presence_was_cancelled()
                    ? CTAP2_ERR_KEEPALIVE_CANCEL
                    : CTAP2_ERR_USER_ACTION_TIMEOUT,
                response, response_length);
    return;
  }
  if (!u2f_generate_credential(rp_id_hash, credential_id, private_key,
                               public_key)) {
    write_error(CTAP2_ERR_OTHER, response, response_length);
    return;
  }
  if (resident &&
      store_discoverable_credential(rp_id_hash, user_id.data, user_id.length,
                                    user_name, credential_id) < 0) {
    memzero(private_key, sizeof(private_key));
    write_error(CTAP2_ERR_KEY_STORE_FULL, response, response_length);
    return;
  }

  uint8_t auth_data[256], signature_base[288], signature[64], der[72];
  size_t auth_length;
  if (!encode_authenticator_data(auth_data, sizeof(auth_data), &auth_length,
                                 rp_id_hash,
                                 0x01 | 0x40 | (uv_verified ? 0x04 : 0), 0,
                                 credential_id, public_key)) {
    write_error(CTAP2_ERR_OTHER, response, response_length);
    return;
  }
  memcpy(signature_base, auth_data, auth_length);
  memcpy(signature_base + auth_length, client_hash.data, 32);
  if (ecdsa_sign(&nist256p1, HASHER_SHA2, private_key, signature_base,
                 auth_length + 32, signature, NULL, NULL) != 0) {
    memzero(private_key, sizeof(private_key));
    write_error(CTAP2_ERR_OTHER, response, response_length);
    return;
  }
  size_t der_length = ecdsa_sig_to_der(signature, der);
  response[0] = CTAP2_OK;
  CborEncoder encoder;
  cbor_encoder_init(&encoder, response + 1, capacity - 1);
  cbor_encode_map(&encoder, 3);
  cbor_encode_uint(&encoder, 1);
  cbor_encode_text(&encoder, "packed", 6);
  cbor_encode_uint(&encoder, 2);
  cbor_encode_bytes(&encoder, auth_data, auth_length);
  cbor_encode_uint(&encoder, 3);
  cbor_encode_map(&encoder, 2);
  cbor_encode_text(&encoder, "alg", 3);
  cbor_encode_int(&encoder, -7);
  cbor_encode_text(&encoder, "sig", 3);
  cbor_encode_bytes(&encoder, der, der_length);
  size_t encoded = cbor_encoder_size(&encoder);
  *response_length = encoded == 0 ? 1 : encoded + 1;
  if (encoded == 0) response[0] = CTAP2_ERR_OTHER;
  memzero(private_key, sizeof(private_key));
  memzero(signature_base, sizeof(signature_base));
  memzero(signature, sizeof(signature));
}

static void get_assertion(const uint8_t* request, size_t request_length,
                          uint8_t* response, size_t capacity,
                          size_t* response_length) {
  CborValue rp_id_value, client_hash, value;
  char rp_id[254];
  if (!map_find(request, request_length, 1, &rp_id_value, NULL, NULL) ||
      !copy_text(&rp_id_value, rp_id, sizeof(rp_id)) ||
      !map_find(request, request_length, 2, &client_hash, NULL, NULL) ||
      client_hash.type != CBOR_TYPE_BYTES || client_hash.length != 32) {
    write_error(CTAP2_ERR_MISSING_PARAMETER, response, response_length);
    return;
  }
  bool ignored_rk, uv_requested = false, up_requested = true;
  const uint8_t* options_slice;
  size_t options_length;
  if (map_find(request, request_length, 5, &value, &options_slice,
               &options_length)) {
    uint8_t options_status =
        value.type == CBOR_TYPE_MAP
            ? parse_options(options_slice, options_length, false, &ignored_rk,
                            &uv_requested, &up_requested)
            : CTAP2_ERR_INVALID_CBOR;
    if (options_status != CTAP2_OK) {
      write_error(options_status, response, response_length);
      return;
    }
  }
  bool uv_verified;
  uint8_t uv_status =
      verify_pin_uv(request, request_length, 6, 7, client_hash.data,
                    uv_requested, false, &uv_verified);
  if (uv_status != CTAP2_OK) {
    write_error(uv_status, response, response_length);
    return;
  }

  uint8_t rp_id_hash[32], credential_id[64];
  memzero(&assertion_sequence, sizeof(assertion_sequence));
  sha256_Raw((const uint8_t*)rp_id, strlen(rp_id), rp_id_hash);
  PasskeyCredential resident;
  memzero(&resident, sizeof(resident));
  int resident_count = 0;
  bool credential_found = false;
  const uint8_t* allow_slice;
  size_t allow_length;
  if (map_find(request, request_length, 3, &value, &allow_slice,
               &allow_length)) {
    if (value.type != CBOR_TYPE_ARRAY) {
      write_error(CTAP2_ERR_INVALID_CBOR, response, response_length);
      return;
    }
    credential_found = credential_list_contains(allow_slice, allow_length,
                                                rp_id_hash, credential_id);
  } else {
    resident_count = find_discoverable_credential(rp_id_hash, &resident);
    credential_found = resident_count > 0;
    if (credential_found)
      memcpy(credential_id, resident.credential_id, sizeof(credential_id));
  }
  if (up_requested && !ctap2_request_user_presence(rp_id, false)) {
    memzero(&assertion_sequence, sizeof(assertion_sequence));
    write_error(ctap2_user_presence_was_cancelled()
                    ? CTAP2_ERR_KEEPALIVE_CANCEL
                    : CTAP2_ERR_USER_ACTION_TIMEOUT,
                response, response_length);
    return;
  }
  if (!credential_found) {
    write_error(CTAP2_ERR_NO_CREDENTIALS, response, response_length);
    return;
  }
  if (resident_count > 1) {
    assertion_sequence.valid = true;
    assertion_sequence.up_verified = up_requested;
    assertion_sequence.uv_verified = uv_verified;
    assertion_sequence.count = (uint8_t)resident_count;
    assertion_sequence.next = 1;
    assertion_sequence.deadline = getSysTime() + 30000;
    assertion_sequence.channel = transport_channel;
    memcpy(assertion_sequence.rp_id_hash, rp_id_hash, 32);
    memcpy(assertion_sequence.client_data_hash, client_hash.data, 32);
  }

  uint8_t private_key[32], public_key[65];
  if (!u2f_load_credential(rp_id_hash, credential_id, private_key,
                           public_key)) {
    write_error(CTAP2_ERR_NO_CREDENTIALS, response, response_length);
    return;
  }
  uint8_t auth_data[37], signature_base[69], signature[64], der[72];
  size_t auth_length;
  uint32_t counter = storage_nextU2FCounter();
  encode_authenticator_data(
      auth_data, sizeof(auth_data), &auth_length, rp_id_hash,
      (up_requested ? 0x01 : 0) | (uv_verified ? 0x04 : 0), counter, NULL,
      NULL);
  memcpy(signature_base, auth_data, auth_length);
  memcpy(signature_base + auth_length, client_hash.data, 32);
  if (ecdsa_sign(&nist256p1, HASHER_SHA2, private_key, signature_base,
                 sizeof(signature_base), signature, NULL, NULL) != 0) {
    memzero(private_key, sizeof(private_key));
    write_error(CTAP2_ERR_OTHER, response, response_length);
    return;
  }
  size_t der_length = ecdsa_sig_to_der(signature, der);
  size_t pairs = resident_count > 0 ? 4 : 3;
  if (resident_count > 1) ++pairs;
  response[0] = CTAP2_OK;
  CborEncoder encoder;
  cbor_encoder_init(&encoder, response + 1, capacity - 1);
  cbor_encode_map(&encoder, pairs);
  cbor_encode_uint(&encoder, 1);
  cbor_encode_map(&encoder, 2);
  cbor_encode_text(&encoder, "id", 2);
  cbor_encode_bytes(&encoder, credential_id, sizeof(credential_id));
  cbor_encode_text(&encoder, "type", 4);
  cbor_encode_text(&encoder, "public-key", 10);
  cbor_encode_uint(&encoder, 2);
  cbor_encode_bytes(&encoder, auth_data, sizeof(auth_data));
  cbor_encode_uint(&encoder, 3);
  cbor_encode_bytes(&encoder, der, der_length);
  if (resident_count > 0) {
    cbor_encode_uint(&encoder, 4);
    cbor_encode_map(&encoder, uv_verified ? 2 : 1);
    cbor_encode_text(&encoder, "id", 2);
    cbor_encode_bytes(&encoder, resident.user_id, resident.user_id_length);
    if (uv_verified) {
      cbor_encode_text(&encoder, "name", 4);
      cbor_encode_text(&encoder, resident.user_name,
                       strnlen(resident.user_name, sizeof(resident.user_name)));
    }
  }
  if (resident_count > 1) {
    cbor_encode_uint(&encoder, 5);
    cbor_encode_uint(&encoder, resident_count);
  }
  size_t encoded = cbor_encoder_size(&encoder);
  *response_length = encoded == 0 ? 1 : encoded + 1;
  if (encoded == 0) response[0] = CTAP2_ERR_OTHER;
  memzero(private_key, sizeof(private_key));
  memzero(signature_base, sizeof(signature_base));
  memzero(signature, sizeof(signature));
}

static void client_pin(const uint8_t* request, size_t request_length,
                       uint8_t* response, size_t capacity, size_t* length) {
  CborValue protocol, subcommand;
  if (!map_find(request, request_length, 1, &protocol, NULL, NULL) ||
      !map_find(request, request_length, 2, &subcommand, NULL, NULL) ||
      protocol.type != CBOR_TYPE_UINT || protocol.value != 1 ||
      subcommand.type != CBOR_TYPE_UINT) {
    write_error(CTAP2_ERR_MISSING_PARAMETER, response, length);
    return;
  }

  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  CborEncoder encoder;
  switch (subcommand.value) {
    case 1: /* getRetries */
      response[0] = CTAP2_OK;
      cbor_encoder_init(&encoder, response + 1, capacity - 1);
      cbor_encode_map(&encoder, 1);
      cbor_encode_uint(&encoder, 3);
      cbor_encode_uint(&encoder, storage.pin_retries);
      *length = cbor_encoder_size(&encoder) + 1;
      return;

    case 2: /* getKeyAgreement */
      generate_key_agreement();
      response[0] = CTAP2_OK;
      cbor_encoder_init(&encoder, response + 1, capacity - 1);
      cbor_encode_map(&encoder, 1);
      cbor_encode_uint(&encoder, 1);
      encode_cose_public_key(&encoder, key_agreement.public_key);
      *length = cbor_encoder_size(&encoder) + 1;
      return;

    case 3: { /* setPIN */
      CborValue pin_auth, encrypted_pin;
      uint8_t shared_secret[32], plaintext[64], digest[32];
      if (storage.pin_set) {
        write_error(CTAP2_ERR_NOT_ALLOWED, response, length);
        return;
      }
      if (!map_find(request, request_length, 4, &pin_auth, NULL, NULL) ||
          !map_find(request, request_length, 5, &encrypted_pin, NULL, NULL) ||
          encrypted_pin.type != CBOR_TYPE_BYTES || encrypted_pin.length != 64 ||
          !shared_secret_from_request(request, request_length, shared_secret) ||
          !valid_pin_auth(shared_secret, encrypted_pin.data,
                          encrypted_pin.length, &pin_auth)) {
        write_error(CTAP2_ERR_PIN_AUTH_INVALID, response, length);
        return;
      }
      aes256_cbc(false, shared_secret, encrypted_pin.data, plaintext,
                 sizeof(plaintext));
      size_t pin_length = 0;
      while (pin_length < sizeof(plaintext) && plaintext[pin_length] != 0)
        ++pin_length;
      bool padding_ok = pin_length < sizeof(plaintext);
      for (size_t i = pin_length; i < sizeof(plaintext); ++i)
        padding_ok = padding_ok && plaintext[i] == 0;
      if (!padding_ok || pin_length < 4 || pin_length > 63) {
        memzero(plaintext, sizeof(plaintext));
        memzero(shared_secret, sizeof(shared_secret));
        write_error(CTAP2_ERR_PIN_POLICY_VIOLATION, response, length);
        return;
      }
      sha256_Raw(plaintext, pin_length, digest);
      random_buffer(storage.pin_salt, sizeof(storage.pin_salt));
      passkey_pin_digest(digest, 16, storage.pin_salt, digest);
      storage.pin_set = 1;
      storage.pin_retries = PASSKEY_PIN_RETRIES;
      memcpy(storage.pin_hash, digest, sizeof(storage.pin_hash));
      storage_setPasskeyData(&storage);
      pin_attempts_since_boot = 0;
      pin_token_valid = false;
      memzero(plaintext, sizeof(plaintext));
      memzero(digest, sizeof(digest));
      memzero(shared_secret, sizeof(shared_secret));
      key_agreement.valid = false;
      write_error(CTAP2_OK, response, length);
      return;
    }

    case 4: { /* changePIN */
      CborValue pin_auth, encrypted_pin, encrypted_hash;
      uint8_t shared_secret[32], plaintext[64], supplied_hash[16], digest[32];
      uint8_t verifier[32];
      uint8_t authenticated_message[80];
      if (!storage.pin_set) {
        write_error(CTAP2_ERR_PIN_NOT_SET, response, length);
        return;
      }
      if (storage.pin_retries == 0) {
        write_error(CTAP2_ERR_PIN_BLOCKED, response, length);
        return;
      }
      if (pin_attempts_since_boot >= 3) {
        write_error(CTAP2_ERR_PIN_AUTH_BLOCKED, response, length);
        return;
      }
      if (!map_find(request, request_length, 4, &pin_auth, NULL, NULL) ||
          !map_find(request, request_length, 5, &encrypted_pin, NULL, NULL) ||
          !map_find(request, request_length, 6, &encrypted_hash, NULL, NULL) ||
          encrypted_pin.type != CBOR_TYPE_BYTES || encrypted_pin.length != 64 ||
          encrypted_hash.type != CBOR_TYPE_BYTES ||
          encrypted_hash.length != 16 ||
          !shared_secret_from_request(request, request_length, shared_secret)) {
        write_error(CTAP2_ERR_MISSING_PARAMETER, response, length);
        return;
      }
      memcpy(authenticated_message, encrypted_pin.data, 64);
      memcpy(authenticated_message + 64, encrypted_hash.data, 16);
      if (!valid_pin_auth(shared_secret, authenticated_message,
                          sizeof(authenticated_message), &pin_auth)) {
        memzero(shared_secret, sizeof(shared_secret));
        write_error(CTAP2_ERR_PIN_AUTH_INVALID, response, length);
        return;
      }
      aes256_cbc(false, shared_secret, encrypted_hash.data, supplied_hash,
                 sizeof(supplied_hash));
      passkey_pin_digest(supplied_hash, sizeof(supplied_hash), storage.pin_salt,
                         verifier);
      if (memcmp_s(verifier, storage.pin_hash, sizeof(storage.pin_hash)) != 0) {
        --storage.pin_retries;
        ++pin_attempts_since_boot;
        storage_setPasskeyData(&storage);
        memzero(shared_secret, sizeof(shared_secret));
        memzero(supplied_hash, sizeof(supplied_hash));
        memzero(verifier, sizeof(verifier));
        write_error(storage.pin_retries == 0 ? CTAP2_ERR_PIN_BLOCKED
                                             : (pin_attempts_since_boot >= 3
                                                    ? CTAP2_ERR_PIN_AUTH_BLOCKED
                                                    : CTAP2_ERR_PIN_INVALID),
                    response, length);
        return;
      }
      aes256_cbc(false, shared_secret, encrypted_pin.data, plaintext,
                 sizeof(plaintext));
      size_t pin_length = 0;
      while (pin_length < sizeof(plaintext) && plaintext[pin_length] != 0)
        ++pin_length;
      bool padding_ok = pin_length < sizeof(plaintext);
      for (size_t i = pin_length; i < sizeof(plaintext); ++i)
        padding_ok = padding_ok && plaintext[i] == 0;
      if (!padding_ok || pin_length < 4 || pin_length > 63) {
        memzero(plaintext, sizeof(plaintext));
        memzero(shared_secret, sizeof(shared_secret));
        write_error(CTAP2_ERR_PIN_POLICY_VIOLATION, response, length);
        return;
      }
      sha256_Raw(plaintext, pin_length, digest);
      random_buffer(storage.pin_salt, sizeof(storage.pin_salt));
      passkey_pin_digest(digest, 16, storage.pin_salt, digest);
      memcpy(storage.pin_hash, digest, sizeof(storage.pin_hash));
      storage.pin_retries = PASSKEY_PIN_RETRIES;
      storage_setPasskeyData(&storage);
      pin_token_valid = false;
      pin_attempts_since_boot = 0;
      key_agreement.valid = false;
      memzero(plaintext, sizeof(plaintext));
      memzero(shared_secret, sizeof(shared_secret));
      memzero(supplied_hash, sizeof(supplied_hash));
      memzero(verifier, sizeof(verifier));
      memzero(digest, sizeof(digest));
      memzero(authenticated_message, sizeof(authenticated_message));
      write_error(CTAP2_OK, response, length);
      return;
    }

    case 5: { /* getPINToken */
      CborValue encrypted_hash;
      uint8_t shared_secret[32], supplied_hash[16], encrypted_token[32];
      uint8_t verifier[32];
      if (!storage.pin_set) {
        write_error(CTAP2_ERR_PIN_NOT_SET, response, length);
        return;
      }
      if (storage.pin_retries == 0) {
        write_error(CTAP2_ERR_PIN_BLOCKED, response, length);
        return;
      }
      if (pin_attempts_since_boot >= 3) {
        write_error(CTAP2_ERR_PIN_AUTH_BLOCKED, response, length);
        return;
      }
      if (!map_find(request, request_length, 6, &encrypted_hash, NULL, NULL) ||
          encrypted_hash.type != CBOR_TYPE_BYTES ||
          encrypted_hash.length != 16 ||
          !shared_secret_from_request(request, request_length, shared_secret)) {
        write_error(CTAP2_ERR_MISSING_PARAMETER, response, length);
        return;
      }
      aes256_cbc(false, shared_secret, encrypted_hash.data, supplied_hash,
                 sizeof(supplied_hash));
      passkey_pin_digest(supplied_hash, sizeof(supplied_hash), storage.pin_salt,
                         verifier);
      if (memcmp_s(verifier, storage.pin_hash, sizeof(storage.pin_hash)) != 0) {
        --storage.pin_retries;
        ++pin_attempts_since_boot;
        storage_setPasskeyData(&storage);
        memzero(shared_secret, sizeof(shared_secret));
        memzero(supplied_hash, sizeof(supplied_hash));
        memzero(verifier, sizeof(verifier));
        write_error(storage.pin_retries == 0 ? CTAP2_ERR_PIN_BLOCKED
                                             : (pin_attempts_since_boot >= 3
                                                    ? CTAP2_ERR_PIN_AUTH_BLOCKED
                                                    : CTAP2_ERR_PIN_INVALID),
                    response, length);
        return;
      }
      storage.pin_retries = PASSKEY_PIN_RETRIES;
      storage_setPasskeyData(&storage);
      pin_attempts_since_boot = 0;
      random_buffer(pin_token, sizeof(pin_token));
      pin_token_valid = true;
      aes256_cbc(true, shared_secret, pin_token, encrypted_token,
                 sizeof(encrypted_token));
      response[0] = CTAP2_OK;
      cbor_encoder_init(&encoder, response + 1, capacity - 1);
      cbor_encode_map(&encoder, 1);
      cbor_encode_uint(&encoder, 2);
      cbor_encode_bytes(&encoder, encrypted_token, sizeof(encrypted_token));
      *length = cbor_encoder_size(&encoder) + 1;
      memzero(shared_secret, sizeof(shared_secret));
      memzero(supplied_hash, sizeof(supplied_hash));
      memzero(verifier, sizeof(verifier));
      memzero(encrypted_token, sizeof(encrypted_token));
      key_agreement.valid = false;
      return;
    }

    default:
      write_error(CTAP2_ERR_INVALID_PARAMETER, response, length);
      return;
  }
}

static void reset_authenticator(uint8_t* response, size_t* response_length) {
  if ((int32_t)(reset_deadline - getSysTime()) <= 0) {
    write_error(CTAP2_ERR_NOT_ALLOWED, response, response_length);
    return;
  }
  if (!ctap2_request_user_presence("all saved passkeys", false)) {
    write_error(ctap2_user_presence_was_cancelled()
                    ? CTAP2_ERR_KEEPALIVE_CANCEL
                    : CTAP2_ERR_OPERATION_DENIED,
                response, response_length);
    return;
  }
  PasskeyStorage storage;
  memzero(&storage, sizeof(storage));
  storage.version = 1;
  storage.pin_retries = PASSKEY_PIN_RETRIES;
  storage_setPasskeyData(&storage);
  memzero(pin_token, sizeof(pin_token));
  memzero(&key_agreement, sizeof(key_agreement));
  pin_token_valid = false;
  pin_attempts_since_boot = 0;
  reset_deadline = 0;
  write_error(CTAP2_OK, response, response_length);
}

static void get_info(uint8_t* response, size_t capacity, size_t* length) {
  CborEncoder encoder;
  if (capacity == 0) {
    *length = 0;
    return;
  }
  response[0] = CTAP2_OK;
  cbor_encoder_init(&encoder, response + 1, capacity - 1);

  /* CTAP 2.0 GetInfo response. Options are conservative until each command is
   * fully backed by storage and user-verification support. */
  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  cbor_encode_map(&encoder, 7);

  cbor_encode_uint(&encoder, 1); /* versions */
  cbor_encode_array(&encoder, 2);
  cbor_encode_text(&encoder, "FIDO_2_0", 8);
  cbor_encode_text(&encoder, "U2F_V2", 6);

  cbor_encode_uint(&encoder, 3); /* aaguid */
  cbor_encode_bytes(&encoder, KEEPKEY_AAGUID, sizeof(KEEPKEY_AAGUID));

  cbor_encode_uint(&encoder, 4); /* options */
  cbor_encode_map(&encoder, 3);
  cbor_encode_text(&encoder, "rk", 2);
  cbor_encode_bool(&encoder, true);
  cbor_encode_text(&encoder, "up", 2);
  cbor_encode_bool(&encoder, true);
  cbor_encode_text(&encoder, "clientPin", 9);
  cbor_encode_bool(&encoder, storage.pin_set != 0);

  cbor_encode_uint(&encoder, 5); /* maxMsgSize */
  cbor_encode_uint(&encoder, 7609);

  cbor_encode_uint(&encoder, 6); /* pinUvAuthProtocols */
  cbor_encode_array(&encoder, 1);
  cbor_encode_uint(&encoder, 1);

  cbor_encode_uint(&encoder, 7); /* maxCredentialCountInList */
  cbor_encode_uint(&encoder, 8);

  cbor_encode_uint(&encoder, 8); /* maxCredentialIdLength */
  cbor_encode_uint(&encoder, 64);

  size_t encoded = cbor_encoder_size(&encoder);
  if (encoded == 0) {
    response[0] = CTAP2_ERR_OTHER;
    *length = 1;
  } else {
    *length = encoded + 1;
  }
}

void ctap2_handle(const uint8_t* request, size_t request_length,
                  uint8_t* response, size_t response_capacity,
                  size_t* response_length) {
  if (response_capacity == 0) {
    *response_length = 0;
    return;
  }
  if (request_length == 0) {
    response[0] = CTAP2_ERR_INVALID_LENGTH;
    *response_length = 1;
    return;
  }
  if ((request[0] == CTAP2_CMD_MAKE_CREDENTIAL ||
       request[0] == CTAP2_CMD_GET_ASSERTION ||
       request[0] == CTAP2_CMD_CLIENT_PIN) &&
      request_length > 1 &&
      !valid_request_map(request + 1, request_length - 1)) {
    write_error(CTAP2_ERR_INVALID_CBOR, response, response_length);
    return;
  }
  if (request[0] != CTAP2_CMD_GET_NEXT_ASSERTION)
    assertion_sequence.valid = false;

  switch (request[0]) {
    case CTAP2_CMD_MAKE_CREDENTIAL:
      if (request_length == 1) {
        write_error(CTAP2_ERR_INVALID_LENGTH, response, response_length);
        return;
      }
      make_credential(request + 1, request_length - 1, response,
                      response_capacity, response_length);
      return;
    case CTAP2_CMD_GET_ASSERTION:
      if (request_length == 1) {
        write_error(CTAP2_ERR_INVALID_LENGTH, response, response_length);
        return;
      }
      get_assertion(request + 1, request_length - 1, response,
                    response_capacity, response_length);
      return;
    case CTAP2_CMD_GET_NEXT_ASSERTION:
      if (request_length != 1) {
        write_error(CTAP2_ERR_INVALID_LENGTH, response, response_length);
        return;
      }
      get_next_assertion(response, response_capacity, response_length);
      return;
    case CTAP2_CMD_GET_INFO:
      if (request_length != 1) {
        response[0] = CTAP2_ERR_INVALID_LENGTH;
        *response_length = 1;
        return;
      }
      get_info(response, response_capacity, response_length);
      return;
    case CTAP2_CMD_CLIENT_PIN:
      if (request_length == 1) {
        write_error(CTAP2_ERR_INVALID_LENGTH, response, response_length);
        return;
      }
      client_pin(request + 1, request_length - 1, response, response_capacity,
                 response_length);
      return;
    case CTAP2_CMD_RESET:
      if (request_length != 1) {
        write_error(CTAP2_ERR_INVALID_LENGTH, response, response_length);
        return;
      }
      reset_authenticator(response, response_length);
      return;
    default:
      response[0] = CTAP2_ERR_INVALID_COMMAND;
      *response_length = 1;
      return;
  }
}
