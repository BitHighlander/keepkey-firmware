#ifndef KEEPKEY_FIRMWARE_SIGNED_METADATA_H
#define KEEPKEY_FIRMWARE_SIGNED_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _EthereumSignTx EthereumSignTx;

#define METADATA_MAX_ARGS 8
#define METADATA_MAX_METHOD_LEN 64
#define METADATA_MAX_ARG_NAME_LEN 32
/* Sized for TOKEN_AMOUNT: decimals(1) + symbol_len(1) + symbol(<=10) +
 * amount(<=32). Other formats remain capped at 32 by their own guards. */
#define METADATA_MAX_ARG_VALUE_LEN 44
#define METADATA_MAX_TOKEN_SYMBOL_LEN 10
#define METADATA_MAX_KEYS 4
#define METADATA_ALIAS_MAX_LEN 31
/* Must equal LoadClearsignSigner.icon max_size and CLEARSIGN_ICON_MAX. */
#define METADATA_ICON_MAX 384
/* hex(sha256(pubkey)[0:8]) + NUL. 64 bits: a 32-bit prefix collision can be
 * ground in hours, passing a different key for the approved one. */
#define METADATA_FINGERPRINT_LEN 17

typedef enum {
  METADATA_OPAQUE = 0,
  METADATA_VERIFIED = 1,
  METADATA_MALFORMED = 2,
} MetadataClassification;

/* LEGACY (v1): per-tx blob with committed tx_hash and host-decoded values;
 * bound to the digest by signed_metadata_enforce. SCHEMA (v2): no tx_hash, no
 * values; the DEVICE decodes args from the calldata it signs, so the display
 * is bound by construction and the catalog can be signed once, offline. */
#define METADATA_VERSION_LEGACY 0x01
#define METADATA_VERSION_SCHEMA 0x02

/* 7.16: [0x03][cert 139][device-decoded schema]. The cert is verified and
 * DISCARDED within one message; no delegation outlives it. */
#define METADATA_VERSION_CERTIFIED 0x03
/* v2 plus roles, a native-value role, a title and a signed intent template
 * (SRS-7.16 §3.7, docs/security/clearsign-intent-template.md). Values are
 * still decoded from the calldata being signed. */
#define METADATA_VERSION_SCHEMA_INTENT 0x05
#define METADATA_INTENT_MAX 96
/* 0x06: a vouched name for one address on one chain (certified only). It
 * describes no transaction; typed-data reviews show it beside the address. */
#define METADATA_VERSION_NAME 0x06
#define METADATA_NAME_MAX 24
/* Widest filled summary; templates that could exceed it are rejected. */
#define METADATA_INTENT_TEXT_MAX 280
#define METADATA_TITLE_MAX 20
/* Intent roles, shared by the EVM and Solana (KKSOLSC1 v3) schemas: the
 * device words the limits screen from these. CAP is a per-use maximum (e.g.
 * each bet), not an outflow. */
#define METADATA_ROLE_NONE 0
#define METADATA_ROLE_SPEND_MAX 1
#define METADATA_ROLE_RECEIVE_MIN 2
#define METADATA_ROLE_SPEND_EXACT 3
#define METADATA_ROLE_RECEIVE_EXACT 4
#define METADATA_ROLE_CAP 5
/* EVM only: a token allowance someone else may draw on (approve). */
#define METADATA_ROLE_ALLOWANCE 6

/* Delegate sentinel, >= METADATA_MAX_KEYS so it can never name a runtime slot.
 * The only key writer (signed_metadata_store_signer) rejects such ids, so a
 * host cannot promote a key into the KeepKey tier: no writer exists. */
#define METADATA_KEYID_DELEGATE 0x80

typedef enum {
  METADATA_TIER_NONE = 0,
  METADATA_TIER_RUNTIME = 1, /* user loaded it this session; annotation only */
  METADATA_TIER_KEEPKEY =
      2, /* KeepKey-delegated; MAY suppress the raw review */
} MetadataTier;

/* The single suppression predicate; conjunctive, so a new tier cannot widen
 * it. */
bool signed_metadata_may_suppress(uint32_t tx_chain_id);

/* This message carried a v3 envelope, verified or not. A failed claim must be
 * refused, never downgraded (SRS R-1.4). */
bool signed_metadata_certified_claimed(void);

/* Empty unless this message carried a verified certificate. */
const char* signed_metadata_delegate_alias(void);

typedef enum {
  ARG_FORMAT_RAW = 0,     /* hex dump (all bytes, paginated) */
  ARG_FORMAT_ADDRESS = 1, /* 20 bytes -> full EIP-55 address, never truncated */
  ARG_FORMAT_AMOUNT = 2,  /* big-endian uint256 -> raw integer, "wei" */
  ARG_FORMAT_BYTES = 3,   /* hex dump (all bytes, paginated) */
  /* Printable label; alias character rules minus length (no '%'). */
  ARG_FORMAT_STRING = 4,
  /* decimals(1) + symbol_len(1) + symbol(<=10, [A-Za-z0-9]) + amount(1..32
   * BE); all-0xFF 32-byte amount renders "UNLIMITED <symbol>". */
  ARG_FORMAT_TOKEN_AMOUNT = 5,
  /* v2/0x05 only: an address that must equal the 20 bytes the schema pins
   * (e.g. a spender), so the template may name that party in words. */
  ARG_FORMAT_ADDRESS_PINNED = 6,
} ArgFormat;

typedef struct {
  char name[METADATA_MAX_ARG_NAME_LEN + 1];
  ArgFormat format;
  uint8_t value[METADATA_MAX_ARG_VALUE_LEN];
  uint16_t value_len;
  uint8_t role; /* v0x05: METADATA_ROLE_* on amounts, else NONE */
} MetadataArg;

typedef struct {
  uint8_t version;
  uint32_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector[4];
  uint8_t tx_hash[32];
  char method_name[METADATA_MAX_METHOD_LEN + 1];
  uint8_t num_args;
  MetadataArg args[METADATA_MAX_ARGS];
  MetadataClassification classification;
  uint32_t timestamp;
  uint8_t key_id;
  uint8_t signature[64];
  uint8_t recovery;
  /* v0x05 */
  uint8_t value_role; /* NONE, SPEND_MAX or SPEND_EXACT for msg.value */
  char title[METADATA_TITLE_MAX + 1];
  char intent[METADATA_INTENT_MAX + 1];
  char vouched_name[METADATA_NAME_MAX + 1]; /* v0x06 */
  uint8_t tx_value[32]; /* msg.value of the matched tx, big-endian */
} SignedMetadata;

/* Intent review helpers shared by the EVM and Solana reviews (SRS-7.16 §3.7,
 * docs/security/clearsign-intent-template.md). One screen: body text, or a
 * byte range to page; false cancels. */
typedef bool (*ReviewEmit)(void* ctx, const char* title, const char* body,
                           const uint8_t* bytes, uint16_t bytes_len);
/* ReviewEmit on the device: text as one screen, bytes as hex pages. */
bool signed_metadata_review_emit(void* ctx, const char* title, const char* body,
                                 const uint8_t* bytes, uint16_t bytes_len);
/* A KeepKey-certified name record, taken by the request it rides ahead of. */
typedef struct {
  bool valid;
  uint32_t chain_id;
  uint8_t address[20];
  char name[METADATA_NAME_MAX + 1];
  char alias[METADATA_ALIAS_MAX_LEN + 2]; /* certificate alias, <= 32 */
  char fp8[9];
} MetadataNameRecord;

/* Copies out the loaded certified name record (if any) and clears all
 * metadata, so a record can only ever name the one request that follows it. */
void signed_metadata_take_name(MetadataNameRecord* out);
/* The v0x05 review. certified: summary, limits, details, who. Runtime: a
 * NOT-verified heading plus limits; the caller's raw review follows. */
bool signed_metadata_build_intent_review(const SignedMetadata* md,
                                         bool certified, const char* alias,
                                         const char* fp, ReviewEmit emit,
                                         void* ctx);

bool signed_metadata_available(void);

/* Shape-only v3 check letting the envelope reach signed_metadata_process()
 * with AdvancedMode off. Grants NO trust; process() verifies everything. */
bool signed_metadata_is_certified_envelope(const uint8_t* payload,
                                           size_t payload_len, uint32_t key_id);

/* True iff the last matches_tx() decoded v2 args from this tx's calldata;
 * reset on every call so it is never stale. Required by v2 enforce. */
bool signed_metadata_schema_decoded(void);

/* v2 schema + native value: v2 cannot bind value, so the caller MUST still
 * show the amount/recipient screen. */
bool signed_metadata_schema_moves_value(void);

void signed_metadata_clear(void);

/* Runtime-loaded signers: RAM-only, loaded after on-device consent, always
 * shown by alias before any page; never warning-free (production uses a
 * root-certified delegate). */

/* Pure validation: slot, compressed secp256k1 point, printable alias. */
bool signed_metadata_signer_valid(uint8_t key_id, const uint8_t* pubkey,
                                  size_t pubkey_len, const char* alias);

/* Post-consent write only: caller MUST have validated and confirmed. RC18
 * rejects persist=true (public storage lacks authenticated integrity). */
bool signed_metadata_store_signer(uint8_t key_id, const uint8_t* pubkey,
                                  const char* alias, const uint8_t* icon,
                                  uint8_t icon_w, uint8_t icon_h,
                                  uint16_t icon_len, bool persist);

/* NULL when the slot has no signer. */
const char* signed_metadata_signer_alias(uint8_t key_id);

/* LoadClearsignSigner consent: icon + alias + fingerprint. */
bool signed_metadata_confirm_load(const char* alias, const char* fingerprint,
                                  const uint8_t* icon, uint8_t icon_w,
                                  uint8_t icon_h, uint16_t icon_len);

/* Drop all runtime-loaded signers (and any metadata they verified). */
void signed_metadata_clear_signers(void);

/* Shown at load and per-tx so the user can correlate the two. */
void signed_metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char out[METADATA_FINGERPRINT_LEN]);

/* Lets non-EVM callers keep their Advanced-mode review after a decode. */
bool signed_metadata_signer_is_runtime(uint8_t key_id);
MetadataClassification signed_metadata_process(const uint8_t* payload,
                                               size_t payload_len,
                                               uint8_t key_id);

/* True iff a runtime signer is loaded for key_id AND the 64-byte compact
 * ECDSA sig verifies over sha256(data). */
bool signed_metadata_verify_attestation(uint8_t key_id, const uint8_t* data,
                                        size_t data_len, const uint8_t* sig,
                                        size_t sig_len);

/* For envelopes carrying the delegate pubkey (ERC-7730). Enforces
 * AdvancedMode; returns the user-approved alias. */
bool signed_metadata_verify_runtime_attestation_for_pubkey(
    const uint8_t pubkey[33], const uint8_t* data, size_t data_len,
    const uint8_t* sig, size_t sig_len,
    char out_alias[METADATA_ALIAS_MAX_LEN + 1]);

/* Aliases are not unique; the fingerprint disambiguates signers. */
bool signed_metadata_signer_fingerprint(uint8_t key_id,
                                        char out[METADATA_FINGERPRINT_LEN]);
/* Display gate binding contract, selector and chain id; the full-tx binding
 * is signed_metadata_enforce(). */
bool signed_metadata_matches_tx(const EthereumSignTx* msg);
bool signed_metadata_confirm(void);

/* True once a verified confirm suppressed the raw-data screen, so signing is
 * gated on the metadata matching the final tx hash. */
bool signed_metadata_relied(void);

/* Called once the sighash exists (send_signature). Fail-closed unless no
 * metadata was relied on or its committed tx_hash equals hash. */
bool signed_metadata_enforce(const uint8_t hash[32]);

/* Pure decision behind signed_metadata_enforce(); exported for tests. */
bool signed_metadata_enforce_decision(bool relied, bool available,
                                      int classification,
                                      const uint8_t* stored_hash,
                                      const uint8_t* hash);

/* v2 has no tx_hash: proceed only if relied-upon metadata is available,
 * VERIFIED and `decoded`, which must be decode_v2_args()'s recorded result
 * for this operation, not inferred from call order. */
bool signed_metadata_enforce_schema_decision(bool relied, bool available,
                                             bool decoded, int classification);

const SignedMetadata* signed_metadata_get(void);

/* A filled template; src is the walker's schema context. */
typedef struct {
  const void* src;
  char* out;
  size_t len;
  size_t used;
  bool ok;
} IntentFill;
void intent_fill_append(IntentFill* f, const char* str, size_t n);
/* Template literals carry no digits: every digit shown is the device's
 * formatting of signed bytes, never server text. */
bool intent_literal_ok(const char* lit, size_t len);
/* "You spend at most" etc.; NULL for METADATA_ROLE_NONE. */
const char* intent_role_text(uint8_t role);
/* Runtime: "<alias> (NOT verified by KeepKey) says:" over the summary. */
bool intent_emit_unverified(ReviewEmit emit, void* ctx, const char* alias,
                            const char* intent);
/* Certified: "Described by <alias> <fp>, certified by KeepKey". */
bool intent_emit_provenance(ReviewEmit emit, void* ctx, const char* alias,
                            const char* fp);

#endif
