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

/* 7.16: a KeepKey-delegated envelope. [0x03][cert 139][device-decoded schema].
 * The certificate is verified and DISCARDED inside one message -- nothing about
 * a delegation survives into the next transaction. */
#define METADATA_VERSION_CERTIFIED 0x03

/* The delegate is addressed by a sentinel that is >= METADATA_MAX_KEYS BY
 * CONSTRUCTION, so it can never name a runtime slot.
 *
 * That is the whole promotion defence, and it is worth stating plainly: a host
 * can write a public key into exactly one array, via exactly one message
 * (LoadClearsignSigner -> signed_metadata_store_signer), and that function
 * already rejects any key_id >= METADATA_MAX_KEYS. Promotion is prevented by
 * the ABSENCE OF A WRITER, not by a check somebody could forget to add.
 *
 * metadata_pubkey_for() is deliberately left untouched by 7.16 for the same
 * reason -- it is shared with Solana, and not modifying it means the KeepKey
 * tier cannot leak there by call-graph accident. */
#define METADATA_KEYID_DELEGATE 0x80

typedef enum {
  METADATA_TIER_NONE = 0,
  METADATA_TIER_RUNTIME = 1, /* user loaded it this session; annotation only */
  METADATA_TIER_KEEPKEY =
      2, /* KeepKey-delegated; MAY suppress the raw review */
} MetadataTier;

/* The single suppression predicate. Positive and conjunctive: every clause must
 * hold. Written this way rather than as an else-arm so that adding a trust tier
 * later cannot silently widen it. */
bool signed_metadata_may_suppress(uint32_t tx_chain_id);

/* True when this message carried a certified (v3) envelope, verified or not.
 * A claimed certified render that cannot be honoured must be refused, never
 * silently downgraded to the additive review (SRS R-1.4). */
bool signed_metadata_certified_claimed(void);

/* Display for the KeepKey tier. Empty unless the current message carried a
 * verified certificate. */
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
} ArgFormat;

typedef struct {
  char name[METADATA_MAX_ARG_NAME_LEN + 1];
  ArgFormat format;
  uint8_t value[METADATA_MAX_ARG_VALUE_LEN];
  uint16_t value_len;
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
} SignedMetadata;

bool signed_metadata_available(void);

/* True only for the reserved KeepKey-certified envelope shape.  This is the
 * narrow pre-verification predicate used by the FSM to let a v3 certificate
 * reach signed_metadata_process() while AdvancedMode is off.  It grants no
 * trust by itself: the compiled root, certificate, delegate signature, and
 * device-decoded schema are still verified by signed_metadata_process(). */
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

#endif
