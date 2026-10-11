#ifndef KEEPKEY_FIRMWARE_SIGNED_METADATA_H
#define KEEPKEY_FIRMWARE_SIGNED_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/uniswap_ur.h"

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
/* Identity icon cap (1bpp mono RLE). Must equal LoadClearsignSigner.icon
 * max_size (messages-ethereum.options). Identities are never persisted. */
#define METADATA_ICON_MAX 384
/* hex(first 8 bytes of sha256(pubkey)) + NUL. 64 bits: a 32-bit prefix
 * collision can be ground in hours, which would let a different key pass for
 * the one the user approved. */
#define METADATA_FINGERPRINT_LEN 17

typedef enum {
  METADATA_OPAQUE = 0,
  METADATA_VERIFIED = 1,
  METADATA_MALFORMED = 2,
} MetadataClassification;

/*
 * Blob format versions (the first payload byte).
 *
 * LEGACY (v1): per-transaction. The blob carries a committed tx_hash and the
 * pre-decoded argument VALUES; the host is trusted for the decode and the
 * device only binds it to the signed digest (signed_metadata_enforce). This is
 * the format that requires an online, per-tx signer holding the attestation
 * key.
 *
 * SCHEMA (v2): static. The blob carries NO tx_hash and NO values — only how to
 * decode the call: (chainId, contract, selector, method, per-arg name + display
 * format [+ static decimals/symbol]). The DEVICE decodes the argument values
 * from the exact calldata it is about to sign, so the display is bound to the
 * signature by construction. No tx_hash, no per-tx signing: the catalog is
 * signed ONCE, offline, and can be served from a host CDN (no hot key).
 */
#define METADATA_VERSION_LEGACY 0x01
#define METADATA_VERSION_SCHEMA 0x02

/* 7.16: a KeepKey-delegated envelope. [0x03][cert 139][device-decoded schema].
 * The certificate is verified and DISCARDED inside one message -- nothing about
 * a delegation survives into the next transaction. */
#define METADATA_VERSION_CERTIFIED 0x03
/* v2 plus roles, a native-value role, a title and a signed intent template
 * (SRS-7.16 §3.7, docs/security/clearsign-intent-template.md). Values are
 * still decoded from the calldata being signed. */
#define METADATA_VERSION_SCHEMA_INTENT 0x05
#define METADATA_INTENT_MAX 96
/* 0x06: a vouched name for one address on one chain (certified only). It
 * describes no transaction; typed-data reviews show it beside the address. */
#define METADATA_VERSION_NAME 0x06
/* Certified only: selects a reviewed firmware decoder for one contract on one
 * chain and carries the token identities the review needs. The device decodes
 * every value from the calldata it signs. */
#define METADATA_VERSION_DECODER 0x07
#define METADATA_DECODER_UNISWAP_UR 1
#define METADATA_MAX_TOKENS 4
#define METADATA_NAME_MAX 24
/* Widest filled summary; templates that could exceed it are rejected. */
#define METADATA_INTENT_TEXT_MAX 280
#define METADATA_TITLE_MAX 20
/* Roles (shared numbering with Solana KKSOLSC1 v3). */
#define METADATA_ROLE_NONE 0
#define METADATA_ROLE_SPEND_MAX 1
#define METADATA_ROLE_RECEIVE_MIN 2
#define METADATA_ROLE_SPEND_EXACT 3
#define METADATA_ROLE_RECEIVE_EXACT 4
#define METADATA_ROLE_CAP 5
/* EVM only: a token allowance someone else may draw on (approve). */
#define METADATA_ROLE_ALLOWANCE 6

/* DYNAMIC_SCHEMA (v4): a certified, firmware-owned decoder selected by a
 * signed one-byte decoder id.  Unlike v1, the signer supplies no displayed
 * values; unlike v2, the calldata need not be a flat list of ABI words.  The
 * device's named decoder validates and extracts every displayed value from the
 * transaction it is signing.  v4 is initially used only for the exact Portals
 * OrderPayload ABI, whose dynamic call array is larger than the 1024-byte
 * initial protobuf chunk while its safety-defining outer order is wholly in
 * that chunk. */
#define METADATA_VERSION_DYNAMIC_SCHEMA 0x04

typedef enum {
  METADATA_DECODER_NONE = 0,
  METADATA_DECODER_PORTALS_NATIVE_ORDER_V1 = 1,
} MetadataDecoder;

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
bool signed_metadata_delegate_fingerprint(char out[METADATA_FINGERPRINT_LEN]);

/*
 * Argument display formats. The goal of clear-signing is that the device
 * answers WHO the user is dealing with (validated contract address, protocol
 * name), WHAT the transaction does (method + human-readable typed args:
 * recipient, "Amount: 1,000 USDC"), and WHY the decode can be trusted
 * (signer attestation bound to the exact tx hash). RAW/BYTES hex dumps are
 * the fallback, not the product.
 */
typedef enum {
  ARG_FORMAT_RAW = 0,     /* hex dump (all bytes, paginated) */
  ARG_FORMAT_ADDRESS = 1, /* 20 bytes -> full EIP-55 address, never truncated */
  ARG_FORMAT_AMOUNT = 2,  /* big-endian uint256 -> raw integer, "wei" */
  ARG_FORMAT_BYTES = 3,   /* hex dump (all bytes, paginated) */
  /* Attested label, e.g. protocol: "Uniswap V2": 1..32 printable ASCII
   * bytes, '%' excluded. */
  ARG_FORMAT_STRING = 4,
  /* decimals(1) + symbol_len(1) + symbol(<=10, [A-Za-z0-9]) + amount(1..32
   * big-endian). Rendered as a decimal-scaled amount with the symbol, e.g.
   * "1000 USDC"; all-0xFF 32-byte amounts render "UNLIMITED <symbol>". */
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
  uint8_t address[20];
  uint8_t decimals;
  char symbol[METADATA_MAX_TOKEN_SYMBOL_LEN + 1];
} MetadataToken;

typedef struct {
  uint8_t version;
  uint8_t decoder_id;
  uint32_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector[4];
  uint8_t tx_hash[32];
  char method_name[METADATA_MAX_METHOD_LEN + 1];
  uint8_t num_args;
  /* A decoder entry (v0x07) has no schema arguments or intent: it shares
   * their RAM with its plan, token identities and summary. */
  union {
    struct {
      MetadataArg args[METADATA_MAX_ARGS];
      char intent[METADATA_INTENT_MAX + 1];
    };
    struct {
      UrPlan ur_plan; /* scratch while matching */
      MetadataToken tokens[METADATA_MAX_TOKENS];
      UrSummary ur; /* filled when the tx matches */
    };
  };
  MetadataClassification classification;
  uint32_t timestamp;
  uint8_t key_id;
  uint8_t signature[64];
  uint8_t recovery;
  /* v0x05 */
  uint8_t value_role; /* NONE, SPEND_MAX or SPEND_EXACT for msg.value */
  char title[METADATA_TITLE_MAX + 1];
  char vouched_name[METADATA_NAME_MAX + 1]; /* v0x06 */
  uint8_t tx_value[32]; /* msg.value of the matched tx, big-endian */
  uint8_t tx_value_len;
  /* v0x07 */
  uint8_t decoder;
  uint8_t num_tokens;
} SignedMetadata;

/* One review screen: text, or (BYTES) a byte range to page. */
typedef bool (*MetadataReviewEmit)(void* ctx, const char* title,
                                   const char* body, const uint8_t* bytes,
                                   uint16_t bytes_len);
/* Placeholders "{n}" (arg) / "{v}" (msg.value) well-formed and in range,
 * every amount covered, {v} present iff the value has a role. */
bool signed_metadata_intent_valid(const SignedMetadata* md);
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
/* v0x07 Uniswap review: summary, limits, recipient, permit, fee, contract,
 * provenance. Emits nothing partial: false if any line cannot be built. */
bool signed_metadata_build_ur_review(const SignedMetadata* md,
                                     const char* alias, const char* fp,
                                     MetadataReviewEmit emit, void* ctx);
bool signed_metadata_build_intent_review(const SignedMetadata* md,
                                         bool certified, const char* alias,
                                         const char* fp,
                                         MetadataReviewEmit emit, void* ctx);

bool signed_metadata_available(void);

/* True only for the reserved KeepKey-certified envelope shape.  This is the
 * narrow pre-verification predicate used by the FSM to let a v3 certificate
 * reach signed_metadata_process() while AdvancedMode is off.  It grants no
 * trust by itself: the compiled root, certificate, delegate signature, and
 * device-decoded schema are still verified by signed_metadata_process(). */
bool signed_metadata_is_certified_envelope(const uint8_t* payload,
                                           size_t payload_len, uint32_t key_id);

/* True when the stored v2 (schema) metadata was decoded from the current tx's
 * calldata by the most recent signed_metadata_matches_tx() call. Reset at the
 * top of every matches_tx() so it reflects only that call (never a stale prior
 * match). The v2 enforce path requires it; exported for unit testing. */
bool signed_metadata_schema_decoded(void);

/* True when the matched schema is v2 AND the transaction carries native value
 * the schema cannot bind. On the runtime tier this is informational: the
 * ordinary amount screen always runs after metadata. Where
 * signed_metadata_may_suppress() lets the decoded display replace the
 * raw-calldata screen, the caller MUST still show the amount/recipient screen
 * when this is true. */
bool signed_metadata_schema_moves_value(void);

void signed_metadata_clear(void);

/*
 * Runtime-loaded clearsign signers (the development/self-service path).
 *
 * A signer is a compressed secp256k1 pubkey + display alias loaded into a
 * key slot at the host's request, gated by a mandatory on-device confirm
 * (see fsm_msgLoadClearsignSigner). Loaded signers live in RAM only and are
 * gone on reboot. Metadata verified by a loaded signer always shows a
 * identity screen naming the alias before any clearsign page. A runtime signer
 * is never a warning-free path: the production path instead carries a
 * root-certified delegate in each v3 envelope.
 */

/* Pure validation: slot in range, pubkey a valid compressed secp256k1 point,
 * alias non-empty printable ASCII within METADATA_ALIAS_MAX_LEN. No state, no
 * I/O. */
bool signed_metadata_signer_valid(uint8_t key_id, const uint8_t* pubkey,
                                  size_t pubkey_len, const char* alias);

/* Store a signer into a slot. Caller (the FSM handler) MUST have passed
 * signed_metadata_signer_valid() and obtained on-device user confirmation
 * first — this function is the post-consent write, nothing more.
 *
 * icon (optional, icon_len<=384, 1bpp mono RLE) is kept as the session icon for
 * the slot; icon_len==0 => text-only identity. RC18 rejects persist=true before
 * changing the session slot because public storage lacks authenticated
 * integrity. */
bool signed_metadata_store_signer(uint8_t key_id, const uint8_t* pubkey,
                                  const char* alias, const uint8_t* icon,
                                  uint8_t icon_w, uint8_t icon_h,
                                  uint16_t icon_len, bool persist);

/* Resolve a slot's alias / icon from the RAM session copy. alias returns NULL
 * and icon returns false when the slot has no signer / no icon (text-only).
 * Used by the per-tx confirm. */
const char* signed_metadata_signer_alias(uint8_t key_id);
bool signed_metadata_signer_icon(uint8_t key_id, const uint8_t** icon_out,
                                 uint8_t* w_out, uint8_t* h_out,
                                 uint16_t* len_out);

/* The LoadClearsignSigner consent screen: leads with the identity's logo (if
 * any) + alias + fingerprint. Returns true iff the user confirmed. The FSM
 * handler calls this before storing the signer. */
bool signed_metadata_confirm_load(const char* alias, const char* fingerprint,
                                  const uint8_t* icon, uint8_t icon_w,
                                  uint8_t icon_h, uint16_t icon_len);

/* Drop all runtime-loaded signers (and any metadata they verified). */
void signed_metadata_clear_signers(void);

/* out = hex of the first 8 bytes of sha256(pubkey[33]), NUL-terminated.
 * Shown at load-confirm and on the per-tx warning screen so the user can
 * correlate the two. */
void signed_metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char out[METADATA_FINGERPRINT_LEN]);

/* True when the currently stored metadata was verified by a runtime-loaded
 * signer (=> its confirm flow is warning-first, never "Insight Verified"). */
bool signed_metadata_from_loaded_signer(void);
/* True when key_id currently resolves to a runtime-loaded signer. This lets
 * non-EVM callers preserve their normal Advanced-mode review after showing an
 * additive schema decode. */
bool signed_metadata_signer_is_runtime(uint8_t key_id);
MetadataClassification signed_metadata_process(const uint8_t* payload,
                                               size_t payload_len,
                                               uint8_t key_id);

/* Generic attestation check reusing the (chain-agnostic) clear-sign signer
 * keyring: returns true iff a runtime signer is loaded for `key_id` AND the
 * 64-byte compact ECDSA signature `sig` verifies over sha256(data). Used by
 * non-EVM paths (e.g. Solana signed token definitions) that want to trust
 * host-supplied data only when a loaded signer attests to it. */
bool signed_metadata_verify_attestation(uint8_t key_id, const uint8_t* data,
                                        size_t data_len, const uint8_t* sig,
                                        size_t sig_len);

/* Verify an attestation only when `pubkey` exactly matches a runtime-loaded
 * signer. This is for protocols whose signed envelope carries the delegate
 * key rather than a keyring slot (ERC-7730). AdvancedMode is enforced here,
 * and the user-approved runtime alias is returned on success. */
bool signed_metadata_verify_runtime_attestation_for_pubkey(
    const uint8_t pubkey[33], const uint8_t* data, size_t data_len,
    const uint8_t* sig, size_t sig_len,
    char out_alias[METADATA_ALIAS_MAX_LEN + 1]);

/* Fingerprint (hex of sha256(pubkey)[0:8]) of the runtime signer loaded in
 * `key_id`, written NUL-terminated to `out`. Returns false if no signer is
 * present. Lets non-EVM callers disambiguate signers (aliases are not unique)
 * the same way the EVM per-tx warning does. */
bool signed_metadata_signer_fingerprint(uint8_t key_id,
                                        char out[METADATA_FINGERPRINT_LEN]);
/* Display gate: does this metadata plausibly describe `msg`? Binds contract
 * address, selector and chain id so the wrong method is never shown. The
 * authoritative full-tx binding is enforced later by signed_metadata_enforce().
 */
bool signed_metadata_matches_tx(const EthereumSignTx* msg);
bool signed_metadata_confirm(void);

/* A certified Uniswap call longer than the first chunk (token -> ETH swaps
 * are 1,028-1,294 B on Base; split routes up to 1,818 B). matches_tx()
 * decodes the first chunk and returns false with ur_pending() true; feed()
 * decodes each later chunk as it arrives (nothing of the call is held) and,
 * at the last byte, matches the whole call: true then means it matched. The
 * caller shows signed_metadata_confirm() only after that. */
bool signed_metadata_ur_pending(void);
bool signed_metadata_ur_feed(const uint8_t* bytes, uint32_t len);

/* True once the user approved the decoded metadata screens, so signing is
 * gated on the metadata matching the final tx hash. On the runtime tier the
 * screens are additive: the ordinary amount and raw-data review still follows
 * them. Only signed_metadata_may_suppress() lets them replace the raw-data
 * review. */
bool signed_metadata_relied(void);

/* Authoritative binding, called after the real Ethereum sighash is finalized
 * (in send_signature, the only point it exists). Returns true if signing may
 * proceed: either no metadata was relied upon, or the relied-upon metadata's
 * committed tx_hash equals `hash`. Fail-closed on any mismatch. */
bool signed_metadata_enforce(const uint8_t hash[32]);

/* Pure enforcement decision, exported for unit testing. Given the module flags
 * and the metadata's committed tx hash, decides whether signing may proceed for
 * the just-finalized `hash`. signed_metadata_enforce() is a thin wrapper that
 * feeds the module state into this function. No state, no I/O. */
bool signed_metadata_enforce_decision(bool relied, bool available,
                                      int classification,
                                      const uint8_t* stored_hash,
                                      const uint8_t* hash);

/* Pure enforcement decision for v2 (static schema) blobs, exported for unit
 * testing. v2 has no committed tx_hash; the binding is structural (args decoded
 * from the signed calldata), so signing proceeds when the relied-upon metadata
 * is available, VERIFIED, and was actually decoded (`decoded`) — no digest
 * comparison. `decoded` must be the recorded result of decode_v2_args() for
 * this signing operation, not inferred from call order.
 * signed_metadata_enforce() dispatches here when the stored blob's version is
 * METADATA_VERSION_SCHEMA. */
bool signed_metadata_enforce_schema_decision(bool relied, bool available,
                                             bool decoded, int classification);

const SignedMetadata* signed_metadata_get(void);

#endif
