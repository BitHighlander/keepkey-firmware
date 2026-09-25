#ifndef KEEPKEY_FIRMWARE_ERC7730_CATALOG_H
#define KEEPKEY_FIRMWARE_ERC7730_CATALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi.h"
#include "keepkey/firmware/signed_metadata.h"
#include "trezor/crypto/sha2.h"

#define ERC7730_PROGRAM_MAX_SIZE (16u * 1024u)
#define ERC7730_TRANSPORT_CHUNK_MAX 1024u
#define ERC7730_CATALOG_MAX_PROOF_DEPTH 16u
#define ERC7730_PROGRAM_HEADER_SIZE 179u
#define ERC7730_PROGRAM_MAX_SECTIONS 9u
#define ERC7730_DELEGATE_RECORD_LEN 139u
#define ERC7730_DELEGATE_ALIAS_LEN 32u
#define ERC7730_DELEGATE_PUBKEY_LEN 33u
#define ERC7730_DELEGATE_OFF_VERSION 0u
#define ERC7730_DELEGATE_OFF_SCOPE 2u
#define ERC7730_DELEGATE_OFF_ALIAS 10u
#define ERC7730_DELEGATE_OFF_PUBKEY 42u
/* Limits shared by the preload verifier and the replay readers. The verifier
 * enforces the readers' limits so a definition that preloads cannot fail a
 * later replay. */
#define ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS 64u
#define ERC7730_LITERAL_MAX_LENGTH 258u

/* Revocation lever. The device keeps no revocation state and never writes
 * flash for it: a firmware update that raises this floor refuses every
 * definition whose signed issuance epoch is below it. Enforced facts are
 * exactly: issuance_epoch >= ERC7730_MIN_ISSUANCE_EPOCH and
 * issuance_epoch >= revocation_epoch (both from the signed header). The
 * header's revocation_epoch and provider_id are otherwise NOT enforced; they
 * are retained in Erc7730CatalogIdentity for hosts and audit only. The floor
 * is 0 because the reference compiler (python-keepkey erc7730_compiler)
 * emits issuance epoch 0 by default. */
#define ERC7730_MIN_ISSUANCE_EPOCH 0u

/* Delegate certificate record (139 bytes), as authenticated today:
 *   [0]        version, must be 1 (checked, not signed);
 *   [2..5]     scope, must equal the header chain id (checked, not signed);
 *   [10..41]   alias, format-checked only; the alias shown to the user is the
 *              one the user approved when loading the runtime signer;
 *   [42..74]   delegate pubkey. It must equal a runtime signer the user
 *              loaded, and the envelope signature must verify under it.
 * Bytes 1, 6..9 and 75..138 are ignored. Real certificates carry a root
 * signature and validity data there that this firmware (which embeds no
 * ClearSign root) cannot check, so they carry no meaning on the device. The
 * envelope signature covers only the purpose tag and the Merkle root, which
 * commits to the program; it does not cover any certificate byte. */

typedef enum {
  ERC7730_DEFINITION_CALLDATA = 1,
  ERC7730_DEFINITION_EIP712 = 2,
  ERC7730_DEFINITION_TOKEN = 3,
  ERC7730_DEFINITION_NETWORK = 4,
} Erc7730DefinitionKind;

typedef enum {
  ERC7730_CATALOG_MORE = 0,
  ERC7730_CATALOG_COMPLETE,
  ERC7730_CATALOG_BAD_SEQUENCE,
  ERC7730_CATALOG_BAD_ENVELOPE,
  ERC7730_CATALOG_BAD_PROGRAM,
  ERC7730_CATALOG_UNTRUSTED,
} Erc7730CatalogResult;

/* Authenticated lookup facts retained after a streamed envelope is accepted.
 * No pointer refers into a transport message and no descriptor bytes survive.
 */
typedef struct {
  uint8_t definition_id[32];
  uint64_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector_or_type_hash[32];
  uint32_t provider_id;
  uint32_t issuance_epoch;
  uint32_t revocation_epoch;
  uint32_t program_length;
  uint32_t envelope_length;
  char delegate_alias[ERC7730_DELEGATE_ALIAS_LEN + 1];
  char delegate_fingerprint[METADATA_FINGERPRINT_LEN];
  uint8_t kind;
} Erc7730CatalogIdentity;

/* Incremental verifier. Its size is bounded independently of descriptor size;
 * callers may place it in a workflow union shared with EIP-712 state. */
typedef struct {
  SHA256_CTX envelope_hash;
  SHA256_CTX leaf_hash;
  uint8_t expected_id[32];
  uint8_t header[ERC7730_PROGRAM_HEADER_SIZE];
  uint8_t cert[ERC7730_DELEGATE_RECORD_LEN];
  uint8_t signature[64];
  uint8_t merkle[32];
  uint8_t sibling[32];
  uint32_t total_length;
  uint32_t received;
  uint32_t program_length;
  uint32_t program_received;
  uint32_t section_remaining;
  uint32_t section_offset;
  uint64_t abi_child_mask;
  uint64_t literal_set_mask;
  uint8_t literal_classes[32];    /* ERC7730_CLASS_* per literal, 4 bits each */
  uint8_t date_strings[12];       /* strings "timestamp"/"blockheight", 1 bit */
  uint8_t short_strings[12];      /* signer strings that fit value screens */
  uint64_t literal_decimals_mask; /* one-byte decimals up to 77 */
  uint8_t path_arrays[64];     /* ABI node of each path's [] step, or 0xff */
  uint64_t path_iterable_mask; /* paths that end on their [] step */
  uint8_t formatter_value_array;
  uint8_t display_iteration_array;
  bool formatter_any_array;
  bool display_in_iteration;
  bool path_array_indexed;
  bool path_last_full;
  uint16_t cert_length;
  uint16_t field_received;
  uint16_t section_mask;
  uint16_t table_counts[8];
  uint16_t abi_node_count;
  uint16_t abi_node_index;
  uint16_t entry_count;
  uint16_t entry_index;
  uint16_t entry_length;
  uint16_t entry_offset;
  uint16_t previous_length;
  uint8_t state;
  uint8_t header_received;
  uint8_t proof_count;
  uint8_t proof_index;
  uint8_t last_section;
  uint8_t sections_seen;
  uint8_t recovery;
  uint8_t abi_max_depth;
  uint8_t max_string_length;
  uint8_t utf8_remaining;
  uint8_t utf8_lower;
  uint8_t utf8_upper;
  uint8_t compare_state;
  uint8_t path_source;
  uint8_t path_step_count;
  uint8_t path_step_index;
  uint8_t path_step_opcode;
  uint8_t path_step_remaining;
  uint8_t path_slice_flags;
  bool path_full_seen;
  uint8_t path_node;
  uint8_t literal_kind;
  uint8_t literal_first;
  uint8_t literal_second;
  uint16_t literal_subcount;
  uint16_t literal_previous;
  uint32_t formatter_roles;
  uint8_t formatter_kind;
  uint8_t formatter_arg_count;
  uint8_t formatter_arg_index;
  uint8_t formatter_last_role;
  uint8_t display_depth;
  bool display_intent_run_closed;
  bool formatter_value_literal;
  uint8_t display_max_depth;
  uint8_t binding_kind;
  uint8_t binding_previous_kind;
  uint16_t binding_previous_length;
  uint8_t binding_domain_fields;
  bool binding_header_match;
  bool leaf_finalized;
  bool failed;
} Erc7730CatalogVerifier;

/* Caller-owned second-pass state, suitable for a workflow scratch union. */
typedef struct {
  Erc7730CatalogVerifier verifier;
  uint32_t program_length;
} Erc7730CatalogReplay;

void erc7730_catalog_begin(Erc7730CatalogVerifier* v,
                           const uint8_t definition_id[32],
                           uint32_t total_length);

Erc7730CatalogResult erc7730_catalog_feed(Erc7730CatalogVerifier* v,
                                          uint32_t offset, const uint8_t* data,
                                          size_t data_len,
                                          Erc7730CatalogIdentity* identity);

void erc7730_catalog_abort(Erc7730CatalogVerifier* v);

/* Single offline-preload slot. Verifier storage is overlaid with the accepted
 * identity after authentication, so both never add together in .bss. */
Erc7730CatalogResult erc7730_catalog_preload_chunk(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset,
    bool* complete);
bool erc7730_catalog_preloaded(Erc7730CatalogIdentity* identity);
bool erc7730_catalog_preloaded_replay_begin(uint8_t definition_id[32],
                                            uint32_t* total_length);
bool erc7730_catalog_preloaded_replay_waiting(uint8_t definition_id[32],
                                              uint32_t* next_offset,
                                              uint32_t* total_length);
Erc7730CatalogResult erc7730_catalog_preloaded_replay_feed(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset, bool* complete,
    uint32_t* program_offset, const uint8_t** program_data,
    size_t* program_data_len);
bool erc7730_catalog_matches_calldata(const Erc7730CatalogIdentity* identity,
                                      uint64_t chain_id,
                                      const uint8_t contract_address[20],
                                      const uint8_t selector[4]);
bool erc7730_catalog_matches_eip712(const Erc7730CatalogIdentity* identity,
                                    uint64_t chain_id,
                                    const uint8_t* verifying_contract,
                                    bool has_verifying_contract,
                                    const uint8_t primary_type_hash[32]);
/* Returned bytes remain untrusted until a complete replay of the envelope has
 * passed erc7730_catalog_feed() for identity->definition_id. */
bool erc7730_catalog_program_chunk(const Erc7730CatalogIdentity* identity,
                                   uint32_t envelope_offset,
                                   const uint8_t* envelope_data,
                                   size_t envelope_data_len,
                                   uint32_t* program_offset,
                                   const uint8_t** program_data,
                                   size_t* program_data_len);
void erc7730_catalog_replay_begin(Erc7730CatalogReplay* replay,
                                  const Erc7730CatalogIdentity* identity);
Erc7730CatalogResult erc7730_catalog_replay_feed(
    Erc7730CatalogReplay* replay, const uint8_t definition_id[32],
    uint32_t offset, uint32_t total_length, const uint8_t* data,
    size_t data_len, uint32_t* program_offset, const uint8_t** program_data,
    size_t* program_data_len, Erc7730CatalogIdentity* accepted_identity);
void erc7730_catalog_clear_preload(void);

#endif
