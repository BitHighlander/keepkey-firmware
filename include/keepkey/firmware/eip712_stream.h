/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * Portions derived from OneKey firmware-classic1s
 * (legacy/firmware/ethereum_typed_data.h, commit 885e51d3), which is
 * LGPL-3.0-or-later and itself carries the Trezor copyright chain
 * (Alex Beregszaszi, Pavol Rusnak, Jochen Hoenicke). The encodeData rules,
 * the value validation and the encodeType dependency closure follow that
 * implementation; the memory design does not -- see eip712_stream.c.
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

#ifndef KEEPKEY_FIRMWARE_EIP712_STREAM_H
#define KEEPKEY_FIRMWARE_EIP712_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "messages-ethereum.pb.h"

/* Longest type string we render: a struct name (< EIP712_MAX_STRUCT_NAME) or
 * an elementary type, plus array suffixes such as "[10][10][10][10]". */
#define EIP712_MAX_TYPE_NAME 112

/* Nesting bound and C-stack recursion bound; checked BEFORE descending. Each
 * nested struct and each array dimension is one frame: UniswapX's V3 Dutch
 * order witness.baseOutputs[i].curve.relativeAmounts needs six. */
#define EIP712_MAX_DEPTH 6

/* Longest review path ("witness.baseOutputs[0].curve.relativeAmounts[0]"),
 * with its NUL. The member names along the open frames share one buffer of
 * this size: whatever fits the path fits the buffer. */
#define EIP712_MAX_PATH 160

/* Shared pool of 32-byte member encodings; a completed container collapses to
 * one digest in its parent's slot. Only ONE SHA3_CTX (~400 B) is ever live,
 * which is what fits SRAM. Struct widths along a path add up. The outermost
 * open array hashes its elements as they arrive and takes no slots, so
 * Seaport needs 11 + 6 whatever its item counts. An array of fixed-size
 * leaves nested inside it hashes into that one SHA3_CTX, so a UniswapX V3
 * curve inside baseOutputs[] takes none; any other nested array takes one
 * slot per element. */
#define EIP712_MAX_SLOTS 24

/* Widest value one EthereumTypedDataValueAck carries, and the chunk size of a
 * longer one. */
#define EIP712_MAX_LEAF 1024

/* Longest dynamic `bytes` or `string` value, sent in EIP712_MAX_LEAF chunks
 * that are hashed and shown as they arrive, never held whole. Real documents
 * run past 64 KB: Safe MultiSend data to 174,084 B (ENS endowment Safe) and
 * Snapshot bodies to 50,000 characters, up to 150,000 B of UTF-8. 1 MiB is
 * more than a mainnet block's worth of non-zero calldata. */
#define EIP712_MAX_VALUE (1024u * 1024u)

/* Distinct struct types one primary type may reference, including itself.
 * Permit2's PermitSingle needs 2, Seaport's OrderComponents 3, Across 4, a
 * UniswapX PriorityOrder witness 6 and a UniswapX V3DutchOrder witness 7. */
#define EIP712_MAX_STRUCTS 7

/* The wire allows 80; each byte costs EIP712_MAX_STRUCTS + 4 of SRAM. 48 holds
 * Hyperliquid's "HyperliquidTransaction:ApproveBuilderFee" (40). */
#define EIP712_MAX_STRUCT_NAME 48

/* Member names: hashed, and shown in every review path. */
#define EIP712_MAX_MEMBER_NAME 32

/* A domain member the facts cannot hold (Ethermint's string verifyingContract
 * and salt, chainId 0, a name that is not a string) is shown and hashed, but
 * nothing may bind to that domain. */
#define EIP712_DOMAIN_UNBINDABLE 0x80

typedef struct {
  uint64_t chain_id;
  uint8_t verifying_contract[20];
  uint8_t primary_type_hash[32];
  bool has_chain_id;
  bool has_verifying_contract;
  bool has_primary_type_hash;
  uint8_t domain_hashes[3][32]; /* name, version, salt */
  /* Bit i: member i (name, version, salt, chainId, verifyingContract) was
   * seen, plus EIP712_DOMAIN_UNBINDABLE. */
  uint8_t domain_present;
} Eip712DomainFacts;

/* Canonical ASCII identifier: the bytes hashed are the bytes rendered. Member
 * names are [A-Za-z_$][A-Za-z0-9_$]*, shorter than EIP712_MAX_MEMBER_NAME. */
bool eip712_identifier_ok(const char* name);

/* A struct type name: as a member name, but ':' may follow the first
 * character ("HyperliquidTransaction:UsdSend"), and shorter than
 * EIP712_MAX_STRUCT_NAME. ':' is never one of encodeType's delimiters. */
bool eip712_type_identifier_ok(const char* name);

/* Member list by struct name, NULL if not supplied. Unit tests back it with
 * a fixture table. */
typedef const EthereumTypedDataStructAck* (*Eip712StructLookup)(
    const char* name, void* ctx);

/* Assemble encodeType(name) and hash it, per EIP-712:
 *
 *   encodeType = <primary segment> || <each referenced struct, SORTED BY NAME>
 *
 * The sort is the part the old parser got wrong: eip712.c appended referenced
 * definitions in DISCOVERY order and there is no sort call anywhere in it, so
 * two structs named out of alphabetical order produced a typeHash no compliant
 * verifier reproduces -- an internally consistent device signing something
 * nobody else agrees the document says.
 *
 * Returns false if a referenced struct is missing, the closure exceeds
 * EIP712_MAX_STRUCTS, or any member type cannot be spelled. */
bool eip712_type_hash(const char* name, Eip712StructLookup lookup, void* ctx,
                      uint8_t out[32]);

/* Render a field's Solidity type exactly as encodeType must spell it --
 * "uint256", "bytes32", "Person[3]", "int16[2][][4]". This string is part of
 * typeHash, so a divergence here is a divergence in the signature.
 * Returns false if the type is not expressible or would overflow `out`. */
bool eip712_type_name(const EthereumTypedDataStructAck_EthereumFieldType* field,
                      char* out, size_t out_len);

/* Encode one validated leaf into exactly 32 bytes, per EIP-712 encodeData.
 * `value`/`value_len` are the raw big-endian bytes from the host. */
bool eip712_encode_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len, uint8_t out[32]);

/* A validated uintN/intN leaf (exactly N big-endian bytes) in decimal, signed
 * for intN. This is the text the review screen shows. */
bool eip712_render_integer(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t len, char* out, size_t out_size);

/* Reject a leaf whose bytes cannot mean what its declared type says.
 * Runs BEFORE encoding and before display, so nothing unvalidated is shown. */
bool eip712_validate_leaf(
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len);

/* Keep only facts the domain stream proves; duplicates fail closed. A member
 * of a type the facts cannot hold marks them unbindable instead of failing. */
bool eip712_domain_facts_observe(
    Eip712DomainFacts* facts, const char* member_name,
    const EthereumTypedDataStructAck_EthereumFieldType* field,
    const uint8_t* value, uint16_t value_len);

bool eip712_stream_domain_facts(Eip712DomainFacts* facts);
/* The domain separator (source 5) or the primary type hash (source 6) of the
 * document being walked, for ERC-7730 container paths. */
bool eip712_stream_container_hash(uint16_t source_index, uint8_t value[32]);
/* The signing account's path while a certified definition is in use, so the
 * ERC-7730 runtime can recognise the signer's own address. */
bool eip712_stream_signer_path(uint32_t address_n[6], size_t* count);
bool eip712_stream_domain_matches(uint8_t field, uint8_t literal_kind,
                                  const uint8_t* value, size_t length,
                                  bool require_absent);

/* ── The walk ────────────────────────────────────────────────────────
 *
 * KeepKey has no blocking request/response primitive. wait_for_tiny_msg is a
 * 64-byte channel for ButtonAck and PinAck; a StructAck is 6 KB. OneKey drives
 * its walk from a re-entrant call() that pumps usbPoll() from inside a handler,
 * and that cannot be transplanted here.
 *
 * So the walk is a RESUMABLE state machine. Each handler runs to completion,
 * emits at most one request, and returns; the next Ack resumes it. State lives
 * in one static block, and the member_path is the cursor.
 *
 * Two sequential machines:
 *   A. typeHash -- for the struct a frame is about to hash, stream its
 *      encodeType closure and cache the digest.
 *   B. values   -- walk members, absorbing each leaf as it is displayed.
 */

typedef enum {
  EIP712_IDLE = 0,
  EIP712_WANT_STRUCT, /* a StructAck will arrive next */
  EIP712_WANT_VALUE,  /* a ValueAck will arrive next */
  EIP712_FAILED,
} Eip712Wait;

/* What the machine wants next. The walk never writes a message: RESP_INIT uses
 * msg_resp, which is private to fsm.c, and keeping key material and the wire
 * out of the walk is what lets the whole thing be unit-tested. */
typedef enum {
  EIP712_REQ_NONE = 0,
  EIP712_REQ_STRUCT,     /* send EthereumTypedDataStructRequest */
  EIP712_REQ_VALUE,      /* send EthereumTypedDataValueRequest */
  EIP712_REQ_DEFINITION, /* authenticate the preloaded ERC-7730 program */
  EIP712_REQ_DONE,       /* both hashes ready: derive, sign, respond */
  EIP712_REQ_FAIL,       /* send Failure(error) */
  EIP712_REQ_CANCELLED,  /* the user declined a screen */
} Eip712ReqKind;

/* A canonical Uniswap Permit2 PermitSingle (domain = the Permit2 contract,
 * type hash = the published one), captured from the hashed bytes so the
 * device can describe it in words before signing (SRS-7.16 §3.7). */
typedef struct {
  bool valid;
  uint64_t chain_id;
  uint8_t token[20];
  uint8_t amount[20];  /* uint160, big-endian */
  uint64_t expiration; /* uint48 */
  uint64_t nonce;      /* uint48 */
  uint8_t spender[20];
  uint8_t sig_deadline[32]; /* uint256, big-endian */
} Eip712Permit2;

extern const uint8_t EIP712_PERMIT2_ADDRESS[20];

typedef bool (*Eip712ReviewEmit)(void* ctx, const char* title,
                                 const char* body);

/* Summary, limits, details, who. spender_name is a ClearSign-vouched name
 * for the spender (NULL if none); alias/fp name the vouching delegate. */
bool eip712_permit2_review(const Eip712Permit2* p, const char* spender_name,
                           const char* alias, const char* fp,
                           Eip712ReviewEmit emit, void* ctx);

/* "2026-05-10 06:19 UTC"; Unix time past year 9999 is shown as a number. */
void eip712_format_utc(uint64_t t, char* out, size_t len);

typedef struct {
  Eip712ReqKind kind;
  char struct_name[EIP712_MAX_STRUCT_NAME];
  uint32_t member_path[EIP712_MAX_DEPTH + 2];
  uint8_t member_path_len;
  /* A chunked value: the offset of the bytes wanted next. */
  bool has_value_offset;
  uint32_t value_offset;
  const char* error;
  uint8_t domain_separator[32];
  uint8_t message_hash[32];
  uint32_t address_n[6];
  size_t address_n_count;
  /* For the final signing screen. */
  char primary_type[EIP712_MAX_STRUCT_NAME];
  bool message_empty;
  bool domain_empty; /* no domain member was shown: it has none */
  bool domain_only;  /* primaryType EIP712Domain: sign keccak(0x1901 || ds) */
  Eip712Permit2 permit2; /* valid: review it in words before signing */
} Eip712Next;

const Eip712Next* eip712_stream_next(void);

/* Begin a signing session. Fills in the first request. */
bool eip712_stream_begin(const EthereumSignTypedData* msg,
                         bool require_definition);
bool eip712_stream_definition_accepted(void);
/* Resume the first certified field or replay message values for the next.
 * The reviewed domain and signing path remain fixed across these passes. */
bool eip712_stream_resume_for_field(void);

/* False = session torn down and EIP712_REQ_FAIL or EIP712_REQ_CANCELLED
 * staged; the caller must still pump it to send the terminal response. */
bool eip712_stream_on_struct(const EthereumTypedDataStructAck* ack);
bool eip712_stream_on_value(const EthereumTypedDataValueAck* ack);

/* True while a session is live, so the FSM can reject an out-of-order Ack. */
Eip712Wait eip712_stream_waiting(void);

/* Drop all session state. Called on completion, failure, Initialize and
 * ClearSession -- a half-walked document must never survive into the next one.
 */
void eip712_stream_abort(void);

#endif /* KEEPKEY_FIRMWARE_EIP712_STREAM_H */
