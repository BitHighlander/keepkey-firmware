/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_SOLANA_H
#define KEEPKEY_FIRMWARE_SOLANA_H

#include "trezor/crypto/bip32.h"
#include "messages-solana.pb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SOL_DECIMALS 9
#define SOL_PUBKEY_SIZE 32
#define SOL_SIG_SIZE 64
#define SOL_MAX_ACCOUNTS 32
/* KKSOLSW1: how many lookup-table-resolved accounts a provider may attest for
   one transaction. Bounded because the preimage and the screens are both
   linear in it, and because a provider that needs to name more than eight
   accounts is describing something the user cannot meaningfully review. */
#define SOL_MAX_LUT_ACCOUNTS 8
#define SOL_MAX_INSTRUCTIONS 8
#define SOL_LAMPORTS_DIVISOR 1000000000ULL
#define SOL_MAX_TOKEN_DECIMALS 18
#define SOL_MAX_DISPLAY_DECIMALS 9

/* Versioned transaction marker */
#define SOL_VERSION_FLAG 0x80
#define SOL_VERSION_MASK 0x7F

/* Compact-u16 encoding constants */
#define SOL_COMPACT_U16_CONTINUATION 0x80
#define SOL_COMPACT_U16_DATA_MASK 0x7F
#define SOL_COMPACT_U16_BYTE3_MAX 3

/* System program instruction indices */
#define SOL_SYS_CREATE_ACCOUNT 0
#define SOL_SYS_ASSIGN 1
#define SOL_SYS_TRANSFER 2
#define SOL_SYS_ADVANCE_NONCE 4
#define SOL_SYS_WITHDRAW_NONCE 5
#define SOL_SYS_INITIALIZE_NONCE 6
#define SOL_SYS_AUTHORIZE_NONCE 7
#define SOL_SYS_ALLOCATE 8

/* SPL Token program instruction indices */
#define SOL_TOKEN_TRANSFER_IX 3
#define SOL_TOKEN_APPROVE_IX 4
#define SOL_TOKEN_REVOKE_IX 5
#define SOL_TOKEN_SET_AUTHORITY_IX 6
#define SOL_TOKEN_MINT_TO_IX 7
#define SOL_TOKEN_BURN_IX 8
#define SOL_TOKEN_CLOSE_ACCOUNT_IX 9
#define SOL_TOKEN_FREEZE_ACCOUNT_IX 10
#define SOL_TOKEN_THAW_ACCOUNT_IX 11
#define SOL_TOKEN_TRANSFER_CHECKED_IX 12
#define SOL_TOKEN_MINT_TO_CHECKED_IX 14
#define SOL_TOKEN_BURN_CHECKED_IX 15
#define SOL_TOKEN_SYNC_NATIVE_IX 17

/* Stake program instruction indices */
#define SOL_STAKE_AUTHORIZE_IX 1
#define SOL_STAKE_DELEGATE_IX 2
#define SOL_STAKE_SPLIT_IX 3
#define SOL_STAKE_WITHDRAW_IX 4
#define SOL_STAKE_DEACTIVATE_IX 5
#define SOL_STAKE_MERGE_IX 7

/* Vote program instruction indices */
#define SOL_VOTE_AUTHORIZE_IX 1
#define SOL_VOTE_WITHDRAW_IX 3
#define SOL_VOTE_UPDATE_VALIDATOR_IX 4
#define SOL_VOTE_UPDATE_COMMISSION_IX 5

/* Compute Budget program instruction indices */
#define SOL_CB_REQUEST_HEAP_FRAME 1
#define SOL_CB_SET_COMPUTE_UNIT_LIMIT 2
#define SOL_CB_SET_COMPUTE_UNIT_PRICE 3
#define SOL_CB_SET_LOADED_ACCOUNTS_SIZE 4

/* Well-known program IDs */
extern const uint8_t SOL_SYSTEM_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_TOKEN_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_TOKEN_2022_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_STAKE_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_VOTE_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_ATA_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_COMPUTE_BUDGET_PROGRAM[SOL_PUBKEY_SIZE];
extern const uint8_t SOL_MEMO_PROGRAM[SOL_PUBKEY_SIZE];

/* Instruction types recognized by the parser */
typedef enum {
  SOL_INSTR_SYSTEM_TRANSFER,
  SOL_INSTR_SYSTEM_CREATE_ACCOUNT,
  SOL_INSTR_SYSTEM_ADVANCE_NONCE,
  SOL_INSTR_SYSTEM_WITHDRAW_NONCE,
  SOL_INSTR_SYSTEM_INITIALIZE_NONCE,
  SOL_INSTR_SYSTEM_AUTHORIZE_NONCE,
  SOL_INSTR_SYSTEM_ASSIGN,
  SOL_INSTR_SYSTEM_ALLOCATE,
  SOL_INSTR_TOKEN_TRANSFER,
  SOL_INSTR_TOKEN_TRANSFER_CHECKED,
  SOL_INSTR_TOKEN_APPROVE,
  SOL_INSTR_TOKEN_REVOKE,
  SOL_INSTR_TOKEN_SET_AUTHORITY,
  SOL_INSTR_TOKEN_MINT_TO,
  SOL_INSTR_TOKEN_BURN,
  SOL_INSTR_TOKEN_CLOSE_ACCOUNT,
  SOL_INSTR_TOKEN_FREEZE_ACCOUNT,
  SOL_INSTR_TOKEN_THAW_ACCOUNT,
  SOL_INSTR_TOKEN_SYNC_NATIVE,
  SOL_INSTR_STAKE_DELEGATE,
  SOL_INSTR_STAKE_WITHDRAW,
  SOL_INSTR_STAKE_AUTHORIZE,
  SOL_INSTR_STAKE_SPLIT,
  SOL_INSTR_STAKE_DEACTIVATE,
  SOL_INSTR_STAKE_MERGE,
  SOL_INSTR_VOTE_AUTHORIZE,
  SOL_INSTR_VOTE_WITHDRAW,
  SOL_INSTR_VOTE_UPDATE_VALIDATOR,
  SOL_INSTR_VOTE_UPDATE_COMMISSION,
  SOL_INSTR_ATA_CREATE,
  SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME,
  SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT,
  SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE,
  SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE,
  SOL_INSTR_MEMO,
  SOL_INSTR_UNKNOWN,
} SolanaInstrType;

/* Parsed instruction */
typedef struct {
  SolanaInstrType type;
  uint8_t program_id[SOL_PUBKEY_SIZE];
  /* Decoded fields (filled based on type) */
  uint8_t from[SOL_PUBKEY_SIZE];
  uint8_t to[SOL_PUBKEY_SIZE];
  uint8_t authority[SOL_PUBKEY_SIZE];
  uint8_t extra[SOL_PUBKEY_SIZE];
  uint64_t amount;
  uint64_t lamports;
  uint64_t extra_value;
  /* For token transfers */
  uint8_t mint[SOL_PUBKEY_SIZE];
  bool has_mint;
  uint8_t extra_u8;
  /* Points into solana_inspectTx's buffer; valid only while it is. */
  const uint8_t* data;
  uint16_t data_len;
  /* Same lifetime as `data`. */
  const uint8_t* acct_indices;
  uint8_t num_acct_indices;
  /* True when this instruction reaches into an unresolved address-lookup
   * table. A certified parse appends the delegate-attested canonical lookup
   * keys before decoding, so successfully resolved instructions are false. */
  bool external;
} SolanaParsedInstruction;

/* Parsed transaction header */
typedef struct {
  uint8_t num_required_sigs;
  uint8_t num_readonly_signed;
  uint8_t num_readonly_unsigned;
  uint8_t num_accounts;
  /* How many of `accounts` are the message's own static keys. The rest, when
   * a certified parse appended them, are lookup-table keys the signed bytes
   * reference only by index. */
  uint8_t num_static_accounts;
  uint8_t accounts[SOL_MAX_ACCOUNTS][SOL_PUBKEY_SIZE];
  uint8_t recent_blockhash[SOL_PUBKEY_SIZE];
  /* True when a v0 message contains at least one serialized address lookup
   * table entry. This remains true after certified resolution and lets the
   * policy layer distinguish an unknown self-contained program (schema-only
   * certification is sufficient) from an externally-resolved transaction
   * (a transaction-bound LUT proof is mandatory). */
  bool has_address_lookups;
  uint8_t num_instructions;
  SolanaParsedInstruction instructions[SOL_MAX_INSTRUCTIONS];
} SolanaParsedTx;

/* Firmware review result for a Solana message */
typedef enum {
  SOL_TX_REVIEW_MALFORMED = 0,
  SOL_TX_REVIEW_OPAQUE,
  SOL_TX_REVIEW_VERIFIED,
} SolanaTxReview;

/* Firmware-owned tokens: only stable mint/decimals identities. */
typedef struct {
  uint8_t mint[SOL_PUBKEY_SIZE];
  const char* symbol;
  uint8_t decimals;
} SolanaKnownToken;

/* ── KKSOLSC1: reusable instruction schemas, attested once per (program,
 * discriminator); values are decoded from the signed bytes. Safety is
 * structural completeness: disc + arg widths == data length EXACTLY; every
 * displayed account index exists; lookup-table accounts only once bound to
 * this transaction by a Solana ClearSign certificate; every OTHER instruction
 * is one firmware already recognises.
 *
 * Canonical payload (all integers big-endian, text printable ASCII, no '%'):
 *   magic          8   "KKSOLSC1"
 *   version        1   1 or 2
 *   program_id    32
 *   disc_len       1   1..8
 *   discriminator  disc_len
 *   program name   1 + 1..SOL_SCHEMA_NAME_MAX
 *   instr name     1 + 1..SOL_SCHEMA_NAME_MAX
 *   n_args         1   0..4 (v1), 0..SOL_SCHEMA_MAX_ARGS (v2)
 *     per arg:     type(1) label_len(1) label
 *     TOKEN_AMOUNT (v2) appends mint_account(1)
 *   n_accounts     1   0..SOL_SCHEMA_MAX_ACCOUNTS
 *     per account: index(1) label_len(1) label
 * No bytes may follow. Args are laid out sequentially from the end of the
 * discriminator, in declaration order.
 */
#define SOL_SCHEMA_NAME_MAX 20
#define SOL_SCHEMA_LABEL_MAX 16
#define SOL_SCHEMA_V1_MAX_ARGS 4
#define SOL_SCHEMA_MAX_ARGS 8
#define SOL_SCHEMA_MAX_ACCOUNTS 4
#define SOL_SCHEMA_DISC_MAX 8

typedef enum {
  SOL_SCHEMA_ARG_U64 = 1,      /* 8 bytes, shown as a decimal integer */
  SOL_SCHEMA_ARG_U8 = 2,       /* 1 byte */
  SOL_SCHEMA_ARG_PUBKEY = 3,   /* 32 bytes, shown base58 */
  SOL_SCHEMA_ARG_OPAQUE32 = 4, /* 32 bytes, shown in full over pages */
  SOL_SCHEMA_ARG_LAMPORTS = 5, /* 8 bytes, shown as decimal SOL */
  /* v2: 8-byte raw amount of the token whose mint is instruction account
   * mint_account. Scaled and named only by a trusted token definition for
   * that mint; otherwise shown raw beside the full mint address. */
  SOL_SCHEMA_ARG_TOKEN_AMOUNT = 6,
  SOL_SCHEMA_ARG_DURATION = 7, /* v2: 8-byte seconds, shown in exact units */
} SolanaSchemaArgType;

typedef struct {
  SolanaSchemaArgType type;
  char label[SOL_SCHEMA_LABEL_MAX + 1];
  uint8_t mint_account; /* TOKEN_AMOUNT only; fits the struct's padding */
} SolanaSchemaArg;

typedef struct {
  uint8_t index;
  char label[SOL_SCHEMA_LABEL_MAX + 1];
} SolanaSchemaAccount;

typedef struct {
  uint8_t program_id[SOL_PUBKEY_SIZE];
  uint8_t disc[SOL_SCHEMA_DISC_MAX];
  uint8_t disc_len;
  char program_name[SOL_SCHEMA_NAME_MAX + 1];
  char instruction_name[SOL_SCHEMA_NAME_MAX + 1];
  SolanaSchemaArg args[SOL_SCHEMA_MAX_ARGS];
  uint8_t num_args;
  SolanaSchemaAccount accounts[SOL_SCHEMA_MAX_ACCOUNTS];
  uint8_t num_accounts;
} SolanaInstrSchema;

/* Bytes one arg consumes; 0 = unknown type (rejected). */
uint16_t solana_schemaArgWidth(SolanaSchemaArgType t);

bool solana_parseInstrSchema(const uint8_t* payload, size_t payload_len,
                             SolanaInstrSchema* out);

/* Find the described instruction and enforce the KKSOLSC1 safety rules
 * above; returns its index via `out_index`. */
bool solana_schemaApplies(const SolanaInstrSchema* schema,
                          const SolanaParsedTx* tx, uint8_t* out_index);

/* The same proof for a root-certified schema, of either version, which
 * additionally admits SystemProgram Transfer companions whose every account is
 * one of the message's static keys: the certified review renders each one in
 * full (funding account, amount, destination) through
 * solana_confirmInstruction, and its destination is then always a key the
 * signed bytes contain, never one a lookup-table proof resolved. */
bool solana_schemaAppliesCertified(const SolanaInstrSchema* schema,
                                   const SolanaParsedTx* tx,
                                   uint8_t* out_index);

/* DURATION display in exact units: whole days, else whole hours, else whole
 * minutes, else seconds ("N d", "N h", "N min", "N s"). */
void solana_formatDuration(char* buf, size_t len, uint64_t seconds);

/* The token definition that may name and scale a schema TOKEN_AMOUNT for
 * `mint`, or NULL. Each review tier keeps its own trust root: a certified
 * review accepts only a definition signed by the certificate's delegate
 * ("KeepKeySolanaTokenDef/2", the certified Pump token attestation, for the
 * SPL Token or Token-2022 program); a runtime review only one attested by the
 * user-loaded signer that signed the schema (solana_token_info_trusted, and
 * signer_key_id == msg->schema_signer_key_id). Either way the decimals must be
 * displayable (<= SOL_MAX_DISPLAY_DECIMALS), the symbol a bare ticker, and the
 * symbol not one the firmware's known-token table gives to another mint
 * (compared ignoring case): a "USDC" definition for any mint but Circle's is
 * not trusted, and the amount is shown raw beside its mint. */
const SolanaTokenInfo* solana_schemaTrustedToken(
    const SolanaSignTx* msg, const uint8_t mint[SOL_PUBKEY_SIZE],
    bool certified);

/* TOKEN_AMOUNT display, always ending in the full mint address on its own
 * row. With a trusted definition: the amount scaled by its decimals and
 * labelled with its symbol ("1000 SDICE\n<mint>") -- a symbol names a
 * token but does not identify one, since anyone can mint a "USDC". Without
 * one: the raw integer ("N base units of mint\n<mint>") -- never a guessed
 * scale or symbol. False only when the mint cannot be encoded, and the caller
 * must then refuse. */
bool solana_formatSchemaTokenAmount(char* buf, size_t len, uint64_t amount,
                                    const uint8_t mint[SOL_PUBKEY_SIZE],
                                    const SolanaTokenInfo* trusted);

/* The token definition resolved for the last TOKEN_AMOUNT mint of one review,
 * so each mint's definition is verified once. Zero it before the first arg. */
typedef struct {
  const uint8_t* mint;
  const SolanaTokenInfo* token;
} SolanaSchemaTokenCache;

/* The display text of schema arg `arg` of instruction `ix`, whose value
 * starts at `data` (inside ix->data; the applies check proved the whole arg
 * is there). A TOKEN_AMOUNT's mint is the tx key of the instruction's own
 * account arg->mint_account -- parsed->accounts[ix->acct_indices[...]] -- and
 * only a definition trusted in this review's tier (`certified`) may scale and
 * name it. OPAQUE32 has no text form: the caller pages its bytes instead of
 * calling this. False for OPAQUE32 and for any value that cannot be shown;
 * the caller must then refuse. */
bool solana_schemaArgValue(const SolanaSignTx* msg, bool certified,
                           const SolanaParsedTx* parsed,
                           const SolanaParsedInstruction* ix,
                           const SolanaSchemaArg* arg, const uint8_t* data,
                           SolanaSchemaTokenCache* cache, char* buf,
                           size_t len);

/* Inspect a raw Solana transaction and classify it for signing UX */
SolanaTxReview solana_inspectTx(const uint8_t* raw, size_t raw_len,
                                SolanaParsedTx* tx);

/* Inspect a v0 message after appending the canonical lookup-table account list
 * attested for this exact message. The account order is the Solana runtime
 * order: all writable lookup keys followed by all readonly lookup keys, across
 * the message's lookup entries. The parser proves the serialized lookup index
 * count equals `num_lut_accounts`; it never accepts extra or missing keys.
 * Trust verification is deliberately outside this parser and MUST happen
 * before a caller uses the result to suppress Advanced Mode. */
SolanaTxReview solana_inspectTxWithTrustedLut(
    const uint8_t* raw, size_t raw_len,
    const uint8_t (*lut_accounts)[SOL_PUBKEY_SIZE], size_t num_lut_accounts,
    SolanaParsedTx* tx);

/* Plain text (printable ASCII or '\n') not containing `pubkey`, so it cannot
 * authorize a transaction. */
bool solana_rawMessageIsPlainText(const uint8_t* msg, size_t len,
                                  const uint8_t pubkey[SOL_PUBKEY_SIZE]);

/* Parse a raw Solana transaction */
bool solana_parseTx(const uint8_t* raw, size_t raw_len, SolanaParsedTx* tx);

/* Format SOL amount */
void solana_formatAmount(char* buf, size_t len, uint64_t lamports);

/* Format token amount with decimals */
void solana_formatTokenAmount(char* buf, size_t len, uint64_t amount,
                              const char* symbol, uint8_t decimals);

/* Look up a firmware-owned token identity by its signed mint account. */
const SolanaKnownToken* solana_findKnownToken(
    const uint8_t mint[SOL_PUBKEY_SIZE]);

/* Canonical SPL ATA for (owner, token_program, mint). */
bool solana_deriveAssociatedTokenAddress(
    const uint8_t owner[SOL_PUBKEY_SIZE],
    const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]);

/* Accept a host-proposed owner only if its ATA equals the signed
 * destination; `out` is untouched on false. */
bool solana_findTokenRecipientOwner(
    const SolanaSignTx* msg, const uint8_t token_program[SOL_PUBKEY_SIZE],
    const uint8_t mint[SOL_PUBKEY_SIZE],
    const uint8_t destination[SOL_PUBKEY_SIZE], uint8_t out[SOL_PUBKEY_SIZE]);

/* Look up token info from the host-provided list */
const SolanaTokenInfo* solana_findTokenInfo(
    const SolanaSignTx* msg, const uint8_t mint[SOL_PUBKEY_SIZE]);

/* Valid user-loaded-signer attestation over (mint, decimals, symbol). The
 * caller must still match decimals to the signed instruction. */
bool solana_token_info_trusted(const SolanaTokenInfo* ti);

/* Label for a signed TransferChecked amount: the firmware-table symbol, or an
 * attested symbol whose decimals equal the signed ones; NULL otherwise. */
const char* solana_displaySymbol(const SolanaTokenInfo* ti,
                                 const SolanaKnownToken* known,
                                 uint8_t signed_decimals);

/* Solana per-transaction compute-unit cap; also bounds an explicit limit. */
#define SOL_MAX_COMPUTE_UNITS 1400000u

/* KKSOLSW1: is the host-supplied lookup-table account list attested by a
 * clear-sign signer FOR THIS EXACT TRANSACTION?
 *
 * A v0 message may source instruction accounts from an Address Lookup Table.
 * Those bytes are not in the message being signed, so the device cannot derive
 * them and forces the whole transaction opaque -- refused without AdvancedMode,
 * an explicit blind sign with it. A runtime provider may attest the resolved
 * list, which is shown before that blind-sign warning (annotation only); a
 * root-certified delegate's proof is what lets a certified schema clear-sign.
 *
 * Preimage, domain-tagged so a signature made for any other purpose cannot be
 * replayed as one, and bound to the message so it cannot be replayed onto a
 * different transaction:
 *
 *   "KeepKeySolanaTxAccounts/1" || sha256(message) || count(le32) || key[i](32)
 *
 * where message is raw_tx without a leading zero signature count, i.e. the
 * bytes the device signs.
 *
 * Returns false unless a signer is loaded for `key_id` and the signature
 * verifies. Annotation only: the caller still runs the unverified review. */
bool solana_lut_accounts_trusted(const uint8_t* raw_tx, size_t raw_len,
                                 const uint8_t (*accounts)[32],
                                 size_t num_accounts, uint32_t signer_key_id,
                                 const uint8_t* sig, size_t sig_len);

/* Certified KKSOLSW1 verification. Unlike the runtime helper above, this uses
 * the delegate carried by a KeepKey root certificate scoped to Solana (501),
 * so it is independent of session signer slots and Advanced Mode. */
bool solana_lut_accounts_certified(const uint8_t* raw_tx, size_t raw_len,
                                   const uint8_t (*accounts)[32],
                                   size_t num_accounts,
                                   const uint8_t* certificate,
                                   size_t certificate_len, const uint8_t* sig,
                                   size_t sig_len);

/* ceil(price * min(limit, SOL_MAX_COMPUTE_UNITS) / 1e6) lamports; false on
 * > UINT64_MAX (refuse). */
bool solana_priority_fee_lamports(uint64_t price, uint64_t limit,
                                  uint64_t* out);

/* Sign transaction */
bool solana_signTx(const HDNode* node, const SolanaSignTx* msg,
                   SolanaSignedTx* resp);

/* Sign a Solana off-chain message with domain separation.
 *
 * Builds the spec envelope (0xFF || "solana offchain" || version || format
 * || length:u16 || message) and Ed25519-signs it. Format 2 (extended
 * UTF-8) is rejected — only formats 0 (ASCII) and 1 (UTF-8 limited) are
 * supported on this device.
 *
 * Caller must have populated node->public_key (hdnode_fill_public_key).
 */
bool solana_offchain_message_sign(const HDNode* node,
                                  const SolanaSignOffchainMessage* msg,
                                  SolanaOffchainMessageSignature* resp);

#endif /* KEEPKEY_FIRMWARE_SOLANA_H */
