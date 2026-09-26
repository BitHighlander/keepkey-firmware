#ifndef KEEPKEY_FIRMWARE_ERC7730_WORKFLOW_H
#define KEEPKEY_FIRMWARE_ERC7730_WORKFLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi_stream.h"
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_format.h"
#include "keepkey/firmware/erc7730_program.h"
#include "keepkey/firmware/erc7730_tx.h"
#include "trezor/crypto/sha2.h"

typedef enum {
  ERC7730_WORKFLOW_IDLE = 0,
  ERC7730_WORKFLOW_REPLAY,
  ERC7730_WORKFLOW_SELECT,
  ERC7730_WORKFLOW_READY,
  ERC7730_WORKFLOW_CALLDATA,
  ERC7730_WORKFLOW_TYPED_DATA,
  ERC7730_WORKFLOW_COMPLETE,
  ERC7730_WORKFLOW_FAILED,
} Erc7730WorkflowPhase;

typedef enum {
  ERC7730_SELECTION_NONE = 0,
  ERC7730_SELECTION_DISPLAY,
  ERC7730_SELECTION_STRING,
  ERC7730_SELECTION_FORMATTER,
  ERC7730_SELECTION_PATH,
  ERC7730_SELECTION_LITERAL,
} Erc7730SelectionKind;

typedef enum {
  ERC7730_DISPLAY_NONE = 0,
  ERC7730_DISPLAY_INTENT_STRING,
  ERC7730_DISPLAY_INSTRUCTION,
  ERC7730_DISPLAY_LABEL,
  ERC7730_DISPLAY_FORMATTER,
  ERC7730_DISPLAY_PATH,
  ERC7730_DISPLAY_DOMAIN_STRING,
  ERC7730_DISPLAY_ARG_LITERAL,  /* a literal argument or literal path */
  ERC7730_DISPLAY_ARG_STRING,   /* the string a raw literal refers to */
  ERC7730_DISPLAY_ARG_ALIAS,    /* one native-asset alias address */
  ERC7730_DISPLAY_ARG_MESSAGE,  /* the field's string: message, date
                                   encoding, unit base or enum label */
  ERC7730_DISPLAY_ARG_ENUM_KEY, /* one enum entry's key */
} Erc7730DisplayStage;

/* The most arguments an executable formatter carries (tokenAmount: value,
 * token, threshold, message, aliases). */
#define ERC7730_FIELD_MAX_ARGUMENTS 5u

/* One field's formatter arguments, resolved one at a time: each may need its
 * own definition replay or calldata pass. Only what a later argument or the
 * final screen needs is kept. */
typedef struct {
  Erc7730FormatterArgument arguments[ERC7730_FIELD_MAX_ARGUMENTS];
  uint8_t kind;
  uint8_t argument_count;
  uint8_t next_argument;
  uint8_t pending_role;
  uint8_t value[32];   /* the role-1 word, for every kind but raw/addressName */
  uint8_t address[20]; /* tokenAmount token, nftName collection */
  union {
    uint16_t aliases[ERC7730_CAP_ALIAS_SET_MAX];    /* tokenAmount */
    uint16_t enum_entries[ERC7730_CAP_ENUM_MAX][2]; /* enum: key, label */
  } list;
  uint16_t text; /* the one string an argument names, fetched last */
  uint8_t list_count;
  uint8_t list_next;
  uint8_t value_class;
  uint8_t decimals;
  bool has_value;
  bool has_address;
  bool has_text;
  bool token_native;
  bool threshold_reached;
} Erc7730Field;

/* The workflow owns every pointer-bearing interpreter object. No pointer into
 * a protobuf transport buffer survives a handler return. */
typedef struct {
  Erc7730CatalogIdentity identity;
  Erc7730TxContinuation continuation;
  Erc7730ProgramLoader loader;
  union {
    Erc7730ProgramDisplay display;
    Erc7730ProgramString string;
    Erc7730ProgramFormatter formatter;
    Erc7730ProgramPath path;
    Erc7730ProgramLiteral literal;
  } selection;
  /* Display materialization precedes calldata streaming, so the two pieces of
   * state never coexist. Overlay the two-byte formatter cursor with the much
   * larger stream state instead of spending permanent SRAM on both. */
  union {
    Erc7730AbiStream calldata;
    uint16_t current_formatter;
  };
  char intent[ERC7730_PROGRAM_MAX_STRING_LENGTH + 1u];
  char label[ERC7730_PROGRAM_MAX_STRING_LENGTH + 1u];
  uint16_t display_index;
  uint8_t domain_field;
  uint8_t phase;
  Erc7730Field field;
  /* Nonzero while showing part intent_part of intent_parts of the
   * interpolated intent; such a part has no label. */
  uint8_t intent_part;
  uint8_t intent_parts;
  bool intent_value;
  uint8_t selection_kind : 4;
  uint8_t display_stage : 4;
  bool typed_data;
  bool calldata_validated; /* the first, validating calldata pass is done */
  bool intent_confirmed;
  bool identity_confirmed;
  SHA256_CTX calldata_hash;
  uint8_t reviewed_digest[32];
  bool reviewed_digest_set;
  bool signing_pass;
} Erc7730Workflow;

/* One Ethereum workflow exists at a time. Keeping ownership here ensures FSM
 * definition replies and ethereum.c calldata chunks operate on the same state.
 */
Erc7730Workflow* erc7730_workflow_state(void);

bool erc7730_workflow_begin(Erc7730Workflow* workflow,
                            const Erc7730CatalogIdentity* identity,
                            const EthereumSignTx* tx);
bool erc7730_workflow_begin_eip712(Erc7730Workflow* workflow,
                                   const Erc7730CatalogIdentity* identity);
bool erc7730_workflow_waiting(const Erc7730Workflow* workflow,
                              uint8_t definition_id[32], uint32_t* offset,
                              uint32_t* total_length);
Erc7730CatalogResult erc7730_workflow_replay_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete);
bool erc7730_workflow_select_display(Erc7730Workflow* workflow,
                                     uint16_t instruction_index);
bool erc7730_workflow_select_string(Erc7730Workflow* workflow,
                                    uint16_t string_index);
bool erc7730_workflow_select_formatter(Erc7730Workflow* workflow,
                                       uint16_t formatter_index);
bool erc7730_workflow_select_path(Erc7730Workflow* workflow,
                                  uint16_t path_index);
bool erc7730_workflow_select_literal(Erc7730Workflow* workflow,
                                     uint16_t literal_index);
Erc7730CatalogResult erc7730_workflow_selection_feed(
    Erc7730Workflow* workflow, const EthereumClearSignDefinitionChunk* chunk,
    bool* complete);
bool erc7730_workflow_selected_display(const Erc7730Workflow* workflow,
                                       Erc7730DisplayInstruction* instruction,
                                       uint16_t* instruction_count);
bool erc7730_workflow_selected_string(const Erc7730Workflow* workflow,
                                      const char** value, size_t* value_len);
bool erc7730_workflow_selected_formatter(const Erc7730Workflow* workflow,
                                         Erc7730Formatter* formatter);
bool erc7730_workflow_selected_path(const Erc7730Workflow* workflow,
                                    Erc7730Path* path);
bool erc7730_workflow_restore_and_start_calldata(Erc7730Workflow* workflow,
                                                 EthereumSignTx* tx);
bool erc7730_workflow_restore_and_start_capture(Erc7730Workflow* workflow,
                                                EthereumSignTx* tx,
                                                const Erc7730Path* path);
bool erc7730_workflow_start_eip712_capture(Erc7730Workflow* workflow,
                                           const Erc7730Path* path);
bool erc7730_workflow_eip712_observe(Erc7730Workflow* workflow,
                                     const uint32_t* member_path,
                                     size_t member_path_count,
                                     const uint8_t* value, size_t value_len);
bool erc7730_workflow_eip712_finish(Erc7730Workflow* workflow);
bool erc7730_workflow_eip712_commit(Erc7730Workflow* workflow,
                                    const uint8_t domain[32],
                                    const uint8_t message[32]);
bool erc7730_workflow_restore_complete(const Erc7730Workflow* workflow,
                                       EthereumSignTx* tx);
bool erc7730_workflow_start_signing(Erc7730Workflow* workflow,
                                    EthereumSignTx* tx);
Erc7730AbiResult erc7730_workflow_calldata_feed(Erc7730Workflow* workflow,
                                                const uint8_t* data,
                                                size_t data_len);
Erc7730AbiResult erc7730_workflow_calldata_finish(Erc7730Workflow* workflow);
bool erc7730_workflow_active(const Erc7730Workflow* workflow);
bool erc7730_workflow_complete(const Erc7730Workflow* workflow);
bool erc7730_workflow_calldata_waiting(const Erc7730Workflow* workflow,
                                       size_t* remaining);
const Erc7730CatalogIdentity* erc7730_workflow_identity(
    const Erc7730Workflow* workflow);
bool erc7730_workflow_preserve_selected_string(Erc7730Workflow* workflow,
                                               bool intent);
bool erc7730_workflow_format_captured_raw(const Erc7730Workflow* workflow,
                                          char* output, size_t output_size);
bool erc7730_workflow_advance_display(Erc7730Workflow* workflow);
/* Begin resolving the arguments of a selected, executable formatter. */
bool erc7730_workflow_field_begin(Erc7730Workflow* workflow,
                                  const Erc7730Formatter* formatter);
/* The class and bytes of the value just captured from calldata or typed data.
 */
bool erc7730_workflow_captured(const Erc7730Workflow* workflow,
                               Erc7730AbiCapture* capture, uint8_t* cls);
/* Record the value of the pending argument of a multi-argument formatter.
 * Values of the wrong class are refused, as the preload verifier already
 * refused them. */
bool erc7730_workflow_field_value(Erc7730Workflow* workflow, uint8_t cls,
                                  const uint8_t* value, size_t value_len);
/* Return from a completed capture pass to program selection within the same
 * field, discarding the calldata stream. */
bool erc7730_workflow_resume_field(Erc7730Workflow* workflow);
/* Interpolated-intent parts counted by the last display selection. */
uint16_t erc7730_workflow_intent_parts(const Erc7730Workflow* workflow);
void erc7730_workflow_abort(Erc7730Workflow* workflow);

#endif
