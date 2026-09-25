#ifndef KEEPKEY_FIRMWARE_ERC7730_CAPABILITIES_H
#define KEEPKEY_FIRMWARE_ERC7730_CAPABILITIES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_program.h"

/* What this firmware's ERC-7730 runtime executes. The preload verifier
 * (erc7730_catalog.c) refuses every program outside this table and the
 * runtime (fsm_msg_ethereum.h, erc7730_workflow.c) checks the same
 * predicates, so a definition that preloads cannot fail part-way through its
 * review because of its program shape. Widen the table only together with the
 * runtime that executes the new shape, and keep python-keepkey's
 * erc7730_compiler.DEVICE_CAPABILITIES in step. */

#define ERC7730_CAP_BIT(n) (UINT32_C(1) << (n))

/* Display opcodes: 1 intent, 2 intent text, 3 intent value, 4 field, 10 end.
 * Opcodes 2 and 3 form one run directly after the intent; each is shown as a
 * numbered part of the interpolated intent. */
#define ERC7730_CAP_DISPLAY_OPCODES                               \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3) | \
   ERC7730_CAP_BIT(4) | ERC7730_CAP_BIT(10))
/* Formatter kinds: 1 raw, 2 amount (native), 3 tokenAmount, 4 nftName,
 * 5 date, 6 duration, 7 unit, 8 enum, 10 addressName. */
#define ERC7730_CAP_FORMATTER_KINDS                               \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3) | \
   ERC7730_CAP_BIT(4) | ERC7730_CAP_BIT(5) | ERC7730_CAP_BIT(6) | \
   ERC7730_CAP_BIT(7) | ERC7730_CAP_BIT(8) | ERC7730_CAP_BIT(10))
/* Path sources: 1 value, 2 container, 3 literal. Path step opcodes: 1 index.
 */
#define ERC7730_CAP_PATH_SOURCES \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3))
#define ERC7730_CAP_PATH_STEP_OPCODES ERC7730_CAP_BIT(1)
/* Containers the runtime reads, for calldata definitions only: 1 @.from (the
 * signing account, derived on device), 2 @.to (the transaction target) and
 * 3 @.value (the transaction's native value). */
#define ERC7730_CAP_CONTAINERS \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3))
/* Display conditions (program section 5) are not executed. */
#define ERC7730_CAP_CONDITIONS false
/* A tokenAmount native-currency alias set may name at most this many
 * addresses, so the runtime can hold their literal indices. */
#define ERC7730_CAP_ALIAS_SET_MAX 4u
/* An enum map may hold at most this many entries (the registry's largest has
 * ten), so the runtime can hold their key and label indices. */
#define ERC7730_CAP_ENUM_MAX 16u

/* The type of a formatter argument's value, as the verifier knows it at
 * preload and the runtime knows it when the value arrives. 1-7 are the ABI
 * leaf kinds (erc7730_abi.h); literals map to the class of what they hold. */
enum {
  ERC7730_CLASS_NONE = 0,
  ERC7730_CLASS_UINT = 1,
  ERC7730_CLASS_INT = 2,
  ERC7730_CLASS_ADDRESS = 3,
  ERC7730_CLASS_BOOL = 4,
  ERC7730_CLASS_STRING = 7,      /* also any program string (source 3) */
  ERC7730_CLASS_STRING_REF = 8,  /* literal kind 4: an index into strings */
  ERC7730_CLASS_ALIAS_SET = 9,   /* literal kind 9 of at most ALIAS_SET_MAX */
  ERC7730_CLASS_UINT_SMALL = 10, /* literal kind 1 of one byte: 0-255 */
  ERC7730_CLASS_DATE_ENCODING = 11, /* the string "timestamp" or "blockheight"
                                     */
  ERC7730_CLASS_ENUM_MAP = 12,      /* literal kind 8 of at most ENUM_MAX */
  ERC7730_CLASS_FLAG = 13,          /* literal kind 6: a boolean */
};

/* The class of a literal of kind `kind`. `extent` is its length for kind 1
 * and its member count for kinds 8 and 9. */
uint8_t erc7730_cap_literal_class(uint8_t kind, uint16_t extent);
/* The class of program string `text`: a date encoding, or any string. */
uint8_t erc7730_cap_string_class(const char* text, size_t length);
/* Whether argument `role` of formatter `kind` may carry a value of `cls`. */
bool erc7730_cap_value(uint8_t kind, uint8_t role, uint8_t cls);

/* Formatter argument roles `kind` may carry, and the sources each role may
 * use (a bitmask of ERC7730_CAP_BIT(source)). Role 1 is the value. */
uint32_t erc7730_cap_formatter_roles(uint8_t kind);
uint32_t erc7730_cap_formatter_required_roles(uint8_t kind);
uint8_t erc7730_cap_argument_sources(uint8_t kind, uint8_t role);

bool erc7730_cap_display(const Erc7730DisplayInstruction* instruction,
                         uint16_t pc);
bool erc7730_cap_formatter(const Erc7730Formatter* formatter);
bool erc7730_cap_path(const Erc7730Path* path);

#endif
