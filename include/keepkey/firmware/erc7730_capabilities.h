#ifndef KEEPKEY_FIRMWARE_ERC7730_CAPABILITIES_H
#define KEEPKEY_FIRMWARE_ERC7730_CAPABILITIES_H

#include <stdbool.h>
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

/* Display opcodes: 1 intent, 4 field, 10 end. */
#define ERC7730_CAP_DISPLAY_OPCODES \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(4) | ERC7730_CAP_BIT(10))
/* Formatter kinds: 1 raw. */
#define ERC7730_CAP_FORMATTER_KINDS ERC7730_CAP_BIT(1)
/* Path sources: 1 value. Path step opcodes: 1 index. */
#define ERC7730_CAP_PATH_SOURCES ERC7730_CAP_BIT(1)
#define ERC7730_CAP_PATH_STEP_OPCODES ERC7730_CAP_BIT(1)
/* Display conditions (program section 5) are not executed. */
#define ERC7730_CAP_CONDITIONS false

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
