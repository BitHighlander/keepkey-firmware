#include "keepkey/firmware/erc7730_capabilities.h"

uint32_t erc7730_cap_formatter_roles(uint8_t kind) {
  if (kind > 31 || (ERC7730_CAP_FORMATTER_KINDS & ERC7730_CAP_BIT(kind)) == 0)
    return 0;
  return ERC7730_CAP_BIT(1);
}

uint32_t erc7730_cap_formatter_required_roles(uint8_t kind) {
  return erc7730_cap_formatter_roles(kind) != 0 ? ERC7730_CAP_BIT(1) : 0;
}

uint8_t erc7730_cap_argument_sources(uint8_t kind, uint8_t role) {
  if (role > 31 ||
      (erc7730_cap_formatter_roles(kind) & ERC7730_CAP_BIT(role)) == 0)
    return 0;
  return (uint8_t)ERC7730_CAP_BIT(1);
}

bool erc7730_cap_display(const Erc7730DisplayInstruction* instruction,
                         uint16_t pc) {
  if (!instruction || instruction->flags != 0 || instruction->opcode > 31 ||
      (ERC7730_CAP_DISPLAY_OPCODES & ERC7730_CAP_BIT(instruction->opcode)) == 0)
    return false;
  const uint16_t a = instruction->a, b = instruction->b, c = instruction->c;
  switch (instruction->opcode) {
    case 1: /* intent: string a, and only as the first instruction */
      return pc == 0 && a != UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
    case 4: /* field: label string a, formatter b, no condition */
      return pc != 0 && a != UINT16_MAX && b != UINT16_MAX &&
             (ERC7730_CAP_CONDITIONS || c == UINT16_MAX);
    case 10: /* end */
      return pc != 0 && a == UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
    default:
      return false;
  }
}

bool erc7730_cap_formatter(const Erc7730Formatter* formatter) {
  if (!formatter || formatter->flags != 0 ||
      formatter->argument_count > ERC7730_FORMATTER_MAX_ARGUMENTS)
    return false;
  uint32_t roles = 0;
  for (uint8_t i = 0; i < formatter->argument_count; i++) {
    const Erc7730FormatterArgument* argument = &formatter->arguments[i];
    if (argument->source > 7 ||
        (erc7730_cap_argument_sources(formatter->kind, argument->role) &
         ERC7730_CAP_BIT(argument->source)) == 0 ||
        (roles & ERC7730_CAP_BIT(argument->role)) != 0)
      return false;
    roles |= ERC7730_CAP_BIT(argument->role);
  }
  const uint32_t required =
      erc7730_cap_formatter_required_roles(formatter->kind);
  return required != 0 && (roles & required) == required;
}

bool erc7730_cap_path(const Erc7730Path* path) {
  if (!path || path->source > 7 ||
      (ERC7730_CAP_PATH_SOURCES & ERC7730_CAP_BIT(path->source)) == 0 ||
      path->step_count == 0 || path->step_count >= ERC7730_ABI_MAX_DEPTH)
    return false;
  for (uint8_t i = 0; i < path->step_count; i++) {
    if (path->steps[i].opcode > 31 ||
        (ERC7730_CAP_PATH_STEP_OPCODES &
         ERC7730_CAP_BIT(path->steps[i].opcode)) == 0)
      return false;
  }
  return true;
}
