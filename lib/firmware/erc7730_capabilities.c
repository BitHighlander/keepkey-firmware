#include "keepkey/firmware/erc7730_capabilities.h"

uint32_t erc7730_cap_formatter_roles(uint8_t kind) {
  if (kind > 31 || (ERC7730_CAP_FORMATTER_KINDS & ERC7730_CAP_BIT(kind)) == 0)
    return 0;
  if (kind == 3) /* value, token, threshold, message, native aliases */
    return ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(7) |
           ERC7730_CAP_BIT(8) | ERC7730_CAP_BIT(22);
  return ERC7730_CAP_BIT(1);
}

uint32_t erc7730_cap_formatter_required_roles(uint8_t kind) {
  if (erc7730_cap_formatter_roles(kind) == 0) return 0;
  return kind == 3 ? ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2)
                   : ERC7730_CAP_BIT(1);
}

uint8_t erc7730_cap_argument_sources(uint8_t kind, uint8_t role) {
  if (role > 31 ||
      (erc7730_cap_formatter_roles(kind) & ERC7730_CAP_BIT(role)) == 0)
    return 0;
  switch (role) {
    case 7:  /* threshold: a literal */
    case 22: /* native aliases: a literal set */
      return (uint8_t)ERC7730_CAP_BIT(2);
    case 8: /* message: a string */
      return (uint8_t)ERC7730_CAP_BIT(3);
    default: /* value and token: a path */
      return (uint8_t)ERC7730_CAP_BIT(1);
  }
}

uint8_t erc7730_cap_literal_class(uint8_t kind, uint16_t set_count) {
  switch (kind) {
    case 1:
      return ERC7730_CLASS_UINT;
    case 4:
      return ERC7730_CLASS_STRING_REF;
    case 5:
      return ERC7730_CLASS_ADDRESS;
    case 9:
      return set_count != 0 && set_count <= ERC7730_CAP_ALIAS_SET_MAX
                 ? ERC7730_CLASS_ALIAS_SET
                 : ERC7730_CLASS_NONE;
    default:
      return ERC7730_CLASS_NONE;
  }
}

bool erc7730_cap_value(uint8_t kind, uint8_t role, uint8_t cls) {
  if (cls == ERC7730_CLASS_NONE) return false;
  if (kind == 1 && role == 1) /* raw: any ABI leaf, a string or an address */
    return cls <= ERC7730_CLASS_STRING_REF;
  if (kind == 10 && role == 1) return cls == ERC7730_CLASS_ADDRESS;
  if (kind == 3) {
    switch (role) {
      case 1:
      case 7:
        return cls == ERC7730_CLASS_UINT;
      case 2:
        return cls == ERC7730_CLASS_ADDRESS;
      case 22:
        return cls == ERC7730_CLASS_ALIAS_SET;
      default:
        return false;
    }
  }
  return false;
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
    case 2: /* intent text: string a */
    case 3: /* intent value: formatter a */
      return pc != 0 && a != UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
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
      (ERC7730_CAP_PATH_SOURCES & ERC7730_CAP_BIT(path->source)) == 0)
    return false;
  if (path->source == 2) /* a container: no steps */
    return path->step_count == 0 && path->source_index <= 31 &&
           (ERC7730_CAP_CONTAINERS & ERC7730_CAP_BIT(path->source_index)) != 0;
  if (path->source == 3) /* a literal: no steps */
    return path->step_count == 0 && path->source_index != UINT16_MAX;
  if (path->step_count == 0 || path->step_count >= ERC7730_ABI_MAX_DEPTH)
    return false;
  for (uint8_t i = 0; i < path->step_count; i++) {
    if (path->steps[i].opcode > 31 ||
        (ERC7730_CAP_PATH_STEP_OPCODES &
         ERC7730_CAP_BIT(path->steps[i].opcode)) == 0)
      return false;
  }
  return true;
}
