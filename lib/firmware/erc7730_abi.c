#include "keepkey/firmware/erc7730_abi.h"

#include <limits.h>

bool erc7730_abi_node_dynamic(const Erc7730AbiProgram* p, uint16_t index,
                              uint8_t depth, bool* dynamic) {
  if (!p || !p->nodes || index >= p->node_count ||
      depth > ERC7730_ABI_MAX_DEPTH)
    return false;
  const Erc7730AbiNode* n = &p->nodes[index];
  switch (n->kind) {
    case ERC7730_ABI_BYTES:
    case ERC7730_ABI_STRING:
      *dynamic = true;
      return true;
    case ERC7730_ABI_ARRAY: {
      if (n->array_length == ERC7730_ABI_DYNAMIC_ARRAY) {
        *dynamic = true;
        return true;
      }
      return erc7730_abi_node_dynamic(p, n->first_child, depth + 1, dynamic);
    }
    case ERC7730_ABI_TUPLE:
      for (uint16_t i = 0; i < n->child_count; i++) {
        bool child_dynamic = false;
        if (!erc7730_abi_node_dynamic(p, (uint16_t)(n->first_child + i),
                                      depth + 1, &child_dynamic))
          return false;
        if (child_dynamic) {
          *dynamic = true;
          return true;
        }
      }
      *dynamic = false;
      return true;
    default:
      *dynamic = false;
      return true;
  }
}

Erc7730AbiResult erc7730_abi_validate_program(const Erc7730AbiProgram* p) {
  if (!p || !p->nodes || p->node_count == 0 ||
      p->node_count > ERC7730_ABI_MAX_NODES || p->root >= p->node_count)
    return ERC7730_ABI_BAD_PROGRAM;
  if (p->root != 0 || p->nodes[0].kind != ERC7730_ABI_TUPLE)
    return ERC7730_ABI_BAD_PROGRAM;
  uint64_t child_mask = 0;
  uint8_t depths[ERC7730_ABI_MAX_NODES] = {0};
  depths[0] = 1;
  for (uint16_t i = 0; i < p->node_count; i++) {
    const Erc7730AbiNode* n = &p->nodes[i];
    if (depths[i] == 0) return ERC7730_ABI_BAD_PROGRAM;
    switch (n->kind) {
      case ERC7730_ABI_UINT:
      case ERC7730_ABI_INT:
        if (n->size < 8 || n->size > 256 || (n->size & 7) != 0)
          return ERC7730_ABI_BAD_PROGRAM;
        break;
      case ERC7730_ABI_FIXED_BYTES:
        if (n->size == 0 || n->size > 32) return ERC7730_ABI_BAD_PROGRAM;
        break;
      case ERC7730_ABI_ADDRESS:
      case ERC7730_ABI_BOOL:
      case ERC7730_ABI_BYTES:
      case ERC7730_ABI_STRING:
        break;
      case ERC7730_ABI_TUPLE:
        if (n->child_count == 0) {
          if (i != 0 || p->node_count != 1 || n->first_child != 0)
            return ERC7730_ABI_BAD_PROGRAM;
          break;
        }
        if (n->first_child <= i || n->first_child >= p->node_count ||
            n->child_count > p->node_count - n->first_child)
          return ERC7730_ABI_BAD_PROGRAM;
        break;
      case ERC7730_ABI_ARRAY:
        if (n->child_count != 1 || n->first_child <= i ||
            n->first_child >= p->node_count ||
            (n->array_length != ERC7730_ABI_DYNAMIC_ARRAY &&
             (n->array_length == 0 ||
              n->array_length > ERC7730_ABI_MAX_ARRAY_ELEMENTS)))
          return ERC7730_ABI_BAD_PROGRAM;
        break;
      default:
        return ERC7730_ABI_BAD_PROGRAM;
    }
    if (n->kind == ERC7730_ABI_TUPLE || n->kind == ERC7730_ABI_ARRAY) {
      for (uint16_t child_index = 0; child_index < n->child_count;
           child_index++) {
        const uint16_t child = (uint16_t)(n->first_child + child_index);
        const uint64_t child_bit = UINT64_C(1) << child;
        if ((child_mask & child_bit) != 0) return ERC7730_ABI_BAD_PROGRAM;
        child_mask |= child_bit;
        depths[child] = (uint8_t)(depths[i] + 1u);
        if (depths[child] > ERC7730_ABI_MAX_DEPTH)
          return ERC7730_ABI_RESOURCE_LIMIT;
      }
    }
  }
  const uint64_t expected_children = p->node_count == 64
                                         ? UINT64_MAX & ~UINT64_C(1)
                                         : (UINT64_C(1) << p->node_count) - 2u;
  if (child_mask != expected_children) return ERC7730_ABI_BAD_PROGRAM;
  bool ignored = false;
  if (!erc7730_abi_node_dynamic(p, p->root, 0, &ignored))
    return ERC7730_ABI_RESOURCE_LIMIT;
  return ERC7730_ABI_OK;
}
