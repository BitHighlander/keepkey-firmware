/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * Portions derived from OneKey firmware-classic1s
 * (legacy/firmware/ethereum_typed_data.h, commit 885e51d3), LGPL-3.0-or-later,
 * which itself carries the Trezor copyright chain (Alex Beregszaszi,
 * Pavol Rusnak, Jochen Hoenicke).
 *
 * Taken from that implementation: the encodeData rules, the leaf validation,
 * and the shape of the encodeType dependency closure.
 *
 * NOT taken from it: the memory design. OneKey declares a ~31 KB
 * TypedDataEnvelope on the stack and holds the whole schema; that is roughly
 * 1.8x this device's entire runtime SRAM. See eip712_stream.h for what
 * replaces it.
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

#include "keepkey/firmware/eip712_stream.h"

#include <stdio.h>
#include <string.h>

#include "keepkey/board/util.h"
#include "memzero.h"
#include "sha3.h"

typedef EthereumTypedDataStructAck_EthereumFieldType Eip712FieldType;
typedef EthereumTypedDataStructAck_EthereumDataType Eip712DataType;

/* ── encodeType spelling ─────────────────────────────────────────────
 *
 * The type string is hashed into typeHash, so getting a character wrong here
 * is not a display bug -- it silently produces a signature over a different
 * document. Spellings are canonical: "uint256", never "uint0256"; "bytes"
 * for the dynamic form, "bytes32" for the fixed one.
 */
bool eip712_type_name(const Eip712FieldType *field, char *out, size_t out_len) {
  if (!field || !out || out_len == 0) return false;

  const char *base;
  char scratch[EIP712_MAX_TYPE_NAME];

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT: {
      /* size is carried in BYTES on the wire and spelled in BITS. Anything
       * outside 1..32 bytes has no canonical spelling, so refuse rather than
       * invent one. */
      if (!field->has_size || field->size < 1 || field->size > 32) return false;
      const char *stem =
          field->data_type == EthereumTypedDataStructAck_EthereumDataType_UINT
              ? "uint"
              : "int";
      snprintf(scratch, sizeof(scratch), "%s%u", stem,
               (unsigned)(field->size * 8));
      base = scratch;
      break;
    }
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      if (field->has_size) {
        if (field->size < 1 || field->size > 32) return false;
        snprintf(scratch, sizeof(scratch), "bytes%u", (unsigned)field->size);
        base = scratch;
      } else {
        base = "bytes";
      }
      break;
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      base = "string";
      break;
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
      base = "bool";
      break;
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      base = "address";
      break;
    case EthereumTypedDataStructAck_EthereumDataType_STRUCT:
      if (!field->has_struct_name || field->struct_name[0] == '\0')
        return false;
      base = field->struct_name;
      break;
    default:
      /* ARRAY is reserved on this wire: dimensions live in array_levels, and a
       * field whose data_type IS an array means the host is speaking a
       * protocol we did not agree to. */
      return false;
  }

  size_t len = strlen(base);
  if (len + 1 > out_len) return false;
  memcpy(out, base, len);
  out[len] = '\0';

  /* Dimensions in written order: int16[2][][4] is array_levels {2, 0, 4}. */
  for (size_t i = 0; i < field->array_levels_count; i++) {
    char dim[16];
    if (field->array_levels[i] == 0) {
      memcpy(dim, "[]", 3);
    } else {
      snprintf(dim, sizeof(dim), "[%u]", (unsigned)field->array_levels[i]);
    }
    size_t dim_len = strlen(dim);
    if (len + dim_len + 1 > out_len) return false;
    memcpy(out + len, dim, dim_len);
    len += dim_len;
    out[len] = '\0';
  }
  return true;
}

/* ── encodeData ──────────────────────────────────────────────────────
 *
 * Every member encodes to exactly 32 bytes. Atomics pad, dynamics hash.
 * Structs and arrays never reach here: the walker folds them first and hands
 * the parent their 32-byte digest.
 */
static void write_rightpad32(const uint8_t *value, uint16_t value_len,
                             uint8_t out[32]) {
  memset(out, 0, 32);
  memcpy(out, value, value_len);
}

static void write_leftpad32(const uint8_t *value, uint16_t value_len,
                            bool is_signed, uint8_t out[32]) {
  /* Sign-extend a negative intN to 256 bits. An unsigned value, and a
   * zero-length one, extend with zeroes. */
  if (is_signed && value_len > 0 && (value[0] & 0x80)) {
    memset(out, 0xFF, 32);
  } else {
    memset(out, 0x00, 32);
  }
  memcpy(out + (32 - value_len), value, value_len);
}

bool eip712_encode_leaf(const Eip712FieldType *field, const uint8_t *value,
                        uint16_t value_len, uint8_t out[32]) {
  if (!field || !out) return false;
  if (value_len > 32 &&
      field->data_type != EthereumTypedDataStructAck_EthereumDataType_STRING &&
      !(field->data_type == EthereumTypedDataStructAck_EthereumDataType_BYTES &&
        !field->has_size)) {
    /* Only the dynamic forms may exceed a word; everything else would be
     * silently truncated by the padders. */
    return false;
  }
  if (value_len > 0 && !value) return false;

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      if (field->has_size) {
        write_rightpad32(value, value_len, out);
      } else {
        keccak_256(value, value_len, out);
      }
      return true;
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      keccak_256(value, value_len, out);
      return true;
    case EthereumTypedDataStructAck_EthereumDataType_INT:
      write_leftpad32(value, value_len, true, out);
      return true;
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      write_leftpad32(value, value_len, false, out);
      return true;
    default:
      return false;
  }
}

/* ── leaf validation ─────────────────────────────────────────────────
 *
 * Runs before encoding AND before display, so nothing unvalidated ever
 * reaches the screen or the hash.
 */
static bool is_valid_utf8_printable(const uint8_t *s, uint16_t len) {
  uint16_t i = 0;
  while (i < len) {
    uint8_t c = s[i];
    /* Control bytes are rejected outright. The renderer's injectivity -- that
     * two different strings cannot draw the same screen -- is what the user's
     * consent rests on, and a bare newline or NUL breaks it. */
    if (c < 0x20 || c == 0x7F) return false;
    uint8_t extra;
    uint32_t cp;
    if (c < 0x80) {
      i++;
      continue;
    } else if ((c & 0xE0) == 0xC0) {
      extra = 1;
      cp = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
      extra = 2;
      cp = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
      extra = 3;
      cp = c & 0x07;
    } else {
      return false;
    }
    if (i + extra >= len) return false;
    for (uint8_t k = 1; k <= extra; k++) {
      uint8_t cc = s[i + k];
      if ((cc & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (cc & 0x3F);
    }
    /* Overlong encodings and surrogates are two spellings of one character,
     * which would break injectivity the same way a control byte does. */
    if (extra == 1 && cp < 0x80) return false;
    if (extra == 2 && cp < 0x800) return false;
    if (extra == 3 && cp < 0x10000) return false;
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;
    i += extra + 1;
  }
  return true;
}

bool eip712_validate_leaf(const Eip712FieldType *field, const uint8_t *value,
                          uint16_t value_len) {
  if (!field) return false;
  if (value_len > 0 && !value) return false;

  switch (field->data_type) {
    case EthereumTypedDataStructAck_EthereumDataType_BOOL:
      return value_len == 1 && (value[0] == 0 || value[0] == 1);
    case EthereumTypedDataStructAck_EthereumDataType_ADDRESS:
      return value_len == 20;
    case EthereumTypedDataStructAck_EthereumDataType_STRING:
      return is_valid_utf8_printable(value, value_len);
    case EthereumTypedDataStructAck_EthereumDataType_BYTES:
      /* bytesN is exactly N. Dynamic bytes is any length we can hold. */
      if (field->has_size) return value_len == field->size;
      return value_len <= EIP712_MAX_LEAF;
    case EthereumTypedDataStructAck_EthereumDataType_UINT:
    case EthereumTypedDataStructAck_EthereumDataType_INT:
      /* The host sends the declared width, big endian, no padding games. A
       * short value would left-pad into a different number than the host
       * meant, and a long one would not fit the word. */
      if (!field->has_size || field->size < 1 || field->size > 32) return false;
      return value_len == field->size;
    default:
      return false;
  }
}

/* ── encodeType ──────────────────────────────────────────────────────
 *
 *   encodeType(S) = seg(S) || seg(D1) || seg(D2) || ...
 *
 * where D1..Dn are every struct S transitively references, SORTED BY NAME,
 * and seg(T) = "T(type1 name1,type2 name2,...)".
 *
 * The sort is what eip712.c never did. It appended referenced definitions in
 * discovery order -- there is no sort call anywhere in that file -- so a
 * document naming two structs out of alphabetical order hashed a type string
 * no compliant verifier reproduces. The device would have been internally
 * consistent and still signing something nobody else agrees the document says.
 *
 * Nothing is stored: each segment is streamed into a keccak context as it is
 * fetched, so only the closure's NAMES are held.
 */

typedef struct {
  char names[EIP712_MAX_STRUCTS][EIP712_MAX_STRUCT_NAME];
  uint8_t count;
} Eip712Closure;

static bool closure_contains(const Eip712Closure *c, const char *name) {
  for (uint8_t i = 0; i < c->count; i++) {
    if (strcmp(c->names[i], name) == 0) return true;
  }
  return false;
}

static bool closure_add(Eip712Closure *c, const char *name) {
  size_t len = strlen(name);
  if (len == 0 || len + 1 > EIP712_MAX_STRUCT_NAME) return false;
  if (closure_contains(c, name)) return true;
  if (c->count >= EIP712_MAX_STRUCTS) return false;
  memcpy(c->names[c->count], name, len + 1);
  c->count++;
  return true;
}

/* Collect every struct `name` transitively references, excluding itself.
 * Iterative: the worklist is the closure itself, walked as it grows, so a
 * cyclical schema terminates on the already-present check rather than
 * recursing. EIP-712 leaves cyclical data undefined; we simply do not loop. */
static bool closure_collect(const char *name, Eip712StructLookup lookup,
                            void *ctx, Eip712Closure *out) {
  Eip712Closure seen;
  memset(&seen, 0, sizeof(seen));
  if (!closure_add(&seen, name)) return false;

  for (uint8_t i = 0; i < seen.count; i++) {
    const EthereumTypedDataStructAck *def = lookup(seen.names[i], ctx);
    if (!def) return false;
    for (size_t m = 0; m < def->members_count; m++) {
      const Eip712FieldType *ft = &def->members[m].type;
      if (ft->data_type != EthereumTypedDataStructAck_EthereumDataType_STRUCT)
        continue;
      if (!ft->has_struct_name) return false;
      if (!closure_add(&seen, ft->struct_name)) return false;
      /* `seen` grows while we iterate it, which is the traversal. */
    }
  }

  /* The primary type leads and is not sorted with the rest. */
  memset(out, 0, sizeof(*out));
  for (uint8_t i = 1; i < seen.count; i++) {
    if (!closure_add(out, seen.names[i])) return false;
  }

  /* Insertion sort by name. n <= EIP712_MAX_STRUCTS, so this is cheaper and
   * far easier to audit than pulling in qsort. */
  for (uint8_t i = 1; i < out->count; i++) {
    char key[EIP712_MAX_STRUCT_NAME];
    memcpy(key, out->names[i], EIP712_MAX_STRUCT_NAME);
    int8_t j = (int8_t)i - 1;
    while (j >= 0 && strcmp(out->names[j], key) > 0) {
      memcpy(out->names[j + 1], out->names[j], EIP712_MAX_STRUCT_NAME);
      j--;
    }
    memcpy(out->names[j + 1], key, EIP712_MAX_STRUCT_NAME);
  }
  return true;
}

/* Stream "Name(type1 name1,type2 name2,...)" into the hash. */
static bool hash_type_segment(const char *name, Eip712StructLookup lookup,
                              void *ctx, SHA3_CTX *hash) {
  const EthereumTypedDataStructAck *def = lookup(name, ctx);
  if (!def) return false;

  keccak_Update(hash, (const uint8_t *)name, strlen(name));
  keccak_Update(hash, (const uint8_t *)"(", 1);

  for (size_t m = 0; m < def->members_count; m++) {
    char type_name[EIP712_MAX_TYPE_NAME];
    if (!eip712_type_name(&def->members[m].type, type_name, sizeof(type_name)))
      return false;
    const char *member_name = def->members[m].name;
    if (member_name[0] == '\0') return false;

    if (m > 0) keccak_Update(hash, (const uint8_t *)",", 1);
    keccak_Update(hash, (const uint8_t *)type_name, strlen(type_name));
    keccak_Update(hash, (const uint8_t *)" ", 1);
    keccak_Update(hash, (const uint8_t *)member_name, strlen(member_name));
  }

  keccak_Update(hash, (const uint8_t *)")", 1);
  return true;
}

bool eip712_type_hash(const char *name, Eip712StructLookup lookup, void *ctx,
                      uint8_t out[32]) {
  if (!name || !lookup || !out) return false;
  if (strlen(name) == 0 || strlen(name) + 1 > EIP712_MAX_STRUCT_NAME)
    return false;

  Eip712Closure deps;
  if (!closure_collect(name, lookup, ctx, &deps)) return false;

  SHA3_CTX hash;
  keccak_256_Init(&hash);
  if (!hash_type_segment(name, lookup, ctx, &hash)) return false;
  for (uint8_t i = 0; i < deps.count; i++) {
    if (!hash_type_segment(deps.names[i], lookup, ctx, &hash)) return false;
  }
  keccak_Final(&hash, out);
  return true;
}

/* ── Session state ───────────────────────────────────────────────────
 *
 * Every byte here is .bss, and .bss is the only thing that counts against the
 * linker gap -- that gap IS the stack, so transients on it are free.
 *
 * Measured budget: _stack - _ebss is 17,716 B against a 16,384 B floor, so
 * there are 1,332 B to spend. The sizes in eip712_stream.h are chosen to fit
 * with margin, not chosen first and hoped for.
 *
 * The single SHA3_CTX is shared. Only one hash is ever in progress: either an
 * encodeType stream (which spans round trips, so it must live here) or a frame
 * fold (which completes inside one handler and could have been a local). One
 * context serves both because they never overlap.
 */
typedef struct {
  char name[EIP712_MAX_STRUCT_NAME];
  uint8_t slot_base;    /* first slot in the pool belonging to this frame */
  uint8_t member_count; /* members declared by the struct */
  uint8_t member_index; /* next member to absorb */
  bool is_array;        /* array frames hash WITHOUT a typeHash prefix */
  uint16_t array_len;
} Eip712Frame;

static struct {
  bool active;
  Eip712Wait waiting;

  uint32_t address_n[8];
  size_t address_n_count;
  char primary_type[EIP712_MAX_STRUCT_NAME];
  bool metamask_v4_compat;

  /* Root 0 is the domain, root 1 the message; the domain separator is kept
   * while the message is walked. */
  uint8_t root;
  uint8_t domain_separator[32];
  bool have_domain_separator;

  Eip712Frame stack[EIP712_MAX_DEPTH];
  uint8_t depth;

  uint8_t pool[EIP712_MAX_SLOTS][32];
  uint8_t slots_used;

  /* typeHash memo, so a struct used twice is not re-derived. */
  char th_name[EIP712_MAX_STRUCTS][EIP712_MAX_STRUCT_NAME];
  uint8_t th_value[EIP712_MAX_STRUCTS][32];
  uint8_t th_count;

  SHA3_CTX hash;

  uint32_t path[EIP712_MAX_DEPTH + 2];
  uint8_t path_len;
} e712;

Eip712Wait eip712_stream_waiting(void) {
  return e712.active ? e712.waiting : EIP712_IDLE;
}

void eip712_stream_abort(void) { memzero(&e712, sizeof(e712)); }
