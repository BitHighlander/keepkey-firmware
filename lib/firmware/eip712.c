
/*
 * Copyright (c) 2022 markrypto  (cryptoakorn@gmail.com)
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

/*
    Produces hashes based on the metamask v4 rules. This is different from the
   EIP-712 spec in how arrays of structs are hashed but is compatable with
   metamask. See https://github.com/MetaMask/eth-sig-util/pull/107

    eip712 data rules:
    Parser wants to see C strings, not javascript strings:
        requires all complete json message strings to be enclosed by braces,
   i.e., { ... } Cannot have entire json string quoted, i.e., "{ ... }" will not
   work. Remove all quote escape chars, e.g., {"types":  not  {\"types\": ints:
   Strings representing ints must fit into a long size (64-bits). Note: Do not
   prefix ints or uints with 0x All hex and byte strings must be big-endian Byte
   strings and address should be prefixed by 0x
*/

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/tiny-json.h"
#include "trezor/crypto/sha3.h"
#include "trezor/crypto/memzero.h"

static const char* udefList[MAX_USERDEF_TYPES] = {0};
static dm confirmProp;

static const char* nameForValue;

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool decode_address(const char* string, uint8_t decoded[20]) {
  if (!string || strlen(string) != ADDRESS_SIZE || string[0] != '0' ||
      string[1] != 'x') {
    return false;
  }

  for (size_t i = 0; i < 20; i++) {
    const int high = hex_nibble(string[2 + 2 * i]);
    const int low = hex_nibble(string[3 + 2 * i]);
    if (high < 0 || low < 0) return false;
    decoded[i] = (uint8_t)((high << 4) | low);
  }
  return true;
}

/* 7.14.2 restores the released encoder for a deliberately bounded subset:
   flat structs made from canonical atomic EIP-712 types.  The existing encoder
   remains the single hashing implementation; this preflight only proves that
   its assumptions hold before any value is displayed or hashed.  Arrays and
   nested structs fail closed and remain available through the explicit
   AdvancedMode typed-hash endpoint. */
#define EIP712_IDENTIFIER_MAX 32

typedef enum {
  EIP712_ATOMIC_ADDRESS,
  EIP712_ATOMIC_BOOL,
  EIP712_ATOMIC_STRING,
  EIP712_ATOMIC_BYTES,
  EIP712_ATOMIC_BYTES_N,
  EIP712_ATOMIC_UINT,
  EIP712_ATOMIC_INT,
} eip712_atomic_kind;

typedef struct {
  eip712_atomic_kind kind;
  unsigned width;
} eip712_atomic_type;

static size_t json_child_count(const json_t* object) {
  if (!object || (json_getType(object) != JSON_OBJ &&
                  json_getType(object) != JSON_ARRAY)) {
    return 0;
  }
  size_t count = 0;
  for (const json_t* child = json_getChild(object); child;
       child = json_getSibling(child)) {
    count++;
  }
  return count;
}

static size_t json_named_child_count(const json_t* object, const char* name) {
  if (!object || json_getType(object) != JSON_OBJ || !name) return 0;
  size_t count = 0;
  for (const json_t* child = json_getChild(object); child;
       child = json_getSibling(child)) {
    if (json_getName(child) && strcmp(json_getName(child), name) == 0) count++;
  }
  return count;
}

static bool eip712_identifier_is_valid(const char* value) {
  if (!value || value[0] == '\0') return false;
  const size_t len = strlen(value);
  if (len > EIP712_IDENTIFIER_MAX) return false;
  if (!((value[0] >= 'A' && value[0] <= 'Z') ||
        (value[0] >= 'a' && value[0] <= 'z') || value[0] == '_')) {
    return false;
  }
  for (size_t i = 1; i < len; i++) {
    const char c = value[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_')) {
      return false;
    }
  }
  return true;
}

static bool parse_decimal_width(const char* text, unsigned limit,
                                unsigned* width) {
  if (!text || text[0] == '\0') return false;
  unsigned parsed = 0;
  for (const char* p = text; *p; p++) {
    if (*p < '0' || *p > '9') return false;
    const unsigned digit = (unsigned)(*p - '0');
    if (parsed > (limit - digit) / 10u) return false;
    parsed = parsed * 10u + digit;
  }
  *width = parsed;
  return true;
}

static bool eip712_atomic_type_parse(const char* text,
                                     eip712_atomic_type* type) {
  if (!text || !type) return false;
  memset(type, 0, sizeof(*type));
  if (strcmp(text, "address") == 0) {
    type->kind = EIP712_ATOMIC_ADDRESS;
    return true;
  }
  if (strcmp(text, "bool") == 0) {
    type->kind = EIP712_ATOMIC_BOOL;
    return true;
  }
  if (strcmp(text, "string") == 0) {
    type->kind = EIP712_ATOMIC_STRING;
    return true;
  }
  if (strcmp(text, "bytes") == 0) {
    type->kind = EIP712_ATOMIC_BYTES;
    return true;
  }

  unsigned width = 0;
  if (strncmp(text, "bytes", 5) == 0 &&
      parse_decimal_width(text + 5, 32, &width) && width >= 1) {
    type->kind = EIP712_ATOMIC_BYTES_N;
    type->width = width;
    return true;
  }
  if (strncmp(text, "uint", 4) == 0 &&
      parse_decimal_width(text + 4, 256, &width) && width >= 8 &&
      width % 8 == 0) {
    type->kind = EIP712_ATOMIC_UINT;
    type->width = width;
    return true;
  }
  if (strncmp(text, "int", 3) == 0 &&
      parse_decimal_width(text + 3, 256, &width) && width >= 8 &&
      width % 8 == 0) {
    type->kind = EIP712_ATOMIC_INT;
    type->width = width;
    return true;
  }
  return false;
}

static bool eip712_hex_is_valid(const char* text, size_t expected_bytes,
                                bool exact_size) {
  if (!text || text[0] != '0' || text[1] != 'x') return false;
  const size_t chars = strlen(text + 2);
  if ((chars & 1u) != 0 || (exact_size && chars != expected_bytes * 2u)) {
    return false;
  }
  for (size_t i = 0; i < chars; i++) {
    if (hex_nibble(text[i + 2]) < 0) return false;
  }
  return true;
}

static bool eip712_integer_is_valid(const char* text,
                                    const eip712_atomic_type* type) {
  if (!text || !type || text[0] == '\0') return false;
  const bool negative = text[0] == '-';
  const char* digits = negative ? text + 1 : text;
  if (digits[0] == '\0' || (digits[0] == '0' && digits[1] != '\0') ||
      (negative && strcmp(digits, "0") == 0)) {
    return false;
  }
  for (const char* p = digits; *p; p++) {
    if (*p < '0' || *p > '9') return false;
  }
  if (type->kind == EIP712_ATOMIC_UINT && negative) return false;

  /* The released encoder stores values in a signed long long. Prove the
     decimal magnitude fits both that implementation and the declared EIP-712
     width without depending on libc overflow behavior or errno. */
  uint64_t maximum;
  if (type->kind == EIP712_ATOMIC_UINT) {
    maximum = type->width < 63 ? (UINT64_C(1) << type->width) - 1u
                               : (uint64_t)INT64_MAX;
  } else if (negative) {
    maximum =
        type->width < 64 ? UINT64_C(1) << (type->width - 1) : UINT64_C(1) << 63;
  } else {
    maximum = type->width < 64 ? (UINT64_C(1) << (type->width - 1)) - 1u
                               : (uint64_t)INT64_MAX;
  }
  uint64_t magnitude = 0;
  for (const char* p = digits; *p; p++) {
    const uint64_t digit = (uint64_t)(*p - '0');
    if (magnitude > (maximum - digit) / 10u) return false;
    magnitude = magnitude * 10u + digit;
  }
  return true;
}

static bool eip712_atomic_value_is_valid(const json_t* value,
                                         const eip712_atomic_type* type) {
  if (!value || !type) return false;
  const jsonType_t json_type = json_getType(value);
  const char* text = json_getValue(value);
  switch (type->kind) {
    case EIP712_ATOMIC_ADDRESS: {
      uint8_t decoded[20] = {0};
      return json_type == JSON_TEXT && decode_address(text, decoded);
    }
    case EIP712_ATOMIC_BOOL:
      return json_type == JSON_BOOLEAN &&
             (strcmp(text, "true") == 0 || strcmp(text, "false") == 0);
    case EIP712_ATOMIC_STRING:
      return json_type == JSON_TEXT;
    case EIP712_ATOMIC_BYTES:
      return json_type == JSON_TEXT && eip712_hex_is_valid(text, 0, false);
    case EIP712_ATOMIC_BYTES_N:
      return json_type == JSON_TEXT &&
             eip712_hex_is_valid(text, type->width, true);
    case EIP712_ATOMIC_UINT:
    case EIP712_ATOMIC_INT:
      return (json_type == JSON_TEXT || json_type == JSON_INTEGER) &&
             eip712_integer_is_valid(text, type);
  }
  return false;
}

bool eip712_json_is_supported(const char* json) {
  if (!json) return false;
  /* tiny-json replaces every JSON Unicode escape with '?'. Refuse those
     spellings instead of signing a different string from the one the host
     supplied. Raw UTF-8 remains supported and is reviewed byte-for-byte. */
  for (const char* p = json; *p; p++) {
    if (p[0] == '\\' && p[1] == 'u') return false;
  }
  return true;
}

bool eip712_document_is_supported(const json_t* jsonTypes,
                                  const json_t* jsonVals, const char* typeS) {
  if (!jsonTypes || !jsonVals || !eip712_identifier_is_valid(typeS) ||
      json_getType(jsonTypes) != JSON_OBJ || json_child_count(jsonTypes) != 1 ||
      json_named_child_count(jsonTypes, "types") != 1) {
    return false;
  }
  const json_t* types = json_getProperty(jsonTypes, "types");
  if (!types || json_getType(types) != JSON_OBJ ||
      json_named_child_count(types, typeS) != 1) {
    return false;
  }
  const json_t* fields = json_getProperty(types, typeS);
  if (!fields || json_getType(fields) != JSON_ARRAY) return false;

  const char* property =
      strcmp(typeS, "EIP712Domain") == 0 ? "domain" : "message";
  if (json_getType(jsonVals) != JSON_OBJ || json_child_count(jsonVals) != 1 ||
      json_named_child_count(jsonVals, property) != 1) {
    return false;
  }
  const json_t* values = json_getProperty(jsonVals, property);
  if (!values || json_getType(values) != JSON_OBJ ||
      json_child_count(fields) != json_child_count(values)) {
    return false;
  }

  for (const json_t* field = json_getChild(fields); field;
       field = json_getSibling(field)) {
    if (json_getType(field) != JSON_OBJ || json_child_count(field) != 2) {
      return false;
    }
    const json_t* name = json_getChild(field);
    const json_t* type_value = name ? json_getSibling(name) : NULL;
    if (!name || !type_value || !json_getName(name) ||
        !json_getName(type_value) || strcmp(json_getName(name), "name") != 0 ||
        strcmp(json_getName(type_value), "type") != 0 ||
        json_getType(name) != JSON_TEXT ||
        json_getType(type_value) != JSON_TEXT) {
      return false;
    }
    const char* field_name = json_getValue(name);
    const char* field_type = json_getValue(type_value);
    eip712_atomic_type parsed;
    if (!eip712_identifier_is_valid(field_name) ||
        !eip712_atomic_type_parse(field_type, &parsed) ||
        json_named_child_count(values, field_name) != 1 ||
        !eip712_atomic_value_is_valid(json_getProperty(values, field_name),
                                      &parsed)) {
      return false;
    }
    /* A duplicate declaration could otherwise make the field/value counts
       agree while leaving an unrelated value outside the reviewed schema. */
    for (const json_t* other = json_getChild(fields); other;
         other = json_getSibling(other)) {
      if (other == field) continue;
      const json_t* other_name = json_getChild(other);
      if (other_name && json_getValue(other_name) &&
          strcmp(json_getValue(other_name), field_name) == 0) {
        return false;
      }
    }
  }
  return true;
}

bool eip712_empty_message_is_supported(const json_t* jsonVals) {
  if (!jsonVals || json_getType(jsonVals) != JSON_OBJ ||
      json_child_count(jsonVals) != 1 ||
      json_named_child_count(jsonVals, "message") != 1) {
    return false;
  }
  const json_t* message = json_getProperty(jsonVals, "message");
  return message && json_getType(message) == JSON_OBJ &&
         json_child_count(message) == 0;
}

/* Append value to dest, a caller-allocated, NUL-terminated buffer of
   STRBUFSIZE+1 bytes. Returns false and leaves dest untouched if the result
   would not fit. Deliberately never truncates: a truncated encodeType string
   hashes to a typehash the host did not ask for, and two distinct type sets
   sharing a prefix would collide, so callers must fail closed instead. */
static bool append_type_string(char* dest, const char* value) {
  if (!dest || !value) return false;
  const size_t used = strnlen(dest, STRBUFSIZE + 1);
  const size_t added = strlen(value);
  if (used > STRBUFSIZE || added > STRBUFSIZE - used) return false;
  memcpy(dest + used, value, added + 1);
  return true;
}

int encodableType(const char* typeStr) {
  int ctr;

  if (0 == strncmp(typeStr, "address", sizeof("address") - 1)) {
    return ADDRESS;
  }
  if (0 == strncmp(typeStr, "string", sizeof("string") - 1)) {
    return STRING;
  }
  if (0 == strncmp(typeStr, "int", sizeof("int") - 1)) {
    // This could be 'int8', 'int16', ..., 'int256'
    return INT;
  }
  if (0 == strncmp(typeStr, "uint", sizeof("uint") - 1)) {
    // This could be 'uint8', 'uint16', ..., 'uint256'
    return UINT;
  }
  if (0 == strncmp(typeStr, "bytes", sizeof("bytes") - 1)) {
    // This could be 'bytes', 'bytes1', ..., 'bytes32'
    if (0 == strcmp(typeStr, "bytes")) {
      return BYTES;
    } else {
      // parse out the length val
      uint8_t byteTypeSize = (uint8_t)(strtol((typeStr + 5), NULL, 10));
      if (byteTypeSize > 32) {
        return NOT_ENCODABLE;
      } else {
        return BYTES_N;
      }
    }
  }
  if (0 == strcmp(typeStr, "bool")) {
    return BOOL;
  }

  // See if type already defined. If so, skip, otherwise add it to list
  for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
    char typeNoArrTok[MAX_TYPESTRING] = {0};

    strncpy(typeNoArrTok, typeStr, sizeof(typeNoArrTok) - 1);
    strtok(typeNoArrTok, "[");  // eliminate the array tokens if there

    if (udefList[ctr] != 0) {
      if (0 == strncmp(udefList[ctr], typeNoArrTok,
                       strlen(udefList[ctr]) - strlen(typeNoArrTok))) {
        return PREV_USERDEF;
      } else {
      }

    } else {
      udefList[ctr] = typeStr;
      return UDEF_TYPE;
    }
  }
  if (ctr == MAX_USERDEF_TYPES) {
    return TOO_MANY_UDEFS;
  }

  return NOT_ENCODABLE;  // not encodable
}

/*
    Entry:
            eip712Types points to eip712 json type structure to parse
            typeS points to the type to parse from jType
            typeStr points to caller allocated, zeroized string buffer of size
   STRBUFSIZE+1 Exit: typeStr points to hashable type string returns error list
   status

    NOTE: reentrant!
*/
int parseType(const json_t* eip712Types, const char* typeS, char* typeStr) {
  json_t const *tarray, *pairs;
  const json_t* jType;
  char append[STRBUFSIZE + 1] = {0};
  const char* typeType = NULL;
  const json_t* obTest;
  const char* nameTest;

  if (NULL == (jType = json_getProperty(eip712Types, typeS))) {
    return JSON_TYPE_S_ERR;
  }

  if (NULL == (nameTest = json_getName(jType))) {
    return JSON_TYPE_S_NAMEERR;
  }

  if (!append_type_string(typeStr, nameTest) ||
      !append_type_string(typeStr, "(")) {
    return UDEF_NAME_ERROR;
  }

  tarray = json_getChild(jType);
  while (tarray != 0) {
    if (NULL == (pairs = json_getChild(tarray))) {
      return JSON_NO_PAIRS;
    }
    // should be type JSON_TEXT
    if (pairs->type != JSON_TEXT) {
      return JSON_PAIRS_NOTEXT;
    } else {
      if (NULL == (obTest = json_getSibling(pairs))) {
        return JSON_NO_PAIRS_SIB;
      }
      typeType = json_getValue(obTest);
      int encTest = encodableType(typeType);
      if (encTest == UDEF_TYPE) {
        // This is a user-defined type, parse it and append later
        if (']' == typeType[strlen(typeType) - 1]) {
          // array of structs. To parse name, remove array tokens.
          char typeNoArrTok[MAX_TYPESTRING] = {0};
          strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok) - 1);
          if (strlen(typeNoArrTok) < strlen(typeType)) {
            return UDEF_NAME_ERROR;
          }

          strtok(typeNoArrTok, "[");
          int errRet;
          if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
            return errRet;
          }
          if (SUCCESS !=
              (errRet = parseType(eip712Types, typeNoArrTok, append))) {
            return errRet;
          }
        } else {
          int errRet;
          if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
            return errRet;
          }
          if (SUCCESS != (errRet = parseType(eip712Types, typeType, append))) {
            return errRet;
          }
        }
      } else if (encTest == TOO_MANY_UDEFS) {
        return UDEFS_OVERFLOW;
      } else if (encTest == NOT_ENCODABLE) {
        return TYPE_NOT_ENCODABLE;
      }

      const char* pVal = json_getValue(pairs);
      if (NULL == pVal) {
        return JSON_NOPAIRVAL;
      }
      if (!append_type_string(typeStr, typeType) ||
          !append_type_string(typeStr, " ") ||
          !append_type_string(typeStr, pVal) ||
          !append_type_string(typeStr, ",")) {
        return UDEF_NAME_ERROR;
      }
    }
    tarray = json_getSibling(tarray);
  }
  // typeStr ends with a ',' unless there are no parameters to the type.
  if (typeStr[strlen(typeStr) - 1] == ',') {
    // replace last comma with a paren
    typeStr[strlen(typeStr) - 1] = ')';
  } else {
    // append paren, there are no parameters
    if (!append_type_string(typeStr, ")")) {
      return UDEF_NAME_ERROR;
    }
  }
  if (strlen(append) > 0) {
    if (!append_type_string(typeStr, append)) {
      return UDEF_NAME_ERROR;
    }
  }

  return SUCCESS;
}

int encAddress(const char* string, uint8_t* encoded) {
  if (string == NULL) {
    return ADDR_STRING_NULL;
  }
  uint8_t decoded[20];
  if (!decode_address(string, decoded)) {
    return ADDR_STRING_VFLOW;
  }

  memset(encoded, 0, 12);
  memcpy(encoded + 12, decoded, sizeof(decoded));
  return SUCCESS;
}

int encString(const char* string, uint8_t* encoded) {
  struct SHA3_CTX strCtx;

  sha3_256_Init(&strCtx);
  sha3_Update(&strCtx, (const unsigned char*)string, (size_t)strlen(string));
  keccak_Final(&strCtx, encoded);
  return SUCCESS;
}

int encodeBytes(const char* string, uint8_t* encoded) {
  if (!eip712_hex_is_valid(string, 0, false)) return GENERAL_ERROR;
  struct SHA3_CTX byteCtx;
  const char* valStrPtr = string + 2;

  sha3_256_Init(&byteCtx);
  while (*valStrPtr != '\0') {
    const uint8_t value =
        (uint8_t)((hex_nibble(valStrPtr[0]) << 4) | hex_nibble(valStrPtr[1]));
    sha3_Update(&byteCtx, &value, sizeof(value));
    valStrPtr += 2;
  }
  keccak_Final(&byteCtx, encoded);
  return SUCCESS;
}

int encodeBytesN(const char* typeT, const char* string, uint8_t* encoded) {
  eip712_atomic_type parsed;
  if (!eip712_atomic_type_parse(typeT, &parsed) ||
      parsed.kind != EIP712_ATOMIC_BYTES_N) {
    return BYTESN_SIZE_ERROR;
  }
  if (!eip712_hex_is_valid(string, parsed.width, true)) {
    return BYTESN_STRING_ERROR;
  }
  memset(encoded, 0, 32);
  for (size_t i = 0; i < parsed.width; i++) {
    encoded[i] = (uint8_t)((hex_nibble(string[2 + 2 * i]) << 4) |
                           hex_nibble(string[3 + 2 * i]));
  }
  return SUCCESS;
}

/* These screens were review(), which calls confirm_helper() and then returns
   true unconditionally. confirm_helper() returns false when the host sends a
   Cancel or Initialize tiny message, so a host could refuse every field screen
   and encode() would still hash typed data the user never saw. They are
   confirm() now and refusal is reported to parseVals() as USER_CANCELLED, so
   no hash is produced at all. */
int confirmName(const char* name, const char* type) {
  if (!name || !type) return GENERAL_ERROR;
  char field[EIP712_IDENTIFIER_MAX + MAX_TYPESTRING + 2] = {0};
  const int written = snprintf(field, sizeof(field), "%s %s", type, name);
  if (written < 0 || (size_t)written >= sizeof(field)) return GENERAL_ERROR;
  nameForValue = name;
  if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other, "EIP-712 Field",
                     (const uint8_t*)field, (size_t)written)) {
    return USER_CANCELLED;
  }
  return SUCCESS;
}

int confirmValue(const char* value) {
  if (!value ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_Other, "EIP-712 Value",
                     (const uint8_t*)value, strlen(value))) {
    return USER_CANCELLED;
  }
  return SUCCESS;
}

static const char *dsname = NULL, *dsversion = NULL, *dschainId = NULL,
                  *dsverifyingContract = NULL;

bool eip712_parse_canonical_u32(const char* text, uint32_t* value) {
  if (!text || !value || text[0] == '\0') return false;
  if (text[0] == '0' && text[1] != '\0') return false;

  uint32_t parsed = 0;
  for (const char* p = text; *p != '\0'; p++) {
    if (*p < '0' || *p > '9') return false;
    const uint32_t digit = (uint32_t)(*p - '0');
    if (parsed > (UINT32_MAX - digit) / 10) return false;
    parsed = parsed * 10 + digit;
  }

  *value = parsed;
  return true;
}

static void clearDsVals(void) {
  dsname = NULL;
  dsversion = NULL;
  dschainId = NULL;
  dsverifyingContract = NULL;
}

void marshallDsVals(const char* value) {
  if (0 == strncmp(nameForValue, "name", sizeof("name"))) {
    dsname = value;
  }
  if (0 == strncmp(nameForValue, "version", sizeof("version"))) {
    dsversion = value;
  }
  if (0 == strncmp(nameForValue, "chainId", sizeof("chainId"))) {
    dschainId = value;
  }
  if (0 ==
      strncmp(nameForValue, "verifyingContract", sizeof("verifyingContract"))) {
    dsverifyingContract = value;
  }
  return;
}

static int confirmTypedValue(bool ds_vals, const char* value) {
  if (ds_vals) marshallDsVals(value);
  return confirmValue(value);
}

int dsConfirm(void) {
  IconType iconNum = NO_ICON;
  char chainStr[33] = {0};
  char verifyingContract[65] = {0};

  if (dsverifyingContract != NULL) {
    /* EIP-712 types are host-controlled, so verifyingContract may reach this
     * function without having passed through the address encoder. Validate it
     * before any fixed-offset read or display.
     *
     * Merge note (#439 vs #440/GH #436): both branches fixed the same OOB read.
     * This one is kept because it is strictly stronger — it validates the hex
     * digits as well as the length and prefix, and it fails closed. The other
     * checked only length and "0x", then set dsverifyingContract = NULL and
     * fell through to a raw display, so a value like "0xZZZZ..." still reached
     * sscanf and a malformed contract was shown rather than refused. */
    /* Scoped to this block: cppcheck's variableScope rightly flagged it at
       function scope, and CI treats that as fatal. Twenty bytes exactly, the
       destination decode_address() validates into. */
    uint8_t addrHexStr[20] = {0};
    if (!decode_address(dsverifyingContract, addrHexStr)) {
      clearDsVals();
      return ADDR_STRING_VFLOW;
    }
    (void)addrHexStr;
    snprintf(verifyingContract, sizeof(verifyingContract),
             "Verifying Contract: %s", dsverifyingContract);
  }

  if (NULL != dschainId) {
    /* Merge note: the release branch parsed this with sscanf("%" SCNu32),
     * which accepts a trailing space, a leading '+', and non-canonical forms
     * like "007", and cannot report overflow. eip712_parse_canonical_u32()
     * rejects all of those and fails closed, so it is used instead. See the
     * cases in unittests/firmware/ethereum.cpp. */
    uint32_t chainInt = 0;
    if (!eip712_parse_canonical_u32(dschainId, &chainInt)) {
      clearDsVals();
      return GENERAL_ERROR;
    }
    (void)chainInt;
    // As more chains are supported, add icon choice below
    // TBD: not implemented for first release
    // if (chainInt == 1) {
    //     iconNum = ETHEREUM_ICON;
    // }
  }
  if (NULL != dschainId) {
    snprintf(chainStr, 32, "chain %s,  ", dschainId);
  }
  /* Name, version, chain and contract were already reviewed exactly on their
     field/value pages. Keep this convenience summary, but never put the
     host-controlled domain name in the trusted title position. */
  bool confirmed =
      confirm_with_icon(ButtonRequestType_ButtonRequest_Other, iconNum,
                        "EIP-712 Domain", "%s %s", chainStr, verifyingContract);
  /* Clear the marshalled domain values on the refusal path too: they are file
     statics and a later attempt must not inherit them. */
  clearDsVals();
  return confirmed ? SUCCESS : USER_CANCELLED;
}

/*
    Entry:
            eip712Types points to the eip712 types structure
            jType points to eip712 json type structure to parse
            nextVal points to the next value to encode
            msgCtx points to caller allocated hash context to hash encoded
   values into. Exit: msgCtx points to current final hash context returns error
   status

    NOTE: reentrant!
*/
int parseVals(const json_t* eip712Types, const json_t* jType,
              const json_t* nextVal, struct SHA3_CTX* msgCtx) {
  json_t const *tarray, *pairs, *walkVals, *obTest;
  int ctr;
  const char* typeType = NULL;
  uint8_t encBytes[32] = {0};  // holds the encrypted bytes for the message
  const char* valStr = NULL;
  struct SHA3_CTX valCtx = {0};  // local hash context
  bool ds_vals = 0;  // domain sep values are confirmed on a single screen
  int errRet;

  if (0 ==
      strncmp(json_getName(jType), "EIP712Domain", sizeof("EIP712Domain"))) {
    ds_vals = true;
  }

  tarray = json_getChild(jType);

  while (tarray != 0) {
    if (NULL == (pairs = json_getChild(tarray))) {
      return JSON_NO_PAIRS;
    }
    // should be type JSON_TEXT
    if (pairs->type != JSON_TEXT) {
      return JSON_PAIRS_NOTEXT;
    } else {
      const char* typeName = json_getValue(pairs);
      if (NULL == typeName) {
        return JSON_NOPAIRNAME;
      }
      if (NULL == (obTest = json_getSibling(pairs))) {
        return JSON_NO_PAIRS_SIB;
      }
      if (NULL == (typeType = json_getValue(obTest))) {
        return JSON_TYPE_T_NOVAL;
      }
      walkVals = nextVal;
      while (0 != walkVals) {
        if (0 == strcmp(json_getName(walkVals), typeName)) {
          break;
        } else {
          // keep looking for val
          walkVals = json_getSibling(walkVals);
        }
      }

      if (walkVals == 0) {
        return JSON_TYPE_WNOVAL;
      }
      const jsonType_t value_type = json_getType(walkVals);
      const bool hasValue = value_type == JSON_TEXT ||
                            value_type == JSON_INTEGER ||
                            value_type == JSON_BOOLEAN;
      valStr = hasValue ? json_getValue(walkVals) : NULL;
      errRet = confirmName(typeName, typeType);
      if (SUCCESS != errRet) return errRet;

      {
        if (0 == strncmp("address", typeType, strlen("address") - 1)) {
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of addresses
            json_t const* addrVals = json_getChild(walkVals);
            sha3_256_Init(&valCtx);  // hash of concatenated encoded strings
            while (0 != addrVals) {
              // just walk the string values assuming, for fixed sizes, all
              // values are there.
              errRet = confirmTypedValue(ds_vals, json_getValue(addrVals));
              if (SUCCESS != errRet) return errRet;

              errRet = encAddress(json_getValue(addrVals), encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
              sha3_Update(&valCtx, (const unsigned char*)encBytes, 32);
              addrVals = json_getSibling(addrVals);
            }
            keccak_Final(&valCtx, encBytes);
          } else {
            errRet = confirmTypedValue(ds_vals, valStr);
            if (SUCCESS != errRet) return errRet;
            errRet = encAddress(valStr, encBytes);
            if (SUCCESS != errRet) {
              return errRet;
            }
          }

        } else if (0 == strncmp("string", typeType, strlen("string") - 1)) {
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of strings
            json_t const* stringVals = json_getChild(walkVals);
            uint8_t strEncBytes[32];
            sha3_256_Init(&valCtx);  // hash of concatenated encoded strings
            while (0 != stringVals) {
              // just walk the string values assuming, for fixed sizes, all
              // values are there.
              errRet = confirmTypedValue(ds_vals, json_getValue(stringVals));
              if (SUCCESS != errRet) return errRet;
              errRet = encString(json_getValue(stringVals), strEncBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
              sha3_Update(&valCtx, (const unsigned char*)strEncBytes, 32);
              stringVals = json_getSibling(stringVals);
            }
            keccak_Final(&valCtx, encBytes);
          } else {
            errRet = confirmTypedValue(ds_vals, valStr);
            if (SUCCESS != errRet) return errRet;
            errRet = encString(valStr, encBytes);
            if (SUCCESS != errRet) {
              return errRet;
            }
          }

        } else if ((0 == strncmp("uint", typeType, strlen("uint") - 1)) ||
                   (0 == strncmp("int", typeType, strlen("int") - 1))) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return INT_ARRAY_ERROR;
          } else {
            errRet = confirmTypedValue(ds_vals, valStr);
            if (SUCCESS != errRet) return errRet;
            uint8_t negInt = 0;  // 0 is positive, 1 is negative
            if (0 == strncmp("int", typeType, strlen("int") - 1)) {
              if (*valStr == '-') {
                negInt = 1;
              }
            }
            // parse out the length val
            for (ctr = 0; ctr < 32; ctr++) {
              if (negInt) {
                // sign extend negative values
                encBytes[ctr] = 0xFF;
              } else {
                // zero padding for positive
                encBytes[ctr] = 0;
              }
            }
            // all int strings are assumed to be base 10 and fit into 64 bits
            long long intVal = strtoll(valStr, NULL, 10);
            // Needs to be big endian, so add to encBytes appropriately
            encBytes[24] = (intVal >> 56) & 0xff;
            encBytes[25] = (intVal >> 48) & 0xff;
            encBytes[26] = (intVal >> 40) & 0xff;
            encBytes[27] = (intVal >> 32) & 0xff;
            encBytes[28] = (intVal >> 24) & 0xff;
            encBytes[29] = (intVal >> 16) & 0xff;
            encBytes[30] = (intVal >> 8) & 0xff;
            encBytes[31] = (intVal) & 0xff;
          }

        } else if (0 == strncmp("bytes", typeType, strlen("bytes"))) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return BYTESN_ARRAY_ERROR;
          } else {
            // This could be 'bytes', 'bytes1', ..., 'bytes32'
            errRet = confirmTypedValue(ds_vals, valStr);
            if (SUCCESS != errRet) return errRet;
            if (0 == strcmp(typeType, "bytes")) {
              errRet = encodeBytes(valStr, encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }

            } else {
              errRet = encodeBytesN(typeType, valStr, encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
            }
          }

        } else if (0 == strncmp("bool", typeType, strlen(typeType))) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return BOOL_ARRAY_ERROR;
          } else {
            errRet = confirmTypedValue(ds_vals, valStr);
            if (SUCCESS != errRet) return errRet;
            for (ctr = 0; ctr < 32; ctr++) {
              // leading zeros in bool
              encBytes[ctr] = 0;
            }
            if (0 == strncmp(valStr, "true", sizeof("true"))) {
              encBytes[31] = 0x01;
            }
          }

        } else {
          // encode user defined type
          char encSubTypeStr[STRBUFSIZE + 1] = {0};
          // clear out the user-defined types list
          for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
            udefList[ctr] = NULL;
          }

          char typeNoArrTok[MAX_TYPESTRING] = {0};
          // need to get typehash of type first
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of structs. To parse name, remove array tokens.
            strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok) - 1);
            if (strlen(typeNoArrTok) < strlen(typeType)) {
              return UDEF_ARRAY_NAME_ERR;
            }
            strtok(typeNoArrTok, "[");
            if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
              return errRet;
            }
            if (SUCCESS != (errRet = parseType(eip712Types, typeNoArrTok,
                                               encSubTypeStr))) {
              return errRet;
            }
          } else {
            if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
              return errRet;
            }
            if (SUCCESS !=
                (errRet = parseType(eip712Types, typeType, encSubTypeStr))) {
              return errRet;
            }
          }
          sha3_256_Init(&valCtx);
          sha3_Update(&valCtx, (const unsigned char*)encSubTypeStr,
                      (size_t)strlen(encSubTypeStr));
          keccak_Final(&valCtx, encBytes);

          if (']' == typeType[strlen(typeType) - 1]) {
            // array of udefs
            struct SHA3_CTX eleCtx = {0};  // local hash context
            struct SHA3_CTX arrCtx = {0};  // array elements hash context
            uint8_t eleHashBytes[32];

            sha3_256_Init(&arrCtx);

            json_t const* udefVals = json_getChild(walkVals);
            while (0 != udefVals) {
              sha3_256_Init(&eleCtx);
              sha3_Update(&eleCtx, (const unsigned char*)encBytes, 32);
              if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
                return errRet;
              }
              if (SUCCESS !=
                  (errRet = parseVals(
                       eip712Types,
                       json_getProperty(eip712Types, strtok(typeNoArrTok, "]")),
                       json_getChild(udefVals),  // where to get the values
                       &eleCtx  // encode hash happens in parse, this is the
                                // return
                       ))) {
                return errRet;
              }
              keccak_Final(&eleCtx, eleHashBytes);
              sha3_Update(&arrCtx, (const unsigned char*)eleHashBytes, 32);
              // just walk the udef values assuming, for fixed sizes, all values
              // are there.
              udefVals = json_getSibling(udefVals);
            }
            keccak_Final(&arrCtx, encBytes);

          } else {
            sha3_256_Init(&valCtx);
            sha3_Update(&valCtx, (const unsigned char*)encBytes,
                        (size_t)sizeof(encBytes));
            if (STACK_GOOD != (errRet = memcheck(STACK_SIZE_GUARD))) {
              return errRet;
            }
            if (SUCCESS !=
                (errRet = parseVals(
                     eip712Types, json_getProperty(eip712Types, typeType),
                     json_getChild(walkVals),  // where to get the values
                     &valCtx  // val hash happens in parse, this is the return
                     ))) {
              return errRet;
            }
            keccak_Final(&valCtx, encBytes);
          }
        }
      }

      // hash encoded bytes to final context
      sha3_Update(msgCtx, (const unsigned char*)encBytes, 32);
    }
    tarray = json_getSibling(tarray);
  }
  if (ds_vals) {
    errRet = dsConfirm();
    if (SUCCESS != errRet) {
      return errRet;
    }
  }

  return SUCCESS;
}

int encode(const json_t* jsonTypes, const json_t* jsonVals, const char* typeS,
           uint8_t* hashRet) {
  int ctr;
  char encTypeStr[STRBUFSIZE + 1] = {0};
  uint8_t typeHash[32];
  struct SHA3_CTX finalCtx = {0};
  int errRet;
  json_t const* typesProp;
  json_t const* typeSprop;
  json_t const* domainOrMessageProp;
  json_t const* valsProp;
  const char* domOrMsgStr = NULL;

  // clear out the user-defined types list
  for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
    udefList[ctr] = NULL;
  }
  if (NULL == (typesProp = json_getProperty(jsonTypes, "types"))) {
    errRet = JSON_TYPESPROPERR;
    return errRet;
  }
  if (SUCCESS != (errRet = parseType(typesProp, typeS, encTypeStr))) {
    return errRet;
  }

  sha3_256_Init(&finalCtx);
  sha3_Update(&finalCtx, (const unsigned char*)encTypeStr,
              (size_t)strlen(encTypeStr));
  keccak_Final(&finalCtx, typeHash);

  // They typehash must be the first message of the final hash, this is the
  // start
  sha3_256_Init(&finalCtx);
  sha3_Update(&finalCtx, (const unsigned char*)typeHash,
              (size_t)sizeof(typeHash));

  if (NULL == (typeSprop = json_getProperty(
                   typesProp, typeS))) {  // e.g., typeS = "EIP712Domain"
    errRet = JSON_TYPESPROPERR;
    return errRet;
  }

  if (0 == strncmp(typeS, "EIP712Domain", sizeof("EIP712Domain"))) {
    confirmProp = DOMAIN;
    domOrMsgStr = "domain";
  } else {
    // This is the message value encoding
    confirmProp = MESSAGE;
    domOrMsgStr = "message";
  }
  if (NULL == (domainOrMessageProp = json_getProperty(
                   jsonVals, domOrMsgStr))) {  // "message" or "domain" property
    if (confirmProp == DOMAIN) {
      errRet = JSON_DPROPERR;
    } else {
      errRet = JSON_MPROPERR;
    }
    return errRet;
  }
  if (NULL ==
      (valsProp = json_getChild(
           domainOrMessageProp))) {  // "message" or "domain" property values
    if (confirmProp == MESSAGE) {
      errRet = NULL_MSG_HASH;  // this is legal, not an error.
      return errRet;
    }
  }

  if (SUCCESS !=
      (errRet = parseVals(typesProp, typeSprop, valsProp, &finalCtx))) {
    return errRet;
  }

  keccak_Final(&finalCtx, hashRet);
  // clear typeStr
  memzero(encTypeStr, sizeof(encTypeStr));

  return SUCCESS;
}
