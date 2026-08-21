extern "C" {
#include "keepkey/firmware/eip712_stream.h"
#include "messages-ethereum.pb.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>

namespace {

typedef EthereumTypedDataStructAck_EthereumFieldType Field;

Field mk(EthereumTypedDataStructAck_EthereumDataType t) {
  Field f;
  memset(&f, 0, sizeof(f));
  f.data_type = t;
  return f;
}

Field mkSized(EthereumTypedDataStructAck_EthereumDataType t, uint32_t size) {
  Field f = mk(t);
  f.has_size = true;
  f.size = size;
  return f;
}

std::string nameOf(const Field &f) {
  char out[EIP712_MAX_TYPE_NAME];
  if (!eip712_type_name(&f, out, sizeof(out))) return "<refused>";
  return std::string(out);
}

std::string hexOf(const uint8_t *b, size_t n) {
  static const char *d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[b[i] >> 4];
    s += d[b[i] & 0xF];
  }
  return s;
}

}  // namespace

// ── encodeType spelling ─────────────────────────────────────────────
// These strings go into typeHash. A wrong character here is not a display
// bug, it is a signature over a different document.

TEST(Eip712Stream, TypeNameAtomics) {
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32)),
      "uint256");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 1)),
      "uint8");
  EXPECT_EQ(nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2)),
            "int16");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 32)),
      "bytes32");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_BYTES)),
            "bytes");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_STRING)),
            "string");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_BOOL)),
            "bool");
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS)),
            "address");
}

TEST(Eip712Stream, TypeNameRejectsNonCanonicalWidths) {
  // uint0 and uint264 have no canonical spelling. Inventing one would hash a
  // type string no verifier reproduces.
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 0)),
      "<refused>");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 33)),
      "<refused>");
  EXPECT_EQ(
      nameOf(mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 33)),
      "<refused>");
  // A width-less integer is not "uint256" -- EIP-712 requires the width be
  // written, and the bare form is what the old parser silently accepted.
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_UINT)),
            "<refused>");
}

TEST(Eip712Stream, TypeNameArraysInWrittenOrder) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  f.array_levels_count = 3;
  f.array_levels[0] = 2;
  f.array_levels[1] = 0;  // dynamic
  f.array_levels[2] = 4;
  EXPECT_EQ(nameOf(f), "int16[2][][4]");

  Field s = mk(EthereumTypedDataStructAck_EthereumDataType_STRUCT);
  s.has_struct_name = true;
  strcpy(s.struct_name, "Person");
  s.array_levels_count = 1;
  s.array_levels[0] = 0;
  EXPECT_EQ(nameOf(s), "Person[]");
}

TEST(Eip712Stream, TypeNameStructNeedsAName) {
  EXPECT_EQ(nameOf(mk(EthereumTypedDataStructAck_EthereumDataType_STRUCT)),
            "<refused>");
}

// ── encodeData ──────────────────────────────────────────────────────

TEST(Eip712Stream, EncodeUintIsLeftPadded) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t v[32];
  memset(v, 0, sizeof(v));
  v[31] = 0x2a;  // 42
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 32, out));
  EXPECT_EQ(hexOf(out, 32),
            "000000000000000000000000000000000000000000000000000000000000002a");
}

TEST(Eip712Stream, EncodeUnlimitedApprovalSurvives) {
  // The old JSON path parsed integers with strtoll and refused anything above
  // 2^63-1 -- which is every unlimited ERC-20 approval there has ever been.
  // Raw bytes have no such ceiling.
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t v[32];
  memset(v, 0xFF, sizeof(v));
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 32, out));
  EXPECT_EQ(hexOf(out, 32), std::string(64, 'f'));
}

TEST(Eip712Stream, EncodeNegativeIntSignExtends) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  uint8_t v[2] = {0xFF, 0xFE};  // -2 as int16
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 2, out));
  EXPECT_EQ(hexOf(out, 32),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
}

TEST(Eip712Stream, EncodePositiveIntZeroExtends) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  uint8_t v[2] = {0x00, 0x02};
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 2, out));
  EXPECT_EQ(hexOf(out, 32),
            "0000000000000000000000000000000000000000000000000000000000000002");
}

TEST(Eip712Stream, EncodeBytesNIsRightPadded) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 4);
  uint8_t v[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 4, out));
  EXPECT_EQ(hexOf(out, 32),
            "deadbeef00000000000000000000000000000000000000000000000000000000");
}

TEST(Eip712Stream, EncodeDynamicBytesIsHashed) {
  // keccak256("") -- the canonical empty-input digest.
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_BYTES);
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, (const uint8_t *)"", 0, out));
  EXPECT_EQ(hexOf(out, 32),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST(Eip712Stream, EncodeStringIsHashed) {
  // keccak256("abc")
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, (const uint8_t *)"abc", 3, out));
  EXPECT_EQ(hexOf(out, 32),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST(Eip712Stream, EncodeAddressIsLeftPadded) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t v[20];
  memset(v, 0x11, sizeof(v));
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, v, 20, out));
  EXPECT_EQ(hexOf(out, 32),
            "0000000000000000000000001111111111111111111111111111111111111111");
}

// ── validation ──────────────────────────────────────────────────────

TEST(Eip712Stream, ValidateBool) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_BOOL);
  uint8_t t = 1, z = 0, bad = 2;
  EXPECT_TRUE(eip712_validate_leaf(&f, &t, 1));
  EXPECT_TRUE(eip712_validate_leaf(&f, &z, 1));
  EXPECT_FALSE(eip712_validate_leaf(&f, &bad, 1));  // 2 is not a bool
  EXPECT_FALSE(eip712_validate_leaf(&f, &t, 2));    // wrong width
}

TEST(Eip712Stream, ValidateAddressIsExactlyTwentyBytes) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t v[21];
  memset(v, 0, sizeof(v));
  EXPECT_TRUE(eip712_validate_leaf(&f, v, 20));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 19));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 21));
}

TEST(Eip712Stream, ValidateIntegerWidthMustMatchDeclaration) {
  // A short value would left-pad into a different number than the host meant.
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t v[32];
  memset(v, 0, sizeof(v));
  EXPECT_TRUE(eip712_validate_leaf(&f, v, 32));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 31));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 1));
}

TEST(Eip712Stream, ValidateStringRejectsControlBytes) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t *)"Send 1 USDC", 11));
  // An embedded NUL is how bytes past the terminator get signed but never
  // drawn -- the exact defect class 7.14.2 closed for message signing.
  EXPECT_FALSE(eip712_validate_leaf(&f, (const uint8_t *)"a\0b", 3));
  EXPECT_FALSE(eip712_validate_leaf(&f, (const uint8_t *)"a\nb", 3));
}

TEST(Eip712Stream, ValidateStringRejectsMalformedUtf8) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  const uint8_t lone_continuation[] = {0x80};
  EXPECT_FALSE(eip712_validate_leaf(&f, lone_continuation, 1));
  const uint8_t truncated[] = {0xE2, 0x82};  // needs a third byte
  EXPECT_FALSE(eip712_validate_leaf(&f, truncated, 2));
  const uint8_t overlong[] = {0xC0, 0xAF};  // overlong '/'
  EXPECT_FALSE(eip712_validate_leaf(&f, overlong, 2));
  const uint8_t surrogate[] = {0xED, 0xA0, 0x80};
  EXPECT_FALSE(eip712_validate_leaf(&f, surrogate, 3));
  const uint8_t euro[] = {0xE2, 0x82, 0xAC};  // U+20AC, valid
  EXPECT_TRUE(eip712_validate_leaf(&f, euro, 3));
}

TEST(Eip712Stream, ValidateBytesNIsExact) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 4);
  uint8_t v[5] = {0};
  EXPECT_TRUE(eip712_validate_leaf(&f, v, 4));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 3));
  EXPECT_FALSE(eip712_validate_leaf(&f, v, 5));
}
