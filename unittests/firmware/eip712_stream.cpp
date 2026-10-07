extern "C" {
#include "keepkey/board/canvas.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/eip712_stream.h"
#include "keepkey/firmware/eip712_stream.h"  // Public declarations stay guarded.
#include "messages-ethereum.pb.h"
#include "trezor/crypto/sha3.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include "kkconfirm_driver.h"

extern "C" {
#include "keepkey/board/confirm_sm.h"
}

void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_captured_titles(void);

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

std::string nameOf(const Field& f) {
  char out[EIP712_MAX_TYPE_NAME];
  if (!eip712_type_name(&f, out, sizeof(out))) return "<refused>";
  return std::string(out);
}

std::string hexOf(const uint8_t* b, size_t n) {
  static const char* d = "0123456789abcdef";
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

TEST(Eip712Stream, TypeNameRejectsArrayCountPastWireCapacity) {
  Field f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  f.array_levels_count = sizeof(f.array_levels) / sizeof(f.array_levels[0]) + 1;
  EXPECT_EQ(nameOf(f), "<refused>");
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
  ASSERT_TRUE(eip712_encode_leaf(&f, (const uint8_t*)"", 0, out));
  EXPECT_EQ(hexOf(out, 32),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST(Eip712Stream, EncodeStringIsHashed) {
  // keccak256("abc")
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  uint8_t out[32];
  ASSERT_TRUE(eip712_encode_leaf(&f, (const uint8_t*)"abc", 3, out));
  EXPECT_EQ(hexOf(out, 32),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST(Eip712Stream, AccumulatesOnlyValidatedDomainBindingFacts) {
  EXPECT_LE(sizeof(Eip712DomainFacts), 168u);
  Eip712DomainFacts facts{};
  Field chain = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t chain_id[32] = {0};
  chain_id[31] = 1;
  ASSERT_TRUE(eip712_domain_facts_observe(&facts, "chainId", &chain, chain_id,
                                          sizeof(chain_id)));
  EXPECT_TRUE(facts.has_chain_id);
  EXPECT_EQ(facts.chain_id, 1u);
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "chainId", &chain, chain_id,
                                           sizeof(chain_id)));

  Field address = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  uint8_t contract[20];
  for (size_t i = 0; i < sizeof(contract); i++) contract[i] = i;
  ASSERT_TRUE(eip712_domain_facts_observe(&facts, "verifyingContract", &address,
                                          contract, sizeof(contract)));
  EXPECT_TRUE(facts.has_verifying_contract);
  EXPECT_EQ(memcmp(facts.verifying_contract, contract, sizeof(contract)), 0);

  Field name = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  EXPECT_TRUE(eip712_domain_facts_observe(
      &facts, "name", &name, reinterpret_cast<const uint8_t*>("App"), 3));
}

TEST(Eip712Stream, RejectsUnrepresentableOrMalformedDomainBindings) {
  Eip712DomainFacts facts{};
  Field chain = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  uint8_t too_large[32] = {0};
  too_large[0] = 1;
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "chainId", &chain, too_large,
                                           sizeof(too_large)));
  uint8_t zero[32] = {0};
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "chainId", &chain, zero,
                                           sizeof(zero)));
  Field bytes = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, 20);
  uint8_t contract[20] = {0};
  EXPECT_FALSE(eip712_domain_facts_observe(&facts, "verifyingContract", &bytes,
                                           contract, sizeof(contract)));
}

TEST(Eip712Stream, CertifiedWalkPausesBeforeMessageValuesUntilAccepted) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  ASSERT_TRUE(eip712_stream_begin(&begin, true));

  EthereumTypedDataStructAck empty{};
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  ASSERT_STREQ(eip712_stream_next()->struct_name, "EIP712Domain");
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover domain
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash domain type
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // complete domain
  ASSERT_STREQ(eip712_stream_next()->struct_name, "Mail");
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // discover message
  ASSERT_TRUE(eip712_stream_on_struct(&empty));  // hash message type

  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DEFINITION);
  EXPECT_EQ(eip712_stream_waiting(), EIP712_IDLE);
  EXPECT_TRUE(eip712_stream_definition_accepted());
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  EXPECT_STREQ(eip712_stream_next()->struct_name, "Mail");
  EXPECT_FALSE(eip712_stream_definition_accepted());
  eip712_stream_abort();
}

TEST(Eip712Stream, RefusesSchemaChangesAfterDiscoveryAndHashing) {
  for (int repeat_phase : {1, 2}) {
    EthereumSignTypedData begin{};
    strcpy(begin.primary_type, "Mail");
    ASSERT_TRUE(eip712_stream_begin(&begin, false));
    EthereumTypedDataStructAck schema{};
    for (int i = 0; i < repeat_phase; i++)
      ASSERT_TRUE(eip712_stream_on_struct(&schema));
    schema.members_count = 1;
    strcpy(schema.members[0].name, "injected");
    schema.members[0].type =
        mk(EthereumTypedDataStructAck_EthereumDataType_BOOL);
    EXPECT_FALSE(eip712_stream_on_struct(&schema));
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
  }
}

TEST(Eip712Stream, EnforcesSignedDomainNameAndAbsenceConstraints) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  ASSERT_TRUE(eip712_stream_begin(&begin, true));
  EthereumTypedDataStructAck domain{};
  domain.members_count = 1;
  strcpy(domain.members[0].name, "name");
  domain.members[0].type =
      mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&domain));
  EthereumTypedDataValueAck value{};
  value.value.size = 3;
  memcpy(value.value.bytes, "App", 3);
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(eip712_stream_on_value(&value));
  EXPECT_EQ(kkconfirm_drain(), 0);
  EthereumTypedDataStructAck empty{};
  for (int i = 0; i < 2; i++) ASSERT_TRUE(eip712_stream_on_struct(&empty));
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DEFINITION);
  EXPECT_TRUE(
      eip712_stream_domain_matches(1, 4, (const uint8_t*)"App", 3, false));
  EXPECT_FALSE(
      eip712_stream_domain_matches(1, 4, (const uint8_t*)"Other", 5, false));
  EXPECT_FALSE(eip712_stream_domain_matches(1, 0, nullptr, 0, true));
  EXPECT_TRUE(eip712_stream_domain_matches(2, 0, nullptr, 0, true));
  EXPECT_FALSE(
      eip712_stream_domain_matches(2, 4, (const uint8_t*)"1", 1, false));
  eip712_stream_abort();
  EXPECT_FALSE(
      eip712_stream_domain_matches(1, 4, (const uint8_t*)"App", 3, false));
}

TEST(Eip712Stream, CertifiedFieldReplayPreservesDomainAndSigningPath) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Mail");
  begin.address_n_count = 1;
  begin.address_n[0] = 0x8000002c;
  ASSERT_TRUE(eip712_stream_begin(&begin, true));
  EthereumTypedDataStructAck empty{};
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&empty));
  EthereumTypedDataStructAck schema{};
  schema.members_count = 1;
  strcpy(schema.members[0].name, "amount");
  schema.members[0].type =
      mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  for (int i = 0; i < 2; i++) ASSERT_TRUE(eip712_stream_on_struct(&schema));
  ASSERT_TRUE(eip712_stream_resume_for_field());
  ASSERT_TRUE(eip712_stream_on_struct(&schema));
  EthereumTypedDataValueAck value{};
  value.value.size = 32;
  value.value.bytes[31] = 42;
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(eip712_stream_on_value(&value));
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  const auto first = *eip712_stream_next();
  EXPECT_EQ(kkconfirm_drain(), 0);
  ASSERT_TRUE(eip712_stream_resume_for_field());
  EXPECT_STREQ(eip712_stream_next()->struct_name, "Mail");
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&schema));
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(eip712_stream_on_value(&value));
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_EQ(memcmp(first.domain_separator,
                   eip712_stream_next()->domain_separator, 32),
            0);
  EXPECT_EQ(memcmp(first.message_hash, eip712_stream_next()->message_hash, 32),
            0);
  EXPECT_EQ(eip712_stream_next()->address_n[0], begin.address_n[0]);
  EXPECT_EQ(kkconfirm_drain(), 0);
  eip712_stream_abort();
  EXPECT_FALSE(eip712_stream_resume_for_field());
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
  EXPECT_TRUE(eip712_validate_leaf(&f, (const uint8_t*)"Send 1 USDC", 11));
  // An embedded NUL is how bytes past the terminator get signed but never
  // drawn -- the exact defect class 7.14.2 closed for message signing.
  EXPECT_FALSE(eip712_validate_leaf(&f, (const uint8_t*)"a\0b", 3));
  EXPECT_FALSE(eip712_validate_leaf(&f, (const uint8_t*)"a\nb", 3));
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

// ── encodeType / typeHash ───────────────────────────────────────────
//
// Backed by a fixture lookup rather than a device, which is the whole point of
// taking the lookup as a callback: the type graph is testable without an
// emulator, and these are the vectors a compliant verifier must agree with.

namespace {

struct Fixture {
  std::map<std::string, EthereumTypedDataStructAck> defs;
};

const EthereumTypedDataStructAck* fixtureLookup(const char* name, void* ctx) {
  Fixture* f = static_cast<Fixture*>(ctx);
  auto it = f->defs.find(std::string(name));
  return it == f->defs.end() ? nullptr : &it->second;
}

void addMember(EthereumTypedDataStructAck& ack, const char* mname,
               const Field& type) {
  auto& m = ack.members[ack.members_count++];
  memset(&m, 0, sizeof(m));
  m.type = type;
  strcpy(m.name, mname);
}

Field structField(const char* sname) {
  Field f = mk(EthereumTypedDataStructAck_EthereumDataType_STRUCT);
  f.has_struct_name = true;
  strcpy(f.struct_name, sname);
  return f;
}

std::string typeHashHex(Fixture& f, const char* primary) {
  uint8_t out[32];
  if (!eip712_type_hash(primary, fixtureLookup, &f, out)) return "<refused>";
  return hexOf(out, 32);
}

// keccak256 of a literal, for building expectations in the test itself.
std::string keccakHex(const std::string& s) {
  uint8_t out[32];
  keccak_256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), out);
  return hexOf(out, 32);
}

}  // namespace

TEST(Eip712Stream, ReviewIdentifiersAreCanonicalAndNeverTruncated) {
  EXPECT_TRUE(eip712_identifier_ok("PermitSingle"));
  EXPECT_TRUE(eip712_identifier_ok("sigDeadline"));
  EXPECT_TRUE(eip712_identifier_ok("_value$2"));

  EXPECT_FALSE(eip712_identifier_ok(""));
  EXPECT_FALSE(eip712_identifier_ok("2value"));
  EXPECT_FALSE(eip712_identifier_ok("line\nbreak"));
  EXPECT_FALSE(eip712_identifier_ok("amount%08x"));
  EXPECT_FALSE(eip712_identifier_ok("member-name"));
  EXPECT_FALSE(eip712_identifier_ok("identifier_that_would_be_truncated"));
  // ':' is a struct-name character only (Hyperliquid's user-signed actions).
  EXPECT_FALSE(eip712_identifier_ok("HyperliquidTransaction:UsdSend"));
}

TEST(Eip712Stream, StructTypeNamesAllowAColonAndFortySevenCharacters) {
  EXPECT_TRUE(eip712_type_identifier_ok("PermitSingle"));
  EXPECT_TRUE(eip712_type_identifier_ok("HyperliquidTransaction:UsdSend"));
  EXPECT_TRUE(
      eip712_type_identifier_ok("HyperliquidTransaction:ApproveBuilderFee"));
  const std::string longest(EIP712_MAX_STRUCT_NAME - 1, 'T');
  EXPECT_GE(longest.size(), 47u);
  EXPECT_TRUE(eip712_type_identifier_ok(longest.c_str()));
  EXPECT_FALSE(eip712_type_identifier_ok((longest + "T").c_str()));
  EXPECT_FALSE(eip712_type_identifier_ok(":UsdSend"));
  EXPECT_FALSE(eip712_type_identifier_ok("Hyperliquid Transaction"));
  EXPECT_FALSE(eip712_type_identifier_ok("Order(uint256 a)"));
  EXPECT_FALSE(eip712_type_identifier_ok(""));

  // encodeType spells the name byte for byte.
  Fixture f;
  auto& send = f.defs["HyperliquidTransaction:UsdSend"];
  memset(&send, 0, sizeof(send));
  addMember(send, "destination",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(send, "time",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 8));
  EXPECT_EQ(typeHashHex(f, "HyperliquidTransaction:UsdSend"),
            keccakHex("HyperliquidTransaction:UsdSend(string destination,"
                      "uint64 time)"));
}

TEST(Eip712Stream, TypeHashRejectsDuplicateMemberNames) {
  Fixture f;
  auto& permit = f.defs["Permit"];
  memset(&permit, 0, sizeof(permit));
  addMember(permit, "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  addMember(permit, "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  EXPECT_EQ(typeHashHex(f, "Permit"), "<refused>");
}

TEST(Eip712Stream, TypeHashMatchesTheSpecExample) {
  // The canonical EIP-712 example. Note Person sorts AFTER Mail's own segment
  // and is appended, not interleaved.
  Fixture f;
  auto& person = f.defs["Person"];
  memset(&person, 0, sizeof(person));
  addMember(person, "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(person, "wallet",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));

  auto& mail = f.defs["Mail"];
  memset(&mail, 0, sizeof(mail));
  addMember(mail, "from", structField("Person"));
  addMember(mail, "to", structField("Person"));
  addMember(mail, "contents",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));

  // The expectation is the PUBLISHED literal, not a keccak of a string written
  // in this test. That distinction is the whole point: an expectation this test
  // derives the same way the implementation does would agree with a shared
  // misreading of the spec and still go green.
  //
  // Source: assets/eip-712/Example.js in the ethereum/EIPs repository -- the
  // reference implementation EIP-712 itself links to. Its assertions publish
  // typeHash('Mail') verbatim. Independently republished by Example.sol in the
  // same directory, by MetaMask eth-sig-util's hashStruct snapshots for both
  // V3 and V4, and by Mrtenz/eip-712.
  EXPECT_EQ(typeHashHex(f, "Mail"),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");

  // And the string itself, so a failure says WHICH half diverged.
  EXPECT_EQ(typeHashHex(f, "Mail"),
            keccakHex("Mail(Person from,Person to,string contents)"
                      "Person(string name,address wallet)"));
}

TEST(Eip712Stream, ReferencedStructsAreSortedByName) {
  // THE CANARY. eip712.c appends referenced definitions in DISCOVERY order and
  // contains no sort call, so this document -- which names Zebra before Apple
  // -- is exactly the case it gets wrong. Two devices would disagree with each
  // other and both would look internally consistent.
  Fixture f;
  auto& zebra = f.defs["Zebra"];
  memset(&zebra, 0, sizeof(zebra));
  addMember(zebra, "stripes",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  auto& apple = f.defs["Apple"];
  memset(&apple, 0, sizeof(apple));
  addMember(apple, "colour",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));

  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "z", structField("Zebra"));  // referenced FIRST
  addMember(m, "a", structField("Apple"));  // referenced SECOND

  // Alphabetical, not discovery order: Apple before Zebra.
  EXPECT_EQ(typeHashHex(f, "M"), keccakHex("M(Zebra z,Apple a)"
                                           "Apple(string colour)"
                                           "Zebra(uint256 stripes)"));
}

TEST(Eip712Stream, SortIsNotMerelyReversedDiscoveryOrder) {
  // The Zebra/Apple canary above is WEAKER THAN IT LOOKS. Zebra is discovered
  // before Apple, so plain "reverse the discovery list" produces the same
  // order as a correct sort and a buggy implementation passes it.
  //
  // Discovering in ALPHABETICAL order separates them, because now reversal is
  // the one thing that gets it wrong:
  //   discovery  [Alpha, Bravo]
  //   reversed   [Bravo, Alpha]   <- wrong
  //   SORTED     [Alpha, Bravo]   <- correct
  //
  // The two canaries are complementary and neither is redundant: Zebra/Apple
  // catches "no sort at all", this one catches "reversed". Deleting either
  // leaves a wrong implementation that passes the other. The five-dependency
  // case in RefusesADocumentWiderThanTheClosure separates all three at once.
  Fixture f;
  const char* names[] = {"Alpha", "Bravo"};
  for (const char* n : names) {
    auto& d = f.defs[n];
    memset(&d, 0, sizeof(d));
    addMember(d, "v",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  }
  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "a", structField("Alpha"));
  addMember(m, "b", structField("Bravo"));

  EXPECT_EQ(typeHashHex(f, "M"), keccakHex("M(Alpha a,Bravo b)"
                                           "Alpha(uint256 v)"
                                           "Bravo(uint256 v)"));
}

TEST(Eip712Stream, RefusesADocumentWiderThanTheClosure) {
  // EIP712_MAX_STRUCTS bounds the closure INCLUDING the primary type, so the
  // real ceiling is that many distinct struct types in one document. A
  // UniswapX PriorityOrder witness sits exactly at it; one more dependency
  // must be REFUSED rather than silently truncated, because a truncated
  // closure still produces a well-formed 32-byte typeHash -- one that no
  // verifier reproduces.
  // Discovered neither sorted nor reverse-sorted.
  const char* names[] = {"Delta", "Alpha", "Foxtrot",
                         "Bravo", "Echo",  "Charlie"};
  static_assert(sizeof(names) / sizeof(names[0]) == EIP712_MAX_STRUCTS,
                "one dependency more than fits");
  for (size_t used = EIP712_MAX_STRUCTS - 1; used <= EIP712_MAX_STRUCTS;
       used++) {
    Fixture f;
    auto& m = f.defs["M"];
    memset(&m, 0, sizeof(m));
    std::string head = "M(", tail;
    std::vector<std::string> sorted;
    for (size_t i = 0; i < used; i++) {
      auto& d = f.defs[names[i]];
      memset(&d, 0, sizeof(d));
      addMember(d, "v",
                mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
      char member[2] = {(char)('a' + i), 0};
      addMember(m, member, structField(names[i]));
      head += std::string(i ? "," : "") + names[i] + " " + member;
      sorted.push_back(names[i]);
    }
    std::sort(sorted.begin(), sorted.end());
    for (const std::string& n : sorted) tail += n + "(uint256 v)";
    if (used < EIP712_MAX_STRUCTS) {
      EXPECT_EQ(typeHashHex(f, "M"), keccakHex(head + ")" + tail));
    } else {
      EXPECT_EQ(typeHashHex(f, "M"), "<refused>");
    }
  }
}

TEST(Eip712Stream, TransitivelyReferencedStructsAreCollectedAndSorted) {
  // A struct reached only THROUGH another dependency still belongs in the
  // closure, and still sorts among the rest rather than trailing the struct
  // that introduced it.
  Fixture f;
  auto& inner = f.defs["Aardvark"];
  memset(&inner, 0, sizeof(inner));
  addMember(inner, "n",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  auto& mid = f.defs["Zulu"];
  memset(&mid, 0, sizeof(mid));
  addMember(mid, "deep", structField("Aardvark"));  // only reachable via Zulu

  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "z", structField("Zulu"));

  EXPECT_EQ(typeHashHex(f, "M"), keccakHex("M(Zulu z)"
                                           "Aardvark(uint256 n)"
                                           "Zulu(Aardvark deep)"));
}

TEST(Eip712Stream, StructReachableOnlyAsAnArrayElementIsStillInTheClosure) {
  // Trezor fixed exactly this in 2.5.1. An array member still carries
  // data_type STRUCT with array_levels set, so the collector must look at
  // struct_name regardless of the dimensions.
  Fixture f;
  auto& person = f.defs["Person"];
  memset(&person, 0, sizeof(person));
  addMember(person, "wallet",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));

  auto& m = f.defs["Group"];
  memset(&m, 0, sizeof(m));
  Field arr = structField("Person");
  arr.array_levels_count = 1;
  arr.array_levels[0] = 0;  // Person[]
  addMember(m, "members", arr);

  EXPECT_EQ(typeHashHex(f, "Group"),
            keccakHex("Group(Person[] members)Person(address wallet)"));
}

TEST(Eip712Stream, Permit2PermitSingleTypeHash) {
  // The payload that started all of this. PermitSingle nests PermitDetails, so
  // any flat-structs-only implementation cannot sign a Uniswap approval.
  Fixture f;
  auto& details = f.defs["PermitDetails"];
  memset(&details, 0, sizeof(details));
  addMember(details, "token",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(details, "amount",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 20));
  addMember(details, "expiration",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 6));
  addMember(details, "nonce",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 6));

  auto& single = f.defs["PermitSingle"];
  memset(&single, 0, sizeof(single));
  addMember(single, "details", structField("PermitDetails"));
  addMember(single, "spender",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(single, "sigDeadline",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  EXPECT_EQ(typeHashHex(f, "PermitSingle"),
            keccakHex("PermitSingle(PermitDetails details,address spender,"
                      "uint256 sigDeadline)"
                      "PermitDetails(address token,uint160 amount,"
                      "uint48 expiration,uint48 nonce)"));
}

TEST(Eip712Stream, Eip2612PermitTypeHashMatchesUsdcsOwnContract) {
  // Circle publishes this constant in their deployed FiatTokenV2_2 source:
  //   contracts/v2/EIP2612.sol
  //   bytes32 public constant PERMIT_TYPEHASH =
  //       0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
  // OpenZeppelin's ERC20Permit computes the same value. A flat struct, so this
  // pins field order and the atomic spellings rather than the closure.
  Fixture f;
  auto& permit = f.defs["Permit"];
  memset(&permit, 0, sizeof(permit));
  addMember(permit, "owner",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(permit, "spender",
            mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
  addMember(permit, "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  addMember(permit, "nonce",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  addMember(permit, "deadline",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));

  EXPECT_EQ(typeHashHex(f, "Permit"),
            "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9");
}

TEST(Eip712Stream, TypeHashRefusesAMissingStruct) {
  Fixture f;
  auto& m = f.defs["M"];
  memset(&m, 0, sizeof(m));
  addMember(m, "ghost", structField("NotSupplied"));
  EXPECT_EQ(typeHashHex(f, "M"), "<refused>");
}

TEST(Eip712Stream, TypeHashTerminatesOnACycle) {
  // EIP-712 leaves cyclical data undefined. The collector must not recurse
  // forever on a host that supplies one.
  Fixture f;
  auto& a = f.defs["A"];
  memset(&a, 0, sizeof(a));
  addMember(a, "b", structField("B"));
  auto& b = f.defs["B"];
  memset(&b, 0, sizeof(b));
  addMember(b, "a", structField("A"));

  // Terminates. The value is not the interesting part; not hanging is.
  std::string h = typeHashHex(f, "A");
  EXPECT_EQ(h, keccakHex("A(B b)B(A a)"));
}

// ── Review screens and signing policy ────────────────────────────────
namespace {

typedef EthereumTypedDataStructAck Struct;
typedef std::vector<uint8_t> Bytes;

Bytes word(uint8_t low) {
  Bytes b(32, 0);
  b[31] = low;
  return b;
}

// Drive the walk to its end, answering every request from `types` and
// `value(path)`, with `screens` accepted confirmations available. Returns how
// many were used; -1 means more screens were shown than were accepted.
int walk(const char* primary, const std::map<std::string, Struct>& types,
         Bytes (*value)(const std::vector<uint32_t>&), int screens,
         bool certified = false) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, primary);
  if (!kkconfirm_preload(screens, 0)) return -2;
  if (!eip712_stream_begin(&begin, certified))
    return screens - kkconfirm_drain() / 2;
  for (;;) {
    const Eip712Next* next = eip712_stream_next();
    if (next->kind == EIP712_REQ_STRUCT) {
      auto it = types.find(next->struct_name);
      Struct empty{};
      eip712_stream_on_struct(it == types.end() ? &empty : &it->second);
    } else if (next->kind == EIP712_REQ_VALUE) {
      std::vector<uint32_t> path(next->member_path,
                                 next->member_path + next->member_path_len);
      Bytes v = value(path);
      EthereumTypedDataValueAck ack{};
      ack.value.size = v.size();
      memcpy(ack.value.bytes, v.data(), v.size());
      eip712_stream_on_value(&ack);
    } else {
      break;
    }
  }
  // Two messages per screen; negative means the rejection sentinel was used.
  const int unused = kkconfirm_drain();
  return unused < 0 ? -1 : screens - unused / 2;
}

std::string decimal(Field f, const Bytes& v) {
  char out[82];
  if (!eip712_render_integer(&f, v.data(), v.size(), out, sizeof(out)))
    return "<refused>";
  return out;
}

}  // namespace

TEST(Eip712Stream, IntegersRenderInDecimalWithTheirSign) {
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  Field i8 = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 1);
  Field i16 = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  Field i256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 32);
  Bytes thousand(32, 0);
  thousand[30] = 0x03;
  thousand[31] = 0xe8;
  EXPECT_EQ(decimal(u256, thousand), "1000");
  EXPECT_EQ(decimal(u256, Bytes(32, 0)), "0");
  EXPECT_EQ(decimal(u256, Bytes(32, 0xff)),
            "115792089237316195423570985008687907853269984665640564039457584"
            "007913129639935");
  EXPECT_EQ(decimal(i8, Bytes{0x80}), "-128");
  EXPECT_EQ(decimal(i8, Bytes{0x7f}), "127");
  EXPECT_EQ(decimal(i16, Bytes{0xff, 0xff}), "-1");
  Bytes min256(32, 0);
  min256[0] = 0x80;
  EXPECT_EQ(decimal(i256, min256),
            "-57896044618658097711785492504343953926634992332820282019728792"
            "003956564819968");
  // uint does not sign-extend a set top bit.
  Field u8 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 1);
  EXPECT_EQ(decimal(u8, Bytes{0x80}), "128");
}

// A dynamic value longer than one screen body used to be refused by confirm()
// and reported to the host as a user cancel. It is now disclosed in numbered
// parts, each its own confirmation, and the document signs.
TEST(Eip712Stream, LongValuesAreDisclosedInPartsAndSign) {
  std::map<std::string, Struct> types;
  addMember(types["Blob"], "data",
            mk(EthereumTypedDataStructAck_EthereumDataType_BYTES));
  addMember(types["Blob"], "note",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  int used = walk(
      "Blob", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[1] == 0) return Bytes(EIP712_MAX_LEAF, 0xab);
        Bytes s;  // 300 x U+00E9, escaped to four characters per byte
        for (int i = 0; i < 300; i++) {
          s.push_back(0xc3);
          s.push_back(0xa9);
        }
        return s;
      },
      200);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  // 2,050 hex characters and 2,400 escaped ones cannot fit fewer than
  // seven and eight 351-character bodies.
  EXPECT_GE(used, 15);
  eip712_stream_abort();
}

// Owner decision 2026-10-07: unlimited permits sign, never refused. The value
// leaf's own screen reads UNLIMITED under a warning title; a finite value and
// a revoking DAI permit keep the ordinary screen.
TEST(Eip712Stream, UnlimitedPermitsSignWithAWarningOnTheirValue) {
  struct Case {
    const char* primary;
    const char* container;
    const char* member;
    Field type;
    Bytes unlimited;
    Bytes finite;
    const char* unlimited_body;
    const char* finite_body;
  };
  const Case cases[] = {
      {"Permit", "Permit", "value",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       Bytes(32, 0xff), word(1), "value\nuint256: UNLIMITED",
       "value\nuint256: 1"},
      {"Permit", "Permit", "allowed",
       mk(EthereumTypedDataStructAck_EthereumDataType_BOOL), Bytes{1}, Bytes{0},
       "allowed\nbool: UNLIMITED (allowed)", "allowed\nbool: false"},
      {"PermitSingle", "PermitDetails", "amount",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 20),
       Bytes(20, 0xff),
       []() {
         Bytes b(20, 0);
         b[19] = 1;
         return b;
       }(),
       "details.amount\nuint160: UNLIMITED", "details.amount\nuint160: 1"},
      {"PermitTransferFrom", "TokenPermissions", "amount",
       mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32),
       Bytes(32, 0xff), word(7), "details.amount\nuint256: UNLIMITED",
       "details.amount\nuint256: 7"},
  };
  static const Case* current;
  static bool unlimited;
  for (const Case& c : cases) {
    SCOPED_TRACE(c.member);
    std::map<std::string, Struct> types;
    addMember(types[c.container], "token",
              mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
    addMember(types[c.container], c.member, c.type);
    if (strcmp(c.primary, c.container) != 0)
      addMember(types[c.primary], "details", structField(c.container));
    current = &c;
    for (bool u : {true, false}) {
      unlimited = u;
      kkconfirm_capture_start();
      int used = walk(
          c.primary, types,
          [](const std::vector<uint32_t>& path) -> Bytes {
            if (path.back() == 0) return Bytes(20, 0x11);
            return unlimited ? current->unlimited : current->finite;
          },
          5);
      const std::vector<std::string> bodies = kkconfirm_capture_finish();
      const std::vector<std::string> titles = kkconfirm_captured_titles();
      EXPECT_EQ(used, 2);  // the token screen, then the value screen
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
      ASSERT_EQ(bodies.size(), 2u);
      EXPECT_EQ(titles[0], "EIP-712 Message");
      EXPECT_EQ(titles[1], u ? "UNLIMITED approval" : "EIP-712 Message");
      EXPECT_EQ(bodies[1], u ? c.unlimited_body : c.finite_body);
      std::string title = titles[1];
      for (char& ch : title) ch = (char)toupper((unsigned char)ch);
      EXPECT_EQ(1u,
                calc_str_line(get_title_font(), title.c_str(), TITLE_WIDTH));
      eip712_stream_abort();
    }
  }
}

// Only the permit members named above get the warning: an all-ones amount in
// any other struct is an ordinary number.
TEST(Eip712Stream, AllOnesOutsideAPermitIsAnOrdinaryNumber) {
  std::map<std::string, Struct> types;
  addMember(types["Order"], "value",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  kkconfirm_capture_start();
  int used = walk(
      "Order", types,
      [](const std::vector<uint32_t>&) -> Bytes { return Bytes(32, 0xff); }, 4);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  EXPECT_GE(used, 1);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  std::string shown;
  for (const std::string& title : kkconfirm_captured_titles())
    EXPECT_EQ(0u, title.rfind("EIP-712 Message", 0)) << title;
  for (const std::string& body : bodies) shown += body;
  EXPECT_EQ(std::string::npos, shown.find("UNLIMITED"));
  EXPECT_NE(std::string::npos, shown.find("115792089237316195"));
  eip712_stream_abort();
}

// eth-sig-util/MetaMask v4 sign keccak(0x1901 || domainSeparator) when the
// primary type is EIP712Domain; walking a "message" would sign another digest.
TEST(Eip712Stream, DomainOnlyPrimaryTypeSignsTheDomainSeparatorAlone) {
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  int used = walk(
      "EIP712Domain", types,
      [](const std::vector<uint32_t>&) -> Bytes {
        return Bytes{'A', 'p', 'p'};
      },
      3);
  EXPECT_EQ(used, 1);
  const Eip712Next* next = eip712_stream_next();
  ASSERT_EQ(next->kind, EIP712_REQ_DONE);
  EXPECT_TRUE(next->domain_only);
  EXPECT_STREQ(next->primary_type, "EIP712Domain");
  // hashStruct(EIP712Domain{name:"App"}) from its spec definition.
  uint8_t type_hash[32], name_hash[32], encoded[64], expected[32];
  keccak_256((const uint8_t*)"EIP712Domain(string name)", 25, type_hash);
  keccak_256((const uint8_t*)"App", 3, name_hash);
  memcpy(encoded, type_hash, 32);
  memcpy(encoded + 32, name_hash, 32);
  keccak_256(encoded, sizeof(encoded), expected);
  EXPECT_EQ(hexOf(next->domain_separator, 32), hexOf(expected, 32));
  eip712_stream_abort();

  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "EIP712Domain");
  EXPECT_FALSE(eip712_stream_begin(&begin, true));
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
}

TEST(Eip712Stream, EmptyMessageIsFlaggedForTheFinalScreen) {
  std::map<std::string, Struct> types;
  types["Nothing"];
  const int used = walk(
      "Nothing", types,
      [](const std::vector<uint32_t>&) -> Bytes { return {}; }, 2);
  EXPECT_EQ(used, 0);
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_TRUE(eip712_stream_next()->message_empty);
  EXPECT_FALSE(eip712_stream_next()->domain_only);
  eip712_stream_abort();
}

// Seaport's OrderComponents has 11 members and holds arrays of 5- and
// 6-member structs, which the former 12-slot pool could never fit.
TEST(Eip712Stream, SeaportShapedDocumentFitsThePool) {
  std::map<std::string, Struct> types;
  Field u256 = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  Field items = structField("ConsiderationItem");
  items.array_levels_count = 1;
  for (int i = 0; i < 10; i++) {
    char name[8];
    snprintf(name, sizeof(name), "f%d", i);
    addMember(types["OrderComponents"], name, u256);
  }
  addMember(types["OrderComponents"], "consideration", items);
  for (int i = 0; i < 6; i++) {
    char name[8];
    snprintf(name, sizeof(name), "g%d", i);
    addMember(types["ConsiderationItem"], name, u256);
  }
  int used = walk(
      "OrderComponents", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path.size() == 2 && path[1] == 10)
          return Bytes{0x00, 0x03};  // three items
        return word(path.back());
      },
      40);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_EQ(used, 10 + 3 * 6);
  eip712_stream_abort();
}

// Every nested struct and every array dimension is one frame. Four fit (the
// UniswapX witness.baseOutputs[i] and eth-sig-util to[i].wallets shapes); a
// fifth is refused before it is pushed.
TEST(Eip712Stream, NestsFourFramesDeepButNotFive) {
  const char* chain[] = {"L1", "L2", "L3", "L4", "L5"};
  for (size_t frames : {4u, 5u}) {
    SCOPED_TRACE(frames);
    std::map<std::string, Struct> types;
    for (size_t i = 0; i + 1 < frames; i++)
      addMember(types[chain[i]], "next", structField(chain[i + 1]));
    addMember(types[chain[frames - 1]], "v",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
    const int used = walk(
        "L1", types,
        [](const std::vector<uint32_t>&) -> Bytes { return word(9); }, 2);
    if (frames == 4) {
      EXPECT_EQ(used, 1);
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    } else {
      EXPECT_EQ(used, 0);
      ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
      EXPECT_STREQ(eip712_stream_next()->error,
                   "EIP-712 document nests too deeply for this device");
    }
    eip712_stream_abort();
  }
}

namespace {

Eip712ReqKind walkMatrix(const std::vector<uint32_t>& written_levels,
                         uint16_t rows, uint16_t cols) {
  EthereumTypedDataStructAck domain{};
  EthereumTypedDataStructAck matrix{};
  Field values = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, 2);
  values.array_levels_count = written_levels.size();
  for (size_t i = 0; i < written_levels.size(); i++)
    values.array_levels[i] = written_levels[i];
  addMember(matrix, "values", values);

  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "Matrix");
  eip712_stream_begin(&begin, false);
  for (int step = 0; step < 100; step++) {
    const Eip712Next* next = eip712_stream_next();
    switch (next->kind) {
      case EIP712_REQ_STRUCT:
        eip712_stream_on_struct(
            strcmp(next->struct_name, "Matrix") == 0 ? &matrix : &domain);
        break;
      case EIP712_REQ_DEFINITION:
        eip712_stream_definition_accepted();
        break;
      case EIP712_REQ_VALUE: {
        EthereumTypedDataValueAck ack{};
        uint16_t v = next->member_path_len == 2   ? rows
                     : next->member_path_len == 3 ? cols
                                                  : 1;
        ack.value.size = 2;
        ack.value.bytes[0] = v >> 8;
        ack.value.bytes[1] = v & 0xff;
        if (!kkconfirm_preload(1, 0)) return EIP712_REQ_NONE;
        eip712_stream_on_value(&ack);
        kkconfirm_drain();
        break;
      }
      default: {
        Eip712ReqKind kind = next->kind;
        eip712_stream_abort();
        return kind;
      }
    }
  }
  eip712_stream_abort();
  return EIP712_REQ_NONE;
}

}  // namespace

TEST(Eip712Stream, FixedDimensionsAreCheckedOutermostFirst) {
  EXPECT_EQ(walkMatrix({2, 4}, 4, 2), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({2, 4}, 2, 2), EIP712_REQ_FAIL);
  EXPECT_EQ(walkMatrix({2, 4}, 4, 4), EIP712_REQ_FAIL);
}

TEST(Eip712Stream, InnerDimensionsAreCheckedToo) {
  EXPECT_EQ(walkMatrix({2, 0}, 3, 2), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({2, 0}, 3, 1), EIP712_REQ_FAIL);
  EXPECT_EQ(walkMatrix({0, 4}, 4, 3), EIP712_REQ_DONE);
  EXPECT_EQ(walkMatrix({0, 4}, 3, 3), EIP712_REQ_FAIL);
}

// Titles do not push the body down when they wrap, so every review title
// must fit one row even for the longest accepted primary type.
TEST(Eip712Stream, LeafTitlesFitOneRowForTheLongestPrimaryType) {
  const std::string primary(EIP712_MAX_STRUCT_NAME - 1, 'W');
  ASSERT_TRUE(eip712_type_identifier_ok(primary.c_str()));
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(types[primary], "amount",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  kkconfirm_capture_start();
  const int used = walk(
      primary.c_str(), types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        return path[0] == 0 ? Bytes{'A', 'p', 'p'} : word(5);
      },
      2);
  kkconfirm_capture_finish();
  EXPECT_EQ(used, 2);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  EXPECT_STREQ(eip712_stream_next()->primary_type, primary.c_str());
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  ASSERT_EQ(titles.size(), 2u);
  for (std::string title : titles) {
    for (char& c : title) c = (char)toupper((unsigned char)c);
    EXPECT_EQ(1u, calc_str_line(get_title_font(), title.c_str(), TITLE_WIDTH))
        << title;
  }
  eip712_stream_abort();
}

// An empty array has no element screens. Its path, declared type and zero
// length are reviewed instead, at every nesting level.
TEST(Eip712Stream, EmptyArraysAreReviewedWithPathAndType) {
  struct Case {
    const char* name;
    Field type;
    std::vector<uint16_t> lengths;  // answered in request order
    std::vector<std::string> screens;
  };
  Field addresses = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  addresses.array_levels_count = 1;
  Field words = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32);
  words.array_levels_count = 1;
  Field grid = words;
  grid.array_levels_count = 2;
  Field items = structField("Item");
  items.array_levels_count = 1;
  const Case cases[] = {
      {"address[]", addresses, {0}, {"recipients\naddress[]: 0 items"}},
      {"uint256[]", words, {0}, {"recipients\nuint256[]: 0 items"}},
      {"outer", grid, {0}, {"recipients\nuint256[][]: 0 items"}},
      {"inner",
       grid,
       {2, 0, 0},
       {"recipients[0]\nuint256[]: 0 items",
        "recipients[1]\nuint256[]: 0 items"}},
      {"structs", items, {0}, {"recipients\nItem[]: 0 items"}},
  };
  static std::vector<uint16_t> lengths;
  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    std::map<std::string, Struct> types;
    addMember(types["Msg"], "amount",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
    addMember(types["Msg"], "recipients", c.type);
    addMember(types["Item"], "to",
              mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS));
    lengths = c.lengths;
    kkconfirm_capture_start();
    const int used = walk(
        "Msg", types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() == 2 && path[1] == 0) return word(7);
          const uint16_t n = lengths.front();
          lengths.erase(lengths.begin());
          return Bytes{(uint8_t)(n >> 8), (uint8_t)n};
        },
        1 + (int)c.screens.size());
    const std::vector<std::string> bodies = kkconfirm_capture_finish();
    EXPECT_EQ(used, 1 + (int)c.screens.size());
    ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    ASSERT_EQ(bodies.size(), 1 + c.screens.size());
    for (size_t i = 0; i < c.screens.size(); i++)
      EXPECT_EQ(bodies[1 + i], c.screens[i]);
    eip712_stream_abort();
  }
}

// A struct without members has no screen of its own: as a member, or as the
// element of an array whose length then goes unseen, it would be signed blind.
TEST(Eip712Stream, StructsWithoutMembersAreRefused) {
  Field single = structField("Z");
  Field many = structField("Z");
  many.array_levels_count = 1;
  for (const Field& pad : {single, many}) {
    std::map<std::string, Struct> types;
    addMember(types["Msg"], "contents",
              mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
    addMember(types["Msg"], "pad", pad);
    types["Z"];  // declared, no members
    walk(
        "Msg", types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() == 2 && path[1] == 0) return Bytes{'h', 'i'};
          return Bytes{0, 5};
        },
        8);
    EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
    eip712_stream_abort();
  }
}

TEST(Eip712Stream, RejectingAnEmptyArrayCancelsTheSignature) {
  std::map<std::string, Struct> types;
  Field recipients = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  recipients.array_levels_count = 1;
  addMember(types["Msg"], "recipients", recipients);
  const int used = walk(
      "Msg", types,
      [](const std::vector<uint32_t>&) -> Bytes { return Bytes{0, 0}; }, 0);
  EXPECT_EQ(used, -1);  // the rejection sentinel answered the empty array
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_CANCELLED);
  eip712_stream_abort();
}

// "uint256" is a legal struct name and spells exactly like the atomic type,
// so the replay check must bind the member's kind, not just its spelling. A
// host switching UINT to STRUCT after hashing would otherwise display nested
// fields and sign their digest as the integer the type hash declared.
TEST(Eip712Stream, ReplayBindsMemberKindNotOnlySpelling) {
  EthereumSignTypedData begin{};
  strcpy(begin.primary_type, "M");
  ASSERT_TRUE(eip712_stream_begin(&begin, false));
  EthereumTypedDataStructAck empty{};
  for (int i = 0; i < 3; i++) ASSERT_TRUE(eip712_stream_on_struct(&empty));
  ASSERT_STREQ(eip712_stream_next()->struct_name, "M");

  EthereumTypedDataStructAck as_uint{};
  addMember(as_uint, "amount",
            mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
  EthereumTypedDataStructAck as_struct{};
  addMember(as_struct, "amount", structField("uint256"));
  ASSERT_EQ(nameOf(as_uint.members[0].type), nameOf(as_struct.members[0].type));

  ASSERT_TRUE(eip712_stream_on_struct(&as_uint));  // discover
  ASSERT_TRUE(eip712_stream_on_struct(&as_uint));  // hash M(uint256 amount)
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_STRUCT);
  EXPECT_FALSE(eip712_stream_on_struct(&as_struct));  // member walk
  ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
  EXPECT_STREQ(eip712_stream_next()->error,
               "EIP-712 schema changed during signing");
  eip712_stream_abort();
}

// Seaport BulkOrder and LooksRare BatchOrder sign 2^h orders at once; the
// device cannot review them, so the shape is refused before any message
// screen. A same-named type of another shape walks as usual.
TEST(Eip712Stream, BulkOrderTreesAreRefusedByShape) {
  struct Case {
    const char* primary;
    const char* order;
    size_t height;
    bool gated;
  };
  const Case cases[] = {
      {"BulkOrder", "OrderComponents", 1, true},
      {"BulkOrder", "OrderComponents", 3, true},
      {"BatchOrder", "Maker", 1, true},
      {"BatchOrder", "Maker", 3, true},
      {"BulkOrder", "Listing", 1, false},
      {"Orders", "OrderComponents", 1, false},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(std::string(c.primary) + " of " + c.order +
                 " h=" + std::to_string(c.height));
    std::map<std::string, Struct> types;
    Field tree = structField(c.order);
    tree.array_levels_count = c.height;
    for (size_t i = 0; i < c.height; i++) tree.array_levels[i] = 2;
    addMember(types[c.primary], "tree", tree);
    addMember(types[c.order], "price",
              mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, 32));
    const int used = walk(
        c.primary, types,
        [](const std::vector<uint32_t>& path) -> Bytes {
          if (path.size() <= 3) return Bytes{0, 2};
          return word(1);
        },
        8);
    if (c.gated) {
      EXPECT_EQ(used, 0);
      ASSERT_EQ(eip712_stream_next()->kind, EIP712_REQ_FAIL);
      EXPECT_STREQ(eip712_stream_next()->error,
                   "Bulk order: sign listings individually");
    } else {
      EXPECT_EQ(used, 2);
      EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
    }
    eip712_stream_abort();
  }
}

// ── Real-world corpus ───────────────────────────────────────────────
// One document per protocol, from the type strings in each protocol's own
// source (eip712_corpus.json lists them). Every one must sign, and its domain
// separator and message hash must equal the values computed outside this
// firmware: a pure-Python encoder written from the spec, cross-checked by
// eth-sig-util and ethers (eip712_corpus_gen.py).
namespace {

struct CorpusMember {
  const char* name;
  const char* type;
};
struct CorpusStruct {
  const char* name;
  std::vector<CorpusMember> members;
};
struct CorpusValue {
  std::vector<uint32_t> path;
  const char* hex;
};
struct CorpusDoc {
  const char* id;
  const char* primary;
  std::vector<CorpusStruct> types;
  std::vector<CorpusValue> values;
  int leaves;
  const char* domain_separator;
  const char* message_hash;
};

const std::vector<CorpusDoc> kCorpus = {
#include "eip712_corpus.inc"
};

// "uint160", "bytes32", "Person[]", "OrderComponents[2][2]" as the host's
// FieldType: dimensions in written order.
Field corpusField(const std::string& spelled) {
  const size_t bracket = spelled.find('[');
  const std::string base = spelled.substr(0, bracket);
  Field f;
  unsigned bits = 0;
  if (sscanf(base.c_str(), "uint%u", &bits) == 1 &&
      "uint" + std::to_string(bits) == base) {
    f = mkSized(EthereumTypedDataStructAck_EthereumDataType_UINT, bits / 8);
  } else if (sscanf(base.c_str(), "int%u", &bits) == 1 &&
             "int" + std::to_string(bits) == base) {
    f = mkSized(EthereumTypedDataStructAck_EthereumDataType_INT, bits / 8);
  } else if (sscanf(base.c_str(), "bytes%u", &bits) == 1 &&
             "bytes" + std::to_string(bits) == base) {
    f = mkSized(EthereumTypedDataStructAck_EthereumDataType_BYTES, bits);
  } else if (base == "bytes") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_BYTES);
  } else if (base == "string") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_STRING);
  } else if (base == "bool") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_BOOL);
  } else if (base == "address") {
    f = mk(EthereumTypedDataStructAck_EthereumDataType_ADDRESS);
  } else {
    f = structField(base.c_str());
  }
  for (size_t at = bracket; at != std::string::npos;
       at = spelled.find('[', at + 1)) {
    f.array_levels[f.array_levels_count++] =
        (uint32_t)strtoul(spelled.c_str() + at + 1, nullptr, 10);
  }
  return f;
}

Bytes fromHex(const char* hex) {
  Bytes out;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    out.push_back((uint8_t)std::stoi(std::string(hex + i, 2), nullptr, 16));
  }
  return out;
}

const CorpusDoc* g_doc;
bool g_missing_value;

Bytes corpusValue(const std::vector<uint32_t>& path) {
  for (const CorpusValue& v : g_doc->values) {
    if (v.path == path) return fromHex(v.hex);
  }
  g_missing_value = true;
  return Bytes{};
}

}  // namespace

TEST(Eip712Stream, RealWorldCorpusSignsWithIndependentDigests) {
  EXPECT_GE(kCorpus.size(), 45u);
  // Max approvals sign, with the warning on the value's own screen.
  const std::map<std::string, std::string> unlimited = {
      {"permit2-PermitSingle-unlimited", "details.amount\nuint160: UNLIMITED"},
      {"eip2612-Permit-unlimited", "value\nuint256: UNLIMITED"},
      {"dai-Permit-allowed", "allowed\nbool: UNLIMITED (allowed)"},
  };
  size_t warned_docs = 0;
  for (const CorpusDoc& doc : kCorpus) {
    SCOPED_TRACE(doc.id);
    std::map<std::string, Struct> types;
    for (const CorpusStruct& s : doc.types) {
      Struct& ack = types[s.name];
      for (const CorpusMember& m : s.members)
        addMember(ack, m.name, corpusField(m.type));
    }
    g_doc = &doc;
    g_missing_value = false;
    // A long value is reviewed in parts, so allow several screens per leaf.
    kkconfirm_capture_start();
    const int used = walk(doc.primary, types, corpusValue, 4 * doc.leaves + 8);
    const std::vector<std::string> bodies = kkconfirm_capture_finish();
    const std::vector<std::string> titles = kkconfirm_captured_titles();
    std::vector<std::string> warned;
    for (size_t i = 0; i < titles.size(); i++)
      if (titles[i] == "UNLIMITED approval") warned.push_back(bodies[i]);
    const auto expect = unlimited.find(doc.id);
    if (expect == unlimited.end()) {
      EXPECT_TRUE(warned.empty());
    } else {
      warned_docs++;
      EXPECT_EQ(warned, std::vector<std::string>{expect->second});
    }
    const Eip712Next* next = eip712_stream_next();
    EXPECT_FALSE(g_missing_value);
    if (next->kind != EIP712_REQ_DONE) {
      ADD_FAILURE() << "refused: "
                    << (next->kind == EIP712_REQ_FAIL && next->error
                            ? next->error
                            : "(no error)");
      eip712_stream_abort();
      continue;
    }
    EXPECT_GE(used, doc.leaves);
    EXPECT_FALSE(next->message_empty);
    EXPECT_STREQ(next->primary_type, doc.primary);
    EXPECT_EQ(hexOf(next->domain_separator, 32), doc.domain_separator);
    EXPECT_EQ(hexOf(next->message_hash, 32), doc.message_hash);
    eip712_stream_abort();
  }
  EXPECT_EQ(warned_docs, unlimited.size());
}

// ── One screen per string ───────────────────────────────────────────
// The body renderer drops a space where it wraps a line and the pager drops
// one at a page start, so a string leaf that keeps a space literally can draw
// the same pixels as the string without it, while the two hash differently.
namespace {

std::string g_note;

// Title plus the canvas the real layout draws, for every captured screen.
std::vector<std::string> pixels(const std::vector<std::string>& titles,
                                const std::vector<std::string>& bodies) {
  std::vector<std::string> out;
  for (size_t i = 0; i < bodies.size(); i++) {
    layout_has_icon(false);
    layout_standard_notification(titles[i].c_str(), bodies[i].c_str(),
                                 NOTIFICATION_REQUEST_NO_ANIMATION);
    const Canvas* canvas = layout_get_canvas();
    out.push_back(titles[i] + '\0' +
                  std::string((const char*)canvas->buffer,
                              (size_t)canvas->width * canvas->height));
  }
  return out;
}

// Every screen a document with one string member `note` draws.
std::vector<std::string> noteScreens(const std::string& note) {
  std::map<std::string, Struct> types;
  addMember(types["EIP712Domain"], "name",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  addMember(types["Msg"], "note",
            mk(EthereumTypedDataStructAck_EthereumDataType_STRING));
  g_note = note;
  kkconfirm_capture_start();
  const int used = walk(
      "Msg", types,
      [](const std::vector<uint32_t>& path) -> Bytes {
        if (path[0] == 0) return Bytes{'A', 'p', 'p'};
        return Bytes(g_note.begin(), g_note.end());
      },
      40);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  EXPECT_GT(used, 0);
  EXPECT_EQ(eip712_stream_next()->kind, EIP712_REQ_DONE);
  eip712_stream_abort();
  return pixels(kkconfirm_captured_titles(), bodies);
}

// The screens confirm() draws for `body` as given, and its page bodies.
std::vector<std::string> rawScreens(const std::string& body,
                                    std::vector<std::string>* pages) {
  kkconfirm_capture_start();
  EXPECT_TRUE(kkconfirm_preload(10, 0));
  EXPECT_TRUE(
      confirm(ButtonRequestType_ButtonRequest_Other, "T", "%s", body.c_str()));
  kkconfirm_drain();
  *pages = kkconfirm_capture_finish();
  return pixels(kkconfirm_captured_titles(), *pages);
}

}  // namespace

TEST(Eip712Stream, StringsDifferingByOneSpaceNeverShareAScreen) {
  const std::string tail = "payTo0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
  const std::string prefix = "note\nstring: ";
  bool wrap_covered = false, page_covered = false;
  // A row holds 37 'X': k = 37 puts the space at the first page break and
  // k = 74 at a line wrap inside the second page. Each window brackets one.
  for (size_t k : {35, 36, 37, 38, 39, 72, 73, 74, 75, 76}) {
    SCOPED_TRACE(k);
    const std::string spaced = std::string(k, 'X') + " " + tail;
    const std::string joined = std::string(k, 'X') + tail;

    // Coverage: shown verbatim, which k put the space where it is dropped?
    std::vector<std::string> pages, unused;
    if (rawScreens(prefix + spaced, &pages) ==
        rawScreens(prefix + joined, &unused)) {
      const std::string raw = prefix + spaced;
      const size_t space = prefix.size() + k;
      size_t pos = 0;
      bool at_page_edge = false;
      for (size_t i = 0; i < pages.size(); i++) {
        while (raw[pos] == ' ') at_page_edge |= pos++ == space;
        pos += pages[i].size();
        at_page_edge |= i + 1 < pages.size() && pos - 1 == space;
      }
      (at_page_edge ? page_covered : wrap_covered) = true;
    }

    EXPECT_TRUE(noteScreens(spaced) != noteScreens(joined));
  }
  // The sweep reached both kinds of dropped space.
  EXPECT_TRUE(wrap_covered);
  EXPECT_TRUE(page_covered);
}
