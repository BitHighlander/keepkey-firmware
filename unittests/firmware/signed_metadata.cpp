/*
 * Unit tests for the EVM clear-signing ("Insight") signed-metadata module.
 *
 * Phase 1 ships with NO built-in verification keys: every signer is loaded
 * at runtime (signed_metadata_store_signer,
 * reached in production through the user-confirmed LoadClearsignSigner FSM
 * handler). The fixture loads the CI test key (02e3b3015c...ab5107) into
 * slot 3 with alias "CI Test"; all vectors are signed in-process with the
 * matching private key (f6d19e15...068a260) and embed key_id=3.
 *
 * signed_metadata_process() and signed_metadata_matches_tx() never draw;
 * screens in signed_metadata_confirm() are driven through kkconfirm_preload().
 * The relied-path enforce truth table is tested through the pure, exported
 * signed_metadata_enforce_decision() (see SECTION 2).
 */

extern "C" {
#include "messages-ethereum.pb.h" /* full EthereumSignTx definition */
#include "messages-solana.pb.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "keepkey/board/draw.h"   /* draw_bitmap_mono_rle (icon decoder) */
#include "keepkey/board/font.h"   /* calc_str_line, get_title_font */
#include "keepkey/board/layout.h" /* LEFT_MARGIN_WITH_ICON */
#include "keepkey/firmware/signed_metadata.h"
#include "trezor/crypto/address.h"   /* ethereum_address_checksum */
#include "keepkey/firmware/solana.h" /* SolanaTokenInfo, solana_token_info_trusted */
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/base58.h"
#include "keepkey/firmware/clearsign_root.h"
#include "keepkey/firmware/ethereum.h"

void setup(void);
}

#include "clearsign_test_cert.h"
#include "solana_real_vectors.h"
#include "gtest/gtest.h"
#include "kkconfirm_driver.h"
#include "test_board.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_captured_titles(void);
bool kkconfirm_readResponse(uint16_t expected, const pb_field_t* fields,
                            void* response);

namespace {

/* Test signing key. Its compressed pubkey is loaded into slot 3 by the fixture.
 */
const uint8_t TEST_PRIV[32] = {0xf6, 0xd1, 0x9e, 0x15, 0xa4, 0x38, 0x5f, 0x03,
                               0xb7, 0x8b, 0x5a, 0x1e, 0x16, 0x14, 0xe7, 0xd9,
                               0xa1, 0x04, 0xd8, 0x1f, 0x73, 0x24, 0x49, 0x87,
                               0x56, 0xe5, 0x71, 0x90, 0x40, 0x68, 0xa2, 0x60};

/* Compressed pubkey of TEST_PRIV; loaded into slot 3 by the fixture. */
const uint8_t EXPECTED_SLOT3_PUB[33] = {
    0x02, 0xe3, 0xb3, 0x01, 0x5c, 0x47, 0xdd, 0xca, 0xab, 0xe4, 0xf8,
    0xe8, 0x72, 0xf1, 0xed, 0x8f, 0x09, 0xca, 0x14, 0x5a, 0x8d, 0x81,
    0x77, 0x0d, 0x92, 0x21, 0x3d, 0x56, 0xda, 0x31, 0xab, 0x51, 0x07};

const uint8_t TEST_KEY_ID = 3;

/* Deterministic, opaque test data. Only internal consistency matters. */
const uint8_t CONTRACT_A[20] = {0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b,
                                0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
                                0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48};
const uint8_t CONTRACT_B[20] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
const uint8_t SEL_TRANSFER[4] = {0xa9, 0x05, 0x9c, 0xbb};
const uint8_t SEL_APPROVE[4] = {0x09, 0x5e, 0xa7, 0xb3};
const uint8_t TX_HASH[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                             0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                             0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
const uint8_t RECIPIENT[20] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                               0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                               0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53};
const uint8_t AMOUNT32[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0,    0,   0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0,    0,   0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xe8};

/* ---- byte writers ------------------------------------------------------- */

void put_u8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }
void put_be16(std::vector<uint8_t>& v, uint16_t x) {
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xff));
}
void put_be32(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back((uint8_t)(x >> 24));
  v.push_back((uint8_t)(x >> 16));
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xff));
}
void put_bytes(std::vector<uint8_t>& v, const uint8_t* b, size_t n) {
  v.insert(v.end(), b, b + n);
}

/* ---- metadata builder --------------------------------------------------- */

struct Arg {
  std::string name;
  uint8_t format;
  std::vector<uint8_t> value;
  int value_len_override;  // -1 => use value.size()
};

Arg mk_arg(const std::string& name, uint8_t format, const uint8_t* value,
           size_t value_len) {
  Arg a;
  a.name = name;
  a.format = format;
  a.value.assign(value, value + value_len);
  a.value_len_override = -1;
  return a;
}

struct Spec {
  uint8_t version;
  uint32_t chain_id;
  std::vector<uint8_t> contract;
  std::vector<uint8_t> selector;
  std::vector<uint8_t> tx_hash;
  std::string method;
  std::vector<Arg> args;
  uint8_t classification;
  uint32_t timestamp;
  uint8_t key_id;
  int method_len_override;  // -1 => use method.size()
  int num_args_override;    // -1 => use args.size()
};

/* Canonical VERIFIED metadata: transfer(to:ADDRESS, amount:AMOUNT) on chain 1.
 */
Spec base_spec() {
  Spec s;
  s.version = 0x01;
  s.chain_id = 1;
  s.contract.assign(CONTRACT_A, CONTRACT_A + 20);
  s.selector.assign(SEL_TRANSFER, SEL_TRANSFER + 4);
  s.tx_hash.assign(TX_HASH, TX_HASH + 32);
  s.method = "transfer";
  s.args.push_back(mk_arg("to", ARG_FORMAT_ADDRESS, RECIPIENT, 20));
  s.args.push_back(mk_arg("amount", ARG_FORMAT_AMOUNT, AMOUNT32, 32));
  s.classification = METADATA_VERIFIED;
  s.timestamp = 0;
  s.key_id = TEST_KEY_ID;
  s.method_len_override = -1;
  s.num_args_override = -1;
  return s;
}

/* Serialize the signed region (version .. key_id), exactly matching
 * parse_metadata_binary() / serialize_metadata(). */
std::vector<uint8_t> build_body(const Spec& s) {
  std::vector<uint8_t> b;
  put_u8(b, s.version);
  put_be32(b, s.chain_id);
  put_bytes(b, s.contract.data(), s.contract.size());
  put_bytes(b, s.selector.data(), s.selector.size());
  put_bytes(b, s.tx_hash.data(), s.tx_hash.size());

  uint16_t mlen = s.method_len_override >= 0 ? (uint16_t)s.method_len_override
                                             : (uint16_t)s.method.size();
  put_be16(b, mlen);
  put_bytes(b, (const uint8_t*)s.method.data(), s.method.size());

  uint8_t na = s.num_args_override >= 0 ? (uint8_t)s.num_args_override
                                        : (uint8_t)s.args.size();
  put_u8(b, na);
  for (const Arg& a : s.args) {
    put_u8(b, (uint8_t)a.name.size());
    put_bytes(b, (const uint8_t*)a.name.data(), a.name.size());
    put_u8(b, a.format);
    uint16_t vl = a.value_len_override >= 0 ? (uint16_t)a.value_len_override
                                            : (uint16_t)a.value.size();
    put_be16(b, vl);
    put_bytes(b, a.value.data(), a.value.size());
  }

  put_u8(b, s.classification);
  put_be32(b, s.timestamp);
  put_u8(b, s.key_id);
  return b;
}

/* sha256(body) -> ecdsa sign with TEST_PRIV -> append sig(64) + recovery(1).
 * Mirrors signed_metadata_process(): signed_len = payload_len - 64 - 1. */
std::vector<uint8_t> sign_body(std::vector<uint8_t> body) {
  uint8_t digest[32];
  sha256_Raw(body.data(), body.size(), digest);
  uint8_t sig[64];
  uint8_t pby = 0;
  int rc = ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby, NULL);
  EXPECT_EQ(rc, 0);
  body.insert(body.end(), sig, sig + 64);
  body.push_back((uint8_t)(27 + pby));
  return body;
}

std::vector<uint8_t> base_blob() { return sign_body(build_body(base_spec())); }

void make_msg(EthereumSignTx* msg, const uint8_t contract[20],
              const uint8_t* data, size_t data_len, bool has_chain,
              uint32_t chain) {
  memset(msg, 0, sizeof(*msg));
  msg->has_to = true;
  msg->to.size = 20;
  memcpy(msg->to.bytes, contract, 20);
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = (pb_size_t)data_len;
  memcpy(msg->data_initial_chunk.bytes, data, data_len);
  msg->has_chain_id = has_chain;
  msg->chain_id = chain;
}

/* A standard transfer() calldata chunk that matches base_spec(). */
void make_matching_msg(EthereumSignTx* msg) {
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);
  make_msg(msg, CONTRACT_A, data, sizeof(data), /*has_chain=*/true, 1);
}

const char* TEST_ALIAS = "CI Test";

void set_advanced_mode_for_test(bool enabled) {
  /* The full xunit binary may already have initialized emulator flash in an
   * earlier fixture (notably Authenticator). Re-running storage_init() then
   * attempts to migrate/decrypt an already-live shadow store. The allocation
   * is the shared source of truth, and also keeps this suite runnable alone. */
  if (storage_getLocation() == FLASH_INVALID) {
    setup();
    storage_init();
  }
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", enabled));
}

class SignedMetadataTest : public ::testing::Test {
 protected:
  void SetUp() override {
    set_advanced_mode_for_test(true);
    signed_metadata_clear_signers();
    signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                                 NULL, 0, 0, 0, false);
  }
  void TearDown() override {
    signed_metadata_clear_signers();
    set_advanced_mode_for_test(false);
  }

  void ExpectMalformed(const std::vector<uint8_t>& blob, uint8_t key_id) {
    EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), key_id),
              METADATA_MALFORMED);
    EXPECT_FALSE(signed_metadata_available());
    EXPECT_EQ(signed_metadata_get(), nullptr);
  }
};

/* ===================================================================== *
 *  signed_metadata_process — happy path via a runtime-loaded signer
 * ===================================================================== */

TEST_F(SignedMetadataTest, DerivedPubkeyMatchesSlot3) {
  uint8_t pub[33];
  ecdsa_get_public_key33(&secp256k1, TEST_PRIV, pub);
  EXPECT_EQ(memcmp(pub, EXPECTED_SLOT3_PUB, sizeof(pub)), 0)
      << "TEST_PRIV must derive the loaded slot-3 test pubkey";
}

TEST_F(SignedMetadataTest, ValidVerifiedSlot3) {
  std::vector<uint8_t> blob = base_blob();
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_TRUE(signed_metadata_available());
  const SignedMetadata* m = signed_metadata_get();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->classification, METADATA_VERIFIED);
  EXPECT_EQ(m->chain_id, 1u);
  EXPECT_STREQ(m->method_name, "transfer");
  EXPECT_EQ(m->num_args, 2);
  EXPECT_EQ(memcmp(m->contract_address, CONTRACT_A, 20), 0);
  EXPECT_EQ(memcmp(m->selector, SEL_TRANSFER, 4), 0);
  EXPECT_EQ(memcmp(m->tx_hash, TX_HASH, 32), 0);
  EXPECT_EQ(m->key_id, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, RuntimeMetadataIsInertOutsideAdvancedMode) {
  std::vector<uint8_t> blob = base_blob();
  set_advanced_mode_for_test(false);
  ExpectMalformed(blob, TEST_KEY_ID);

  const uint8_t data[] = "advanced-mode-gate";
  uint8_t digest[32];
  uint8_t sig[64];
  sha256_Raw(data, sizeof(data) - 1, digest);
  ASSERT_EQ(ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, NULL, NULL),
            0);
  EXPECT_FALSE(signed_metadata_verify_attestation(
      TEST_KEY_ID, data, sizeof(data) - 1, sig, sizeof(sig)));
  char alias[METADATA_ALIAS_MAX_LEN + 1] = {0};
  EXPECT_FALSE(signed_metadata_verify_runtime_attestation_for_pubkey(
      EXPECTED_SLOT3_PUB, data, sizeof(data) - 1, sig, sizeof(sig), alias));

  set_advanced_mode_for_test(true);
  // Re-enabling the policy must not resurrect a revoked session signer.
  EXPECT_FALSE(signed_metadata_verify_runtime_attestation_for_pubkey(
      EXPECTED_SLOT3_PUB, data, sizeof(data) - 1, sig, sizeof(sig), alias));
  ExpectMalformed(blob, TEST_KEY_ID);
  ASSERT_TRUE(signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB,
                                           TEST_ALIAS, NULL, 0, 0, 0, false));
  EXPECT_TRUE(signed_metadata_verify_runtime_attestation_for_pubkey(
      EXPECTED_SLOT3_PUB, data, sizeof(data) - 1, sig, sizeof(sig), alias));
  EXPECT_STREQ(alias, TEST_ALIAS);
}

TEST_F(SignedMetadataTest, ValidOpaqueClassification) {
  Spec s = base_spec();
  s.classification = METADATA_OPAQUE;  // 0
  std::vector<uint8_t> blob = sign_body(build_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_OPAQUE);
  EXPECT_TRUE(signed_metadata_available());  // available, but not VERIFIED
  EXPECT_NE(signed_metadata_get(), nullptr);
}

TEST_F(SignedMetadataTest, SelfDeclaredMalformedWithValidSignature) {
  /* A trusted signer can self-declare MALFORMED(2). Signature verifies, so
   * process() returns MALFORMED but leaves the (inert) metadata available. It
   * must never be displayed or relied upon. */
  Spec s = base_spec();
  s.classification = METADATA_MALFORMED;  // 2
  std::vector<uint8_t> blob = sign_body(build_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_MALFORMED);
  EXPECT_TRUE(signed_metadata_available());
  EXPECT_NE(signed_metadata_get(), nullptr);

  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));  // gated on VERIFIED
  EXPECT_FALSE(signed_metadata_confirm());         // gated on VERIFIED
}

/* ===================================================================== *
 *  signed_metadata_process — key-slot guards
 * ===================================================================== */

TEST_F(SignedMetadataTest, KeyIdOutOfRange) {
  ExpectMalformed(base_blob(), /*key_id=*/4);  // >= METADATA_MAX_KEYS
}

TEST_F(SignedMetadataTest, EmptyRotationSlot) {
  Spec s = base_spec();
  s.key_id = 1;  // slot 1: no built-in key, nothing loaded
  ExpectMalformed(sign_body(build_body(s)), /*key_id=*/1);
}

TEST_F(SignedMetadataTest, NullPayload) {
  EXPECT_EQ(signed_metadata_process(nullptr, 200, TEST_KEY_ID),
            METADATA_MALFORMED);
  EXPECT_FALSE(signed_metadata_available());
  EXPECT_EQ(signed_metadata_get(), nullptr);
}

TEST_F(SignedMetadataTest, EmbeddedKeyIdMismatch) {
  Spec s = base_spec();
  s.key_id = 2;  // embedded != protocol key_id (3)
  ExpectMalformed(sign_body(build_body(s)), /*key_id=*/3);
}

TEST_F(SignedMetadataTest, SignatureVerificationFails) {
  std::vector<uint8_t> blob = base_blob();
  blob[146] ^= 0x01;  // flip first signature byte (sig starts after 146B body)
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST(SignedMetadataEnvelope, OnlyReservedCompleteV3ShapeBypassesPolicyGate) {
  std::vector<uint8_t> candidate(141, 0);
  candidate[0] = METADATA_VERSION_CERTIFIED;

  EXPECT_TRUE(signed_metadata_is_certified_envelope(
      candidate.data(), candidate.size(), METADATA_KEYID_DELEGATE));
  EXPECT_FALSE(signed_metadata_is_certified_envelope(
      candidate.data(), candidate.size(), TEST_KEY_ID));
  EXPECT_FALSE(signed_metadata_is_certified_envelope(candidate.data(),
                                                     candidate.size(), 0x180));

  candidate[0] = METADATA_VERSION_SCHEMA;
  EXPECT_FALSE(signed_metadata_is_certified_envelope(
      candidate.data(), candidate.size(), METADATA_KEYID_DELEGATE));
  candidate[0] = METADATA_VERSION_CERTIFIED;
  candidate.resize(140);
  EXPECT_FALSE(signed_metadata_is_certified_envelope(
      candidate.data(), candidate.size(), METADATA_KEYID_DELEGATE));
  EXPECT_FALSE(signed_metadata_is_certified_envelope(nullptr, 141,
                                                     METADATA_KEYID_DELEGATE));
}

/* ===================================================================== *
 *  signed_metadata_process — length guards
 * ===================================================================== */

TEST_F(SignedMetadataTest, PayloadShorterThan65) {
  std::vector<uint8_t> blob = base_blob();
  blob.resize(64);  // process() early guard: payload_len < 65
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, PayloadBetween65And135) {
  std::vector<uint8_t> blob = base_blob();
  blob.resize(100);  // passes <65 guard, fails parser <136 minimum
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, TrailingByteAfterRecovery) {
  std::vector<uint8_t> blob = base_blob();
  blob.push_back(0x00);  // cursor != end
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, MissingRecoveryByte) {
  std::vector<uint8_t> blob = base_blob();
  blob.pop_back();  // truncated tail: read recovery fails
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* ===================================================================== *
 *  parse_metadata_binary — field guards (all re-signed so the PARSE guard,
 *  not the signature check, is what rejects the blob)
 * ===================================================================== */

TEST_F(SignedMetadataTest, BadVersion) {
  Spec s = base_spec();
  s.version = 0x02;
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, EmptyMethodName) {
  Spec s = base_spec();
  s.method = "";  // 2-byte length prefix == 0
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, MethodNameTooLong) {
  Spec s = base_spec();
  s.method = std::string(65, 'A');  // > METADATA_MAX_METHOD_LEN (64)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, MethodNameLengthOverrun) {
  /* Length prefix claims 64 but only "transfer" (8B) is the method; the read
   * consumes downstream bytes and parsing misaligns -> MALFORMED. The clean
   * read_string short-read guard is unreachable under the >=136 floor (after
   * the 63-byte fixed prefix at least 73 bytes always remain), so this pins
   * the observable contract rather than a specific internal branch. The
   * corrupted signature byte makes rejection deterministic even in the
   * vanishingly unlikely event the misaligned parse re-aligns to the end. */
  Spec s = base_spec();
  s.method_len_override = 64;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  blob[blob.size() - 2] ^= 0xFF;  // ensure verify cannot pass
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, NumArgsTooMany) {
  Spec s = base_spec();
  s.num_args_override = 9;  // > METADATA_MAX_ARGS (8)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgNameEmpty) {
  Spec s = base_spec();
  s.args[0] = mk_arg("", ARG_FORMAT_ADDRESS, RECIPIENT, 20);  // name_len == 0
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgNameTooLong) {
  Spec s = base_spec();
  std::string long_name(33, 'x');  // > METADATA_MAX_ARG_NAME_LEN (32)
  s.args[0] = mk_arg(long_name, ARG_FORMAT_ADDRESS, RECIPIENT, 20);
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgFormatOutOfRange) {
  Spec s = base_spec();
  s.args[0].format = 6;  // > ARG_FORMAT_TOKEN_AMOUNT (5)
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

/* ---- ARG_FORMAT_STRING (attested printable label) ----------------------- */

TEST_F(SignedMetadataTest, StringArgAccepted) {
  Spec s = base_spec();
  const char* label = "Uniswap V2";
  s.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, (const uint8_t*)label,
                     strlen(label));
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  const SignedMetadata* m = signed_metadata_get();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->args[0].format, ARG_FORMAT_STRING);
  EXPECT_EQ(memcmp(m->args[0].value, label, strlen(label)), 0);
}

TEST_F(SignedMetadataTest, StringArgRejectsUnprintableAndPercent) {
  const uint8_t nl[] = {'a', '\n', 'b'};
  Spec s = base_spec();
  s.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, nl, sizeof(nl));
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);

  const uint8_t pct[] = {'a', '%', 's'};
  Spec s2 = base_spec();
  s2.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, pct, sizeof(pct));
  ExpectMalformed(sign_body(build_body(s2)), TEST_KEY_ID);

  Spec s3 = base_spec();
  s3.args[0] = mk_arg("protocol", ARG_FORMAT_STRING, pct, 0);  // empty string
  ExpectMalformed(sign_body(build_body(s3)), TEST_KEY_ID);
}

/* ---- ARG_FORMAT_TOKEN_AMOUNT (decimals + symbol + amount) --------------- */

std::vector<uint8_t> token_amount_value(uint8_t decimals,
                                        const std::string& symbol,
                                        const std::vector<uint8_t>& amount) {
  std::vector<uint8_t> v;
  v.push_back(decimals);
  v.push_back((uint8_t)symbol.size());
  v.insert(v.end(), symbol.begin(), symbol.end());
  v.insert(v.end(), amount.begin(), amount.end());
  return v;
}

TEST_F(SignedMetadataTest, TokenAmountAccepted) {
  /* 1.00 USDC: 1000000 raw, 6 decimals */
  std::vector<uint8_t> amt = {0x0F, 0x42, 0x40};
  std::vector<uint8_t> val = token_amount_value(6, "USDC", amt);
  Spec s = base_spec();
  s.args[1] = mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, val.data(), val.size());
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  const SignedMetadata* m = signed_metadata_get();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(m->args[1].value_len, val.size());
}

TEST_F(SignedMetadataTest, TokenAmountUnlimited32BytesAccepted) {
  /* UNLIMITED approve: 32 x 0xFF + symbol -> value_len 38 (> old 32 cap) */
  std::vector<uint8_t> amt(32, 0xFF);
  std::vector<uint8_t> val = token_amount_value(6, "USDC", amt);
  EXPECT_EQ(val.size(), 38u);  // 1+1+4+32
  Spec s = base_spec();
  s.args[1] = mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, val.data(), val.size());
  std::vector<uint8_t> blob = sign_body(build_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
}

TEST_F(SignedMetadataTest, TokenAmountRejectsBadLayout) {
  Spec s = base_spec();
  /* symbol chars outside [A-Za-z0-9] */
  std::vector<uint8_t> bad_sym = token_amount_value(6, "US-C", {0x01});
  s.args[1] =
      mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, bad_sym.data(), bad_sym.size());
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);

  /* decimals > 36 */
  Spec s2 = base_spec();
  std::vector<uint8_t> bad_dec = token_amount_value(37, "USDC", {0x01});
  s2.args[1] =
      mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, bad_dec.data(), bad_dec.size());
  ExpectMalformed(sign_body(build_body(s2)), TEST_KEY_ID);

  /* symbol_len runs past the value (no amount bytes left) */
  Spec s3 = base_spec();
  std::vector<uint8_t> no_amt = {6, 4, 'U', 'S', 'D', 'C'};
  s3.args[1] =
      mk_arg("amount", ARG_FORMAT_TOKEN_AMOUNT, no_amt.data(), no_amt.size());
  ExpectMalformed(sign_body(build_body(s3)), TEST_KEY_ID);

  /* legacy formats must NOT accept the larger 44-byte cap */
  Spec s4 = base_spec();
  std::vector<uint8_t> big(40, 0xAB);
  s4.args[1] = mk_arg("amount", ARG_FORMAT_AMOUNT, big.data(), big.size());
  ExpectMalformed(sign_body(build_body(s4)), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ArgValueTooLong) {
  Spec s = base_spec();
  uint8_t big[33] = {0};
  s.args[0] = mk_arg("to", ARG_FORMAT_BYTES, big, 33);  // > 32
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

/* An ADDRESS arg is drawn as a full 20-byte address, so any other length is
 * refused at parse, not later in the middle of the review. */
TEST_F(SignedMetadataTest, AddressArgMustBeTwentyBytes) {
  const uint8_t word[32] = {0};
  for (size_t len : {0u, 19u, 21u, 32u}) {
    SCOPED_TRACE(len);
    Spec s = base_spec();
    s.args[0] = mk_arg("to", ARG_FORMAT_ADDRESS, word, len);
    ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
  }
}

TEST_F(SignedMetadataTest, ArgValueLengthOverrun) {
  /* value_len prefix claims 32 but only 4 value bytes follow; the read eats
   * into the fixed tail and parsing misaligns -> MALFORMED. As with the method
   * case, the read_bytes short-read guard is dominated by the >=71-byte fixed
   * tail, so this asserts the observable MALFORMED outcome. */
  Spec s = base_spec();
  uint8_t four[4] = {0xde, 0xad, 0xbe, 0xef};
  Arg a = mk_arg("amount", ARG_FORMAT_AMOUNT, four, 4);
  a.value_len_override = 32;
  s.args[1] = a;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  blob[blob.size() - 2] ^= 0xFF;  // ensure verify cannot pass
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, ClassificationOutOfRange) {
  Spec s = base_spec();
  s.classification = 3;  // > 2
  ExpectMalformed(sign_body(build_body(s)), TEST_KEY_ID);
}

/* ===================================================================== *
 *  signed_metadata_matches_tx — display gate
 * ===================================================================== */

TEST_F(SignedMetadataTest, MatchesTxAllBindingsMatch) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxNotAvailable) {
  signed_metadata_clear();
  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxNullMsg) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_FALSE(signed_metadata_matches_tx(nullptr));
}

TEST_F(SignedMetadataTest, MatchesTxNotVerifiedClassification) {
  Spec s = base_spec();
  s.classification = METADATA_OPAQUE;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_OPAQUE);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongToSize) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  msg.to.size = 19;  // not 20 (e.g. contract-create has 0)
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxDataTooShortForSelector) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  make_matching_msg(&msg);
  msg.data_initial_chunk.size = 3;  // < 4
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongContract) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);
  EthereumSignTx msg;
  make_msg(&msg, CONTRACT_B, data, sizeof(data), true, 1);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongSelector) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  uint8_t data[68];
  memcpy(data, SEL_APPROVE, 4);  // approve, not transfer
  memset(data + 4, 0, sizeof(data) - 4);
  EthereumSignTx msg;
  make_msg(&msg, CONTRACT_A, data, sizeof(data), true, 1);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, MatchesTxWrongChainId) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  uint8_t data[68];
  memcpy(data, SEL_TRANSFER, 4);
  memset(data + 4, 0, sizeof(data) - 4);

  EthereumSignTx wrong_chain;
  make_msg(&wrong_chain, CONTRACT_A, data, sizeof(data), true, 137);
  EXPECT_FALSE(signed_metadata_matches_tx(&wrong_chain));

  EthereumSignTx no_chain;
  make_msg(&no_chain, CONTRACT_A, data, sizeof(data), false,
           0);  // treated as 0
  EXPECT_FALSE(signed_metadata_matches_tx(&no_chain));
}

/* ===================================================================== *
 *  signed_metadata_confirm — no-I/O early guards
 * ===================================================================== */

TEST_F(SignedMetadataTest, ConfirmNotAvailable) {
  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_confirm());
}

TEST_F(SignedMetadataTest, ConfirmNotVerified) {
  Spec s = base_spec();
  s.classification = METADATA_OPAQUE;
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_OPAQUE);
  EXPECT_FALSE(signed_metadata_confirm());
}

/* ===================================================================== *
 *  signed_metadata_enforce — module-level not-relied path (reachable
 *  without confirm()'s interactive tail) and clear() reset
 * ===================================================================== */

TEST_F(SignedMetadataTest, EnforceNotReliedAlwaysAllows) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  ASSERT_FALSE(signed_metadata_relied());  // process() never sets relied

  uint8_t wrong[32];
  memcpy(wrong, TX_HASH, 32);
  wrong[0] ^= 0xFF;
  EXPECT_TRUE(signed_metadata_enforce(TX_HASH));
  EXPECT_TRUE(signed_metadata_enforce(wrong));
  EXPECT_TRUE(signed_metadata_enforce(nullptr));
}

TEST_F(SignedMetadataTest, ClearResetsAllState) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  ASSERT_TRUE(signed_metadata_available());

  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_available());
  EXPECT_FALSE(signed_metadata_relied());
  EXPECT_EQ(signed_metadata_get(), nullptr);
  EXPECT_TRUE(signed_metadata_enforce(TX_HASH));  // not relied
}

/* ===================================================================== *
 *  Runtime signer loading — the phase-1 trust path
 * ===================================================================== */

TEST_F(SignedMetadataTest, NoSignerLoadedRejects) {
  signed_metadata_clear_signers();  // undo the fixture's load
  ExpectMalformed(base_blob(), TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, NoCompiledSignerSlots) {
  signed_metadata_clear_signers();
  EXPECT_FALSE(signed_metadata_available());
  for (uint8_t slot = 0; slot < METADATA_MAX_KEYS; slot++) {
    char fingerprint[METADATA_FINGERPRINT_LEN];
    EXPECT_FALSE(signed_metadata_signer_is_runtime(slot))
        << "slot " << (int)slot;
    EXPECT_EQ(signed_metadata_signer_alias(slot), nullptr)
        << "slot " << (int)slot;
    EXPECT_FALSE(signed_metadata_signer_fingerprint(slot, fingerprint))
        << "slot " << (int)slot;
  }
  EXPECT_EQ(signed_metadata_signer_alias(METADATA_MAX_KEYS), nullptr);
}

TEST_F(SignedMetadataTest, FromLoadedSignerTracksMetadata) {
  EXPECT_FALSE(signed_metadata_from_loaded_signer());  // nothing processed
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_TRUE(signed_metadata_from_loaded_signer());
  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_from_loaded_signer());
}

TEST_F(SignedMetadataTest, ClearSignersDropsKeyAndMetadata) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  signed_metadata_clear_signers();
  EXPECT_FALSE(signed_metadata_available());
  EXPECT_EQ(signed_metadata_get(), nullptr);
  ExpectMalformed(blob, TEST_KEY_ID);  // the key itself is gone too
}

TEST_F(SignedMetadataTest, StoreSignerReplacementInvalidatesOldKey) {
  std::vector<uint8_t> blob = base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  uint8_t priv2[32];
  memcpy(priv2, TEST_PRIV, sizeof(priv2));
  priv2[31] ^= 0x5a;  // a different valid scalar
  uint8_t pub2[33];
  ecdsa_get_public_key33(&secp256k1, priv2, pub2);
  signed_metadata_store_signer(TEST_KEY_ID, pub2, "Replacement", NULL, 0, 0, 0,
                               false);

  /* Replacing a signer drops metadata the old one verified... */
  EXPECT_FALSE(signed_metadata_available());
  /* ...and the old key no longer verifies anything. */
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* ---- signed_metadata_signer_valid (pure) ------------------------------ */

/*
 * ── Identity-icon decoder hardening ────────────────────────────────────────
 *
 * The clearsign identity icon is HOST-SUPPLIED and is rendered on the trust
 * screen, so the decoder is an attack surface reachable before the user has
 * approved anything. Regression guards for two review findings:
 *
 *  (1) A 0x80 (n = -128) packet is undecodable: draw_bitmap_mono_rle's counter
 *      is int8_t, so -(-128) wraps back to -128 and breaks its `> 0` invariant.
 *      Under NDEBUG the assert is compiled out and decoding proceeded with a
 *      negative counter (signed-overflow UB). Must fail closed instead.
 *  (2) icon_width must not exceed LEFT_MARGIN_WITH_ICON: text starts at x=40
 *      and the icon is drawn AFTER the text, so a wider icon overwrites the
 *      alias / fingerprint / "NOT verified by KeepKey" warning.
 */
namespace {

struct IconCanvas {
  uint8_t buf[64 * 256];
  Canvas canvas;
  IconCanvas() {
    memset(buf, 0, sizeof(buf));
    canvas.buffer = buf;
    canvas.width = 256;
    canvas.height = 64;
    canvas.dirty = false;
  }
};

bool decode_icon(const std::vector<uint8_t>& data, uint16_t w, uint16_t h,
                 IconCanvas* ic) {
  Image img;
  img.w = w;
  img.h = h;
  img.length = (uint32_t)data.size();
  img.data = data.data();
  AnimationFrame frame;
  frame.x = 0;
  frame.y = 0;
  frame.duration = 0;
  frame.color = 100; /* value*100/100 => data bytes land verbatim */
  frame.image = &img;
  return draw_bitmap_mono_rle(&ic->canvas, &frame, /*erase=*/false);
}

}  // namespace

TEST(SignedMetadataIcon, GoldenVectorDecodes) {
  /* The vector published in messages-ethereum.proto: 03 FF FF 00 (w=2,h=2). */
  IconCanvas ic;
  ASSERT_TRUE(decode_icon({0x03, 0xFF, 0xFF, 0x00}, 2, 2, &ic));
  EXPECT_EQ(ic.buf[0 * 256 + 0], 0xFF);
  EXPECT_EQ(ic.buf[0 * 256 + 1], 0xFF);
  EXPECT_EQ(ic.buf[1 * 256 + 0], 0xFF);
  EXPECT_EQ(ic.buf[1 * 256 + 1], 0x00);
}

TEST(SignedMetadataIcon, LiteralOf128IsRejected) {
  /* n = 0x80 = -128. Spec-valid under the old doc, undecodable in fact:
   * previously asserted (debug) or decoded with a negative counter (NDEBUG). */
  std::vector<uint8_t> data;
  data.push_back(0x80);
  for (int i = 0; i < 128; i++) data.push_back(0xAA);
  IconCanvas ic;
  EXPECT_FALSE(decode_icon(data, 128, 1, &ic));
}

TEST(SignedMetadataIcon, ZeroCountIsRejected) {
  /* n == 0 leaves both counters at 0 and hits the same broken invariant. */
  IconCanvas ic;
  EXPECT_FALSE(decode_icon({0x00, 0xFF}, 1, 1, &ic));
}

TEST(SignedMetadataIcon, MaxLiteralOf127Decodes) {
  /* The boundary that IS valid: n = -127 (0x81). */
  std::vector<uint8_t> data;
  data.push_back(0x81);
  for (int i = 0; i < 127; i++) data.push_back((uint8_t)i);
  IconCanvas ic;
  ASSERT_TRUE(decode_icon(data, 127, 1, &ic));
  EXPECT_EQ(ic.buf[0], 0x00);
  EXPECT_EQ(ic.buf[126], 126);
}

TEST(SignedMetadataIcon, MaxRunOf127Decodes) {
  std::vector<uint8_t> data{0x7F, 0x5A};
  IconCanvas ic;
  ASSERT_TRUE(decode_icon(data, 127, 1, &ic));
  EXPECT_EQ(ic.buf[0], 0x5A);
  EXPECT_EQ(ic.buf[126], 0x5A);
}

TEST(SignedMetadataIcon, TruncatedStreamIsRejected) {
  IconCanvas ic;
  EXPECT_FALSE(decode_icon({0x08, 0xFF}, 4, 4, &ic)); /* claims 8, has 2 */
}

/* ── Exact-validation guards (review round 2) ──────────────────────────────
 * The render path is lenient by construction: it fills the canvas and stops,
 * so it cannot reject a final run that straddles the image or trailing packets.
 * Callers gate on the validator, so the validator must be exact. */

TEST(SignedMetadataIcon, StraddlingRunIsRejected) {
  /* 05 FF for a 2x2: a RUN of 5 into a 4-pixel image. The draw loop would fill
   * 4 and report success; the stream is not well-formed. */
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x05\xFF", 2, 2, 2));
  IconCanvas ic;
  EXPECT_FALSE(decode_icon({0x05, 0xFF}, 2, 2, &ic));
}

TEST(SignedMetadataIcon, TrailingPacketsAreRejected) {
  /* Exactly fills 2x2, then carries an unread packet. */
  EXPECT_FALSE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\x04\xFF\x01\xAA", 4, 2, 2));
}

TEST(SignedMetadataIcon, TruncatedLiteralBodyIsRejected) {
  /* n = -3 promises 3 value bytes, only 2 present. */
  EXPECT_FALSE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\xFD\x01\x02", 3, 3, 1));
}

TEST(SignedMetadataIcon, MissingRunValueByteIsRejected) {
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x04", 1, 4, 1));
}

TEST(SignedMetadataIcon, ValidatorAcceptsExactStreams) {
  /* The golden vector, and the valid boundaries. */
  EXPECT_TRUE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\x03\xFF\xFF\x00", 4, 2, 2));
  EXPECT_TRUE(
      draw_bitmap_mono_rle_valid((const uint8_t*)"\x7F\x5A", 2, 127, 1));
  std::vector<uint8_t> lit;
  lit.push_back(0x81);
  for (int i = 0; i < 127; i++) lit.push_back((uint8_t)i);
  EXPECT_TRUE(
      draw_bitmap_mono_rle_valid(lit.data(), (uint32_t)lit.size(), 127, 1));
}

TEST(SignedMetadataIcon, ValidatorRejectsUndecodableAndZeroCounts) {
  std::vector<uint8_t> lit128;
  lit128.push_back(0x80);
  for (int i = 0; i < 128; i++) lit128.push_back(0xAA);
  EXPECT_FALSE(draw_bitmap_mono_rle_valid(lit128.data(),
                                          (uint32_t)lit128.size(), 128, 1));
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x00\xFF", 2, 1, 1));
  /* The 1x1 accept-and-persist case: 80 FF was previously stored despite never
   * rendering, because only size+dims were checked at the trust boundary. */
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x80\xFF", 2, 1, 1));
}

TEST(SignedMetadataIcon, ValidatorRejectsDegenerateGeometry) {
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x01\xFF", 2, 0, 1));
  EXPECT_FALSE(draw_bitmap_mono_rle_valid((const uint8_t*)"\x01\xFF", 2, 1, 0));
  EXPECT_FALSE(draw_bitmap_mono_rle_valid(NULL, 0, 1, 1));
}

TEST(SignedMetadataIcon, IconColumnCapIsNarrowerThanTheIconHeight) {
  /* The width cap is the 40px text column, NOT the 64px height. A 64px-wide
   * icon at x=0 would span into the text that begins at x=40 and, because the
   * icon is drawn after the text, erase the "NOT verified" warning. */
  EXPECT_EQ(LEFT_MARGIN_WITH_ICON, 40);
  EXPECT_LT(LEFT_MARGIN_WITH_ICON, 64);
}

TEST(SignedMetadataSignerValid, AcceptsValidCompressedKeyAllSlots) {
  for (uint8_t slot = 0; slot < METADATA_MAX_KEYS; slot++) {
    EXPECT_TRUE(
        signed_metadata_signer_valid(slot, EXPECTED_SLOT3_PUB, 33, "CI Test"))
        << "slot " << (int)slot;
  }
}

TEST(SignedMetadataSignerValid, RejectsKeyIdOutOfRange) {
  EXPECT_FALSE(signed_metadata_signer_valid(METADATA_MAX_KEYS,
                                            EXPECTED_SLOT3_PUB, 33, "CI Test"));
}

TEST(SignedMetadataSignerValid, RejectsWrongPubkeyLength) {
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 32, "CI Test"));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 65, "CI Test"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, nullptr, 33, "CI Test"));
}

TEST(SignedMetadataSignerValid, RejectsNonCompressedPrefix) {
  /* 0x04 would make ecdsa_read_pubkey read 65 bytes from a 33-byte buffer —
   * the prefix guard must reject it before the parser ever runs. */
  uint8_t bad[33];
  memcpy(bad, EXPECTED_SLOT3_PUB, sizeof(bad));
  bad[0] = 0x04;
  EXPECT_FALSE(signed_metadata_signer_valid(0, bad, 33, "CI Test"));
  bad[0] = 0x00;  // the "empty slot" sentinel must never load as a key
  EXPECT_FALSE(signed_metadata_signer_valid(0, bad, 33, "CI Test"));
}

TEST(SignedMetadataSignerValid, RejectsBadAlias) {
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, nullptr));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, ""));
  std::string too_long(METADATA_ALIAS_MAX_LEN + 1, 'a');
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33,
                                            too_long.c_str()));
  std::string max_len(METADATA_ALIAS_MAX_LEN, 'a');
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, max_len.c_str()));
  /* Realistic aliases (letters/digits/space/-/_) are accepted. */
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "Pioneer"));
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "KeepKey Swap"));
  EXPECT_TRUE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "my-signer_1"));
  /* Rendered inside quotes on the trust screen — control chars, '%', and
   * semantic-injection punctuation (quote breakout, "." / "(" appending a
   * false "verified by KeepKey." claim) are all rejected. */
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a\nb"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "a%sb"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33,
                                            "a\x7f"
                                            "b"));
  EXPECT_FALSE(signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33,
                                            "x' verified by KeepKey. Safe ("));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "safe.KeepKey"));
  EXPECT_FALSE(
      signed_metadata_signer_valid(0, EXPECTED_SLOT3_PUB, 33, "trust(me)"));
}

TEST(SignedMetadataSignerStore, RejectsPersistenceBeforeSessionMutation) {
  signed_metadata_clear_signers();
  EXPECT_FALSE(signed_metadata_store_signer(
      TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS, nullptr, 0, 0, 0, true));
  EXPECT_EQ(signed_metadata_signer_alias(TEST_KEY_ID), nullptr);
  char fingerprint[METADATA_FINGERPRINT_LEN];
  EXPECT_FALSE(signed_metadata_signer_fingerprint(TEST_KEY_ID, fingerprint));
  signed_metadata_clear_signers();
}

/* ---- signed_metadata_pubkey_fingerprint -------------------------------- */

TEST(SignedMetadataFingerprint, Is64BitSha256Prefix) {
  char fp[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(EXPECTED_SLOT3_PUB, fp);
  // First 8 bytes of sha256(EXPECTED_SLOT3_PUB), computed off-device.
  EXPECT_STREQ(fp, "0C2CB8B9F467F147");
  EXPECT_EQ(strlen(fp), 16u);
  EXPECT_EQ(sizeof(fp), 17u);
}

TEST(SignedMetadataFingerprint, IsSha256Prefix) {
  char fp[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(EXPECTED_SLOT3_PUB, fp);

  /* The expected text is computed here from sha256, not by the code under
     test: uppercase hex of the first (LEN - 1) / 2 digest bytes. */
  uint8_t digest[32];
  sha256_Raw(EXPECTED_SLOT3_PUB, 33, digest);
  char expected[METADATA_FINGERPRINT_LEN];
  for (size_t i = 0; i < (METADATA_FINGERPRINT_LEN - 1) / 2; i++) {
    snprintf(expected + 2 * i, 3, "%02X", digest[i]);
  }
  EXPECT_STREQ(expected, fp);
  EXPECT_EQ(strlen(fp), METADATA_FINGERPRINT_LEN - 1u);
}

/* ===================================================================== *
 *  signed_metadata_enforce_decision — pure enforce truth table (SECTION 2).
 *  Exercises the relied==true cases that confirm()'s OLED/button I/O makes
 *  unreachable from the module-state API in a unit test.
 * ===================================================================== */

TEST(SignedMetadataEnforce, NotReliedAlwaysAllow) {
  uint8_t h[32] = {0};
  uint8_t hw[32] = {1};
  EXPECT_TRUE(
      signed_metadata_enforce_decision(false, true, METADATA_VERIFIED, h, h));
  EXPECT_TRUE(signed_metadata_enforce_decision(false, false, METADATA_OPAQUE,
                                               nullptr, nullptr));
  EXPECT_TRUE(
      signed_metadata_enforce_decision(false, true, METADATA_VERIFIED, h, hw));
}

TEST(SignedMetadataEnforce, ReliedHashMatches) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_TRUE(
      signed_metadata_enforce_decision(true, true, METADATA_VERIFIED, h, h));
}

TEST(SignedMetadataEnforce, ReliedHashMismatch) {
  uint8_t stored[32];
  memcpy(stored, TX_HASH, 32);
  uint8_t got[32];
  memcpy(got, TX_HASH, 32);
  got[0] ^= 0x01;
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                stored, got));
}

TEST(SignedMetadataEnforce, ReliedHashNull) {
  uint8_t stored[32];
  memcpy(stored, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                stored, nullptr));
}

TEST(SignedMetadataEnforce, ReliedNotAvailable) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(
      signed_metadata_enforce_decision(true, false, METADATA_VERIFIED, h, h));
}

TEST(SignedMetadataEnforce, ReliedNotVerified) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(
      signed_metadata_enforce_decision(true, true, METADATA_OPAQUE, h, h));
  EXPECT_FALSE(
      signed_metadata_enforce_decision(true, true, METADATA_MALFORMED, h, h));
}

TEST(SignedMetadataEnforce, ReliedStoredHashNull) {
  uint8_t h[32];
  memcpy(h, TX_HASH, 32);
  EXPECT_FALSE(signed_metadata_enforce_decision(true, true, METADATA_VERIFIED,
                                                nullptr, h));
}

/* ===================================================================== *
 *  SECTION 3 — v2 static-schema blobs + on-device calldata decode
 *
 *  v2 carries NO tx_hash and NO argument values. The blob attests only the
 *  static schema (chainId, contract, selector, method, per-arg name + display
 *  format [+ static decimals/symbol]); the device decodes the actual argument
 *  values from the calldata it is about to sign. These tests drive the full
 *  parse -> verify -> signed_metadata_matches_tx (which decodes) path and check
 *  the decoded MetadataArg values, plus the malformed/rejection cases.
 * ===================================================================== */

struct V2Arg {
  std::string name;
  uint8_t format;
  uint8_t decimals;   /* TOKEN_AMOUNT only */
  std::string symbol; /* TOKEN_AMOUNT only */
  std::vector<uint8_t> pinned; /* ADDRESS_PINNED only */
};

V2Arg v2_addr(const std::string& name) {
  return V2Arg{name, ARG_FORMAT_ADDRESS, 0, "", {}};
}
V2Arg v2_pinned(const std::string& name, const uint8_t* addr, size_t len) {
  return V2Arg{name, ARG_FORMAT_ADDRESS_PINNED, 0, "",
               std::vector<uint8_t>(addr, addr + len)};
}
V2Arg v2_token(const std::string& name, uint8_t decimals,
               const std::string& symbol) {
  return V2Arg{name, ARG_FORMAT_TOKEN_AMOUNT, decimals, symbol, {}};
}

struct V2Spec {
  uint32_t chain_id;
  std::vector<uint8_t> contract;
  std::vector<uint8_t> selector;
  std::string method;
  std::vector<V2Arg> args;
  uint8_t classification;
  uint8_t key_id;
  int num_args_override;  // -1 => use args.size()
};

V2Spec v2_base_spec() {
  V2Spec s;
  s.chain_id = 1;
  s.contract.assign(CONTRACT_A, CONTRACT_A + 20);
  s.selector.assign(SEL_TRANSFER, SEL_TRANSFER + 4);
  s.method = "transfer";
  s.args.push_back(v2_addr("to"));
  s.args.push_back(v2_token("amount", 6, "USDC"));
  s.classification = METADATA_VERIFIED;
  s.key_id = TEST_KEY_ID;
  s.num_args_override = -1;
  return s;
}

std::vector<uint8_t> build_v2_body(const V2Spec& s) {
  std::vector<uint8_t> b;
  put_u8(b, METADATA_VERSION_SCHEMA);
  put_be32(b, s.chain_id);
  put_bytes(b, s.contract.data(), s.contract.size());
  put_bytes(b, s.selector.data(), s.selector.size());
  put_be16(b, (uint16_t)s.method.size());
  put_bytes(b, (const uint8_t*)s.method.data(), s.method.size());
  put_u8(b, s.num_args_override >= 0 ? (uint8_t)s.num_args_override
                                     : (uint8_t)s.args.size());
  for (const V2Arg& a : s.args) {
    put_u8(b, (uint8_t)a.name.size());
    put_bytes(b, (const uint8_t*)a.name.data(), a.name.size());
    put_u8(b, a.format);
    if (a.format == ARG_FORMAT_TOKEN_AMOUNT) {
      put_u8(b, a.decimals);
      put_u8(b, (uint8_t)a.symbol.size());
      put_bytes(b, (const uint8_t*)a.symbol.data(), a.symbol.size());
    }
    if (a.format == ARG_FORMAT_ADDRESS_PINNED) {
      put_bytes(b, a.pinned.data(), a.pinned.size());
    }
  }
  put_u8(b, s.classification);
  put_be32(b, 0);  // timestamp
  put_u8(b, s.key_id);
  return b;
}

std::vector<uint8_t> v2_base_blob() {
  return sign_body(build_v2_body(v2_base_spec()));
}

/* ABI calldata: selector + one 32-byte head word per arg. */
void put_addr_word(std::vector<uint8_t>& d, const uint8_t addr[20]) {
  for (int i = 0; i < 12; i++) d.push_back(0);
  d.insert(d.end(), addr, addr + 20);
}

/* Canonical transfer(to=RECIPIENT, amount=AMOUNT32) calldata (4 + 64 = 68). */
std::vector<uint8_t> v2_transfer_calldata() {
  std::vector<uint8_t> d(SEL_TRANSFER, SEL_TRANSFER + 4);
  put_addr_word(d, RECIPIENT);
  d.insert(d.end(), AMOUNT32, AMOUNT32 + 32);
  return d;
}

void make_v2_msg(EthereumSignTx* msg, const uint8_t contract[20],
                 const std::vector<uint8_t>& data, bool has_len,
                 uint32_t data_length) {
  memset(msg, 0, sizeof(*msg));
  msg->has_to = true;
  msg->to.size = 20;
  memcpy(msg->to.bytes, contract, 20);
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = (pb_size_t)data.size();
  memcpy(msg->data_initial_chunk.bytes, data.data(), data.size());
  msg->has_chain_id = true;
  msg->chain_id = 1;
  msg->has_data_length = has_len;
  msg->data_length = has_len ? data_length : 0;
}

/* Happy path: parse+verify a v2 blob, then matches_tx decodes the args from the
 * transfer calldata and populates stored_metadata. */
TEST_F(SignedMetadataTest, V2SchemaDecodesTransferArgs) {
  std::vector<uint8_t> blob = v2_base_blob();
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_TRUE(signed_metadata_available());

  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->version, METADATA_VERSION_SCHEMA);
  EXPECT_EQ(md->num_args, 2);
  EXPECT_EQ(md->args[0].value_len, 0);  // undecoded before matches_tx

  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));

  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS);
  EXPECT_EQ(md->args[0].value_len, 20);
  EXPECT_EQ(memcmp(md->args[0].value, RECIPIENT, 20), 0);

  EXPECT_EQ(md->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(md->args[1].value_len, 2 + 4 + 32);
  EXPECT_EQ(md->args[1].value[0], 6);  // decimals
  EXPECT_EQ(md->args[1].value[1], 4);  // symlen
  EXPECT_EQ(memcmp(md->args[1].value + 2, "USDC", 4), 0);
  EXPECT_EQ(memcmp(md->args[1].value + 6, AMOUNT32, 32), 0);
}

/* THE v2 drain preventer, restated.
 *
 * A v2 schema commits to calldata only — never to msg->value — so it cannot
 * bind a payable call's amount. The original guard refused any nonzero value,
 * which meant every value-bearing route (a Relay ETH->SOL bridge deposit, for
 * one) was forced to blind-sign: precisely the transactions most worth
 * reviewing. Refusing was not what kept funds safe; SHOWING the amount is.
 *
 * So the match now succeeds and the schema reports that the tx moves value.
 * ethereum.c consumes that to keep the native amount/recipient screen instead
 * of suppressing it, so the user sees the decoded call AND the ETH leaving.
 * The amount is read from the transaction being signed, so nothing unattested
 * reaches the screen and the schema stays transaction-independent. */
TEST_F(SignedMetadataTest, V2SchemaPayableKeepsValueScreen) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  msg.has_value = true;
  msg.value.size = 1;
  msg.value.bytes[0] = 0x01;  // 1 wei — any nonzero value is "payable"

  /* Clear-signs, AND flags that the amount screen must still run. */
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_TRUE(signed_metadata_schema_moves_value());

  /* Zero value: same match, but no extra screen is demanded — proving the
   * flag tracks the value rather than being always-on. */
  msg.value.size = 0;
  msg.has_value = false;
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_FALSE(signed_metadata_schema_moves_value());
}

/* A large, realistic value must set the flag too — not just a 1-wei probe. */
TEST_F(SignedMetadataTest, V2SchemaPayableFlagsRealisticValue) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  msg.has_value = true;
  /* 0.00798 ETH = 0x1c5145d9b6b3ff — the Relay ETH->SOL deposit from a real
   * quote, whose blind-signing prompted this change. */
  const uint8_t kValue[] = {0x1c, 0x51, 0x45, 0xd9, 0xb6, 0xb3, 0xff};
  msg.value.size = sizeof(kValue);
  memcpy(msg.value.bytes, kValue, sizeof(kValue));
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_TRUE(signed_metadata_schema_moves_value());
}

/* THE transaction this whole path exists for: a real Relay ETH->SOL bridge
 * deposit, captured from api.relay.link on 2026-07-27.
 *
 *   to       0x4cd00e387622c35bddb9b4c962c136462338bc31
 *   value    7980129999999999 wei (0.00798 ETH)  <-- PAYABLE
 *   calldata 0x49290c1c + address(depositor) + bytes32(orderId)  = 68 bytes
 *
 * Three things had to be true for this to clear-sign, and each was a real
 * blocker: the call is payable (was refused outright), one arg is an opaque
 * word (BYTES was not accepted in the v2 arg parser), and 4 + 2*32 must
 * exactly equal the calldata length (structural completeness). */
TEST_F(SignedMetadataTest, V2SchemaDecodesRelayEthToSolanaDeposit) {
  const uint8_t RELAY_ROUTER[20] = {0x4c, 0xd0, 0x0e, 0x38, 0x76, 0x22, 0xc3,
                                    0x5b, 0xdd, 0xb9, 0xb4, 0x96, 0x2c, 0x13,
                                    0x64, 0x62, 0x33, 0x8b, 0xc3, 0x31};
  const uint8_t SEL[4] = {0x49, 0x29, 0x0c, 0x1c};
  /* depositor 0x909Ef6B32DfDc12CA86aA710b54c991af3C5F82E */
  const uint8_t DEPOSITOR[20] = {0x90, 0x9e, 0xf6, 0xb3, 0x2d, 0xfd, 0xc1,
                                 0x2c, 0xa8, 0x6a, 0xa7, 0x10, 0xb5, 0x4c,
                                 0x99, 0x1a, 0xf3, 0xc5, 0xf8, 0x2e};
  /* orderId 0x8a2c1211...cb1, verbatim from the quote */
  const uint8_t ORDER_ID[32] = {0x8a, 0x2c, 0x12, 0x11, 0x97, 0xef, 0xc9, 0x5c,
                                0x42, 0xf5, 0x31, 0x42, 0xab, 0x40, 0x97, 0x35,
                                0xee, 0x35, 0x32, 0x87, 0xf8, 0x77, 0xed, 0x4d,
                                0x35, 0x1f, 0x63, 0x09, 0x4d, 0x5b, 0xfc, 0xb1};

  V2Spec s = v2_base_spec();
  s.contract.assign(RELAY_ROUTER, RELAY_ROUTER + 20);
  s.selector.assign(SEL, SEL + 4);
  s.method = "bridgeDeposit";
  s.args.clear();
  s.args.push_back(v2_addr("depositor"));
  s.args.push_back(V2Arg{"orderId", ARG_FORMAT_BYTES, 0, ""});

  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  std::vector<uint8_t> data(SEL, SEL + 4);
  put_addr_word(data, DEPOSITOR);
  data.insert(data.end(), ORDER_ID, ORDER_ID + 32);
  ASSERT_EQ(data.size(), 68u); /* 4 + 2*32, exactly — no remainder */

  EthereumSignTx msg;
  make_v2_msg(&msg, RELAY_ROUTER, data, /*has_len=*/true,
              (uint32_t)data.size());
  /* 0.00798 ETH — the payable part that used to force blind-signing. */
  const uint8_t VALUE[] = {0x1c, 0x51, 0x45, 0xd9, 0xb6, 0xb3, 0xff};
  msg.has_value = true;
  msg.value.size = sizeof(VALUE);
  memcpy(msg.value.bytes, VALUE, sizeof(VALUE));

  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  /* ...and the ETH amount screen must still run, since the schema cannot
   * bind the value. */
  EXPECT_TRUE(signed_metadata_schema_moves_value());

  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->num_args, 2);
  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS);
  EXPECT_EQ(md->args[0].value_len, 20);
  EXPECT_EQ(memcmp(md->args[0].value, DEPOSITOR, 20), 0);
  EXPECT_EQ(md->args[1].format, ARG_FORMAT_BYTES);
  EXPECT_EQ(md->args[1].value_len, 32);
  EXPECT_EQ(memcmp(md->args[1].value, ORDER_ID, 32), 0);
}

/* A v2 schema commits to calldata only. A payable call may use its decoded
 * display, but ethereum.c must also show the transaction's native value. */
TEST_F(SignedMetadataTest, V2PayableCallRequiresNativeValueConfirmation) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true,
              static_cast<uint32_t>(data.size()));
  msg.value.size = 1;
  msg.value.bytes[0] = 1;
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_TRUE(signed_metadata_schema_moves_value());
  msg.value.bytes[0] = 0;
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_FALSE(signed_metadata_schema_moves_value());
  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_schema_moves_value());
}
/* Relay solver swap: selector 0x02d5f05f(token address, amount, requestId) —
 * three fixed single words, EXACTLY the shape pulled from real relay traffic
 * (100-byte calldata: 4 + 3*32, zero remainder, verified across 22 live
 * samples). Proves a v2 static schema clear-signs a relay swap: the device
 * decodes token+amount+id from the very calldata it is about to sign — no
 * tx_hash, no per-tx online signer, schema signed once offline. This is the
 * "add a new service via a signed payload" path for a NON-native contract
 * (relay is not in ethereum_contractHandled). */
TEST_F(SignedMetadataTest, V2SchemaDecodesRelaySolverArgs) {
  const uint8_t RELAY_SOLVER[20] = {0x4c, 0xd0, 0x0e, 0x38, 0x76, 0x22, 0xc3,
                                    0x5b, 0xdd, 0xb9, 0xb4, 0x96, 0x2c, 0x13,
                                    0x64, 0x62, 0x33, 0x8b, 0xc3, 0x31};
  const uint8_t SEL_RELAY[4] = {0x02, 0xd5, 0xf0, 0x5f};
  uint8_t REQ_ID[32] = {0};  // requestId 0x...cd7c from a real sample
  REQ_ID[30] = 0xcd;
  REQ_ID[31] = 0x7c;

  V2Spec s = v2_base_spec();
  s.contract.assign(RELAY_SOLVER, RELAY_SOLVER + 20);
  s.selector.assign(SEL_RELAY, SEL_RELAY + 4);
  s.method = "relaySwap";
  s.args.clear();
  s.args.push_back(v2_addr("token"));
  s.args.push_back(v2_token("amount", 6, "USDC"));
  s.args.push_back(V2Arg{"requestId", ARG_FORMAT_AMOUNT, 0, ""});

  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->version, METADATA_VERSION_SCHEMA);
  EXPECT_EQ(md->num_args, 3);

  // Real relay calldata: selector + token(USDC=CONTRACT_A) + amount +
  // requestId.
  std::vector<uint8_t> data(SEL_RELAY, SEL_RELAY + 4);
  put_addr_word(data, CONTRACT_A);
  data.insert(data.end(), AMOUNT32, AMOUNT32 + 32);
  data.insert(data.end(), REQ_ID, REQ_ID + 32);
  EXPECT_EQ(data.size(), 100u);

  EthereumSignTx msg;
  make_v2_msg(&msg, RELAY_SOLVER, data, /*has_len=*/true,
              (uint32_t)data.size());
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));

  // token → full 20-byte USDC address (never truncated).
  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS);
  EXPECT_EQ(md->args[0].value_len, 20);
  EXPECT_EQ(memcmp(md->args[0].value, CONTRACT_A, 20), 0);

  // amount → TOKEN_AMOUNT [decimals=6, "USDC", 32-byte amount].
  EXPECT_EQ(md->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(md->args[1].value[0], 6);
  EXPECT_EQ(md->args[1].value[1], 4);
  EXPECT_EQ(memcmp(md->args[1].value + 2, "USDC", 4), 0);
  EXPECT_EQ(memcmp(md->args[1].value + 6, AMOUNT32, 32), 0);

  // requestId → raw 32-byte AMOUNT word.
  EXPECT_EQ(md->args[2].format, ARG_FORMAT_AMOUNT);
  EXPECT_EQ(md->args[2].value_len, 32);
  EXPECT_EQ(memcmp(md->args[2].value, REQ_ID, 32), 0);
}

/* has_data_length omitted but the initial chunk IS the whole calldata: allowed.
 */
TEST_F(SignedMetadataTest, V2AcceptsNoDataLengthWhenChunkComplete) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/false, 0);
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
}

/* Reject when the tx claims MORE calldata than the schema accounts for. */
TEST_F(SignedMetadataTest, V2RejectsExtraCalldataLength) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();  // 68 bytes
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, 100);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Reject a partial initial chunk (rest would stream later). */
TEST_F(SignedMetadataTest, V2RejectsPartialInitialChunk) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  data.resize(40);  // selector + partial first word
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, 68);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Reject an ABI address word with non-zero high bytes. */
TEST_F(SignedMetadataTest, V2RejectsDirtyAddressWord) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  data[4] = 0x01;  // first (should-be-zero) byte of the address word
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Wrong selector in calldata -> matches_tx fails before decode. */
TEST_F(SignedMetadataTest, V2RejectsSelectorMismatch) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  memcpy(data.data(), SEL_APPROVE, 4);
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* Metadata describes an Ethereum call. A Wanchain transaction (tx_type) on
 * the same chain id, contract and selector is not one, for either version. */
TEST_F(SignedMetadataTest, MatchesTxRefusesWanchainTypedTx) {
  for (uint32_t tx_type : {1u, 6u}) {
    SCOPED_TRACE(tx_type);
    std::vector<uint8_t> blob = base_blob();
    ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
              METADATA_VERIFIED);
    EthereumSignTx msg;
    make_matching_msg(&msg);
    ASSERT_TRUE(signed_metadata_matches_tx(&msg));
    msg.has_tx_type = true;
    msg.tx_type = tx_type;
    EXPECT_FALSE(signed_metadata_matches_tx(&msg));

    blob = v2_base_blob();
    ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
              METADATA_VERIFIED);
    std::vector<uint8_t> data = v2_transfer_calldata();
    make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true,
                (uint32_t)data.size());
    ASSERT_TRUE(signed_metadata_matches_tx(&msg));
    msg.has_tx_type = true;
    msg.tx_type = tx_type;
    EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  }
}

/* An unsupported display format -> MALFORMED.
 *
 * v2 renders fixed single ABI words only: ADDRESS, AMOUNT, BYTES and
 * TOKEN_AMOUNT. STRING is dynamic (offset + length + payload), so it cannot be
 * read from one 32-byte word and must stay out of scope — accepting it would
 * break the "declared widths equal the calldata length" rule that makes a
 * schema safe without a tx_hash. An out-of-range format byte must fail too. */
TEST_F(SignedMetadataTest, V2RejectsUnsupportedFormat) {
  V2Spec s = v2_base_spec();
  s.args[1] = V2Arg{"data", ARG_FORMAT_STRING, 0, ""};
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  ExpectMalformed(blob, TEST_KEY_ID);

  V2Spec bogus = v2_base_spec();
  bogus.args[1] = V2Arg{"data", (ArgFormat)0x7f, 0, ""};
  std::vector<uint8_t> blob2 = sign_body(build_v2_body(bogus));
  ExpectMalformed(blob2, TEST_KEY_ID);
}

/* BYTES IS supported in v2: an opaque fixed word (a router's order id) still
 * occupies exactly one ABI word, so it neither breaks structural completeness
 * nor needs a dynamic decoder. */
TEST_F(SignedMetadataTest, V2AcceptsBytesArg) {
  V2Spec s = v2_base_spec();
  s.args[1] = V2Arg{"orderId", ARG_FORMAT_BYTES, 0, ""};
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
}

/* Every byte of an opaque BYTES word is shown, on numbered pages: a
 * prefix-only screen would hide a change in the second half of the word. */
TEST_F(SignedMetadataTest, FixedBytesSchemaDecodesEntireWord) {
  V2Spec spec = v2_base_spec();
  spec.args[1] = V2Arg{"data", ARG_FORMAT_BYTES, 0, ""};
  std::vector<uint8_t> blob = sign_body(build_v2_body(spec));
  ASSERT_EQ(METADATA_VERIFIED,
            signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID));
  std::vector<uint8_t> data = v2_transfer_calldata();
  for (size_t i = 36; i < data.size(); ++i) data[i] = (uint8_t)i;
  EthereumSignTx msg;
  make_v2_msg(&msg, CONTRACT_A, data, true, (uint32_t)data.size());
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  const SignedMetadata* decoded = signed_metadata_get();
  ASSERT_NE(nullptr, decoded);
  ASSERT_EQ(32u, decoded->args[1].value_len);
  EXPECT_EQ(0, memcmp(decoded->args[1].value, data.data() + 36, 32));
  // identity, method, contract, address, byte page 1 accepted; page 2 refused.
  ASSERT_TRUE(kkconfirm_preload(5, 1));
  EXPECT_FALSE(signed_metadata_confirm());
  EXPECT_EQ(0, kkconfirm_drain());
}

/* Titles do not move the body down when they wrap, so a 64-character method
 * name used as a title would draw over the contract, arguments and byte pages.
 * Every screen's title must fit one title row. */
TEST_F(SignedMetadataTest, LongMethodNameNeverWrapsTheTitle) {
  Spec s = base_spec();
  s.method = std::string(METADATA_MAX_METHOD_LEN, 'W');
  const uint8_t raw[20] = {0xab};
  s.args.push_back(mk_arg("data", ARG_FORMAT_BYTES, raw, sizeof(raw)));
  std::vector<uint8_t> blob = sign_body(build_body(s));
  ASSERT_EQ(METADATA_VERIFIED,
            signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID));
  EthereumSignTx msg;
  make_matching_msg(&msg);
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  // identity, call (two pages), contract, to, amount, two byte pages.
  ASSERT_TRUE(kkconfirm_preload(8, 0));
  kkconfirm_capture_start();
  EXPECT_TRUE(signed_metadata_confirm());
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  EXPECT_EQ(0, kkconfirm_drain());
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  ASSERT_EQ(8u, titles.size());
  // The identity screen quotes the signer's own alias and disclaims it.
  EXPECT_EQ('\'', bodies[0][0]) << bodies[0];
  EXPECT_NE(std::string::npos, bodies[0].find("NOT verified by KeepKey"))
      << bodies[0];
  // The Call screen still discloses the whole name.
  EXPECT_NE(std::string::npos, (bodies[1] + bodies[2]).find(s.method));
  for (std::string title : titles) {
    for (char& c : title) c = (char)toupper((unsigned char)c);
    EXPECT_EQ(1u, calc_str_line(get_title_font(), title.c_str(),
                                TITLE_WIDTH_WITH_ICON))
        << title;
  }
}

/* Tampered v2 body must fail the signature check. */
TEST_F(SignedMetadataTest, V2RejectsTamperedBody) {
  std::vector<uint8_t> blob = v2_base_blob();
  blob[5] ^= 0xFF;  // flip a contract-address byte in the signed region
  ExpectMalformed(blob, TEST_KEY_ID);
}

/* Zero-arg v2 schema (selector-only call): valid, decodes nothing. */
TEST_F(SignedMetadataTest, V2ZeroArgsSelectorOnly) {
  V2Spec s = v2_base_spec();
  s.args.clear();
  s.method = "poke";
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data(SEL_TRANSFER, SEL_TRANSFER + 4);
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, 4);
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_EQ(signed_metadata_get()->num_args, 0);
}

/* matches_tx() must be idempotent: a second call decodes to the same values
 * (regression for the TOKEN_AMOUNT prefix that used to grow on each call). */
TEST_F(SignedMetadataTest, V2MatchesTxIsIdempotent) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());

  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  const SignedMetadata* md = signed_metadata_get();
  uint16_t len_addr = md->args[0].value_len, len_tok = md->args[1].value_len;

  EXPECT_TRUE(signed_metadata_matches_tx(&msg));  // second call
  EXPECT_EQ(md->args[0].value_len, len_addr);
  EXPECT_EQ(md->args[1].value_len, len_tok);
  EXPECT_EQ(md->args[1].value_len, 2 + 4 + 32);
  EXPECT_EQ(memcmp(md->args[0].value, RECIPIENT, 20), 0);
  EXPECT_EQ(memcmp(md->args[1].value + 6, AMOUNT32, 32), 0);
}

/* The v2 decode flag must reflect ONLY the latest matches_tx() call: a
 * successful decode followed by a mismatching tx must leave it false, so a
 * stale "decoded" proof can never survive into enforce. */
TEST_F(SignedMetadataTest, V2SchemaDecodedFlagNotStaleAfterMismatch) {
  std::vector<uint8_t> blob = v2_base_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EXPECT_FALSE(signed_metadata_schema_decoded());  // not decoded yet

  EthereumSignTx ok;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&ok, CONTRACT_A, data, /*has_len=*/true, (uint32_t)data.size());
  ASSERT_TRUE(signed_metadata_matches_tx(&ok));
  EXPECT_TRUE(signed_metadata_schema_decoded());  // decoded this tx

  /* Now a tx that fails an EARLY binding (wrong contract) — before the decode
   * branch. The flag must be cleared, not left over from the match above. */
  EthereumSignTx bad;
  make_v2_msg(&bad, CONTRACT_B, data, /*has_len=*/true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&bad));
  EXPECT_FALSE(signed_metadata_schema_decoded());
}

/* A pinned address lets a template name the party in words ("Uniswap"), so
 * the schema must match ONLY a word holding exactly that address. */
TEST_F(SignedMetadataTest, PinnedAddressMatchesOnlyThePinnedAddress) {
  V2Spec s = v2_base_spec();
  s.args[0] = v2_pinned("spender", RECIPIENT, 20);
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS_PINNED);

  EthereumSignTx msg;
  std::vector<uint8_t> data = v2_transfer_calldata();
  make_v2_msg(&msg, CONTRACT_A, data, true, (uint32_t)data.size());
  EXPECT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_EQ(memcmp(md->args[0].value, RECIPIENT, 20), 0);

  // Another spender: no match, and the pin survives for the next attempt.
  std::vector<uint8_t> other = data;
  other[4 + 31] ^= 0x01;
  make_v2_msg(&msg, CONTRACT_A, other, true, (uint32_t)other.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  EXPECT_EQ(memcmp(md->args[0].value, RECIPIENT, 20), 0);

  // The right address in a dirty word is not the pinned address.
  std::vector<uint8_t> dirty = data;
  dirty[4] = 0x01;
  make_v2_msg(&msg, CONTRACT_A, dirty, true, (uint32_t)dirty.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, PinnedAddressMustCarryTwentyBytes) {
  V2Spec s = v2_base_spec();
  s.args[0] = v2_pinned("spender", RECIPIENT, 19);
  std::vector<uint8_t> blob = sign_body(build_v2_body(s));
  EXPECT_NE(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
}

/* ---- v2 enforce truth table (pure, no I/O) ------------------------------ */
/* Signature: (relied, available, decoded, classification). */

TEST(SignedMetadataEnforceSchema, NotReliedAlwaysAllow) {
  EXPECT_TRUE(signed_metadata_enforce_schema_decision(false, true, true,
                                                      METADATA_VERIFIED));
  EXPECT_TRUE(signed_metadata_enforce_schema_decision(false, false, false,
                                                      METADATA_OPAQUE));
}

TEST(SignedMetadataEnforceSchema, ReliedVerifiedDecodedAllow) {
  EXPECT_TRUE(signed_metadata_enforce_schema_decision(true, true, true,
                                                      METADATA_VERIFIED));
}

TEST(SignedMetadataEnforceSchema, ReliedButNotDecodedFails) {
  /* The core hardening: relied + available + VERIFIED but decode never ran. */
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, true, false,
                                                       METADATA_VERIFIED));
}

TEST(SignedMetadataEnforceSchema, ReliedButUnavailableOrUnverifiedFails) {
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, false, true,
                                                       METADATA_VERIFIED));
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, true, true,
                                                       METADATA_OPAQUE));
  EXPECT_FALSE(signed_metadata_enforce_schema_decision(true, true, true,
                                                       METADATA_MALFORMED));
}

// Generic attestation primitive (used by the Solana signed-token-definition
// path): a valid signature from a loaded signer verifies; tampering, an
// unloaded key_id, or a wrong signature length are all rejected.
TEST(SignedMetadataAttestation, VerifiesValidRejectsTampered) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  const uint8_t data[] = "KeepKeySolanaTokenDef/1|mint|decimals|USDC";
  const size_t len = sizeof(data) - 1;
  uint8_t digest[32];
  sha256_Raw(data, len, digest);
  uint8_t sig[64];
  uint8_t pby;
  ASSERT_EQ(
      0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby, nullptr));

  EXPECT_TRUE(signed_metadata_verify_attestation(TEST_KEY_ID, data, len, sig,
                                                 sizeof(sig)));

  std::vector<uint8_t> bad(data, data + len);
  bad[0] ^= 0x01;
  EXPECT_FALSE(signed_metadata_verify_attestation(TEST_KEY_ID, bad.data(), len,
                                                  sig, sizeof(sig)));
  EXPECT_FALSE(signed_metadata_verify_attestation((uint8_t)(TEST_KEY_ID + 1),
                                                  data, len, sig, sizeof(sig)));
  EXPECT_FALSE(
      signed_metadata_verify_attestation(TEST_KEY_ID, data, len, sig, 63));

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

// End-to-end test of the production Solana token-definition path: builds the
// exact domain-separated preimage solana_token_info_trusted() reconstructs,
// signs it, and checks acceptance + every rejection branch.
TEST(SolanaTokenDef, TrustedOnlyWithValidAttestation) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  SolanaTokenInfo ti;
  memset(&ti, 0, sizeof(ti));
  ti.has_mint = true;
  ti.mint.size = 32;
  memset(ti.mint.bytes, 0xAB, 32);
  ti.has_symbol = true;
  strcpy(ti.symbol, "BONK");
  ti.has_decimals = true;
  ti.decimals = 6;
  ti.has_signer_key_id = true;
  ti.signer_key_id = TEST_KEY_ID;

  // Canonical preimage: tag || mint(32) || decimals(le32) || symbol.
  std::vector<uint8_t> pre;
  const char* tag = "KeepKeySolanaTokenDef/1";
  pre.insert(pre.end(), tag, tag + strlen(tag));
  pre.insert(pre.end(), ti.mint.bytes, ti.mint.bytes + 32);
  pre.push_back(6);
  pre.push_back(0);
  pre.push_back(0);
  pre.push_back(0);
  pre.insert(pre.end(), ti.symbol, ti.symbol + strlen(ti.symbol));

  uint8_t digest[32];
  sha256_Raw(pre.data(), pre.size(), digest);
  uint8_t sig[64];
  uint8_t pby;
  ASSERT_EQ(
      0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby, nullptr));
  ti.has_signature = true;
  ti.signature.size = 64;
  memcpy(ti.signature.bytes, sig, 64);

  EXPECT_TRUE(solana_token_info_trusted(&ti));

  // Display: attested symbol only when the signed decimals match.
  EXPECT_STREQ(solana_displaySymbol(&ti, nullptr, 6), "BONK");
  EXPECT_EQ(solana_displaySymbol(&ti, nullptr, 9), nullptr);

  // A validly signed label is still not shown when it reuses a symbol the
  // firmware owns for another mint, in any case, or holds a space: each
  // would draw the amount screen the real token gets.
  const size_t head = strlen(tag) + 32 + 4;
  auto sign_symbol = [&](const char* symbol) {
    strcpy(ti.symbol, symbol);
    pre.resize(head);
    pre.insert(pre.end(), symbol, symbol + strlen(symbol));
    sha256_Raw(pre.data(), pre.size(), digest);
    ASSERT_EQ(0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, &pby,
                                   nullptr));
    memcpy(ti.signature.bytes, sig, 64);
  };
  for (const char* spoof : {"USDC", "usdc", "5 USDC", "USD C", "-USDC"}) {
    sign_symbol(spoof);
    ASSERT_TRUE(solana_token_info_trusted(&ti)) << spoof;
    EXPECT_EQ(solana_displaySymbol(&ti, nullptr, 6), nullptr) << spoof;
  }
  sign_symbol("BONK");
  ASSERT_STREQ(solana_displaySymbol(&ti, nullptr, 6), "BONK");

  // Attested-tuple disagreement: a different decimals no longer matches the
  // sig.
  ti.decimals = 9;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  ti.decimals = 6;
  EXPECT_TRUE(solana_token_info_trusted(&ti));

  // Corrupted signature.
  ti.signature.bytes[10] ^= 0x40;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  ti.signature.bytes[10] ^= 0x40;

  // Out-of-range signer slot (256 would narrow to slot 0 without the guard).
  ti.signer_key_id = 256;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  ti.signer_key_id = TEST_KEY_ID;

  // No attestation -> not trusted, and the host's symbol is never displayed,
  // even when its claimed decimals match the signed ones.
  ti.has_signature = false;
  EXPECT_FALSE(solana_token_info_trusted(&ti));
  EXPECT_EQ(solana_displaySymbol(&ti, nullptr, 6), nullptr);
  EXPECT_EQ(solana_displaySymbol(nullptr, nullptr, 6), nullptr);

  // A firmware-known mint shows the table symbol whatever the host sent.
  static const uint8_t usdc_mint[32] = {
      0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
      0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
      0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61};
  const SolanaKnownToken* known = solana_findKnownToken(usdc_mint);
  ASSERT_NE(known, nullptr);
  strcpy(ti.symbol, "FAKE");
  EXPECT_STREQ(solana_displaySymbol(&ti, known, 6), "USDC");
  EXPECT_STREQ(solana_displaySymbol(nullptr, known, 6), "USDC");

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

/* Sign a "KeepKeySolanaTokenDef/1" definition with TEST_PRIV (slot 3). */
void sign_token_def_v1(SolanaTokenInfo* ti) {
  std::vector<uint8_t> pre;
  const char* tag = "KeepKeySolanaTokenDef/1";
  pre.insert(pre.end(), tag, tag + strlen(tag));
  pre.insert(pre.end(), ti->mint.bytes, ti->mint.bytes + 32);
  for (int i = 0; i < 4; i++) pre.push_back((uint8_t)(ti->decimals >> (8 * i)));
  pre.insert(pre.end(), ti->symbol, ti->symbol + strlen(ti->symbol));
  uint8_t digest[32];
  sha256_Raw(pre.data(), pre.size(), digest);
  uint8_t pby;
  ASSERT_EQ(0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest,
                                 ti->signature.bytes, &pby, nullptr));
  ti->has_signature = true;
  ti->signature.size = 64;
}

/* A schema TOKEN_AMOUNT takes its scale and symbol only from a definition
 * trusted in the review's own tier. The runtime signer's definition works on
 * the runtime (AdvancedMode) review -- the positive control -- and is refused
 * on the certified one, whose authority is the root certificate alone. The
 * display-shape rules (decimals <= 9, bare ticker) refuse definitions the
 * signature alone would accept. */
TEST(SolanaTokenDef, SchemaTokenTrustStaysInItsTier) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_schema_signer_key_id = true;
  msg.schema_signer_key_id = TEST_KEY_ID;
  msg.token_info_count = 1;
  SolanaTokenInfo* ti = &msg.token_info[0];
  ti->has_mint = true;
  ti->mint.size = 32;
  memset(ti->mint.bytes, 0xAB, 32);
  ti->has_symbol = true;
  strcpy(ti->symbol, "SDICE");
  ti->has_decimals = true;
  ti->decimals = 6;
  ti->has_signer_key_id = true;
  ti->signer_key_id = TEST_KEY_ID;
  sign_token_def_v1(ti);
  const uint8_t* mint = ti->mint.bytes;

  ASSERT_TRUE(solana_token_info_trusted(ti));
  EXPECT_EQ(solana_schemaTrustedToken(&msg, mint, false), ti);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, mint, true), nullptr);

  char buf[96];
  ASSERT_TRUE(solana_formatSchemaTokenAmount(
      buf, sizeof(buf), 1000000000ULL, mint,
      solana_schemaTrustedToken(&msg, mint, false)));
  EXPECT_STREQ(buf,
               "1000 SDICE\n"
               "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t");

  // Validly signed, but not displayable as a bare ticker / exact scale.
  const struct {
    const char* symbol;
    uint32_t decimals;
  } unsafe[] = {{"SD ICE", 6}, {"SDICE\n", 6}, {".SDICE", 6}, {"SDICE", 10}};
  for (const auto& u : unsafe) {
    strcpy(ti->symbol, u.symbol);
    ti->decimals = u.decimals;
    sign_token_def_v1(ti);
    ASSERT_TRUE(solana_token_info_trusted(ti)) << u.symbol;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, mint, false), nullptr)
        << u.symbol << " " << u.decimals;
  }

  // Without AdvancedMode the runtime signer vouches for nothing.
  strcpy(ti->symbol, "SDICE");
  ti->decimals = 6;
  sign_token_def_v1(ti);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, mint, false), ti);
  set_advanced_mode_for_test(false);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, mint, false), nullptr);

  signed_metadata_clear_signers();
}

/* Base58 of the test mints below: 0xAB x32 and 0xCD x32. */
const char* const kMintAB58 = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
const char* const kMintCD58 = "ErNbLjU6E8tSbZH3REsMeTDP3Z8G52k6YedWwvBpAJ7v";

/* A schema instruction whose accounts 0 and 1 are the mints 0xAB.. and
 * 0xCD.., held at message keys 2 and 1 (key 0 is a payer, 0x11..), so reading
 * instruction account 0 against the message's list names a different key; its
 * data is three u64 amounts: 1,000,000, 2,000,000 and 3,000,000 base units. */
struct TwoMintInstruction {
  SolanaParsedTx tx;
  uint8_t acct_indices[2];
  uint8_t data[24];
};

void build_two_mint_instruction(TwoMintInstruction* t) {
  memset(t, 0, sizeof(*t));
  t->tx.num_accounts = 3;
  t->tx.num_static_accounts = 3;
  memset(t->tx.accounts[0], 0x11, 32);
  memset(t->tx.accounts[1], 0xCD, 32);
  memset(t->tx.accounts[2], 0xAB, 32);
  t->acct_indices[0] = 2;
  t->acct_indices[1] = 1;
  for (int a = 0; a < 3; a++) {
    const uint64_t v = 1000000ULL * (uint64_t)(a + 1);
    for (int b = 0; b < 8; b++) t->data[8 * a + b] = (uint8_t)(v >> (8 * b));
  }
  t->tx.num_instructions = 1;
  SolanaParsedInstruction* ix = &t->tx.instructions[0];
  ix->type = SOL_INSTR_UNKNOWN;
  ix->acct_indices = t->acct_indices;
  ix->num_acct_indices = 2;
  ix->data = t->data;
  ix->data_len = sizeof(t->data);
}

void fill_token_def(SolanaTokenInfo* ti, uint8_t mint_byte, const char* symbol,
                    uint32_t decimals) {
  memset(ti, 0, sizeof(*ti));
  ti->has_mint = true;
  ti->mint.size = 32;
  memset(ti->mint.bytes, mint_byte, 32);
  ti->has_symbol = true;
  strcpy(ti->symbol, symbol);
  ti->has_decimals = true;
  ti->decimals = decimals;
  ti->has_signer_key_id = true;
  ti->signer_key_id = TEST_KEY_ID;
  sign_token_def_v1(ti);
}

/* A signed definition binds a symbol to a mint, not the symbol to a token:
 * anyone can mint a token named "USDT" and have its definition signed. So a
 * trusted TOKEN_AMOUNT is never shown by symbol alone -- the renderer names
 * the mint it actually read from the transaction. ("USDC" itself is refused
 * outright on any mint but Circle's; see the next test.) */
TEST(SolanaTokenDef, SchemaTrustedSymbolIsAlwaysShownWithItsMint) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_schema_signer_key_id = true;
  msg.schema_signer_key_id = TEST_KEY_ID;
  msg.token_info_count = 1;
  fill_token_def(&msg.token_info[0], 0xAB, "USDT", 6);

  static TwoMintInstruction t;
  build_two_mint_instruction(&t);
  const SolanaParsedInstruction* ix = &t.tx.instructions[0];
  ASSERT_EQ(solana_schemaTrustedToken(&msg, t.tx.accounts[2], false),
            &msg.token_info[0]);

  const SolanaSchemaArg arg = {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Max wager", 0};
  SolanaSchemaTokenCache cache = {nullptr, nullptr};
  char value[96];
  ASSERT_TRUE(solana_schemaArgValue(&msg, false, &t.tx, ix, &arg, t.data,
                                    &cache, value, sizeof(value)));
  EXPECT_EQ(std::string(value), std::string("1 USDT\n") + kMintAB58);

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

/* A definition may not take a name the firmware's known-token table gives to
 * another mint. "USDC", in any case, signed for the mint 0xAB.. is trusted on
 * neither tier: the amount is shown raw beside the mint it was read from. On
 * the certified tier no definition here is delegate-signed, so that half
 * cannot tell this rule from a missing signature; the runtime half can. The
 * controls: a longer symbol is only a lookalike, and "usdc" for Circle's own
 * mint is trusted. */
TEST(SolanaTokenDef, SchemaKnownSymbolOnAnotherMintIsNotTrusted) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_schema_signer_key_id = true;
  msg.schema_signer_key_id = TEST_KEY_ID;
  msg.token_info_count = 1;
  SolanaTokenInfo* ti = &msg.token_info[0];

  static TwoMintInstruction t;
  build_two_mint_instruction(&t);
  const SolanaParsedInstruction* ix = &t.tx.instructions[0];
  const SolanaSchemaArg arg = {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Buy-in", 0};
  const auto render = [&](bool certified) {
    SolanaSchemaTokenCache cache = {nullptr, nullptr};
    char value[96] = {0};
    EXPECT_TRUE(solana_schemaArgValue(&msg, certified, &t.tx, ix, &arg, t.data,
                                      &cache, value, sizeof(value)));
    return std::string(value);
  };
  const std::string raw =
      std::string("1000000 base units of mint\n") + kMintAB58;

  for (const char* symbol : {"USDC", "usdc", "UsDc"}) {
    fill_token_def(ti, 0xAB, symbol, 6);
    ASSERT_TRUE(solana_token_info_trusted(ti)) << symbol;
    for (bool certified : {false, true}) {
      EXPECT_EQ(solana_schemaTrustedToken(&msg, t.tx.accounts[2], certified),
                nullptr)
          << symbol << " certified=" << certified;
      EXPECT_EQ(render(certified), raw) << symbol << " certified=" << certified;
    }
  }

  fill_token_def(ti, 0xAB, "USDCX", 6);
  EXPECT_EQ(render(false), std::string("1 USDCX\n") + kMintAB58);

  /* EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v */
  static const uint8_t kCircleUsdc[32] = {
      0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
      0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
      0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61};
  fill_token_def(ti, 0xAB, "usdc", 6);
  memcpy(ti->mint.bytes, kCircleUsdc, 32);
  sign_token_def_v1(ti);
  memcpy(t.tx.accounts[2], kCircleUsdc, 32);
  EXPECT_EQ(solana_schemaTrustedToken(&msg, t.tx.accounts[2], false), ti);
  EXPECT_EQ(render(false),
            "1 usdc\nEPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

/* One review, three TOKEN_AMOUNTs: mint A (trusted), mint B (definition
 * present but its signature broken), mint A again. Each is rendered from its
 * own mint's definition; A's symbol never reaches B. On a certified review the
 * runtime signer's definition counts for nothing, so all three are raw. */
TEST(SolanaTokenDef, SchemaTokenDefinitionNeverCarriesAcrossMints) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_schema_signer_key_id = true;
  msg.schema_signer_key_id = TEST_KEY_ID;
  msg.token_info_count = 2;
  fill_token_def(&msg.token_info[0], 0xAB, "SDICE", 6);
  fill_token_def(&msg.token_info[1], 0xCD, "SDICE", 6);
  msg.token_info[1].signature.bytes[10] ^= 0x40;

  static TwoMintInstruction t;
  build_two_mint_instruction(&t);
  const SolanaParsedInstruction* ix = &t.tx.instructions[0];
  const SolanaSchemaArg args[3] = {
      {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Buy-in", 0},
      {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Allowance", 1},
      {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Max wager", 0},
  };
  const std::string runtime[3] = {
      std::string("1 SDICE\n") + kMintAB58,
      std::string("2000000 base units of mint\n") + kMintCD58,
      std::string("3 SDICE\n") + kMintAB58,
  };
  const std::string certified[3] = {
      std::string("1000000 base units of mint\n") + kMintAB58,
      std::string("2000000 base units of mint\n") + kMintCD58,
      std::string("3000000 base units of mint\n") + kMintAB58,
  };

  for (bool is_certified : {false, true}) {
    SolanaSchemaTokenCache cache = {nullptr, nullptr};
    for (int a = 0; a < 3; a++) {
      char value[96];
      ASSERT_TRUE(solana_schemaArgValue(&msg, is_certified, &t.tx, ix, &args[a],
                                        t.data + 8 * a, &cache, value,
                                        sizeof(value)));
      EXPECT_EQ(std::string(value), is_certified ? certified[a] : runtime[a])
          << args[a].label << " certified=" << is_certified;
    }
  }

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

/* The runtime review names the schema's signer on its first screen. A
 * definition from any other slot -- however validly signed -- does not scale
 * or name the amounts shown under that name. Nor does any runtime definition
 * count on a request addressed to the certificate delegate (0x80), which is
 * what the certified path requires of every request it renders. */
TEST(SolanaTokenDef, SchemaRuntimeTokenMustComeFromTheSchemaSigner) {
  set_advanced_mode_for_test(true);
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               nullptr, 0, 0, 0, false);

  static SolanaSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.token_info_count = 1;
  fill_token_def(&msg.token_info[0], 0xAB, "SDICE", 6);
  ASSERT_TRUE(solana_token_info_trusted(&msg.token_info[0]));

  static TwoMintInstruction t;
  build_two_mint_instruction(&t);
  const SolanaParsedInstruction* ix = &t.tx.instructions[0];
  const uint8_t* mint = t.tx.accounts[2];
  const SolanaSchemaArg arg = {SOL_SCHEMA_ARG_TOKEN_AMOUNT, "Buy-in", 0};
  const std::string raw =
      std::string("1000000 base units of mint\n") + kMintAB58;

  const struct {
    bool has;
    uint32_t schema_signer;
    bool trusted;
  } cases[] = {
      {true, TEST_KEY_ID, true},      /* the positive control */
      {true, TEST_KEY_ID - 1, false}, /* another runtime slot */
      {false, TEST_KEY_ID, false},    /* no schema signer named */
      {true, 0x80, false},            /* certified-shaped request */
  };
  for (const auto& c : cases) {
    msg.has_schema_signer_key_id = c.has;
    msg.schema_signer_key_id = c.schema_signer;
    EXPECT_EQ(solana_schemaTrustedToken(&msg, mint, false) != nullptr,
              c.trusted)
        << c.has << " " << c.schema_signer;
    SolanaSchemaTokenCache cache = {nullptr, nullptr};
    char value[96];
    ASSERT_TRUE(solana_schemaArgValue(&msg, false, &t.tx, ix, &arg, t.data,
                                      &cache, value, sizeof(value)));
    EXPECT_EQ(std::string(value) == raw, !c.trusted)
        << c.has << " " << c.schema_signer << ": " << value;
  }

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

/* ===================================================================== *
 *  v4 firmware-owned dynamic schemas
 * ===================================================================== */

const uint8_t PORTALS_ROUTER[20] = {0xbf, 0x5a, 0x7f, 0x36, 0x29, 0xfb, 0x32,
                                    0x5e, 0x2a, 0x84, 0x53, 0xd5, 0x95, 0xab,
                                    0x10, 0x34, 0x65, 0xf7, 0x5e, 0x62};
const uint8_t PORTALS_SELECTOR[4] = {0xa2, 0xe4, 0x2c, 0x65};
const uint8_t PORTALS_OUTPUT_TOKEN[20] = {
    0x47, 0x0e, 0x8d, 0xe2, 0xeb, 0xae, 0xf5, 0x20, 0x14, 0xa4,
    0x7c, 0xb5, 0xe6, 0xaf, 0x86, 0x88, 0x49, 0x47, 0xf0, 0x8c};

void put_word_u32(std::vector<uint8_t>& data, size_t offset, uint32_t value) {
  ASSERT_LE(offset + 32, data.size());
  memset(data.data() + offset, 0, 32);
  data[offset + 28] = (uint8_t)(value >> 24);
  data[offset + 29] = (uint8_t)(value >> 16);
  data[offset + 30] = (uint8_t)(value >> 8);
  data[offset + 31] = (uint8_t)value;
}

void put_word_address(std::vector<uint8_t>& data, size_t offset,
                      const uint8_t address[20]) {
  ASSERT_LE(offset + 32, data.size());
  memset(data.data() + offset, 0, 12);
  memcpy(data.data() + offset + 12, address, 20);
}

std::vector<uint8_t> portals_v4_blob(
    uint8_t decoder = METADATA_DECODER_PORTALS_NATIVE_ORDER_V1,
    const uint8_t* contract = PORTALS_ROUTER) {
  std::vector<uint8_t> body;
  put_u8(body, METADATA_VERSION_DYNAMIC_SCHEMA);
  put_be32(body, 1);
  put_bytes(body, contract, sizeof(PORTALS_ROUTER));
  put_bytes(body, PORTALS_SELECTOR, sizeof(PORTALS_SELECTOR));
  const char* method = "Portals swap";
  put_be16(body, (uint16_t)strlen(method));
  put_bytes(body, (const uint8_t*)method, strlen(method));
  put_u8(body, decoder);
  put_u8(body, METADATA_VERIFIED);
  put_be32(body, 0);
  put_u8(body, TEST_KEY_ID);
  return sign_body(body);
}

/* Canonical ABI head for portal(((address,uint256,address,uint256,address),
 * (address,address,bytes,uint256)[]),address).  The synthetic call tails are
 * irrelevant to the router's enforced outer order, but their offset table is
 * canonical and wholly present in the initial chunk. */
std::vector<uint8_t> portals_calldata() {
  std::vector<uint8_t> data(1476, 0);
  memcpy(data.data(), PORTALS_SELECTOR, sizeof(PORTALS_SELECTOR));
  put_word_u32(data, 4, 0x40);
  put_word_address(data, 36, CONTRACT_B);
  /* OrderPayload starts at byte 68. inputToken stays address(0) = native. */
  put_word_u32(data, 100, 0x010203);
  put_word_address(data, 132, PORTALS_OUTPUT_TOKEN);
  put_word_u32(data, 164, 0x0a0b0c);
  put_word_address(data, 196, RECIPIENT);
  put_word_u32(data, 228, 0xc0);
  put_word_u32(data, 260, 4);
  put_word_u32(data, 292, 0x80);
  put_word_u32(data, 324, 0x140);
  put_word_u32(data, 356, 0x200);
  put_word_u32(data, 388, 0x2c0);
  return data;
}

void make_portals_msg(EthereumSignTx* msg, const std::vector<uint8_t>& data) {
  memset(msg, 0, sizeof(*msg));
  msg->has_to = true;
  msg->to.size = sizeof(PORTALS_ROUTER);
  memcpy(msg->to.bytes, PORTALS_ROUTER, sizeof(PORTALS_ROUTER));
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = 1024;
  memcpy(msg->data_initial_chunk.bytes, data.data(), 1024);
  msg->has_data_length = true;
  msg->data_length = (uint32_t)data.size();
  msg->has_chain_id = true;
  msg->chain_id = 1;
  msg->has_value = true;
  msg->value.size = 3;
  msg->value.bytes[0] = 0x01;
  msg->value.bytes[1] = 0x02;
  msg->value.bytes[2] = 0x03;
}

TEST_F(SignedMetadataTest, V4PortalsDecodesSafetyDefiningOuterOrder) {
  std::vector<uint8_t> blob = portals_v4_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  EthereumSignTx msg;
  std::vector<uint8_t> data = portals_calldata();
  make_portals_msg(&msg, data);

  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_TRUE(signed_metadata_schema_decoded());
  EXPECT_TRUE(signed_metadata_schema_moves_value());
  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  EXPECT_EQ(md->version, METADATA_VERSION_DYNAMIC_SCHEMA);
  EXPECT_EQ(md->decoder_id, METADATA_DECODER_PORTALS_NATIVE_ORDER_V1);
  ASSERT_EQ(md->num_args, 3);
  EXPECT_STREQ(md->args[0].name, "Output token");
  EXPECT_EQ(md->args[0].format, ARG_FORMAT_ADDRESS);
  EXPECT_EQ(memcmp(md->args[0].value, PORTALS_OUTPUT_TOKEN, 20), 0);
  EXPECT_STREQ(md->args[1].name, "Minimum output");
  EXPECT_EQ(md->args[1].format, ARG_FORMAT_TOKEN_AMOUNT);
  EXPECT_EQ(md->args[1].value[0], 0);
  EXPECT_EQ(md->args[1].value[1], 5);
  EXPECT_EQ(memcmp(md->args[1].value + 2, "units", 5), 0);
  EXPECT_STREQ(md->args[2].name, "Recipient");
  EXPECT_EQ(memcmp(md->args[2].value, RECIPIENT, 20), 0);
}

TEST_F(SignedMetadataTest, V4RejectsUnknownDecoder) {
  std::vector<uint8_t> blob = portals_v4_blob(0x7f);
  ExpectMalformed(blob, TEST_KEY_ID);
}

TEST_F(SignedMetadataTest, V4PortalsDecoderCannotBeAssignedToAnotherContract) {
  std::vector<uint8_t> blob =
      portals_v4_blob(METADATA_DECODER_PORTALS_NATIVE_ORDER_V1, CONTRACT_A);
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  std::vector<uint8_t> data = portals_calldata();
  EthereumSignTx msg;
  make_portals_msg(&msg, data);
  memcpy(msg.to.bytes, CONTRACT_A, 20);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, V4PortalsRejectsValueAndOuterOrderTampering) {
  std::vector<uint8_t> blob = portals_v4_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  std::vector<uint8_t> data = portals_calldata();
  EthereumSignTx msg;
  make_portals_msg(&msg, data);

  msg.value.bytes[2] ^= 1;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  msg.data_initial_chunk.bytes[68 + 31] = 1;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  msg.data_initial_chunk.bytes[132] = 1;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  memset(msg.data_initial_chunk.bytes + 164, 0, 32);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  put_word_u32(data, 4, 0x60);
  memcpy(msg.data_initial_chunk.bytes, data.data(), 1024);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

TEST_F(SignedMetadataTest, V4PortalsRejectsMalformedCallArrayBoundaries) {
  std::vector<uint8_t> blob = portals_v4_blob();
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
  std::vector<uint8_t> data = portals_calldata();
  EthereumSignTx msg;
  make_portals_msg(&msg, data);

  msg.data_length = 1477;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  msg.data_initial_chunk.size = 291;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  memset(msg.data_initial_chunk.bytes + 260, 0, 32);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  msg.data_initial_chunk.bytes[324 + 30] = 0x00;
  msg.data_initial_chunk.bytes[324 + 31] = 0x80;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  make_portals_msg(&msg, data);
  msg.data_initial_chunk.bytes[292 + 31] = 0x81;
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
}

/* ===================================================================== *
 *  Externally issued schema: the verifier's digest contract
 *
 *  This build verifies schemas issued outside the device; it has no
 *  ClearsignAttestorSign handler or wire mapping. The fixture signs the
 *  single SHA256(payload) with a test key and exercises the production
 *  verifier. It does not cover a device-side issuer. SignIdentity's Bitcoin
 *  message framing and 65-byte signature are not this attestation format.
 * ===================================================================== */

TEST(SignedMetadataAttestation, ExternallySignedSchemaVerifies) {
  set_advanced_mode_for_test(true);
  /* Smallest valid KKSOLSC1 payload: no args, no accounts. What matters here
   * is the digest construction, not the schema body. */
  std::vector<uint8_t> payload;
  auto push = [&](const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    payload.insert(payload.end(), b, b + n);
  };
  push("KKSOLSC1", 8);
  payload.push_back(1); /* version */
  payload.insert(payload.end(), 32, 0x42);
  payload.push_back(1);    /* disc_len */
  payload.push_back(0x0d); /* discriminator */
  payload.push_back(5);
  push("Relay", 5);
  payload.push_back(7);
  push("deposit", 7);
  payload.push_back(0); /* no args */
  payload.push_back(0); /* no accounts */

  SolanaInstrSchema schema;
  ASSERT_TRUE(solana_parseInstrSchema(payload.data(), payload.size(), &schema))
      << "the fixture must be a valid schema";

  /* External issuer fixture: compact ECDSA over a single SHA256. */
  uint8_t digest[32];
  sha256_Raw(payload.data(), payload.size(), digest);
  uint8_t sig[64];
  ASSERT_EQ(ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, NULL, NULL),
            0);

  /* Verifier side. */
  signed_metadata_clear_signers();
  signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS,
                               NULL, 0, 0, 0, false);
  EXPECT_TRUE(signed_metadata_verify_attestation(
      TEST_KEY_ID, payload.data(), payload.size(), sig, sizeof(sig)));

  /* A schema the issuer never signed must not ride the same signature. */
  payload[9] ^= 0x01; /* first byte of the program id */
  EXPECT_FALSE(signed_metadata_verify_attestation(
      TEST_KEY_ID, payload.data(), payload.size(), sig, sizeof(sig)));

  signed_metadata_clear_signers();
  set_advanced_mode_for_test(false);
}

/* ===================================================================== *
 *  Solana schema path: every signed companion is shown
 * ===================================================================== */

class SolanaSchemaSignTest : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = nullptr;

  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    previous_flash = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    storage_commit();
    ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
    signed_metadata_clear_signers();
    ASSERT_TRUE(signed_metadata_store_signer(TEST_KEY_ID, EXPECTED_SLOT3_PUB,
                                             TEST_ALIAS, NULL, 0, 0, 0, false));
  }

  void TearDown() override {
    signed_metadata_clear_signers();
    storage_reset();
    emulator_flash_base = previous_flash;
  }
};

/* A schema-matched instruction plus a Memo: the memo (swap intents and
 * destinations ride in it) must be paged before the signature is made. */
TEST_F(SolanaSchemaSignTest, MemoCompanionIsShown) {
  const uint32_t path[4] = {0x80000000u | 44, 0x80000000u | 501, 0x80000000u,
                            0x80000000u};
  uint8_t seed[64];
  mnemonic_to_seed("all all all all all all all all all all all all", "", seed,
                   NULL);
  HDNode node;
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), ED25519_NAME, &node));
  for (uint32_t i : path) ASSERT_EQ(1, hdnode_private_ckd(&node, i));
  hdnode_fill_public_key(&node);

  uint8_t program[32];
  memset(program, 0x42, sizeof(program));
  const std::string memo =
      "=:ETH.ETH:0x4E9B2CA2A1Bb8e5c1C5A0bdf0fA7F5F3dDeadBeE";

  /* Legacy message: [payer, program, memo program]; ix0 = schema match
   * (one-byte discriminator, no args), ix1 = Memo. */
  std::vector<uint8_t> raw = {1, 0, 2, 3};
  raw.insert(raw.end(), node.public_key + 1, node.public_key + 33);
  raw.insert(raw.end(), program, program + 32);
  raw.insert(raw.end(), SOL_MEMO_PROGRAM, SOL_MEMO_PROGRAM + 32);
  raw.insert(raw.end(), 32, 0xBB); /* recent blockhash */
  raw.push_back(2);
  raw.insert(raw.end(), {1, 0, 1, 0x0d});
  raw.insert(raw.end(), {2, 0, (uint8_t)memo.size()});
  raw.insert(raw.end(), memo.begin(), memo.end());

  std::vector<uint8_t> payload;
  payload.insert(payload.end(), {'K', 'K', 'S', 'O', 'L', 'S', 'C', '1', 1});
  payload.insert(payload.end(), program, program + 32);
  payload.insert(payload.end(), {1, 0x0d, 5, 'R', 'e', 'l', 'a', 'y', 7, 'd',
                                 'e', 'p', 'o', 's', 'i', 't', 0, 0});
  uint8_t digest[32];
  sha256_Raw(payload.data(), payload.size(), digest);
  uint8_t sig[64];
  ASSERT_EQ(0,
            ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest, sig, NULL, NULL));

  SolanaSignTx msg = {};
  msg.address_n_count = 4;
  memcpy(msg.address_n, path, sizeof(path));
  msg.has_raw_tx = true;
  msg.raw_tx.size = raw.size();
  memcpy(msg.raw_tx.bytes, raw.data(), raw.size());
  msg.has_schema_payload = true;
  msg.schema_payload.size = payload.size();
  memcpy(msg.schema_payload.bytes, payload.data(), payload.size());
  msg.has_schema_signature = true;
  msg.schema_signature.size = sizeof(sig);
  memcpy(msg.schema_signature.bytes, sig, sizeof(sig));
  msg.has_schema_signer_key_id = true;
  msg.schema_signer_key_id = TEST_KEY_ID;

  /* Schema signer, instruction, memo, blind-sign warning, final confirm. */
  ASSERT_TRUE(kkconfirm_preload(5, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgSolanaSignTx(&msg);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  EXPECT_EQ(0, fsm_test_lastFailureCode()) << fsm_test_lastFailureMessage();
  EXPECT_EQ(0, kkconfirm_drain());
  /* The runtime signer is named the way the EVM Identity screen names it:
   * quoted, fingerprinted, and NOT verified by KeepKey. */
  uint8_t pub_digest[32];
  sha256_Raw(EXPECTED_SLOT3_PUB, 33, pub_digest);
  char fp[17];
  for (int i = 0; i < 8; i++)
    snprintf(fp + 2 * i, 3, "%02X", pub_digest[i]);
  ASSERT_FALSE(titles.empty());
  EXPECT_EQ("Identity", titles[0]);
  EXPECT_EQ(std::string("'") + TEST_ALIAS + "' (" + fp +
                ") describes this tx. NOT verified by KeepKey.",
            bodies[0]);
  std::string shown;
  for (const std::string& b : bodies) shown += b;
  EXPECT_NE(std::string::npos, shown.find(memo)) << shown;
}

TEST_F(SolanaSchemaSignTest, FeaturesReportLutAttestation) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  GetFeatures request = {};
  fsm_msgGetFeatures(&request);
  static Features features;
  features = Features{};
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_Features,
                                     Features_fields, &features));
  EXPECT_TRUE(features.has_supports_solana_lut_attestation);
  EXPECT_TRUE(features.supports_solana_lut_attestation);
  bool reported = false;
  for (pb_size_t i = 0; i < features.capabilities_count; ++i)
    reported |= features.capabilities[i] ==
                Features_Capability_CAPABILITY_SOLANA_LUT_ATTESTATION;
  EXPECT_TRUE(reported);
}

TEST_F(SolanaSchemaSignTest,
       LutAttestationBindsAccountsToTransactionAndSigner) {
  const uint32_t path[4] = {0x80000000u | 44, 0x80000000u | 501, 0x80000000u,
                            0x80000000u};
  uint8_t seed[64];
  mnemonic_to_seed("all all all all all all all all all all all all", "", seed,
                   NULL);
  HDNode node;
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), ED25519_NAME, &node));
  for (uint32_t i : path) ASSERT_EQ(1, hdnode_private_ckd(&node, i));
  hdnode_fill_public_key(&node);

  /* v0 message with two static keys and one writable lookup-table account.
   * The loaded account is absent from the signed transaction bytes. */
  std::vector<uint8_t> raw = {0x80, 1, 0, 1, 2};
  raw.insert(raw.end(), node.public_key + 1, node.public_key + 33);
  raw.insert(raw.end(), 32, 0);    /* system program */
  raw.insert(raw.end(), 32, 0xBB); /* blockhash at offset 69 */
  raw.insert(raw.end(), {1, 1, 1, 2, 4, 2, 0, 0, 0, 1});
  raw.insert(raw.end(), 32, 0x77);  /* lookup table address */
  raw.insert(raw.end(), {1, 3, 0}); /* writable index 3, no readonly keys */

  SolanaSignTx original = {};
  original.address_n_count = 4;
  memcpy(original.address_n, path, sizeof(path));
  original.has_raw_tx = true;
  original.raw_tx.size = raw.size();
  memcpy(original.raw_tx.bytes, raw.data(), raw.size());
  original.lut_account_count = 1;
  original.lut_account[0].size = 32;
  memset(original.lut_account[0].bytes, 0x51, 32);
  original.has_lut_signer_key_id = true;
  original.lut_signer_key_id = TEST_KEY_ID;

  /* Independent issuer construction, not the firmware's trust helper. */
  const char tag[] = "KeepKeySolanaTxAccounts/1";
  std::vector<uint8_t> preimage(tag, tag + sizeof(tag) - 1);
  uint8_t digest[32];
  sha256_Raw(raw.data(), raw.size(), digest);
  preimage.insert(preimage.end(), digest, digest + sizeof(digest));
  preimage.insert(preimage.end(), {1, 0, 0, 0}); /* le32 account count */
  preimage.insert(preimage.end(), 32, 0x51);
  sha256_Raw(preimage.data(), preimage.size(), digest);
  original.has_lut_signature = true;
  original.lut_signature.size = 64;
  ASSERT_EQ(0, ecdsa_sign_digest(&secp256k1, TEST_PRIV, digest,
                                 original.lut_signature.bytes, NULL, NULL));

  /* Independently encoded base58 of 32 bytes of 0x51. */
  const char account[] = "6URwbPipuA4MJLG7LCRRZuWnms3JZ9cRG3z9indXWz8G";
  const std::vector<std::string> blind_titles = {"Blind Sign", "Solana"};
  const std::vector<std::string> blind_bodies = {
      "Sign unverified Solana transaction? "
      "The device cannot fully verify the contents.",
      "Sign this Solana transaction?"};
  for (int mutation = 0; mutation < 6; ++mutation) {
    SCOPED_TRACE(mutation);
    ASSERT_TRUE(kkconfirm_preload(mutation == 0 ? 4 : 2, 0));
    signed_metadata_clear_signers();
    if (mutation != 5)
      ASSERT_TRUE(signed_metadata_store_signer(
          TEST_KEY_ID, EXPECTED_SLOT3_PUB, TEST_ALIAS, NULL, 0, 0, 0, false));
    SolanaSignTx msg = original;
    if (mutation == 1) msg.raw_tx.bytes[69] ^= 1;
    if (mutation == 2) msg.lut_account[0].bytes[0] ^= 1;
    if (mutation == 3) msg.lut_signature.bytes[0] ^= 1;
    if (mutation == 4) msg.lut_signer_key_id = 256 + TEST_KEY_ID; /* aliases the loaded slot */
    kkconfirm_capture_start();
    fsm_test_clearLastFailure();
    fsm_msgSolanaSignTx(&msg);
    const auto bodies = kkconfirm_capture_finish();
    const auto titles = kkconfirm_captured_titles();
    EXPECT_EQ(0, fsm_test_lastFailureCode()) << fsm_test_lastFailureMessage();
    SolanaSignedTx response = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_SolanaSignedTx,
                                       SolanaSignedTx_fields, &response));
    EXPECT_EQ(64u, response.signature.size);
    EXPECT_EQ(0, kkconfirm_drain());
    if (mutation == 0) {
      ASSERT_EQ(4u, bodies.size());
      EXPECT_EQ((std::vector<std::string>{"Lookup Accounts", "Lookup Account",
                                          "Blind Sign", "Solana"}),
                titles);
      EXPECT_NE(std::string::npos, bodies[0].find(TEST_ALIAS));
      EXPECT_NE(std::string::npos, bodies[0].find("NOT verified by KeepKey."));
      EXPECT_EQ(std::string("1/1\n") + account, bodies[1]);
      EXPECT_EQ(blind_bodies[0], bodies[2]);
      EXPECT_EQ(blind_bodies[1], bodies[3]);
    } else {
      EXPECT_EQ(blind_titles, titles);
      EXPECT_EQ(blind_bodies, bodies);
    }
  }
}

/* ---- 7.17: real mainnet messages through the handler ---------------------
 * The fee payer (static key 0, also the token authority) is swapped for this
 * seed's key so the device is a signer; every other byte is as on chain. */
std::vector<uint8_t> sol_unhex(const char* hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    unsigned v = 0;
    sscanf(hex + i, "%2x", &v);
    out.push_back((uint8_t)v);
  }
  return out;
}

std::string sol_b58(const uint8_t* key) {
  char out[64];
  size_t len = sizeof(out);
  return b58enc(out, &len, key, 32) ? std::string(out) : std::string();
}

SolanaSignTx real_solana_request(const char* hex, size_t payer_offset,
                                 std::string* payer_b58) {
  const uint32_t path[4] = {0x80000000u | 44, 0x80000000u | 501, 0x80000000u,
                            0x80000000u};
  uint8_t seed[64];
  mnemonic_to_seed("all all all all all all all all all all all all", "", seed,
                   NULL);
  HDNode node;
  hdnode_from_seed(seed, sizeof(seed), ED25519_NAME, &node);
  for (uint32_t i : path) hdnode_private_ckd(&node, i);
  hdnode_fill_public_key(&node);
  std::vector<uint8_t> raw = sol_unhex(hex);
  memcpy(raw.data() + payer_offset, node.public_key + 1, 32);
  *payer_b58 = sol_b58(node.public_key + 1);
  SolanaSignTx msg = {};
  msg.address_n_count = 4;
  memcpy(msg.address_n, path, sizeof(path));
  msg.has_raw_tx = true;
  msg.raw_tx.size = raw.size();
  memcpy(msg.raw_tx.bytes, raw.data(), raw.size());
  return msg;
}

void add_jupiter_lookup_accounts(SolanaSignTx* msg) {
  msg->lut_account_count = 0;
  for (const char* hex : kJupiterSolUsdcLoaded) {
    const std::vector<uint8_t> k = sol_unhex(hex);
    msg->lut_account[msg->lut_account_count].size = 32;
    memcpy(msg->lut_account[msg->lut_account_count++].bytes, k.data(), 32);
  }
}

const char kLutMark[] = "[from lookup table, not verified by KeepKey]\n";

/* Pages split a body by characters, so a host-resolved key can run onto the
 * next page. The mark comes first: wherever the key starts, the mark sits
 * right above it on that page, and the pages read mark, then key. */
void expect_marked_first(const std::vector<std::string>& bodies,
                         const std::string& key) {
  std::string all;
  for (const std::string& b : bodies) all += b;
  EXPECT_NE(std::string::npos, all.find(kLutMark + key)) << all;
  const std::string head = key.substr(0, 8);
  bool seen = false;
  for (const std::string& b : bodies) {
    for (size_t p = b.find(head); p != std::string::npos;
         p = b.find(head, p + 1)) {
      seen = true;
      EXPECT_TRUE(p >= strlen(kLutMark) &&
                  b.compare(p - strlen(kLutMark), strlen(kLutMark),
                            kLutMark) == 0)
          << "unmarked on its page:\n" << b;
    }
  }
  EXPECT_TRUE(seen) << key;
}

/* Real Jupiter v0 swap with the host's lookup keys: decoded, table keys marked,
 * then the blind-sign warning. Without them it is the bare blind sign. */
TEST_F(SolanaSchemaSignTest, RealJupiterSwapShowsHostLookupAccountsMarked) {
  std::string me;
  /* v0 prefix + 3-byte header + 1-byte key count, then key 0. */
  const SolanaSignTx base = real_solana_request(kJupiterSolUsdcV0Hex, 5, &me);
  const std::string wsol = "So11111111111111111111111111111111111111112";
  const std::string usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  const std::string wsol_acct = "8z4aRG7g8AhKwEGgq2gXznpdqTk9q4uQe8PL8X6KzcCU";

  SolanaSignTx msg = base;
  add_jupiter_lookup_accounts(&msg);
  ASSERT_EQ(41u, msg.lut_account_count);
  /* Heading, 15 instruction screens (the marked USDC mint takes two pages),
   * fee payer, max fee, blind sign, final. */
  ASSERT_TRUE(kkconfirm_preload(20, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgSolanaSignTx(&msg);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  EXPECT_EQ(0, fsm_test_lastFailureCode()) << fsm_test_lastFailureMessage();
  SolanaSignedTx response = {};
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_SolanaSignedTx,
                                     SolanaSignedTx_fields, &response));
  EXPECT_EQ(64u, response.signature.size);
  EXPECT_EQ(0, kkconfirm_drain());
  std::string shown;
  for (size_t i = 0; i < bodies.size(); i++) {
    shown += titles[i] + "|" + bodies[i] + "\n";
  }
  ASSERT_FALSE(titles.empty());
  EXPECT_EQ("Lookup Accounts", titles.front());
  EXPECT_EQ("Host supplied 41 lookup table account(s). NOT verified by KeepKey.",
            bodies.front());
  EXPECT_EQ("Blind Sign", titles[titles.size() - 2]);
  EXPECT_EQ("Solana", titles.back());
  /* Both mints come from the tables: shown, each marked before the key. */
  expect_marked_first(bodies, wsol);
  /* The 44-char USDC mint pages: its first page opens with the mark. */
  expect_marked_first(bodies, usdc);
  bool usdc_paged = false;
  for (size_t i = 0; i + 1 < bodies.size(); i++) {
    if (titles[i] == "Instr 6/8 1/2") {
      EXPECT_EQ(0u, bodies[i].find(std::string("Token mint\n") + kLutMark +
                                   usdc.substr(0, 8)))
          << bodies[i];
      EXPECT_EQ("Instr 6/8 2/2", titles[i + 1]);
      usdc_paged = true;
    }
  }
  EXPECT_TRUE(usdc_paged) << shown;
  std::string all;
  for (const std::string& b : bodies) all += b;
  EXPECT_EQ(std::string::npos, all.find(kLutMark + wsol_acct)) << shown;
  EXPECT_EQ(std::string::npos, all.find(kLutMark + me)) << shown;
  EXPECT_EQ(20u, titles.size()) << shown;
  EXPECT_NE(std::string::npos, shown.find("Send 0.039272743 SOL to " + wsol_acct))
      << shown;
  EXPECT_NE(std::string::npos,
            shown.find("Unknown instruction to program "
                       "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"))
      << shown;
  EXPECT_NE(std::string::npos, shown.find("send balance to\n" + me)) << shown;

  /* Control: the same message with no keys is today's bare blind sign. */
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  SolanaSignTx bare = base;
  fsm_msgSolanaSignTx(&bare);
  (void)kkconfirm_capture_finish();
  EXPECT_EQ((std::vector<std::string>{"Blind Sign", "Solana"}),
            kkconfirm_captured_titles());
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_SolanaSignedTx,
                                     SolanaSignedTx_fields, &response));
  EXPECT_EQ(0, kkconfirm_drain());
}

/* The host's keys never lift the AdvancedMode gate, and a list that does not
 * match the signed indexes (or rides beside a schema) is refused unsigned. */
TEST_F(SolanaSchemaSignTest, HostLookupAccountsAreRefusedNotTrusted) {
  std::string me;
  SolanaSignTx good = real_solana_request(kJupiterSolUsdcV0Hex, 5, &me);
  add_jupiter_lookup_accounts(&good);
  struct Leg {
    const char* name;
    bool advanced;
    int mutate;
    FailureType want;
    const char* text;
  };
  const Leg legs[] = {
      {"AdvancedMode off", false, 0, FailureType_Failure_Other,
       "Enable AdvancedMode to blind-sign"},
      {"one key short", true, 1, FailureType_Failure_SyntaxError,
       "Lookup accounts do not match transaction"},
      {"short key", true, 2, FailureType_Failure_SyntaxError,
       "Lookup accounts do not match transaction"},
      {"beside a runtime schema", true, 3, FailureType_Failure_SyntaxError,
       "Unverified lookup accounts cannot back a schema"},
      /* Refused before the non-standard path warning, like malformed bytes. */
      {"one key short, non-standard path", true, 4,
       FailureType_Failure_SyntaxError,
       "Lookup accounts do not match transaction"},
  };
  for (const Leg& leg : legs) {
    SCOPED_TRACE(leg.name);
    ASSERT_TRUE(storage_setPolicy("AdvancedMode", leg.advanced));
    SolanaSignTx msg = good;
    if (leg.mutate == 1 || leg.mutate == 4) msg.lut_account_count--;
    if (leg.mutate == 4) {
      msg.address_n_count = 5; /* m/44'/501'/0'/0'/0' */
      msg.address_n[4] = 0x80000000u;
    }
    if (leg.mutate == 2) msg.lut_account[7].size = 31;
    if (leg.mutate == 3) {
      msg.has_schema_payload = true;
      msg.schema_payload.size = 1;
    }
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    kkconfirm_capture_start();
    fsm_test_clearLastFailure();
    fsm_msgSolanaSignTx(&msg);
    EXPECT_TRUE(kkconfirm_capture_finish().empty()) << "a screen ran";
    EXPECT_EQ(leg.want, fsm_test_lastFailureCode());
    EXPECT_STREQ(leg.text, fsm_test_lastFailureMessage());
    EXPECT_EQ(2, kkconfirm_drain()) << "a screen ran before the refusal";
  }
}

/* A mint the host resolved is not the signed one: even USDC's address gets no
 * symbol, and the amount is shown in plain tokens beside the marked mint. */
TEST_F(SolanaSchemaSignTest, HostResolvedMintGetsNoSymbol) {
  std::string me;
  /* v0: [device, source, destination, SPL Token]; TransferChecked with the
   * mint at loaded index 4 (one readonly lookup entry). */
  std::vector<uint8_t> raw = {0x80, 1, 0, 1, 4};
  raw.insert(raw.end(), 32, 0x00); /* replaced by the device key below */
  raw.insert(raw.end(), 32, 0x31);
  raw.insert(raw.end(), 32, 0x32);
  raw.insert(raw.end(), SOL_TOKEN_PROGRAM, SOL_TOKEN_PROGRAM + 32);
  raw.insert(raw.end(), 32, 0xBB);
  raw.insert(raw.end(), {1, 3, 4, 1, 4, 2, 0, 10, 12});
  raw.insert(raw.end(), {0x40, 0x42, 0x0F, 0, 0, 0, 0, 0, 6});
  raw.insert(raw.end(), {1});
  raw.insert(raw.end(), 32, 0x55);
  raw.insert(raw.end(), {0, 1, 0});
  std::string hex;
  for (uint8_t b : raw) {
    char h[3];
    snprintf(h, sizeof(h), "%02x", b);
    hex += h;
  }
  SolanaSignTx msg = real_solana_request(hex.c_str(), 5, &me);
  const std::string usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  const std::vector<uint8_t> usdc_key = sol_unhex(
      "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61");
  msg.lut_account_count = 1;
  msg.lut_account[0].size = 32;
  memcpy(msg.lut_account[0].bytes, usdc_key.data(), 32);

  ASSERT_TRUE(kkconfirm_preload(7, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgSolanaSignTx(&msg);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  EXPECT_EQ(0, fsm_test_lastFailureCode()) << fsm_test_lastFailureMessage();
  SolanaSignedTx response = {};
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_SolanaSignedTx,
                                     SolanaSignedTx_fields, &response));
  EXPECT_EQ(0, kkconfirm_drain());
  std::string shown;
  for (size_t i = 0; i < bodies.size(); i++)
    shown += titles[i] + "|" + bodies[i] + "\n";
  EXPECT_EQ(7u, titles.size()) << shown;
  EXPECT_EQ(std::string::npos, shown.find("Known token")) << shown;
  EXPECT_EQ(std::string::npos, shown.find("USDC")) << shown;
  expect_marked_first(bodies, usdc);
  EXPECT_EQ(std::string::npos, shown.find("Verified recipient owner")) << shown;
  EXPECT_NE(std::string::npos, shown.find("Send 1 tokens to ")) << shown;
  EXPECT_EQ("Blind Sign", titles[titles.size() - 2]);
}

/* A destination the host resolved is not the signed one: an owner whose
 * associated account it is gets no "Verified recipient owner", and the
 * destination is shown marked. */
TEST_F(SolanaSchemaSignTest, HostResolvedDestinationGetsNoRecipientOwner) {
  std::string me;
  const std::vector<uint8_t> usdc_key = sol_unhex(
      "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61");
  uint8_t owner[32];
  memset(owner, 0x77, sizeof(owner));
  uint8_t ata[32];
  ASSERT_TRUE(solana_deriveAssociatedTokenAddress(owner, SOL_TOKEN_PROGRAM,
                                                  usdc_key.data(), ata));
  /* v0: [device, source, USDC mint, SPL Token]; TransferChecked of 1 USDC to
   * loaded index 4 (one writable lookup entry). */
  std::vector<uint8_t> raw = {0x80, 1, 0, 2, 4};
  raw.insert(raw.end(), 32, 0x00); /* replaced by the device key below */
  raw.insert(raw.end(), 32, 0x31);
  raw.insert(raw.end(), usdc_key.begin(), usdc_key.end());
  raw.insert(raw.end(), SOL_TOKEN_PROGRAM, SOL_TOKEN_PROGRAM + 32);
  raw.insert(raw.end(), 32, 0xBB);
  raw.insert(raw.end(), {1, 3, 4, 1, 2, 4, 0, 10, 12});
  raw.insert(raw.end(), {0x40, 0x42, 0x0F, 0, 0, 0, 0, 0, 6});
  raw.insert(raw.end(), {1});
  raw.insert(raw.end(), 32, 0x55);
  raw.insert(raw.end(), {1, 0, 0});
  std::string hex;
  for (uint8_t b : raw) {
    char h[3];
    snprintf(h, sizeof(h), "%02x", b);
    hex += h;
  }
  SolanaSignTx msg = real_solana_request(hex.c_str(), 5, &me);
  msg.lut_account_count = 1;
  msg.lut_account[0].size = 32;
  memcpy(msg.lut_account[0].bytes, ata, 32);
  msg.token_recipient_owner_count = 1;
  msg.token_recipient_owner[0].size = 32;
  memcpy(msg.token_recipient_owner[0].bytes, owner, 32);

  /* Heading, from, known mint, owner warning, send (2 pages), blind, final. */
  const size_t SCREENS = 8;
  ASSERT_TRUE(kkconfirm_preload(SCREENS, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgSolanaSignTx(&msg);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  EXPECT_EQ(0, fsm_test_lastFailureCode()) << fsm_test_lastFailureMessage();
  SolanaSignedTx response = {};
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_SolanaSignedTx,
                                     SolanaSignedTx_fields, &response));
  EXPECT_EQ(0, kkconfirm_drain());
  std::string shown;
  for (size_t i = 0; i < bodies.size(); i++)
    shown += titles[i] + "|" + bodies[i] + "\n";
  EXPECT_EQ(SCREENS, titles.size()) << shown;
  EXPECT_EQ(std::string::npos, shown.find("Verified recipient owner"))
      << shown;
  EXPECT_EQ(std::string::npos, shown.find(sol_b58(owner))) << shown;
  EXPECT_NE(std::string::npos,
            shown.find("Recipient owner does not match signed token account."))
      << shown;
  expect_marked_first(bodies, sol_b58(ata));
  EXPECT_EQ("Blind Sign", titles[titles.size() - 2]);
}

/* Real PYUSD transfer: verified, no AdvancedMode needed. */
TEST_F(SolanaSchemaSignTest, RealPyusdTransferIsClearSigned) {
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  std::string me;
  /* Legacy: 3-byte header + 1-byte key count, then key 0. */
  SolanaSignTx msg = real_solana_request(kPyusdTransferHex, 4, &me);
  /* 2 compute budget, 3 account create, 3 transfer, 2 fee, final. */
  ASSERT_TRUE(kkconfirm_preload(11, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgSolanaSignTx(&msg);
  const std::vector<std::string> bodies = kkconfirm_capture_finish();
  const std::vector<std::string> titles = kkconfirm_captured_titles();
  EXPECT_EQ(0, fsm_test_lastFailureCode()) << fsm_test_lastFailureMessage();
  SolanaSignedTx response = {};
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_SolanaSignedTx,
                                     SolanaSignedTx_fields, &response));
  EXPECT_EQ(0, kkconfirm_drain());
  std::string shown;
  for (size_t i = 0; i < bodies.size(); i++)
    shown += titles[i] + "|" + bodies[i] + "\n";
  EXPECT_EQ(std::string::npos, shown.find("Blind Sign")) << shown;
  EXPECT_NE(std::string::npos,
            shown.find("Token mint\n2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"))
      << shown;
  EXPECT_NE(std::string::npos,
            shown.find("Transfer from Token-2022 account\n"
                       "8b3GTFQQAVdz1r949JZPG1eVMfaAULCHnbkAmw1wv12f"))
      << shown;
  EXPECT_NE(std::string::npos,
            shown.find("Send 605446.589474 tokens to "
                       "D3g4DtwKPKSq4dab4w2DBDWLRabKXf47W8cZvwdGjWzA?"))
      << shown;
  EXPECT_NE(std::string::npos,
            shown.find("Create token account\n"
                       "D3g4DtwKPKSq4dab4w2DBDWLRabKXf47W8cZvwdGjWzA"))
      << shown;
  EXPECT_EQ("Solana", titles.back());
  EXPECT_EQ(11u, titles.size()) << shown;
}

}  // namespace

/* ---- 7.16 certified (v3) envelopes: fail closed (SRS R-1.2, R-1.4) -------
 *
 * The test installs its own root and mints certificates exactly as the
 * ceremony does (root signs the EIP-712 digest of cert[0..74]). The delegate is
 * TEST_PRIV, so sign_body() produces the inner description it vouches for. */
namespace {

const uint8_t CERT_ROOT_PRIV[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11};

std::vector<uint8_t> mint_cert(uint32_t scope, uint8_t flags,
                               const uint8_t delegate_pub[33]) {
  return rootCert(CERT_ROOT_PRIV, delegate_pub, flags, scope, 1818806400u,
                  "Test Delegate");
}

std::vector<uint8_t> envelope(const std::vector<uint8_t>& cert,
                              const std::vector<uint8_t>& inner) {
  std::vector<uint8_t> e(1, METADATA_VERSION_CERTIFIED);
  e.insert(e.end(), cert.begin(), cert.end());
  e.insert(e.end(), inner.begin(), inner.end());
  return e;
}

class CertifiedMetadataTest : public SignedMetadataTest {
 protected:
  uint8_t root_pub[33];
  void SetUp() override {
    SignedMetadataTest::SetUp();
    ecdsa_get_public_key33(&secp256k1, CERT_ROOT_PRIV, root_pub);
    clearsign_root_set_test_root(root_pub);
  }
  void TearDown() override {
    clearsign_root_set_test_root(NULL);
    SignedMetadataTest::TearDown();
  }
  MetadataClassification Process(const std::vector<uint8_t>& e) {
    return signed_metadata_process(e.data(), e.size(),
                                   METADATA_KEYID_DELEGATE);
  }
  void ExpectRefusedButClaimed(const std::vector<uint8_t>& e) {
    EXPECT_EQ(METADATA_MALFORMED, Process(e));
    EXPECT_FALSE(signed_metadata_available());
    EXPECT_FALSE(signed_metadata_may_suppress(1));
    EXPECT_TRUE(signed_metadata_certified_claimed())
        << "a failed certified claim must stay visible to SignTx";
  }
};

}  // namespace

TEST_F(CertifiedMetadataTest, VerifiedDescriptionMaySuppressOnlyOnItsChain) {
  auto e = envelope(mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                              EXPECTED_SLOT3_PUB),
                    v2_base_blob());
  EXPECT_EQ(METADATA_VERIFIED, Process(e));
  EXPECT_TRUE(signed_metadata_available());
  EXPECT_TRUE(signed_metadata_certified_claimed());
  EXPECT_TRUE(signed_metadata_may_suppress(1));
  EXPECT_FALSE(signed_metadata_may_suppress(137));
  EXPECT_STREQ("Test Delegate", signed_metadata_delegate_alias());
}

TEST_F(CertifiedMetadataTest, ScopeMustEqualTheDescribedChain) {
  V2Spec other_chain = v2_base_spec();
  other_chain.chain_id = 137;
  ExpectRefusedButClaimed(envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_v2_body(other_chain))));
}

/* EVM chain ids and non-EVM scopes share one number space: a Solana-scoped
 * certificate must not certify an EVM description on chain 501. */
TEST_F(CertifiedMetadataTest, NonEvmScopeNeverCertifiesAnEvmChain) {
  V2Spec chain_501 = v2_base_spec();
  chain_501.chain_id = CLEARSIGN_SCOPE_SOLANA;
  ExpectRefusedButClaimed(envelope(mint_cert(CLEARSIGN_SCOPE_SOLANA,
                                             CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                                             EXPECTED_SLOT3_PUB),
                                   sign_body(build_v2_body(chain_501))));
}

TEST_F(CertifiedMetadataTest, CertificateWithoutMaySuppressIsRefused) {
  ExpectRefusedButClaimed(
      envelope(mint_cert(1, 0, EXPECTED_SLOT3_PUB), v2_base_blob()));
}

TEST_F(CertifiedMetadataTest, DescriptionSignedByAnotherKeyIsRefused) {
  uint8_t other_pub[33];
  ecdsa_get_public_key33(&secp256k1, CERT_ROOT_PRIV, other_pub);
  ExpectRefusedButClaimed(envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, other_pub),
      v2_base_blob()));
}

TEST_F(CertifiedMetadataTest, SignerSuppliedV1ValuesAreRefused) {
  ExpectRefusedButClaimed(envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      base_blob()));
}

TEST_F(CertifiedMetadataTest, ClearEndsTheClaimAndRuntimeNeverMakesOne) {
  ExpectRefusedButClaimed(
      envelope(mint_cert(1, 0, EXPECTED_SLOT3_PUB), v2_base_blob()));
  signed_metadata_clear();
  EXPECT_FALSE(signed_metadata_certified_claimed());

  set_advanced_mode_for_test(true);
  std::vector<uint8_t> runtime = base_blob();
  signed_metadata_process(runtime.data(), runtime.size(), TEST_KEY_ID);
  EXPECT_FALSE(signed_metadata_certified_claimed());
  set_advanced_mode_for_test(false);
}

/* ---- v0x05: roles + intent (SRS-7.16 §3.7) ---- */

namespace {
struct IntentSpec {
  V2Spec v2;
  std::vector<uint8_t> roles; /* one per arg */
  uint8_t value_role;
  std::string title, intent;
};

std::vector<uint8_t> build_intent_body(const IntentSpec& s) {
  std::vector<uint8_t> b;
  put_u8(b, METADATA_VERSION_SCHEMA_INTENT);
  put_be32(b, s.v2.chain_id);
  put_bytes(b, s.v2.contract.data(), s.v2.contract.size());
  put_bytes(b, s.v2.selector.data(), s.v2.selector.size());
  put_be16(b, (uint16_t)s.v2.method.size());
  put_bytes(b, (const uint8_t*)s.v2.method.data(), s.v2.method.size());
  put_u8(b, (uint8_t)s.v2.args.size());
  for (size_t i = 0; i < s.v2.args.size(); i++) {
    const V2Arg& a = s.v2.args[i];
    put_u8(b, (uint8_t)a.name.size());
    put_bytes(b, (const uint8_t*)a.name.data(), a.name.size());
    put_u8(b, a.format);
    if (a.format == ARG_FORMAT_TOKEN_AMOUNT) {
      put_u8(b, a.decimals);
      put_u8(b, (uint8_t)a.symbol.size());
      put_bytes(b, (const uint8_t*)a.symbol.data(), a.symbol.size());
    }
    if (a.format == ARG_FORMAT_ADDRESS_PINNED) {
      put_bytes(b, a.pinned.data(), a.pinned.size());
    }
    put_u8(b, s.roles[i]);
  }
  put_u8(b, s.value_role);
  put_u8(b, (uint8_t)s.title.size());
  put_bytes(b, (const uint8_t*)s.title.data(), s.title.size());
  put_u8(b, (uint8_t)s.intent.size());
  put_bytes(b, (const uint8_t*)s.intent.data(), s.intent.size());
  put_u8(b, s.v2.classification);
  put_be32(b, 0);
  put_u8(b, s.v2.key_id);
  return b;
}

/* Relay depositNative on mainnet, as the catalog will describe it. */
IntentSpec relay_intent() {
  static const uint8_t ROUTER[20] = {0x4c, 0xd0, 0x0e, 0x38, 0x76, 0x22, 0xc3,
                                     0x5b, 0xdd, 0xb9, 0xb4, 0xc9, 0x62, 0xc1,
                                     0x36, 0x46, 0x23, 0x38, 0xbc, 0x31};
  static const uint8_t SEL[4] = {0x49, 0x29, 0x0c, 0x1c};
  IntentSpec s;
  s.v2 = v2_base_spec();
  s.v2.contract.assign(ROUTER, ROUTER + 20);
  s.v2.selector.assign(SEL, SEL + 4);
  s.v2.method = "bridgeDeposit";
  s.v2.args.clear();
  s.v2.args.push_back(v2_addr("depositor"));
  s.v2.args.push_back(V2Arg{"orderId", ARG_FORMAT_BYTES, 0, "", {}});
  s.roles = {METADATA_ROLE_NONE, METADATA_ROLE_NONE};
  s.value_role = METADATA_ROLE_SPEND_EXACT;
  s.title = "Relay";
  s.intent = "Bridge {v} through Relay for {0}; delivery is by Relay";
  return s;
}

struct Shown {
  std::string title, body;
};
bool collect_shown(void* ctx, const char* title, const char* body,
                   const uint8_t* bytes, uint16_t bytes_len) {
  auto* out = static_cast<std::vector<Shown>*>(ctx);
  out->push_back({title, bytes ? std::string(bytes_len, '*') : body});
  return true;
}
}  // namespace

/* Uniswap's first step on any chain: an unlimited approve to Permit2. The
 * pinned spender lets the sentence name the party; the allowance role states
 * the limit as someone else's permission, not as the user's spend. */
TEST_F(SignedMetadataTest, IntentSchemaPermit2ApproveReviewsWhoWhatWhyLimit) {
  static const uint8_t PERMIT2[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4,
                                      0x73, 0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9,
                                      0xf6, 0xb4, 0x3a, 0xc7, 0x8b, 0xa3};
  static const uint8_t SEL_APPROVE[4] = {0x09, 0x5e, 0xa7, 0xb3};
  IntentSpec s;
  s.v2 = v2_base_spec();
  s.v2.selector.assign(SEL_APPROVE, SEL_APPROVE + 4);
  s.v2.method = "approve";
  s.v2.args.clear();
  s.v2.args.push_back(v2_pinned("Spender", PERMIT2, 20));
  s.v2.args.push_back(v2_token("Allowance", 6, "USDC"));
  s.roles = {METADATA_ROLE_NONE, METADATA_ROLE_ALLOWANCE};
  s.value_role = METADATA_ROLE_NONE;
  s.title = "Uniswap";
  s.intent = "Let the Uniswap approval contract spend up to {1} for trades you sign";
  std::vector<uint8_t> blob = sign_body(build_intent_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  std::vector<uint8_t> data(SEL_APPROVE, SEL_APPROVE + 4);
  put_addr_word(data, PERMIT2);
  for (int i = 0; i < 32; i++) data.push_back(0xff);
  EthereumSignTx msg;
  make_v2_msg(&msg, s.v2.contract.data(), data, true, (uint32_t)data.size());
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));

  std::vector<Shown> got;
  ASSERT_TRUE(signed_metadata_build_intent_review(
      signed_metadata_get(), true, "KeepKey Alpha 716", "A9531B9D",
      collect_shown, &got));
  ASSERT_GE(got.size(), 3u);
  EXPECT_EQ(got[0].title, "Uniswap");
  EXPECT_EQ(got[0].body,
            "Let the Uniswap approval contract spend up to UNLIMITED USDC for "
            "trades you sign");
  EXPECT_EQ(got[1].title, "Limits");
  EXPECT_EQ(got[1].body, "Can spend up to\nUNLIMITED USDC");
  char permit2[43] = "0x";
  ethereum_address_checksum(PERMIT2, permit2 + 2, false, 1);
  bool spender_shown = false;
  for (const Shown& sh : got) {
    if (sh.title == "Spender" && sh.body == permit2) spender_shown = true;
  }
  EXPECT_TRUE(spender_shown);  // the full address is never hidden

  // Role 7 does not exist: the schema is refused, not reinterpreted.
  s.roles[1] = 7;
  blob = sign_body(build_intent_body(s));
  EXPECT_NE(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
}

/* ERC-7730's threshold: a token amount of 2^255 or more reads UNLIMITED;
 * 2^255 - 1 is shown exactly, never as unlimited. */
TEST_F(SignedMetadataTest, TokenAmountIsUnlimitedFromTwoToThe255) {
  static const uint8_t PERMIT2[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4,
                                      0x73, 0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9,
                                      0xf6, 0xb4, 0x3a, 0xc7, 0x8b, 0xa3};
  static const uint8_t SEL_APPROVE[4] = {0x09, 0x5e, 0xa7, 0xb3};
  IntentSpec s;
  s.v2 = v2_base_spec();
  s.v2.selector.assign(SEL_APPROVE, SEL_APPROVE + 4);
  s.v2.method = "approve";
  s.v2.args.clear();
  s.v2.args.push_back(v2_pinned("Spender", PERMIT2, 20));
  s.v2.args.push_back(v2_token("Allowance", 6, "USDC"));
  s.roles = {METADATA_ROLE_NONE, METADATA_ROLE_ALLOWANCE};
  s.value_role = METADATA_ROLE_NONE;
  s.title = "Uniswap";
  s.intent = "Let the Uniswap approval contract spend up to {1} for trades you sign";
  const struct {
    uint8_t top, rest;
    const char* limit;
  } cases[] = {
      {0x80, 0x00, "Can spend up to\nUNLIMITED USDC"},
      {0x7f, 0xff,
       "Can spend up to\n57896044618658097711785492504343953926634992332820282"
       "019728792003956564.819967 USDC"},
  };
  for (const auto& c : cases) {
    std::vector<uint8_t> blob = sign_body(build_intent_body(s));
    ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
              METADATA_VERIFIED);
    std::vector<uint8_t> data(SEL_APPROVE, SEL_APPROVE + 4);
    put_addr_word(data, PERMIT2);
    data.push_back(c.top);
    for (int i = 1; i < 32; i++) data.push_back(c.rest);
    EthereumSignTx msg;
    make_v2_msg(&msg, s.v2.contract.data(), data, true, (uint32_t)data.size());
    ASSERT_TRUE(signed_metadata_matches_tx(&msg));
    std::vector<Shown> got;
    ASSERT_TRUE(signed_metadata_build_intent_review(
        signed_metadata_get(), true, "KeepKey Alpha 716", "A9531B9D",
        collect_shown, &got));
    ASSERT_GE(got.size(), 2u);
    EXPECT_EQ(got[1].body, c.limit);
  }
}

TEST_F(SignedMetadataTest, IntentSchemaRelayDepositReviewsWhoWhatWhyLimits) {
  IntentSpec s = relay_intent();
  std::vector<uint8_t> blob = sign_body(build_intent_body(s));
  ASSERT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);

  static const uint8_t DEPOSITOR[20] = {
      0x90, 0x9e, 0xf6, 0xb3, 0x2d, 0xfd, 0xc1, 0x2c, 0xa8, 0x6a,
      0xa7, 0x10, 0xb5, 0x4c, 0x99, 0x1a, 0xf3, 0xc5, 0xf8, 0x2e};
  std::vector<uint8_t> data(s.v2.selector.begin(), s.v2.selector.end());
  put_addr_word(data, DEPOSITOR);
  for (int i = 0; i < 32; i++) data.push_back((uint8_t)i);
  EthereumSignTx msg;
  make_v2_msg(&msg, s.v2.contract.data(), data, true, (uint32_t)data.size());
  const uint8_t VALUE[] = {0x1c, 0x61, 0x0b, 0x2e,
                           0x77, 0x40, 0x00};  // 0.007988 ETH
  msg.has_value = true;
  msg.value.size = sizeof(VALUE);
  memcpy(msg.value.bytes, VALUE, sizeof(VALUE));
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  // The value has a role, so the Limits screen states it: no extra screen.
  EXPECT_FALSE(signed_metadata_schema_moves_value());

  const SignedMetadata* md = signed_metadata_get();
  ASSERT_NE(md, nullptr);
  std::vector<Shown> got;
  ASSERT_TRUE(signed_metadata_build_intent_review(
      md, true, "KeepKey Vault", "A9531B9D", collect_shown, &got));
  char depositor[43] = "0x", router[43] = "0x";
  ethereum_address_checksum(DEPOSITOR, depositor + 2, false, 1);
  ethereum_address_checksum(s.v2.contract.data(), router + 2, false, 1);
  const std::string short_dep =
      std::string(depositor, 6) + "..." + std::string(depositor + 38);
  ASSERT_EQ(got.size(), 6u);
  EXPECT_EQ(got[0].title, "Relay");
  EXPECT_EQ(got[0].body, "Bridge 0.007988 ETH through Relay for " + short_dep +
                             "; delivery is by Relay");
  EXPECT_EQ(got[1].title, "Limits");
  EXPECT_EQ(got[1].body, "You spend\n0.007988 ETH");
  EXPECT_EQ(got[2].title, "Contract");
  EXPECT_EQ(got[2].body, std::string("bridgeDeposit\n") + router);
  EXPECT_EQ(got[3].title, "depositor");  // shortened in the sentence
  EXPECT_EQ(got[3].body, depositor);
  EXPECT_EQ(got[4].title, "orderId");  // paged bytes
  EXPECT_EQ(got[5].title, "KeepKey ClearSign");
  EXPECT_EQ(got[5].body,
            "Described by KeepKey Vault A9531B9D\n"
            "certified by KeepKey");

  // Runtime tier: heading + limits only; the caller's raw review follows.
  got.clear();
  ASSERT_TRUE(signed_metadata_build_intent_review(md, false, "Acme", "00",
                                                  collect_shown, &got));
  ASSERT_EQ(got.size(), 2u);
  EXPECT_EQ(got[0].title, "Unverified");
  EXPECT_EQ(got[0].body.rfind("Acme (NOT verified by KeepKey) says:\n", 0), 0u);
}

/* Body exactly as the ClearSign server serializes the Relay entry (Vault
 * evm-certified-schema.test.ts pins the same hex), minus its 0x80 key id. */
TEST_F(SignedMetadataTest, IntentSchemaParsesTheServerSerializedRelayBody) {
  std::vector<uint8_t> body = {
      0x05, 0x00, 0x00, 0x00, 0x01, 0x4c, 0xd0, 0x0e, 0x38, 0x76, 0x22, 0xc3,
      0x5b, 0xdd, 0xb9, 0xb4, 0xc9, 0x62, 0xc1, 0x36, 0x46, 0x23, 0x38, 0xbc,
      0x31, 0x49, 0x29, 0x0c, 0x1c, 0x00, 0x0d, 0x62, 0x72, 0x69, 0x64, 0x67,
      0x65, 0x44, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x02, 0x09, 0x64, 0x65,
      0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x01, 0x00, 0x07, 0x6f, 0x72,
      0x64, 0x65, 0x72, 0x49, 0x64, 0x03, 0x00, 0x03, 0x05, 0x52, 0x65, 0x6c,
      0x61, 0x79, 0x36, 0x42, 0x72, 0x69, 0x64, 0x67, 0x65, 0x20, 0x7b, 0x76,
      0x7d, 0x20, 0x74, 0x68, 0x72, 0x6f, 0x75, 0x67, 0x68, 0x20, 0x52, 0x65,
      0x6c, 0x61, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x7b, 0x30, 0x7d, 0x3b,
      0x20, 0x64, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x79, 0x20, 0x69, 0x73,
      0x20, 0x62, 0x79, 0x20, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x01, 0x00, 0x00,
      0x00, 0x00};
  std::vector<uint8_t> ours = build_intent_body(relay_intent());
  ours.pop_back();  // key id
  ASSERT_EQ(body, ours);
  body.push_back(TEST_KEY_ID);
  std::vector<uint8_t> blob = sign_body(body);
  EXPECT_EQ(signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID),
            METADATA_VERIFIED);
}

TEST_F(SignedMetadataTest, IntentSchemaRejectsBadRolesCoverageAndPlaceholders) {
  auto verdict = [&](const IntentSpec& s) {
    std::vector<uint8_t> blob = sign_body(build_intent_body(s));
    return signed_metadata_process(blob.data(), blob.size(), TEST_KEY_ID);
  };
  EXPECT_EQ(verdict(relay_intent()), METADATA_VERIFIED);  // control
  IntentSpec s = relay_intent();
  s.intent = "Bridge through Relay for {0}";  // value has a role, {v} absent
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.value_role = METADATA_ROLE_NONE;  // {v} without a value role
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.intent = "Bridge {v} for {1}";  // BYTES cannot sit in a sentence
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.intent = "Bridge {v} for {0}, about 1 ETH";  // server-written value
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.intent = "{v}{v}{v}{v}";  // 4 x 90 > 280
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.intent = "Bridge {v} for {2}";  // out of range
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.roles = {METADATA_ROLE_SPEND_MAX, METADATA_ROLE_NONE};  // role on address
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  s = relay_intent();
  s.value_role = METADATA_ROLE_RECEIVE_MIN;  // the value is only ever spent
  EXPECT_EQ(verdict(s), METADATA_MALFORMED);
  // A token amount must carry a role and appear in the sentence.
  IntentSpec t = relay_intent();
  t.v2.args.push_back(v2_token("amount", 6, "USDC"));
  t.roles = {METADATA_ROLE_NONE, METADATA_ROLE_NONE, METADATA_ROLE_NONE};
  t.intent = "Bridge {v} for {0} and {2}";
  EXPECT_EQ(verdict(t), METADATA_MALFORMED);
  t.roles[2] = METADATA_ROLE_SPEND_EXACT;
  EXPECT_EQ(verdict(t), METADATA_VERIFIED);
  t.intent = "Bridge {v} for {0}";
  EXPECT_EQ(verdict(t), METADATA_MALFORMED);
}

/* The certified path end to end: envelope accepted, the tx matched, the
 * certified review shown screen by screen, and the ETH amount screen skipped
 * because Limits states msg.value. */
TEST_F(CertifiedMetadataTest, IntentSchemaCertifiedReviewReplacesRawAndValue) {
  IntentSpec s = relay_intent();
  auto e = envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_intent_body(s)));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));
  ASSERT_TRUE(signed_metadata_may_suppress(1));

  static const uint8_t DEPOSITOR[20] = {
      0x90, 0x9e, 0xf6, 0xb3, 0x2d, 0xfd, 0xc1, 0x2c, 0xa8, 0x6a,
      0xa7, 0x10, 0xb5, 0x4c, 0x99, 0x1a, 0xf3, 0xc5, 0xf8, 0x2e};
  std::vector<uint8_t> data(s.v2.selector.begin(), s.v2.selector.end());
  put_addr_word(data, DEPOSITOR);
  for (int i = 0; i < 32; i++) data.push_back((uint8_t)i);
  EthereumSignTx msg;
  make_v2_msg(&msg, s.v2.contract.data(), data, true, (uint32_t)data.size());
  msg.has_value = true;
  msg.value.size = 1;
  msg.value.bytes[0] = 1;
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_FALSE(signed_metadata_schema_moves_value());

  // Summary, Limits, Contract, depositor, orderId (2 pages), Who.
  ASSERT_TRUE(kkconfirm_preload(7, 0));
  EXPECT_TRUE(signed_metadata_confirm());
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(signed_metadata_relied());
}

/* The ETH amount screen is skipped ONLY when Limits states msg.value: a
 * certified 0x05 schema whose value has no role keeps it for a payable call. */
TEST_F(CertifiedMetadataTest, IntentSchemaWithoutValueRoleKeepsTheValueScreen) {
  IntentSpec s = relay_intent();
  s.value_role = METADATA_ROLE_NONE;
  s.intent = "Bridge through Relay for {0}; delivery is by Relay";
  ASSERT_EQ(METADATA_VERIFIED,
            Process(envelope(mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                                       EXPECTED_SLOT3_PUB),
                             sign_body(build_intent_body(s)))));
  static const uint8_t DEPOSITOR[20] = {
      0x90, 0x9e, 0xf6, 0xb3, 0x2d, 0xfd, 0xc1, 0x2c, 0xa8, 0x6a,
      0xa7, 0x10, 0xb5, 0x4c, 0x99, 0x1a, 0xf3, 0xc5, 0xf8, 0x2e};
  std::vector<uint8_t> data(s.v2.selector.begin(), s.v2.selector.end());
  put_addr_word(data, DEPOSITOR);
  for (int i = 0; i < 32; i++) data.push_back((uint8_t)i);
  EthereumSignTx msg;
  make_v2_msg(&msg, s.v2.contract.data(), data, true, (uint32_t)data.size());
  msg.has_value = true;
  msg.value.size = 1;
  msg.value.bytes[0] = 1;
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_TRUE(signed_metadata_schema_moves_value());
}

/* SRS-7.16 R-7.4: a certified approve opens with its summary, which states
 * the allowance as UNLIMITED <symbol>, so ethereum.c's separate warning waits
 * for it. Only the certified tier, on its chain, with the amount word decoded
 * as a token amount, says so. */
TEST_F(CertifiedMetadataTest, CertifiedApproveIntentStatesTheAllowance) {
  static const uint8_t PERMIT2[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4,
                                      0x73, 0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9,
                                      0xf6, 0xb4, 0x3a, 0xc7, 0x8b, 0xa3};
  static const uint8_t SEL_APPROVE[4] = {0x09, 0x5e, 0xa7, 0xb3};
  IntentSpec s;
  s.v2 = v2_base_spec();
  s.v2.selector.assign(SEL_APPROVE, SEL_APPROVE + 4);
  s.v2.method = "approve";
  s.v2.args.clear();
  s.v2.args.push_back(v2_pinned("Spender", PERMIT2, 20));
  s.v2.args.push_back(v2_token("Allowance", 6, "USDC"));
  s.roles = {METADATA_ROLE_NONE, METADATA_ROLE_ALLOWANCE};
  s.value_role = METADATA_ROLE_NONE;
  s.title = "Uniswap";
  s.intent = "Let the Uniswap approval contract spend up to {1}";

  std::vector<uint8_t> data(SEL_APPROVE, SEL_APPROVE + 4);
  put_addr_word(data, PERMIT2);
  for (int i = 0; i < 32; i++) data.push_back(0xff);
  EthereumSignTx msg;
  make_v2_msg(&msg, s.v2.contract.data(), data, true, (uint32_t)data.size());

  std::vector<uint8_t> body = sign_body(build_intent_body(s));
  ASSERT_EQ(METADATA_VERIFIED,
            signed_metadata_process(body.data(), body.size(), TEST_KEY_ID));
  EXPECT_FALSE(signed_metadata_certified_states_allowance(&msg, 1));

  ASSERT_EQ(METADATA_VERIFIED,
            Process(envelope(mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                                       EXPECTED_SLOT3_PUB),
                             body)));
  EXPECT_TRUE(signed_metadata_certified_states_allowance(&msg, 1));
  EXPECT_FALSE(signed_metadata_certified_states_allowance(&msg, 137));

  // A plain amount names no token: the warning stays.
  s.v2.args[1] = V2Arg{"Allowance", ARG_FORMAT_AMOUNT, 0, "", {}};
  ASSERT_EQ(METADATA_VERIFIED,
            Process(envelope(mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                                       EXPECTED_SLOT3_PUB),
                             sign_body(build_intent_body(s)))));
  EXPECT_FALSE(signed_metadata_certified_states_allowance(&msg, 1));
}

/* v0x06: a vouched address name (Permit2 spender). It names, never describes
 * a transaction, and only the KeepKey-certified tier can supply it. */
namespace {
std::vector<uint8_t> name_body(uint32_t chain, const uint8_t addr[20],
                               const std::string& name, uint8_t key_id) {
  std::vector<uint8_t> b;
  put_u8(b, METADATA_VERSION_NAME);
  put_be32(b, chain);
  put_bytes(b, addr, 20);
  put_u8(b, (uint8_t)name.size());
  put_bytes(b, (const uint8_t*)name.data(), name.size());
  put_u8(b, METADATA_VERIFIED);
  put_be32(b, 0);
  put_u8(b, key_id);
  return b;
}
const uint8_t UR_V2[20] = {0x66, 0xa9, 0x89, 0x3c, 0xc0, 0x7d, 0x91,
                           0xd9, 0x56, 0x44, 0xae, 0xdd, 0x05, 0xd0,
                           0x3f, 0x95, 0xe1, 0xdb, 0xa8, 0xaf};
}  // namespace

TEST_F(CertifiedMetadataTest, NameRecordNamesOnlyItsAddressOnItsChain) {
  auto e = envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(name_body(1, UR_V2, "Uniswap Universal Router",
                          METADATA_KEYID_DELEGATE)));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));
  // A name claims no transaction: SignTx must not refuse because of it.
  EXPECT_FALSE(signed_metadata_certified_claimed());

  // It can never describe calldata, even to the named address.
  std::vector<uint8_t> data = v2_transfer_calldata();
  EthereumSignTx msg;
  make_v2_msg(&msg, UR_V2, data, true, (uint32_t)data.size());
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));

  MetadataNameRecord r;
  signed_metadata_take_name(&r);
  ASSERT_TRUE(r.valid);
  EXPECT_EQ(r.chain_id, 1u);
  EXPECT_EQ(memcmp(r.address, UR_V2, 20), 0);
  EXPECT_STREQ(r.name, "Uniswap Universal Router");
  EXPECT_STREQ(r.alias, "Test Delegate");
  EXPECT_EQ(strlen(r.fp8), 8u);
  // Taken once: the next request finds nothing.
  EXPECT_FALSE(signed_metadata_available());
  signed_metadata_take_name(&r);
  EXPECT_FALSE(r.valid);
}

TEST_F(CertifiedMetadataTest, NameRecordScopedToAnotherChainIsRefused) {
  ExpectRefusedButClaimed(envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(name_body(42161, UR_V2, "Uniswap Universal Router",
                          METADATA_KEYID_DELEGATE))));
}

TEST_F(SignedMetadataTest, RuntimeSignerCannotNameAnAddress) {
  std::vector<uint8_t> blob =
      sign_body(name_body(1, UR_V2, "Uniswap Universal Router", TEST_KEY_ID));
  // Refused, not acknowledged as Verified and then silently dropped.
  ExpectMalformed(blob, TEST_KEY_ID);
  MetadataNameRecord r;
  signed_metadata_take_name(&r);
  EXPECT_FALSE(r.valid);
}

/* The exact bytes the ClearSign server serializes for Uniswap's mainnet
 * UniversalRouterV2 (Vault evm-certified-schema.test.ts pins the same hex). */
TEST_F(CertifiedMetadataTest, NameRecordParsesTheServerSerializedBody) {
  const std::vector<uint8_t> body = {
      0x06, 0x00, 0x00, 0x00, 0x01, 0x66, 0xa9, 0x89, 0x3c, 0xc0, 0x7d, 0x91,
      0xd9, 0x56, 0x44, 0xae, 0xdd, 0x05, 0xd0, 0x3f, 0x95, 0xe1, 0xdb, 0xa8,
      0xaf, 0x18, 0x55, 0x6e, 0x69, 0x73, 0x77, 0x61, 0x70, 0x20, 0x55, 0x6e,
      0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6c, 0x20, 0x52, 0x6f, 0x75, 0x74,
      0x65, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80};
  ASSERT_EQ(body, name_body(1, UR_V2, "Uniswap Universal Router",
                            METADATA_KEYID_DELEGATE));
  ASSERT_EQ(METADATA_VERIFIED,
            Process(envelope(mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                                       EXPECTED_SLOT3_PUB),
                             sign_body(body))));
}

/* ---- v0x07: certified Uniswap Universal Router decoder ------------------- */

#include "uniswap_ur_realworld.h"
#include "uniswap_ur_sample.h"
#include "uniswap_ur_v4_routers.h"
#include "uniswap_ur_vectors.h"

namespace {

std::vector<uint8_t> ur_unhex(const std::string& h) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < h.size(); i += 2)
    out.push_back((uint8_t)std::stoul(h.substr(i, 2), nullptr, 16));
  return out;
}

std::string hex_of(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

/* Real Base call 0xd873988f...: PERMIT2_PERMIT + V3_SWAP_EXACT_IN, an
 * unlimited Permit2 allowance on 0x41b4..35ef, swap into Base USDC. */
const urv::Vec& base_permit_swap() {
  for (const auto& v : urv::accepted())
    if (v.tx.rfind("0xd873988f", 0) == 0) return v;
  static urv::Vec none;
  return none;
}

struct UrToken {
  std::string address, symbol;
  uint8_t decimals;
};

std::vector<uint8_t> build_decoder_body(const std::vector<uint8_t>& router,
                                        uint32_t chain,
                                        const std::vector<UrToken>& tokens) {
  std::vector<uint8_t> b;
  put_u8(b, METADATA_VERSION_DECODER);
  put_be32(b, chain);
  put_bytes(b, router.data(), router.size());
  const uint8_t sel[4] = {0x35, 0x93, 0x56, 0x4c};
  put_bytes(b, sel, 4);
  put_be16(b, 7);
  put_bytes(b, (const uint8_t*)"execute", 7);
  put_u8(b, METADATA_DECODER_UNISWAP_UR);
  put_u8(b, 7);
  put_bytes(b, (const uint8_t*)"Uniswap", 7);
  put_u8(b, (uint8_t)tokens.size());
  for (const UrToken& t : tokens) {
    std::vector<uint8_t> a = ur_unhex(t.address);
    put_bytes(b, a.data(), 20);
    put_u8(b, t.decimals);
    put_u8(b, (uint8_t)t.symbol.size());
    put_bytes(b, (const uint8_t*)t.symbol.data(), t.symbol.size());
  }
  put_u8(b, METADATA_VERIFIED);
  put_be32(b, 0);
  put_u8(b, TEST_KEY_ID);
  return b;
}

const std::vector<UrToken> kSwapTokens = {
    {"41b481c3d2e3960f8f312212adfeecf6ce7c35ef", "TOKA", 18},
    {"833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USDC", 6},
};

void make_ur_msg(EthereumSignTx* msg, const std::vector<uint8_t>& router,
                 const std::vector<uint8_t>& data) {
  make_v2_msg(msg, router.data(), data, true, (uint32_t)data.size());
  msg->has_chain_id = true;
  msg->chain_id = 8453;
}

}  // namespace

TEST_F(CertifiedMetadataTest, UniswapSwapReviewsWhoWhatLimitsFromCalldata) {
  const urv::Vec& v = base_permit_swap();
  ASSERT_FALSE(v.calldata.empty());
  std::vector<uint8_t> router = ur_unhex(v.router);
  std::vector<uint8_t> data = ur_unhex(v.calldata);
  auto e = envelope(
      mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(router, 8453, kSwapTokens)));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));

  EthereumSignTx msg;
  make_ur_msg(&msg, router, data);
  ASSERT_TRUE(signed_metadata_matches_tx(&msg));
  EXPECT_TRUE(signed_metadata_may_suppress(8453));
  EXPECT_FALSE(signed_metadata_schema_moves_value());

  std::vector<Shown> got;
  ASSERT_TRUE(signed_metadata_build_ur_review(
      signed_metadata_get(), "Test Delegate", "A9531B9D", collect_shown,
      &got));
  char r[43] = "0x";
  ethereum_address_checksum(router.data(), r + 2, false, 8453);
  std::vector<std::pair<std::string, std::string>> want = {
      {"Uniswap",
       "Swap 366.279323182464682886 TOKA for at least 17.41144 USDC"},
      {"Limits", "You spend\n366.279323182464682886 TOKA"},
      {"Limits", "You receive at least\n17.41144 USDC"},
      {"Allowance",
       "This router may spend up to UNLIMITED TOKA until 2026-11-02 UTC"},
      {"Contract", std::string("execute\n") + r},
      {"KeepKey ClearSign",
       "Described by Test Delegate A9531B9D\ncertified by KeepKey"},
  };
  ASSERT_EQ(got.size(), want.size());
  for (size_t i = 0; i < want.size(); i++) {
    EXPECT_EQ(got[i].title, want[i].first) << i;
    EXPECT_EQ(got[i].body, want[i].second) << i;
  }

  // One changed byte (the swap's minimum) and the entry no longer matches.
  std::vector<uint8_t> other = data;
  other[other.size() - 40] ^= 0x01;
  make_ur_msg(&msg, router, other);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg) &&
               memcmp(signed_metadata_get()->ur.amount_out,
                      ur_unhex(v.steps[1].limit).data(), 32) == 0);
}

TEST_F(CertifiedMetadataTest, UniswapSwapWithoutEveryTokenIdentityIsRefused) {
  const urv::Vec& v = base_permit_swap();
  std::vector<uint8_t> router = ur_unhex(v.router);
  std::vector<uint8_t> data = ur_unhex(v.calldata);
  auto e = envelope(
      mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(router, 8453, {kSwapTokens[1]})));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));
  EthereumSignTx msg;
  make_ur_msg(&msg, router, data);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));
  // The claim stays visible: SignTx refuses rather than blind-signing.
  EXPECT_TRUE(signed_metadata_certified_claimed());
}

/* Ahead of a typed-data request (a Permit2 PermitSingle), a certified 0x07
 * entry lends the review its token identities and names its own contract;
 * only on its own chain and only for the tokens it lists. */
TEST_F(CertifiedMetadataTest, DecoderRecordLendsTokenIdentitiesToTypedData) {
  const std::vector<uint8_t> router =
      ur_unhex("6ff5693b99212da76ad316178a184ab56d299b43");
  const std::vector<UrToken> tokens = {
      {"cbb7c0000ab88b473b1f5afd9ef808440eed33bf", "cbBTC", 8},
      {"833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USDC", 6},
  };
  ASSERT_EQ(METADATA_VERIFIED,
            Process(envelope(mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                                       EXPECTED_SLOT3_PUB),
                             sign_body(build_decoder_body(router, 8453,
                                                          tokens)))));
  MetadataNameRecord r;
  signed_metadata_take_name(&r);
  ASSERT_TRUE(r.valid);
  EXPECT_EQ(r.chain_id, 8453u);
  EXPECT_EQ(memcmp(r.address, router.data(), 20), 0);
  EXPECT_STREQ(r.name, "Uniswap");
  EXPECT_STREQ(r.alias, "Test Delegate");
  ASSERT_EQ(r.num_tokens, 2u);

  const std::vector<uint8_t> cbbtc = ur_unhex(tokens[0].address);
  const MetadataToken* t = signed_metadata_record_token(&r, 8453, cbbtc.data());
  ASSERT_NE(t, nullptr);
  EXPECT_STREQ(t->symbol, "cbBTC");
  EXPECT_EQ(t->decimals, 8);
  // Another chain, or a token the entry does not list: no identity.
  EXPECT_EQ(signed_metadata_record_token(&r, 42161, cbbtc.data()), nullptr);
  std::vector<uint8_t> other = cbbtc;
  other[19] ^= 1;
  EXPECT_EQ(signed_metadata_record_token(&r, 8453, other.data()), nullptr);
  // Taken once.
  signed_metadata_take_name(&r);
  EXPECT_FALSE(r.valid);
  EXPECT_EQ(signed_metadata_record_token(&r, 8453, cbbtc.data()), nullptr);

  // A name record carries no token identities.
  ASSERT_EQ(METADATA_VERIFIED,
            Process(envelope(
                mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW,
                          EXPECTED_SLOT3_PUB),
                sign_body(name_body(8453, router.data(), "Uniswap Router",
                                    METADATA_KEYID_DELEGATE)))));
  signed_metadata_take_name(&r);
  ASSERT_TRUE(r.valid);
  EXPECT_EQ(signed_metadata_record_token(&r, 8453, cbbtc.data()), nullptr);
}

TEST_F(CertifiedMetadataTest, UniswapDecoderEntryIsCertifiedOrNothing) {
  const urv::Vec& v = base_permit_swap();
  std::vector<uint8_t> router = ur_unhex(v.router);
  std::vector<uint8_t> runtime = sign_body(build_decoder_body(router, 8453,
                                                              kSwapTokens));
  set_advanced_mode_for_test(true);
  EXPECT_EQ(METADATA_MALFORMED,
            signed_metadata_process(runtime.data(), runtime.size(),
                                    TEST_KEY_ID));
  set_advanced_mode_for_test(false);
  // A certificate for another chain does not certify Base.
  auto e = envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(router, 8453, kSwapTokens)));
  EXPECT_EQ(METADATA_MALFORMED, Process(e));
}

/* Token -> ETH (permit, swap, unwrap) is 1,028-1,178 B on Base: past the
 * first chunk. The device holds every byte and reviews only after the last
 * one; a prefix never matches. */
namespace {
const urv::Vec* token_to_eth_over_first_chunk() {
  for (const auto& v : urv::accepted()) {
    if (v.calldata.size() / 2 > 1024 && v.steps.size() == 3 &&
        v.steps[0].kind == UR_PERMIT2_PERMIT &&
        v.steps[1].kind == UR_V3_SWAP_EXACT_IN &&
        v.steps[2].kind == UR_UNWRAP_WETH)
      return &v;
  }
  return nullptr;
}

/* SignTx's first chunk: never a match from a prefix, only pending. */
bool defer_first_chunk(const urv::Vec& v, const std::vector<uint8_t>& data,
                       EthereumSignTx* msg) {
  std::vector<uint8_t> router = ur_unhex(v.router);
  std::vector<uint8_t> first(data.begin(), data.begin() + 1024);
  make_ur_msg(msg, router, first);
  msg->data_length = (uint32_t)data.size();
  return !signed_metadata_matches_tx(msg) && signed_metadata_ur_pending();
}
}  // namespace

TEST_F(CertifiedMetadataTest, UniswapTokenToEthIsReviewedAfterTheLastByte) {
  const urv::Vec* v = token_to_eth_over_first_chunk();
  ASSERT_NE(v, nullptr);
  std::vector<uint8_t> data = ur_unhex(v->calldata);
  auto e = envelope(
      mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(ur_unhex(v->router), 8453,
                                   {{v->steps[0].token_in, "TOKA", 6}})));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));

  EthereumSignTx msg;
  ASSERT_TRUE(defer_first_chunk(*v, data, &msg));
  EXPECT_FALSE(signed_metadata_relied());
  ASSERT_TRUE(signed_metadata_ur_feed(data.data() + 1024,
                                      (uint32_t)data.size() - 1024));
  EXPECT_FALSE(signed_metadata_ur_pending());

  const SignedMetadata* md = signed_metadata_get();
  EXPECT_TRUE(md->ur.out_is_eth);
  EXPECT_FALSE(md->ur.in_is_eth);
  EXPECT_EQ(0, memcmp(md->ur.amount_in, ur_unhex(v->steps[1].amount).data(), 32));
  // The floor is the unwrap's minimum, which sits past byte 1024.
  EXPECT_EQ(0, memcmp(md->ur.amount_out, ur_unhex(v->steps[2].amount).data(), 32));
  std::vector<Shown> got;
  ASSERT_TRUE(signed_metadata_build_ur_review(md, "Test Delegate", "A9531B9D",
                                              collect_shown, &got));
  ASSERT_FALSE(got.empty());
  EXPECT_EQ(got[0].title, "Uniswap");
  EXPECT_NE(got[0].body.find(" ETH"), std::string::npos) << got[0].body;
}

TEST_F(CertifiedMetadataTest, UniswapDeferredReviewRefusesShortLongOrTamperedCalls) {
  const urv::Vec* v = token_to_eth_over_first_chunk();
  ASSERT_NE(v, nullptr);
  std::vector<uint8_t> data = ur_unhex(v->calldata);
  auto e = envelope(
      mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(ur_unhex(v->router), 8453,
                                   {{v->steps[0].token_in, "TOKA", 6}})));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));
  EthereumSignTx msg;
  const uint32_t tail = (uint32_t)data.size() - 1024;

  // A byte short: still pending, nothing decoded (SignTx needs every byte).
  ASSERT_TRUE(defer_first_chunk(*v, data, &msg));
  EXPECT_TRUE(signed_metadata_ur_feed(data.data() + 1024, tail - 1));
  EXPECT_TRUE(signed_metadata_ur_pending());
  EXPECT_FALSE(signed_metadata_relied());

  // A byte over.
  ASSERT_TRUE(defer_first_chunk(*v, data, &msg));
  std::vector<uint8_t> more(data.begin() + 1024, data.end());
  more.push_back(0);
  EXPECT_FALSE(signed_metadata_ur_feed(more.data(), (uint32_t)more.size()));
  EXPECT_FALSE(signed_metadata_ur_pending());

  // The tail decides what is shown: a changed unwrap minimum is shown as is.
  std::vector<uint8_t> other = data;
  other[other.size() - 33] ^= 0x01;  // inside the unwrap's amountMin word
  ASSERT_TRUE(defer_first_chunk(*v, other, &msg));
  ASSERT_TRUE(signed_metadata_ur_feed(other.data() + 1024, tail));
  EXPECT_NE(0, memcmp(signed_metadata_get()->ur.amount_out,
                      ur_unhex(v->steps[2].amount).data(), 32));

  // Past the old 1,472-byte buffer: held and decoded, not refused for its
  // length. Bytes after the last input are not read (nor by abi.decode).
  std::vector<uint8_t> big = data;
  big.resize(1473);
  ASSERT_TRUE(defer_first_chunk(*v, big, &msg));
  EXPECT_TRUE(signed_metadata_ur_feed(big.data() + 1024,
                                      (uint32_t)big.size() - 1024));
  EXPECT_FALSE(signed_metadata_ur_pending());

  // A call that fits the first chunk is decoded at once, never pending.
  std::vector<uint8_t> small(data.begin(), data.begin() + 1024);
  make_ur_msg(&msg, ur_unhex(v->router), small);
  EXPECT_FALSE(signed_metadata_matches_tx(&msg));  // truncated: no decode
  EXPECT_FALSE(signed_metadata_ur_pending());
}

/* D-021: a real split-route call past the old 1,472-byte buffer, which the
 * device refused for its length. Streamed in SignTx's chunks it is reviewed
 * like any other. */
TEST_F(CertifiedMetadataTest, UniswapCallPastTheOldBufferIsReviewed) {
  const std::vector<uint8_t> router =
      ur_unhex("d6145b2d3f379919e8cdeda7b97e37c4b2ca9c40");
  const uint8_t zero[32] = {0};
  const urs::Call* call = nullptr;
  UrPlan plan;
  UrSummary want;
  for (const auto& c : urs::calls()) {
    if (c.calldata.size() > 1472 &&
        ur_decode(c.calldata.data(), c.calldata.size(), router.data(), &plan) &&
        ur_summarize(&plan, router.data(), zero, &want)) {
      call = &c;
      break;
    }
  }
  ASSERT_NE(call, nullptr) << "no reviewable call over 1,472 B in the sample";
  const std::vector<uint8_t>& data = call->calldata;
  std::vector<UrToken> tokens;
  if (!want.in_is_eth)
    tokens.push_back({hex_of(want.token_in, 20), "TOKA", 6});
  if (!want.out_is_eth)
    tokens.push_back({hex_of(want.token_out, 20), "TOKB", 18});
  auto e = envelope(
      mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(router, 8453, tokens)));
  ASSERT_EQ(METADATA_VERIFIED, Process(e));

  EthereumSignTx msg;
  std::vector<uint8_t> first(data.begin(), data.begin() + 1024);
  make_ur_msg(&msg, router, first);
  msg.data_length = (uint32_t)data.size();
  ASSERT_FALSE(signed_metadata_matches_tx(&msg));
  ASSERT_TRUE(signed_metadata_ur_pending());
  size_t at = 1024;
  while (data.size() - at > 200) {  // uneven chunks
    ASSERT_TRUE(signed_metadata_ur_feed(data.data() + at, 200)) << call->tx;
    EXPECT_TRUE(signed_metadata_ur_pending());
    at += 200;
  }
  ASSERT_TRUE(signed_metadata_ur_feed(data.data() + at,
                                      (uint32_t)(data.size() - at)))
      << call->tx;
  EXPECT_FALSE(signed_metadata_ur_pending());
  const SignedMetadata* md = signed_metadata_get();
  EXPECT_EQ(0, memcmp(&md->ur, &want, sizeof(want))) << call->tx;
  std::vector<Shown> got;
  ASSERT_TRUE(signed_metadata_build_ur_review(md, "Test Delegate", "A9531B9D",
                                              collect_shown, &got));
  ASSERT_FALSE(got.empty());
  EXPECT_EQ(got[0].title, "Uniswap");
}

/* D-019/D-021: real UR 2.1.2 V4 swaps on Base, a plain one and one through a
 * hooked pool, streamed in 200-byte data chunks after the first 1,024. */
namespace {
void review_v4_call(bool hooked, std::vector<Shown>* got) {
  const std::vector<uint8_t> router =
      ur_unhex("d6145b2d3f379919e8cdeda7b97e37c4b2ca9c40");
  const urs::Call* call = nullptr;
  UrPlan plan;
  UrSummary want;
  for (const auto& c : urs::calls()) {
    bool v4 = false;
    if (c.calldata.size() <= 1024 || !c.ok ||
        !ur_decode(c.calldata.data(), c.calldata.size(), router.data(), &plan))
      continue;
    for (size_t i = 0; i < plan.n; i++)
      v4 = v4 || plan.steps[i].kind == UR_V4_SWAP_EXACT_IN;
    if (v4 && plan.n == 1 && (plan.n_hooks > 0) == hooked &&
        ur_summarize(&plan, router.data(), c.value.data(), &want)) {
      call = &c;
      break;
    }
  }
  ASSERT_NE(call, nullptr);
  const std::vector<uint8_t>& data = call->calldata;
  std::vector<UrToken> tokens;
  if (!want.in_is_eth) tokens.push_back({hex_of(want.token_in, 20), "TOKA", 6});
  if (!want.out_is_eth)
    tokens.push_back({hex_of(want.token_out, 20), "TOKB", 18});
  auto e = envelope(
      mint_cert(8453, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(router, 8453, tokens)));
  ASSERT_EQ(METADATA_VERIFIED, signed_metadata_process(e.data(), e.size(),
                                                       METADATA_KEYID_DELEGATE));
  EthereumSignTx msg;
  std::vector<uint8_t> first(data.begin(), data.begin() + 1024);
  make_ur_msg(&msg, router, first);
  msg.data_length = (uint32_t)data.size();
  msg.value.size = 32;
  memcpy(msg.value.bytes, call->value.data(), 32);
  ASSERT_FALSE(signed_metadata_matches_tx(&msg));
  ASSERT_TRUE(signed_metadata_ur_pending());
  size_t at = 1024;
  while (data.size() - at > 200) {
    ASSERT_TRUE(signed_metadata_ur_feed(data.data() + at, 200)) << call->tx;
    at += 200;
  }
  ASSERT_TRUE(signed_metadata_ur_feed(data.data() + at,
                                      (uint32_t)(data.size() - at)))
      << call->tx;
  EXPECT_FALSE(signed_metadata_ur_pending());
  const SignedMetadata* md = signed_metadata_get();
  EXPECT_EQ(0, memcmp(&md->ur, &want, sizeof(want))) << call->tx;
  ASSERT_TRUE(signed_metadata_build_ur_review(md, "Test Delegate", "A9531B9D",
                                              collect_shown, got));
  printf("%s (%zu B, %s):\n", call->tx.c_str(), data.size(),
         hooked ? "hooked pool" : "plain pool");
  for (const auto& s : *got)
    printf("  [%s] %s\n", s.title.c_str(), s.body.c_str());
}
}  // namespace

TEST_F(CertifiedMetadataTest, UniswapV4SwapIsReviewedFromItsChunks) {
  std::vector<Shown> got;
  review_v4_call(false, &got);
  ASSERT_FALSE(got.empty());
  EXPECT_EQ(got[0].title, "Uniswap");
  for (const auto& s : got) EXPECT_EQ(s.title.find("Pool hook"), std::string::npos);
}

TEST_F(CertifiedMetadataTest, UniswapV4HookIsShown) {
  std::vector<Shown> got;
  review_v4_call(true, &got);
  size_t hooks = 0;
  for (const auto& s : got) hooks += s.title == "Pool hook";
  EXPECT_EQ(hooks, 1u);
}

/* Real V4 swaps to the other listed routers (Ethereum UR 2.0 / 2.1.1 /
 * 2.1.2, Base UR 2.0, Arbitrum UR 2.0 / 2.1.2), each under a certificate for
 * its own chain, streamed in 200-byte chunks after the first 1,024: the
 * device reviews what ur_summarize says, and a certificate for another
 * chain does not make the entry apply. */
TEST_F(CertifiedMetadataTest, UniswapV4OnEveryListedRouterIsReviewedOnItsChain) {
  /* Every screen of the first such call per router, title and full body.
   * TOKA / TOKB are the test's identities (6 and 18 decimals), not the
   * tokens' own. */
  const std::map<std::string, std::vector<std::pair<std::string, std::string>>>
      screens = {
          {"23617e59a5925b2a4bf75d73ff6711cd0b29de85",  // Ethereum UR 2.1.2
           {{"Uniswap",
             "Swap 0.001 ETH for at least 2579.065420826155348709 TOKB"},
            {"Limits", "You spend\n0.001 ETH"},
            {"Limits", "You receive at least\n2579.065420826155348709 TOKB"},
            {"Recipient",
             "Output goes to\n0x5f46E5fF883eA67ea5Cc92E77ED32a90dae27170"},
            {"Contract", "execute\n0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85"},
            {"KeepKey ClearSign",
             "Described by Test Delegate A9531B9D\ncertified by KeepKey"}}},
          {"4c82d1fbfe28c977cbb58d8c7ff8fcf9f70a2cca",  // Ethereum UR 2.1.1
           {{"Uniswap",
             "Swap 0.151916760629316603 ETH for at least "
             "0.000000000305960247 TOKB"},
            {"Limits", "You spend\n0.151916760629316603 ETH"},
            {"Limits", "You receive at least\n0.000000000305960247 TOKB"},
            {"Recipient",
             "Output goes to\n0x909Ef6B32DfDc12CA86aA710b54c991af3C5F82E"},
            {"Contract", "execute\n0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA"},
            {"KeepKey ClearSign",
             "Described by Test Delegate A9531B9D\ncertified by KeepKey"}}},
          {"66a9893cc07d91d95644aedd05d03f95e1dba8af",  // Ethereum UR 2.0
           {{"Uniswap", "Swap 1.3 ETH for at least 0.000000003293705049 TOKB"},
            {"Limits", "You spend\n1.3 ETH"},
            {"Limits", "You receive at least\n0.000000003293705049 TOKB"},
            {"Recipient",
             "Output goes to\n0x141D9959cAe3853b035000490C03991eB70Fc4aC"},
            {"Fee",
             "0.25% of the output to\n"
             "0x000000fee13a103A10D593b9AE06b3e05F2E7E1c"},
            {"Contract", "execute\n0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"},
            {"KeepKey ClearSign",
             "Described by Test Delegate A9531B9D\ncertified by KeepKey"}}},
          {"6ff5693b99212da76ad316178a184ab56d299b43",  // Base UR 2.0
           {{"Uniswap",
             "Swap 10000000000 TOKA for at least 0.000000000008292364 TOKB"},
            {"Limits", "You spend\n10000000000 TOKA"},
            {"Limits", "You receive at least\n0.000000000008292364 TOKB"},
            {"Recipient",
             "Output goes to\n0x141D9959cAe3853b035000490C03991eB70Fc4aC"},
            {"Allowance",
             "This router may spend up to UNLIMITED TOKA until "
             "2026-05-02 UTC"},
            {"Contract", "execute\n0x6fF5693b99212Da76ad316178A184AB56D299b43"},
            {"KeepKey ClearSign",
             "Described by Test Delegate A9531B9D\ncertified by KeepKey"}}},
          {"2d01411773c8c24805306e89a41f7855c3c4fe65",  // Arbitrum UR 2.1.2
           {{"Uniswap",
             "Swap 0.00102 ETH for at least 0.000000000002399249 TOKB"},
            {"Limits", "You spend\n0.00102 ETH"},
            {"Limits", "You receive at least\n0.000000000002399249 TOKB"},
            {"Recipient",
             "Output goes to\n0x3Df0742385a6F0688fB6B12a7C25dC7A9E6aAEbe"},
            {"Contract", "execute\n0x2d01411773c8C24805306E89A41F7855C3c4Fe65"},
            {"KeepKey ClearSign",
             "Described by Test Delegate A9531B9D\ncertified by KeepKey"}}},
          {"a51afafe0263b40edaef0df8781ea9aa03e381a3",  // Arbitrum UR 2.0
           {{"Uniswap",
             "Swap 19.3023 TOKA for at least 2.691975216520974078 TOKB"},
            {"Limits", "You spend\n19.3023 TOKA"},
            {"Limits", "You receive at least\n2.691975216520974078 TOKB"},
            {"Recipient",
             "Output goes to\n0x041e9e88288C0C62B8549C50A759a74a1a65b6b7"},
            {"Contract", "execute\n0xA51afAFe0263b40EdaEf0Df8781eA9aa03E381a3"},
            {"KeepKey ClearSign",
             "Described by Test Delegate A9531B9D\ncertified by KeepKey"}}},
      };
  std::set<std::string> done;
  for (const auto& x : urx::calls()) {
    if (done.count(x.router) || x.calldata.compare(0, 8, "3593564c") != 0)
      continue;
    const std::vector<uint8_t> router = ur_unhex(x.router);
    const std::vector<uint8_t> data = ur_unhex(x.calldata);
    const std::vector<uint8_t> value = ur_unhex(x.value);
    UrPlan plan;
    UrSummary want;
    if (data.size() <= 1024 ||
        !ur_decode(data.data(), data.size(), router.data(), &plan) ||
        !ur_summarize(&plan, router.data(), value.data(), &want))
      continue;
    bool v4 = false;
    for (size_t i = 0; i < plan.n; i++)
      v4 = v4 || plan.steps[i].kind == UR_V4_SWAP_EXACT_IN;
    if (!v4) continue;
    std::vector<UrToken> tokens;
    if (!want.in_is_eth)
      tokens.push_back({hex_of(want.token_in, 20), "TOKA", 6});
    if (!want.out_is_eth)
      tokens.push_back({hex_of(want.token_out, 20), "TOKB", 18});
    for (int other = 0; other < 2; other++) {
      // other: an entry certified for chain 10, sent with this tx's chain.
      const uint32_t chain = other ? 10 : x.chain;
      auto e = envelope(
          mint_cert(chain, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
          sign_body(build_decoder_body(router, chain, tokens)));
      ASSERT_EQ(METADATA_VERIFIED,
                signed_metadata_process(e.data(), e.size(),
                                        METADATA_KEYID_DELEGATE))
          << x.tx;
      EthereumSignTx msg;
      std::vector<uint8_t> first(data.begin(), data.begin() + 1024);
      make_ur_msg(&msg, router, first);
      msg.chain_id = x.chain;
      msg.data_length = (uint32_t)data.size();
      msg.value.size = 32;
      memcpy(msg.value.bytes, value.data(), 32);
      if (other) {
        EXPECT_FALSE(signed_metadata_matches_tx(&msg)) << x.tx;
        EXPECT_FALSE(signed_metadata_ur_pending()) << x.tx;
        continue;
      }
      ASSERT_FALSE(signed_metadata_matches_tx(&msg)) << x.tx;
      ASSERT_TRUE(signed_metadata_ur_pending()) << x.tx;
      size_t at = 1024;
      while (data.size() - at > 200) {
        ASSERT_TRUE(signed_metadata_ur_feed(data.data() + at, 200)) << x.tx;
        at += 200;
      }
      ASSERT_TRUE(signed_metadata_ur_feed(data.data() + at,
                                          (uint32_t)(data.size() - at)))
          << x.tx;
      const SignedMetadata* md = signed_metadata_get();
      EXPECT_EQ(0, memcmp(&md->ur, &want, sizeof(want))) << x.tx;
      std::vector<Shown> got;
      ASSERT_TRUE(signed_metadata_build_ur_review(md, "Test Delegate",
                                                  "A9531B9D", collect_shown,
                                                  &got));
      const auto want_screens = screens.find(x.router);
      ASSERT_NE(want_screens, screens.end()) << x.router;
      ASSERT_EQ(got.size(), want_screens->second.size()) << x.tx;
      for (size_t i = 0; i < got.size(); i++) {
        EXPECT_EQ(got[i].title, want_screens->second[i].first)
            << x.tx << " " << i;
        EXPECT_EQ(got[i].body, want_screens->second[i].second)
            << x.tx << " " << i;
      }
    }
    done.insert(x.router);
  }
  /* Each listed router other than Base UR 2.1.2 (covered above), by name. */
  std::set<std::string> want;
  for (const auto& r : screens) want.insert(r.first);
  EXPECT_EQ(done, want);
}

/* A real exact-output swap on Ethereum UR 1.2 (0x0b11139a...: 0.59 ETH for
 * 1,503.75 USDT, of which a TRANSFER pays 3.75 USDT to the app's fee
 * address and a SWEEP delivers the rest): the fee is shown as that amount,
 * and "You receive" is what the SWEEP guarantees after it. */
TEST_F(CertifiedMetadataTest, UniswapTransferFeeIsShownAsAnAmount) {
  const urr::Call* x = nullptr;
  for (const auto& c : urr::calls())
    if (c.tx.rfind("0x0b11139a", 0) == 0) x = &c;
  ASSERT_NE(x, nullptr);
  const std::vector<uint8_t> router = ur_unhex(x->router);
  const std::vector<uint8_t> data = ur_unhex(x->calldata);
  const std::vector<uint8_t> value = ur_unhex(x->value);
  ASSERT_GT(data.size(), 1024u);
  auto e = envelope(
      mint_cert(1, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
      sign_body(build_decoder_body(
          router, 1, {{"dac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6}})));
  ASSERT_EQ(METADATA_VERIFIED,
            signed_metadata_process(e.data(), e.size(),
                                    METADATA_KEYID_DELEGATE));
  EthereumSignTx msg;
  std::vector<uint8_t> first(data.begin(), data.begin() + 1024);
  make_ur_msg(&msg, router, first);
  msg.chain_id = 1;
  msg.data_length = (uint32_t)data.size();
  msg.value.size = 32;
  memcpy(msg.value.bytes, value.data(), 32);
  ASSERT_FALSE(signed_metadata_matches_tx(&msg));
  ASSERT_TRUE(signed_metadata_ur_pending());
  ASSERT_TRUE(signed_metadata_ur_feed(data.data() + 1024,
                                      (uint32_t)(data.size() - 1024)));
  std::vector<Shown> got;
  ASSERT_TRUE(signed_metadata_build_ur_review(
      signed_metadata_get(), "Test Delegate", "A9531B9D", collect_shown,
      &got));
  const std::vector<std::pair<std::string, std::string>> want = {
      {"Uniswap", "Swap at most 0.591976099483018075 ETH for 1500 USDT"},
      {"Limits", "You spend at most\n0.591976099483018075 ETH"},
      {"Limits", "You receive\n1500 USDT"},
      {"Fee", "3.75 USDT to\n0x000000fee13a103A10D593b9AE06b3e05F2E7E1c"},
      {"Contract", "execute\n0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"},
      {"KeepKey ClearSign",
       "Described by Test Delegate A9531B9D\ncertified by KeepKey"},
  };
  ASSERT_EQ(got.size(), want.size());
  for (size_t i = 0; i < want.size(); i++) {
    EXPECT_EQ(got[i].title, want[i].first) << i;
    EXPECT_EQ(got[i].body, want[i].second) << i;
  }
}

/* The 2026-10-03 root ceremony (Base, Arbitrum): the device's own verifier,
 * under the alpha root (installed as the test root; 7.16 compiles in the
 * production root), accepts each certificate for its chain only. Certificates
 * are public; the root's private key never left the root KeepKey. */
TEST(ClearsignRootCeremony20261003, RealCertificatesVerifyOnTheirChainOnly) {
  const char* certs[2] = {
      "0101000021056b359b004b6565704b657920416c706861203731360000000000000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea02b2dc9f48abcd2e46d4850cfd3f4638bcd78bd822b88d56dc66bb34c167e3509597a8d3e86a37f14c5b89a504b04f2868e5fcb3ff93f317e2cae7b1cfca149559a272a3ea713125d37757a98",
      "01010000a4b16b359b004b6565704b657920416c706861203731360000000000000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea02b2dc9f48abcd2e46d4850cf2fe56b2ec1cd8540b8c5eff6ad5c30b5aea85edd7499c3340074e0df12cba0d31a973fb36ab9cc9e3ca759fba08dd96908e3f5541b891f00fc6ff941e9365a6c"};
  const uint32_t scopes[2] = {8453, 42161};
  AlphaTestRoot alpha;
  ASSERT_TRUE(clearsign_root_is_present());
  for (int i = 0; i < 2; i++) {
    std::vector<uint8_t> c = ur_unhex(certs[i]);
    ASSERT_EQ(c.size(), (size_t)CLEARSIGN_CERT_LEN);
    uint8_t pub[CLEARSIGN_PUBKEY_LEN];
    char alias[CLEARSIGN_ALIAS_LEN + 1];
    EXPECT_TRUE(clearsign_root_cert_delegate(c.data(), c.size(), scopes[i],
                                             pub, alias)) << scopes[i];
    EXPECT_STREQ(alias, "KeepKey Alpha 716");
    EXPECT_EQ(memcmp(pub, EXPECTED_SLOT3_PUB, 33) == 0, false);  // not the CI key
    EXPECT_FALSE(clearsign_root_cert_delegate(c.data(), c.size(), 1, pub,
                                              alias)) << "Ethereum scope";
    c[60] ^= 1;  // inside the delegate key
    EXPECT_FALSE(clearsign_root_cert_delegate(c.data(), c.size(), scopes[i],
                                              pub, alias));
  }
}

/* ---- 7.17: a 0x06 name beside the native approve spender (G03) ----------
 *
 * Request bytes captured from swaps.pro through Desktop on 2026-10-29
 * (docs/clearsign-case-studies/swapspro-20261029/requests): approve 25000
 * USDC to CoW's GPv2VaultRelayer on Ethereum. Fees and nonce are from the
 * same session's 0x approve capture (the CoW capture has no fee fields). */
namespace {

const char kCowApprove[] =
    "095ea7b3000000000000000000000000c92e8bdf79f0507f65a392b0ab4667716bfe0110"
    "00000000000000000000000000000000000000000000000000000005d21dba00";
const uint8_t kMainnetUsdc[20] = {0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b,
                                  0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
                                  0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48};
const uint8_t kCowRelayer[20] = {0xc9, 0x2e, 0x8b, 0xdf, 0x79, 0xf0, 0x50,
                                 0x7f, 0x65, 0xa3, 0x92, 0xb0, 0xab, 0x46,
                                 0x67, 0x71, 0x6b, 0xfe, 0x01, 0x10};
// 0x AllowanceHolder, the spender of the same session's 0x route.
const uint8_t kZxAllowanceHolder[20] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xf3, 0x68, 0x4f,
    0x28, 0xc6, 0x75, 0x38, 0xd4, 0xd0, 0x72, 0xc2, 0x27, 0x34};
const char kCowRelayerText[] = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110";

EthereumSignTx usdcTx(const std::string& data_hex) {
  EthereumSignTx msg = {};
  const uint32_t path[5] = {0x8000002c, 0x8000003c, 0x80000000, 0, 0};
  memcpy(msg.address_n, path, sizeof(path));
  msg.address_n_count = 5;
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_type = true;
  msg.type = 2;
  msg.has_nonce = true;
  msg.nonce.size = 1;
  msg.nonce.bytes[0] = 0x07;
  msg.has_gas_limit = true;
  msg.gas_limit.size = 2;
  msg.gas_limit.bytes[0] = 0xea;
  msg.gas_limit.bytes[1] = 0x60;
  const uint8_t max_fee[5] = {0x0d, 0x52, 0xbe, 0xf1, 0x38};
  msg.has_max_fee_per_gas = true;
  msg.max_fee_per_gas.size = sizeof(max_fee);
  memcpy(msg.max_fee_per_gas.bytes, max_fee, sizeof(max_fee));
  const uint8_t tip[4] = {0x3b, 0x9a, 0xca, 0x00};
  msg.has_max_priority_fee_per_gas = true;
  msg.max_priority_fee_per_gas.size = sizeof(tip);
  memcpy(msg.max_priority_fee_per_gas.bytes, tip, sizeof(tip));
  msg.has_to = true;
  msg.to.size = 20;
  memcpy(msg.to.bytes, kMainnetUsdc, 20);
  const std::vector<uint8_t> data = ur_unhex(data_hex);
  msg.has_data_length = msg.has_data_initial_chunk = true;
  msg.data_length = (uint32_t)data.size();
  msg.data_initial_chunk.size = (pb_size_t)data.size();
  memcpy(msg.data_initial_chunk.bytes, data.data(), data.size());
  return msg;
}

struct NamedRun {
  std::vector<std::string> titles, bodies;
  int code = 0;
  std::string message;
  std::string signature;  // hex(v r s), empty unless signed
};

/* Loads `record` (if any) as Desktop would, then signs, approving `yes`
 * screens and declining the next. */
NamedRun signWithRecord(const std::vector<uint8_t>* record,
                        MetadataClassification want, EthereumSignTx msg,
                        int yes) {
  NamedRun run;
  kk_test_board_init();
  fsm_init();
  fsm_test_clearLastFailure();
  kkconfirm_drain();
  signed_metadata_clear();
  if (record) {
    EXPECT_EQ(want, signed_metadata_process(record->data(), record->size(),
                                            METADATA_KEYID_DELEGATE));
  }
  EXPECT_TRUE(kkconfirm_preload(yes, 1));
  HDNode node = {};
  const uint8_t seed[32] = {1};
  EXPECT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
  kkconfirm_capture_start();
  ethereum_signing_init(&msg, &node, /*needs_confirm=*/true);
  run.bodies = kkconfirm_capture_finish();
  run.titles = kkconfirm_captured_titles();
  run.code = (int)fsm_test_lastFailureCode();
  run.message = fsm_test_lastFailureMessage();
  if (run.code == 0) {
    EthereumTxRequest response{};
    if (kkconfirm_readResponse(MessageType_MessageType_EthereumTxRequest,
                               EthereumTxRequest_fields, &response) &&
        response.has_signature_r && response.has_signature_s) {
      run.signature = std::to_string(response.signature_v) + ":" +
                      hex_of(response.signature_r.bytes, 32) +
                      hex_of(response.signature_s.bytes, 32);
    }
  }
  kkconfirm_drain();
  ethereum_signing_abort();
  return run;
}

std::string joined(const NamedRun& run, const std::string& title_prefix) {
  std::string out;
  for (size_t i = 0; i < run.titles.size() && i < run.bodies.size(); i++)
    if (run.titles[i].rfind(title_prefix, 0) == 0) out += run.bodies[i];
  return out;
}

/* Removes the one "KeepKey ClearSign" screen from `run` and returns its body;
 * `*at` is where it was. What is left must be the unnamed review. */
std::string takeVouch(NamedRun* run, size_t* at) {
  EXPECT_EQ(1, std::count(run->titles.begin(), run->titles.end(),
                          "KeepKey ClearSign"))
      << ::testing::PrintToString(run->titles);
  auto it = std::find(run->titles.begin(), run->titles.end(),
                      "KeepKey ClearSign");
  if (it == run->titles.end()) {
    *at = 0;
    return "";
  }
  *at = (size_t)(it - run->titles.begin());
  std::string body = run->bodies.at(*at);
  run->titles.erase(it);
  run->bodies.erase(run->bodies.begin() + *at);
  return body;
}

std::string testDelegateFp8() {
  char fp[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(EXPECTED_SLOT3_PUB, fp);
  return std::string(fp, 8);
}

/* A plain 1 ETH send to `to`, same session fees as usdcTx(). */
EthereumSignTx ethSendTx(const uint8_t to[20]) {
  EthereumSignTx msg = usdcTx("");
  memcpy(msg.to.bytes, to, 20);
  msg.has_data_length = msg.has_data_initial_chunk = false;
  msg.data_length = 0;
  msg.data_initial_chunk.size = 0;
  const uint8_t one_eth[8] = {0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00};
  msg.has_value = true;
  msg.value.size = sizeof(one_eth);
  memcpy(msg.value.bytes, one_eth, sizeof(one_eth));
  return msg;
}

class ApproveNameTest : public CertifiedMetadataTest {
 protected:
  void SetUp() override {
    CertifiedMetadataTest::SetUp();
    set_advanced_mode_for_test(false);  // a native approve never needs it
  }
  std::vector<uint8_t> Record(uint32_t chain, const uint8_t addr[20],
                              const std::string& name) {
    return envelope(
        mint_cert(chain, CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, EXPECTED_SLOT3_PUB),
        sign_body(name_body(chain, addr, name, METADATA_KEYID_DELEGATE)));
  }
  // Every screen approved: the unnamed reference run.
  NamedRun Unnamed(const EthereumSignTx& msg) {
    return signWithRecord(nullptr, METADATA_VERIFIED, msg, 16);
  }
};

}  // namespace

/* The name gets a screen of its own right after the approve screen, which
 * stays exactly the 7.16 one: the full spender address on one page. */
TEST_F(ApproveNameTest, VerifiedNameForTheSpenderIsShownAfterIt) {
  const EthereumSignTx msg = usdcTx(kCowApprove);
  const auto record = Record(1, kCowRelayer, "CoW Protocol");
  NamedRun named = signWithRecord(&record, METADATA_VERIFIED, msg, 16);
  ASSERT_EQ(0, named.code) << named.message;
  NamedRun plain = Unnamed(msg);
  ASSERT_EQ(0, plain.code) << plain.message;

  size_t at = 0;
  EXPECT_EQ("Spender: CoW Protocol\nnamed by Test Delegate " +
                testDelegateFp8() + "\ncertified by KeepKey",
            takeVouch(&named, &at));
  EXPECT_EQ(plain.titles, named.titles);
  EXPECT_EQ(plain.bodies, named.bodies);
  ASSERT_GT(at, 0u);
  EXPECT_EQ("Approve", named.titles[at - 1]);
  EXPECT_EQ(std::string("Approve withdrawal of up to 25000 USDC by ") +
                kCowRelayerText + "?",
            named.bodies[at - 1]);
  ASSERT_FALSE(plain.signature.empty());
  EXPECT_EQ(plain.signature, named.signature);
}

TEST_F(ApproveNameTest, NameForAnotherSpenderIsIgnored) {
  const EthereumSignTx msg = usdcTx(kCowApprove);
  const auto record = Record(1, kZxAllowanceHolder, "0x AllowanceHolder");
  NamedRun other = signWithRecord(&record, METADATA_VERIFIED, msg, 16);
  NamedRun plain = Unnamed(msg);
  ASSERT_EQ(0, other.code) << other.message;
  ASSERT_FALSE(other.signature.empty());
  EXPECT_EQ(plain.titles, other.titles);
  EXPECT_EQ(plain.bodies, other.bodies);
  EXPECT_EQ(plain.signature, other.signature);
}

TEST_F(ApproveNameTest, NameForTheSpenderOnAnotherChainIsIgnored) {
  const EthereumSignTx msg = usdcTx(kCowApprove);
  // A verified Base name for the same relayer address.
  const auto record = Record(8453, kCowRelayer, "CoW Protocol");
  NamedRun other = signWithRecord(&record, METADATA_VERIFIED, msg, 16);
  NamedRun plain = Unnamed(msg);
  ASSERT_EQ(0, other.code) << other.message;
  ASSERT_FALSE(other.signature.empty());
  EXPECT_EQ(plain.titles, other.titles);
  EXPECT_EQ(plain.bodies, other.bodies);
  EXPECT_EQ(plain.signature, other.signature);
}

TEST_F(ApproveNameTest, MalformedNameRecordRefusesTheApprove) {
  auto record = Record(1, kCowRelayer, "CoW Protocol");
  record[record.size() - 10] ^= 1;  // inside the delegate's signature
  NamedRun run = signWithRecord(&record, METADATA_MALFORMED,
                                usdcTx(kCowApprove), 16);
  EXPECT_EQ(FailureType_Failure_Other, run.code);
  EXPECT_EQ("Certified description invalid or not for this tx", run.message);
  EXPECT_TRUE(run.titles.empty()) << ::testing::PrintToString(run.titles);
  EXPECT_TRUE(run.signature.empty());
}

/* Unlimited: the name follows the warning, and the approve screen after it
 * does not repeat it. Both address screens are the 7.16 ones. */
TEST_F(ApproveNameTest, UnlimitedWarningIsFollowedByTheName) {
  std::string hex = kCowApprove;
  hex.replace(hex.size() - 64, 64, std::string(64, 'f'));
  const EthereumSignTx msg = usdcTx(hex);
  const auto record = Record(1, kCowRelayer, "CoW Protocol");
  NamedRun named = signWithRecord(&record, METADATA_VERIFIED, msg, 16);
  ASSERT_EQ(0, named.code) << named.message;
  NamedRun plain = Unnamed(msg);
  ASSERT_EQ(0, plain.code) << plain.message;
  size_t at = 0;
  const std::string vouch = takeVouch(&named, &at);
  EXPECT_EQ(0u, vouch.find("Spender: CoW Protocol\n")) << vouch;
  EXPECT_EQ(1u, at);
  EXPECT_EQ(plain.titles, named.titles);
  EXPECT_EQ(plain.bodies, named.bodies);
  ASSERT_FALSE(named.titles.empty());
  EXPECT_EQ("UNLIMITED approval", named.titles[0]);
  EXPECT_EQ(std::string("Allow ") + kCowRelayerText + " to spend ALL your USDC",
            named.bodies[0]);
  ASSERT_FALSE(named.signature.empty());
  EXPECT_EQ(plain.signature, named.signature);

  // increaseAllowance gets the same named warning; declining the name screen
  // signs nothing.
  EthereumSignTx inc = msg;
  memcpy(inc.data_initial_chunk.bytes, "\x39\x50\x93\x51", 4);
  NamedRun declined = signWithRecord(&record, METADATA_VERIFIED, inc, 1);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, declined.code);
  EXPECT_EQ((std::vector<std::string>{"UNLIMITED approval",
                                      "KeepKey ClearSign"}),
            declined.titles);
  EXPECT_EQ(named.bodies[0], declined.bodies[0]);
  EXPECT_EQ(vouch, declined.bodies[1]);
  EXPECT_TRUE(declined.signature.empty());
}

/* The same record names an ERC-20 transfer's recipient. */
TEST_F(ApproveNameTest, VerifiedNameForATransferRecipientIsShown) {
  std::string hex = kCowApprove;
  hex.replace(0, 8, "a9059cbb");
  const EthereumSignTx msg = usdcTx(hex);
  const auto record = Record(1, kCowRelayer, "CoW Protocol");
  NamedRun named = signWithRecord(&record, METADATA_VERIFIED, msg, 16);
  ASSERT_EQ(0, named.code) << named.message;
  NamedRun plain = Unnamed(msg);
  size_t at = 0;
  EXPECT_EQ(0u, takeVouch(&named, &at).find("Recipient: CoW Protocol\n"));
  EXPECT_EQ(plain.titles, named.titles);
  EXPECT_EQ(plain.bodies, named.bodies);
  ASSERT_GT(at, 0u);
  EXPECT_EQ(std::string("Send 25000 USDC to ") + kCowRelayerText,
            named.bodies[at - 1]);
  ASSERT_FALSE(named.signature.empty());
  EXPECT_EQ(plain.signature, named.signature);
}

/* A plain ETH send (no calldata) names its recipient the same way, and a
 * record for another address leaves the send exactly as it was. */
TEST_F(ApproveNameTest, VerifiedNameForANativeSendRecipientIsShown) {
  const EthereumSignTx msg = ethSendTx(kCowRelayer);
  const auto record = Record(1, kCowRelayer, "CoW Protocol");
  NamedRun named = signWithRecord(&record, METADATA_VERIFIED, msg, 16);
  ASSERT_EQ(0, named.code) << named.message;
  NamedRun plain = Unnamed(msg);
  ASSERT_EQ(0, plain.code) << plain.message;
  size_t at = 0;
  EXPECT_EQ("Recipient: CoW Protocol\nnamed by Test Delegate " +
                testDelegateFp8() + "\ncertified by KeepKey",
            takeVouch(&named, &at));
  EXPECT_EQ(plain.titles, named.titles);
  EXPECT_EQ(plain.bodies, named.bodies);
  ASSERT_GT(at, 0u);
  EXPECT_EQ("Send", named.titles[at - 1]);
  EXPECT_EQ(std::string("Send 1 ETH to ") + kCowRelayerText,
            named.bodies[at - 1]);
  ASSERT_FALSE(plain.signature.empty());
  EXPECT_EQ(plain.signature, named.signature);

  const auto other_record =
      Record(1, kZxAllowanceHolder, "0x AllowanceHolder");
  NamedRun other = signWithRecord(&other_record, METADATA_VERIFIED, msg, 16);
  ASSERT_EQ(0, other.code) << other.message;
  EXPECT_EQ(plain.titles, other.titles);
  EXPECT_EQ(plain.bodies, other.bodies);
  EXPECT_EQ(plain.signature, other.signature);
}

/* Production name records: batch 2 of the 2026-10-16 ClearSign ceremony
 * (signed-catalog-batch2.json), verified under the compiled-in production
 * root. Uniswap's Universal Router on Ethereum, and another router address
 * named on BNB Chain only. A 24-character name and the production alias
 * still leave the approve screen whole and the name on one screen. */
TEST_F(ApproveNameTest, ProductionNameRecordsNameOnlyTheirSpenderOnTheirChain) {
  const std::vector<uint8_t> eth_ur = ur_unhex(
      "030101000000016cb3ad994b6565704b657920436c6561725369676e00000000"
      "000000000000000000000003bb5314410309cc4e56b8140565106714e4dbf33f"
      "6d75e2c89b78e0e6cb1cd1655c9f942208d3b4812e1a9434993f65d9c05990cb"
      "e379faade132d14987cbfaeb387f0dd3e015210934fe1103770b89272e64a653"
      "97d5d22a3501aa089ea13000060000000166a9893cc07d91d95644aedd05d03f"
      "95e1dba8af18556e697377617020556e6976657273616c20526f757465720100"
      "00000080362cd9a3aa09724ff3758120fc36f96c207a28f4290d7f7415976b75"
      "d090f87d758ad594ec569c63736cc94f4bd63af4d66edd778f6472cd8e8f28e8"
      "860c52be01");
  const std::vector<uint8_t> bsc_ur = ur_unhex(
      "030101000000386cb3ad994b6565704b657920436c6561725369676e00000000"
      "00000000000000000000000250edcaf4c63b0922bd1d3171a1bf3ee3fb2dec5d"
      "c8c316c8a0706a079f5ab8021950a0c858d54f27668aff057711a484582d3c56"
      "30fe7246d452ba85fd57a053554d4d22ca57aa97443541bb2dd1b70ace1e24dd"
      "6d48120fc9704cd363883a170600000038ec8b0f7ffe3ae75d7ffab09429e367"
      "5bb63503e418556e697377617020556e6976657273616c20526f757465720100"
      "0000008097d9e9c94f5e03c18e328c25fee813a9a58b95a1d62bceb9c3289b12"
      "e228d208448dc499cc9f5b7b19dc2eee58c0b2e399b6203654176350e742cbec"
      "fc12949f00");
  clearsign_root_set_test_root(nullptr);  // the compiled-in production root
  std::string hex = kCowApprove;
  hex.replace(32, 40, "66a9893cc07d91d95644aedd05d03f95e1dba8af");
  NamedRun named = signWithRecord(&eth_ur, METADATA_VERIFIED, usdcTx(hex), 16);
  ASSERT_EQ(0, named.code) << named.message;
  NamedRun plain = Unnamed(usdcTx(hex));
  size_t at = 0;
  EXPECT_EQ("Spender: Uniswap Universal Router\nnamed by KeepKey ClearSign "
            "FDD258EC\ncertified by KeepKey",
            takeVouch(&named, &at));
  EXPECT_EQ(plain.titles, named.titles);
  EXPECT_EQ(plain.bodies, named.bodies);
  ASSERT_GT(at, 0u);
  EXPECT_EQ("Approve", named.titles[at - 1]);
  EXPECT_EQ("Approve withdrawal of up to 25000 USDC by "
            "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af?",
            named.bodies[at - 1]);
  ASSERT_FALSE(named.signature.empty());
  EXPECT_EQ(plain.signature, named.signature);

  // The BNB Chain record names its address there, not on Ethereum.
  hex.replace(32, 40, "ec8b0f7ffe3ae75d7ffab09429e3675bb63503e4");
  NamedRun other =
      signWithRecord(&bsc_ur, METADATA_VERIFIED, usdcTx(hex), 16);
  plain = Unnamed(usdcTx(hex));
  ASSERT_EQ(0, other.code) << other.message;
  ASSERT_FALSE(other.signature.empty());
  EXPECT_EQ(plain.titles, other.titles);
  EXPECT_EQ(plain.bodies, other.bodies);
  EXPECT_EQ(plain.signature, other.signature);
}
