#include "gtest/gtest.h"
#include <cstring>
#include <vector>

extern "C" {
#include "keepkey/firmware/signing.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/transaction.h"
}

namespace {

constexpr uint32_t H(uint32_t i) { return 0x80000000 | i; }

// m/<purpose>'/0'/0'/1/0 -- a first change address in the first account.
struct ChangePath {
  uint32_t n[5];
  explicit ChangePath(uint32_t purpose) : n{H(purpose), H(0), H(0), 1, 0} {}
};

bool Forbidden(uint32_t in_purpose, uint32_t out_purpose,
               OutputScriptType out_script_type) {
  ChangePath in(in_purpose), out(out_purpose);
  return isCrossAccountSegwitChangeForbidden(in.n, 5, out.n, 5,
                                             out_script_type);
}

}  // namespace

// Regression: a BIP86 change path paired with any non-taproot script type used
// to fall through to the generic path check, which accepted it as change. That
// suppressed the output confirmation screen while serializing the change to a
// script no BIP86 wallet ever scans for.
TEST(Signing, TaprootChangeMustUseTaprootScriptType) {
  EXPECT_TRUE(Forbidden(86, 86, OutputScriptType_PAYTOADDRESS));
  EXPECT_TRUE(Forbidden(86, 86, OutputScriptType_PAYTOWITNESS));
  EXPECT_TRUE(Forbidden(86, 86, OutputScriptType_PAYTOP2SHWITNESS));
}

TEST(Signing, MatchedPurposeAndScriptTypeAreAllowed) {
  EXPECT_FALSE(Forbidden(86, 86, OutputScriptType_PAYTOTAPROOT));
  EXPECT_FALSE(Forbidden(44, 44, OutputScriptType_PAYTOADDRESS));
  EXPECT_FALSE(Forbidden(49, 49, OutputScriptType_PAYTOP2SHWITNESS));
  EXPECT_FALSE(Forbidden(84, 84, OutputScriptType_PAYTOWITNESS));
}

// The pre-taproot direction of the same rule, kept honest by this test.
TEST(Signing, LegacyChangeMayNotClaimTaprootScriptType) {
  EXPECT_TRUE(Forbidden(44, 44, OutputScriptType_PAYTOTAPROOT));
  EXPECT_TRUE(Forbidden(49, 49, OutputScriptType_PAYTOTAPROOT));
  EXPECT_TRUE(Forbidden(84, 84, OutputScriptType_PAYTOTAPROOT));
}

TEST(Signing, MultisigQuorumMustBeBoundedBeforeFeeAccounting) {
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  multisig.has_m = true;
  multisig.m = 2;
  multisig.pubkeys_count = 3;
  EXPECT_TRUE(transaction_multisig_quorum_is_valid(&multisig));

  multisig.has_m = false;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.has_m = true;

  multisig.m = 0;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.m = UINT32_MAX;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.m = 4;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));

  multisig.m = 1;
  multisig.pubkeys_count = 0;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.pubkeys_count = 16;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));

  EXPECT_FALSE(transaction_multisig_quorum_is_valid(nullptr));
}

TEST(Signing, ScriptTypeChecksumEncodingIsAbiIndependent) {
  uint8_t encoded[4] = {0xff, 0xff, 0xff, 0xff};
  signing_encode_script_type(InputScriptType_SPENDTAPROOT, encoded);
  const uint32_t value = (uint32_t)InputScriptType_SPENDTAPROOT;
  EXPECT_EQ(encoded[0], (uint8_t)value);
  EXPECT_EQ(encoded[1], (uint8_t)(value >> 8));
  EXPECT_EQ(encoded[2], (uint8_t)(value >> 16));
  EXPECT_EQ(encoded[3], (uint8_t)(value >> 24));
  EXPECT_EQ(sizeof(encoded), 4U);
}

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
extern "C" bool signing_test_state_is_cleared(void);

namespace {
std::vector<uint8_t> SigningPixels() {
  Canvas* canvas = layout_get_canvas();
  return {canvas->buffer, canvas->buffer + canvas->width * canvas->height};
}
}  // namespace

TEST(Signing, EveryInputSequenceIsShownExactly) {
  const struct {
    uint32_t index;
    uint32_t sequence;
    const char* body;
  } vectors[] = {
      {0, UINT32_MAX, "Input #1\nSequence: 4294967295"},
      {7, 0xfffffffe,
       "Input #8\nSequence: 4294967294\nNon-final: lock or replacement rules "
       "may apply."},
      {2, 0xfffffffd,
       "Input #3\nSequence: 4294967293\nNon-final: lock or replacement rules "
       "may apply."},
      {9, 4194305,
       "Input #10\nSequence: 4194305\nNon-final: lock or replacement rules may "
       "apply."},
      {3, 0,
       "Input #4\nSequence: 0\nNon-final: lock or replacement rules may "
       "apply."},
  };
  for (const auto& v : vectors) {
    SCOPED_TRACE(v.body);
    ASSERT_TRUE(kkconfirm_preload(8, 0));
    ASSERT_TRUE(confirm(ButtonRequestType_ButtonRequest_SignTx,
                        "Input sequence", "%s", v.body));
    const auto expected = SigningPixels();
    const int remaining = kkconfirm_drain();
    ASSERT_TRUE(kkconfirm_preload(8, 0));
    EXPECT_TRUE(signing_confirm_input_sequence(v.index, v.sequence));
    EXPECT_EQ(expected, SigningPixels());
    EXPECT_EQ(remaining, kkconfirm_drain());
  }
}

TEST(Signing, NonDefaultHeaderFieldsCannotBypassCancellation) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_FALSE(signing_confirm_transaction_fields(UINT32_MAX, 0, 0, false));
  EXPECT_EQ(0, kkconfirm_drain());

  // Approve version/locktime, reject the separately displayed expiry.
  ASSERT_TRUE(kkconfirm_preload(1, 1));
  EXPECT_FALSE(signing_confirm_transaction_fields(4, 0, UINT32_MAX, true));
  EXPECT_EQ(0, kkconfirm_drain());

  // Approve the exact fields, reject the nonzero lock-time warning.
  for (uint32_t lock : {1U, 499999999U, 500000000U, UINT32_MAX}) {
    ASSERT_TRUE(kkconfirm_preload(1, 1));
    EXPECT_FALSE(signing_confirm_transaction_fields(2, lock, 0, false));
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

TEST(Signing, HeaderReviewShowsExactVersionLockAndExpiry) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(confirm(ButtonRequestType_ButtonRequest_SignTx,
                      "Transaction fields",
                      "Version: 4294967295\nLock time: 0"));
  const auto expected_header = SigningPixels();
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(signing_confirm_transaction_fields(UINT32_MAX, 0, 0, false));
  EXPECT_EQ(expected_header, SigningPixels());
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(confirm(ButtonRequestType_ButtonRequest_SignTx,
                      "Transaction expiry", "Expiry height: 4294967295"));
  const auto expected_expiry = SigningPixels();
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(signing_confirm_transaction_fields(4, 0, UINT32_MAX, true));
  EXPECT_EQ(expected_expiry, SigningPixels());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Signing, LegacyConsistencyChecksumBindsReviewedSequence) {
  TxInputType input = TxInputType_init_zero;
  input.prev_hash.size = 32;
  input.prev_hash.bytes[0] = 17;
  input.script_type = InputScriptType_SPENDADDRESS;
  input.sequence = UINT32_MAX;
  Hasher h;
  uint8_t approved[32], mutated[32];
  hasher_Init(&h, HASHER_SHA2D);
  signing_hash_input_check(&h, &input);
  hasher_Final(&h, approved);
  for (uint32_t sequence : {0U, 1U, 0xfffffffdU, 0xfffffffeU}) {
    input.sequence = sequence;
    hasher_Init(&h, HASHER_SHA2D);
    signing_hash_input_check(&h, &input);
    hasher_Final(&h, mutated);
    EXPECT_NE(0, memcmp(approved, mutated, 32));
  }
}

TEST(Signing, PhaseOneSequenceRejectionAbortsBeforeProceeding) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  CoinType coin = *coinByName("Bitcoin");
  coin.has_taproot = false;
  coin.taproot = false;
  coin.force_bip143 = true;
  HDNode root = {};
  SignTx request = SignTx_init_zero;
  request.inputs_count = 1;
  request.outputs_count = 1;
  request.version = 2;
  signing_init(&request, &coin, &root);
  TransactionType ack = TransactionType_init_zero;
  ack.inputs_count = 1;
  ack.inputs[0].prev_hash.size = 32;
  ack.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  ack.inputs[0].has_amount = true;
  ack.inputs[0].amount = 100000;
  ack.inputs[0].sequence = 1;
  signing_txack(&ack);
  EXPECT_TRUE(signing_test_state_is_cleared());
  EXPECT_EQ(0, kkconfirm_drain());
  signing_abort();
}
