// gtest first: confirm_sm.h defines an isprint() macro that collides with the
// standard library declaration when C++ headers are included afterwards.
#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/transaction.h"
}

// confirm() auto-accept driver, defined in thorchain.cpp (same binary).
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Transaction, TaprootInputWeightIncludesWitness) {
  CoinType coin = CoinType_init_zero;
  TxInputType input = TxInputType_init_zero;
  input.script_type = InputScriptType_SPENDTAPROOT;

  // 41 non-witness bytes * 4 plus a one-item witness containing the fixed
  // 64-byte SIGHASH_DEFAULT Schnorr signature.
  ASSERT_EQ(230U, tx_input_weight(&coin, &input));
}

TEST(Transaction, UnsupportedOmniDisclosesTheCompleteRawPayload) {
  std::vector<uint8_t> payload(220, 0x00);
  memcpy(payload.data(), "omni", 4);
  payload[7] = 1;  // unsupported transaction type, not Simple Send (type 0)

  size_t pages = 0;
  size_t offset = 0;
  while (offset < payload.size()) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        payload.data() + offset, payload.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    pages++;
  }
  ASSERT_GT(pages, 1u)
      << "fixture must distinguish raw pagination from one generic warning";

  ASSERT_TRUE(kkconfirm_preload(static_cast<int>(pages), 0));
  EXPECT_TRUE(confirm_omni(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Confirm OMNI", payload.data(), payload.size()));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Transaction, MultisigQuorumRejectsUnsatisfiableScripts) {
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  CoinType coin = CoinType_init_zero;
  uint8_t output[512] = {0};
  uint8_t hash[32] = {0};

  multisig.has_m = true;
  multisig.m = 2;
  multisig.pubkeys_count = 1;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  EXPECT_EQ(compile_script_multisig(&coin, &multisig, output), 0U);
  EXPECT_EQ(compile_script_multisig_hash(&coin, &multisig, hash), 0U);

  multisig.m = 0;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.m = 16;
  multisig.pubkeys_count = 16;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));

  multisig.m = 2;
  multisig.pubkeys_count = 3;
  EXPECT_TRUE(transaction_multisig_quorum_is_valid(&multisig));
}

TEST(Transaction, MultisigCompilersRejectUnsatisfiableQuorums) {
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  uint8_t output[256] = {0};
  uint8_t hash[32] = {0};

  struct InvalidQuorum {
    bool has_m;
    uint32_t m;
    pb_size_t n;
  };
  const InvalidQuorum invalid[] = {
      {false, 1, 1}, {true, 0, 1},  {true, 1, 0},
      {true, 2, 1},  {true, 1, 16}, {true, 16, 16},
  };

  for (const auto& test : invalid) {
    multisig.has_m = test.has_m;
    multisig.m = test.m;
    multisig.pubkeys_count = test.n;
    EXPECT_FALSE(multisig_quorum_is_valid(&multisig));
    EXPECT_EQ(0u, compile_script_multisig(nullptr, &multisig, output));
    EXPECT_EQ(0u, compile_script_multisig_hash(nullptr, &multisig, hash));
  }
}

extern "C" {
#include "keepkey/firmware/txin_check.h"
}

// compile_output() hands txin_dgst_save_and_reset() `prefix_len + in->address`
// for cashaddr coins, a pointer INTO a 130-byte field. The save copied a fixed
// ADDR_STR_LEN bytes from it, reading prefix_len bytes past the field. Place
// the string flush against a PROT_NONE guard page: the old copy faults, a
// string-bounded copy stops at the NUL.
TEST(Transaction, DuplicateDigestSaveCopiesTheStringNotTheField) {
  const long page = sysconf(_SC_PAGESIZE);
  ASSERT_GT(page, 0);
  uint8_t *region = static_cast<uint8_t *>(
      mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  ASSERT_NE(region, MAP_FAILED);
  ASSERT_EQ(mprotect(region + page, page, PROT_NONE), 0);

  static const char addr[] = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
  char *at_edge = reinterpret_cast<char *>(region + page - sizeof(addr));
  memcpy(at_edge, addr, sizeof(addr));

  txin_dgst_initialize();
  EXPECT_EXIT(
      {
        txin_dgst_save_and_reset("0.001 BCH", at_edge);
        exit(0);
      },
      ::testing::ExitedWithCode(0), "");
  munmap(region, 2 * page);
}

// page_body_confirm() counts pages and stops counting at 100. It then rendered
// exactly that many, called the 100th "last", and returned approval with body
// bytes still unshown. A body that needs more pages than can be shown must be
// refused, not approved in part.
TEST(Confirm, PagerRefusesABodyItCannotShowInFull) {
  // 351 newlines: BODY_CHAR_MAX - 1, the widest body confirm() accepts
  // without source truncation, laid out one empty row per byte.
  const std::string body(BODY_CHAR_MAX - 1, '\n');
  ASSERT_TRUE(kkconfirm_preload(100, 0));
  EXPECT_FALSE(confirm(ButtonRequestType_ButtonRequest_Other, "Sign Message",
                       "%s", body.c_str()));
  // Refused before any page was drawn: every preloaded approval is unspent
  // (one ButtonAck + one DebugLinkDecision per screen).
  EXPECT_EQ(2 * 100, kkconfirm_drain());
}
