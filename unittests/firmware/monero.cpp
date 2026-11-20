extern "C" {
#include "keepkey/board/keepkey_button.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/monero.h"
#include "keepkey/firmware/signing_session.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/zcash.h"
#include "monero_probe.h"
#include "monero_session_probe.h"
#include "keepkey/board/timer.h"

bool keepkey_before_message_dispatch(MessageType msg_id);
}

#include "gtest/gtest.h"
#include "test_board.h"
#include "generated/monero_core_vectors.h"

#include <cstring>
#include <string>
#include <vector>

/* The fixtures in monero_core_vectors.h come from pinned Monero Core
 * arithmetic (tools/monero-feasibility/reference.py) over the published
 * "abandon ... about" and "alcohol woman ..." mnemonics: key_seed is the
 * SLIP-10 node key at m/44'/128'/account'. */

namespace {

std::string label_wallet(const MoneroCoreCase& c) {
  const std::string label = c.label;
  return label.substr(0, label.find("-sub"));
}

std::vector<const MoneroCoreCase*> wallet_cases(const std::string& wallet) {
  std::vector<const MoneroCoreCase*> out;
  for (size_t i = 0; i < MONERO_CORE_CASE_COUNT; ++i)
    if (label_wallet(monero_core_cases[i]) == wallet)
      out.push_back(&monero_core_cases[i]);
  return out;
}

MoneroTransferDetails transfer(const MoneroCoreCase& c, bool explicit_sub) {
  MoneroTransferDetails td = {};
  td.has_out_key = true;
  td.out_key.size = 32;
  std::memcpy(td.out_key.bytes, c.output_public, 32);
  td.has_tx_pub_key = true;
  td.tx_pub_key.size = 32;
  std::memcpy(td.tx_pub_key.bytes, c.tx_public, 32);
  td.has_internal_output_index = true;
  td.internal_output_index = c.output_index;
  if (explicit_sub) {
    td.has_sub_addr_major = td.has_sub_addr_minor = true;
    td.sub_addr_major = c.major;
    td.sub_addr_minor = c.minor;
  }
  return td;
}

/* The transcript the host commits to: Keccak over the per-output hashes. */
void control_hash(const std::vector<MoneroTransferDetails>& tds,
                  uint8_t out[32]) {
  std::vector<uint8_t> all;
  for (const auto& td : tds) {
    uint8_t item[32];
    monero_probe_transcript_item(td.out_key.bytes, td.tx_pub_key.bytes,
                                 td.internal_output_index, item);
    all.insert(all.end(), item, item + 32);
  }
  monero_probe_keccak(all.data(), all.size(), out);
}

MoneroKeyImageExportInitRequest init_request(
    const std::vector<MoneroTransferDetails>& tds) {
  MoneroKeyImageExportInitRequest init = {};
  init.has_num = true;
  init.num = tds.size();
  init.has_hash = true;
  init.hash.size = 32;
  control_hash(tds, init.hash.bytes);
  init.address_n_count = 3;
  init.address_n[0] = 0x8000002c;
  init.address_n[1] = 0x80000080;
  init.address_n[2] = 0x80000000;
  /* The subaddresses the fixtures use, for outputs without explicit indices. */
  const uint32_t subs[][2] = {{0, 1}, {1, 0}, {100, 100}};
  init.subs_count = 3;
  for (int i = 0; i < 3; ++i) {
    init.subs[i].has_account = true;
    init.subs[i].account = subs[i][0];
    init.subs[i].minor_indices_count = 1;
    init.subs[i].minor_indices[0] = subs[i][1];
  }
  return init;
}

class MoneroSession : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    keepkey_user_activity(); /* no idle lock in the middle of a test */
    fsm_abort_signing_workflows();
  }
  void TearDown() override { fsm_abort_signing_workflows(); }
};

}  // namespace

TEST(Monero, PathIsExactlyThreeHardenedLevels) {
  const uint32_t good[] = {0x8000002c, 0x80000080, 0x80000005};
  EXPECT_TRUE(monero_path_valid(good, 3));
  EXPECT_FALSE(monero_path_valid(good, 2));
  const uint32_t four[] = {0x8000002c, 0x80000080, 0x80000000, 0};
  EXPECT_FALSE(monero_path_valid(four, 4));
  const uint32_t soft[] = {0x8000002c, 0x80000080, 0};
  EXPECT_FALSE(monero_path_valid(soft, 3));
  const uint32_t other_coin[] = {0x8000002c, 0x80000001, 0x80000000};
  EXPECT_FALSE(monero_path_valid(other_coin, 3));
  EXPECT_EQ(nullptr, monero_network_name(3));
}

TEST(Monero, AddressesMatchMoneroCore) {
  ASSERT_EQ(96u, MONERO_CORE_CASE_COUNT);
  for (size_t i = 0; i < MONERO_CORE_CASE_COUNT; ++i) {
    const MoneroCoreCase& c = monero_core_cases[i];
    char address[MONERO_ADDRESS_CAPACITY];
    ASSERT_TRUE(monero_get_address(c.key_seed, 0, c.major, c.minor, address))
        << c.label;
    EXPECT_EQ(std::string(c.address), std::string(address)) << c.label;
    EXPECT_EQ(MONERO_ADDRESS_LENGTH, std::strlen(address));
  }
}

TEST(Monero, NetworksUseTheirOwnPrefixes) {
  const MoneroCoreCase& c = monero_core_cases[0];
  char main[MONERO_ADDRESS_CAPACITY], test[MONERO_ADDRESS_CAPACITY],
      stage[MONERO_ADDRESS_CAPACITY];
  ASSERT_TRUE(monero_get_address(c.key_seed, 0, 0, 0, main));
  ASSERT_TRUE(monero_get_address(c.key_seed, 1, 0, 0, test));
  ASSERT_TRUE(monero_get_address(c.key_seed, 2, 0, 0, stage));
  EXPECT_EQ('4', main[0]);
  EXPECT_EQ('9', test[0]);
  EXPECT_EQ('5', stage[0]);
  char bad[MONERO_ADDRESS_CAPACITY];
  std::memset(bad, 'x', sizeof(bad));
  EXPECT_FALSE(monero_get_address(c.key_seed, 3, 0, 0, bad));
  EXPECT_EQ('\0', bad[0]);
}

TEST(Monero, WatchKeyIsTheCoreViewSecret) {
  for (size_t i = 0; i < MONERO_CORE_CASE_COUNT; ++i) {
    const MoneroCoreCase& c = monero_core_cases[i];
    if (c.minor != 0 || c.output_index != 0) continue;
    uint8_t view[32];
    char address[MONERO_ADDRESS_CAPACITY];
    ASSERT_TRUE(monero_get_watch_key(c.key_seed, 0, c.major, view, address))
        << c.label;
    EXPECT_EQ(0, std::memcmp(view, c.view_secret, 32)) << c.label;
    EXPECT_EQ(std::string(c.address), std::string(address)) << c.label;
    EXPECT_NE(0, std::memcmp(view, c.spend_secret, 32));
  }
}

TEST_F(MoneroSession, KeyImagesMatchMoneroCore) {
  for (const char* wallet :
       {"abandon-account0", "abandon-account1", "trezor-account0",
        "trezor-account1"}) {
    const auto cases = wallet_cases(wallet);
    ASSERT_EQ(24u, cases.size());
    /* Half the outputs name their subaddress, the others are found among the
     * subaddresses listed at init. Batches of up to four. */
    std::vector<MoneroTransferDetails> tds;
    for (size_t i = 0; i < cases.size(); ++i)
      tds.push_back(transfer(*cases[i], i % 2 == 0));
    MoneroKeyImageExportInitRequest init = init_request(tds);
    init.address_n[2] = 0x80000000 | (std::string(wallet).back() - '0');
    ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init)) << wallet;
    EXPECT_EQ(SIGNING_SESSION_MONERO_KEY_IMAGE, signing_session_owner());
    EXPECT_TRUE(fsm_workflowInProgress());

    std::vector<MoneroExportedKeyImage> exported;
    uint32_t permil = 0;
    for (size_t at = 0; at < tds.size(); at += 4) {
      MoneroKeyImageSyncStepRequest step = {};
      step.tdis_count = 0;
      for (size_t j = at; j < tds.size() && j < at + 4; ++j)
        step.tdis[step.tdis_count++] = tds[j];
      MoneroKeyImageSyncStepAck ack = {};
      ASSERT_TRUE(monero_key_image_step(&step, &ack, &permil)) << wallet;
      ASSERT_EQ(step.tdis_count, ack.kis_count);
      for (pb_size_t j = 0; j < ack.kis_count; ++j)
        exported.push_back(ack.kis[j]);
    }
    EXPECT_EQ(1000u, permil);
    uint8_t key[32];
    ASSERT_TRUE(monero_key_image_finish(key)) << wallet;
    EXPECT_FALSE(monero_key_image_active());
    EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
    EXPECT_TRUE(signing_session_is_zero());

    for (size_t i = 0; i < cases.size(); ++i) {
      ASSERT_EQ(12u, exported[i].iv.size);
      ASSERT_EQ(112u, exported[i].blob.size);
      uint8_t plain[96];
      ASSERT_TRUE(monero_probe_decrypt(key, exported[i].iv.bytes,
                                       exported[i].blob.bytes, plain))
          << cases[i]->label;
      EXPECT_EQ(0, std::memcmp(plain, cases[i]->key_image, 32))
          << cases[i]->label;
      EXPECT_TRUE(
          monero_probe_verify_signature(plain, cases[i]->output_public))
          << cases[i]->label;
    }
  }
}

TEST_F(MoneroSession, WrongTranscriptReleasesNoKeyAndWipes) {
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  init.hash.bytes[0] ^= 1;
  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  MoneroKeyImageSyncStepRequest step = {};
  step.tdis_count = 1;
  step.tdis[0] = tds[0];
  MoneroKeyImageSyncStepAck ack = {};
  ASSERT_TRUE(monero_key_image_step(&step, &ack, nullptr));
  uint8_t key[32];
  std::memset(key, 0xa5, sizeof(key));
  EXPECT_FALSE(monero_key_image_finish(key));
  EXPECT_EQ(std::string(32, '\0'), std::string((char*)key, 32));
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, FinishBeforeEveryOutputFails) {
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true),
                                            transfer(*cases[1], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  MoneroKeyImageSyncStepRequest step = {};
  step.tdis_count = 1;
  step.tdis[0] = tds[0];
  MoneroKeyImageSyncStepAck ack = {};
  ASSERT_TRUE(monero_key_image_step(&step, &ack, nullptr));
  uint8_t key[32];
  EXPECT_FALSE(monero_key_image_finish(key));
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, MoreOutputsThanAnnouncedEndTheSession) {
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  MoneroKeyImageSyncStepRequest step = {};
  step.tdis_count = 2;
  step.tdis[0] = step.tdis[1] = tds[0];
  MoneroKeyImageSyncStepAck ack = {};
  EXPECT_FALSE(monero_key_image_step(&step, &ack, nullptr));
  EXPECT_EQ(0u, ack.kis_count);
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, ForeignOutputIsRefusedAndEndsTheSession) {
  /* An output of the other fixture wallet: ownership fails. */
  const auto mine = wallet_cases("abandon-account0");
  const auto theirs = wallet_cases("trezor-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*theirs[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  ASSERT_TRUE(monero_key_image_begin(mine[0]->key_seed, &init));
  MoneroKeyImageSyncStepRequest step = {};
  step.tdis_count = 1;
  step.tdis[0] = tds[0];
  MoneroKeyImageSyncStepAck ack = {};
  EXPECT_FALSE(monero_key_image_step(&step, &ack, nullptr));
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, TorsionedOrNoncanonicalKeysAreRefused) {
  const auto cases = wallet_cases("abandon-account0");
  /* A point of order 4 (y = 0) as R, the same as the output key, and a
   * noncanonical encoding (y = p + 1, which reduces to the identity). */
  static const uint8_t order4[32] = {0};
  static const uint8_t noncanonical[32] = {
      0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
  for (int variant = 0; variant < 3; ++variant) {
    MoneroTransferDetails td = transfer(*cases[0], true);
    if (variant == 0)
      std::memcpy(td.tx_pub_key.bytes, order4, 32);
    else if (variant == 1)
      std::memcpy(td.out_key.bytes, order4, 32);
    else
      std::memcpy(td.tx_pub_key.bytes, noncanonical, 32);
    std::vector<MoneroTransferDetails> tds = {td};
    MoneroKeyImageExportInitRequest init = init_request(tds);
    ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
    MoneroKeyImageSyncStepRequest step = {};
    step.tdis_count = 1;
    step.tdis[0] = td;
    MoneroKeyImageSyncStepAck ack = {};
    EXPECT_FALSE(monero_key_image_step(&step, &ack, nullptr)) << variant;
    EXPECT_TRUE(signing_session_is_zero());
  }
}

TEST_F(MoneroSession, InitIsValidated) {
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  init.num = MONERO_KEY_IMAGE_MAX_OUTPUTS + 1;
  EXPECT_FALSE(monero_key_image_begin(cases[0]->key_seed, &init));
  init = init_request(tds);
  init.hash.size = 31;
  EXPECT_FALSE(monero_key_image_begin(cases[0]->key_seed, &init));
  init = init_request(tds);
  init.subs[0].minor_indices_count = 0;
  EXPECT_FALSE(monero_key_image_begin(cases[0]->key_seed, &init));
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  EXPECT_TRUE(signing_session_is_zero());
}

#if ZCASH_PRIVACY
TEST_F(MoneroSession, ArenaHasOneOwnerAtATime) {
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  EXPECT_EQ(nullptr, signing_session_get(SIGNING_SESSION_ZCASH));
  EXPECT_EQ(nullptr, signing_session_claim(SIGNING_SESSION_FREE));

  /* Zcash holds it: Monero can neither read it nor take it. */
  uint8_t* zcash = (uint8_t*)signing_session_claim(SIGNING_SESSION_ZCASH);
  ASSERT_NE(nullptr, zcash);
  std::memset(zcash, 0x5a, 64);
  EXPECT_EQ(nullptr, signing_session_get(SIGNING_SESSION_MONERO_KEY_IMAGE));
  EXPECT_EQ(nullptr, signing_session_claim(SIGNING_SESSION_MONERO_KEY_IMAGE));
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  EXPECT_FALSE(monero_key_image_begin(cases[0]->key_seed, &init));
  EXPECT_FALSE(monero_key_image_active());
  /* A Monero abort leaves the Zcash bytes alone. */
  monero_session_abort();
  EXPECT_EQ(SIGNING_SESSION_ZCASH, signing_session_owner());
  EXPECT_EQ(0x5a, zcash[0]);
  EXPECT_EQ(0x5a, zcash[63]);

  /* Once Zcash releases, Monero gets a wiped arena. */
  zcash_signing_abort();
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  EXPECT_TRUE(signing_session_is_zero());
  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  EXPECT_EQ(SIGNING_SESSION_MONERO_KEY_IMAGE, signing_session_owner());
  EXPECT_FALSE(signing_session_is_zero());
  /* Monero's bytes never read as an active Zcash session. */
  EXPECT_FALSE(zcash_signing_is_active());
  /* A Zcash abort leaves Monero's session alone. */
  zcash_signing_abort();
  EXPECT_TRUE(monero_key_image_active());
  EXPECT_EQ(nullptr, signing_session_claim(SIGNING_SESSION_ZCASH));
}
#endif

TEST_F(MoneroSession, EveryRevocationWipesTheSession) {
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);

  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  fsm_abort_signing_workflows();
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());

  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  session_clear(true); /* lock, PIN failure, Initialize, ClearSession */
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, DispatchGateKeepsOnlyStatusRequestsAndOwnSteps) {
  const auto cases = wallet_cases("abandon-account0");
  std::vector<MoneroTransferDetails> tds = {transfer(*cases[0], true)};
  MoneroKeyImageExportInitRequest init = init_request(tds);
  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));

  for (MessageType keep :
       {MessageType_MessageType_GetFeatures, MessageType_MessageType_GetCoinTable,
        MessageType_MessageType_MoneroKeyImageSyncStepRequest,
        MessageType_MessageType_MoneroKeyImageSyncFinalRequest}) {
    EXPECT_TRUE(keepkey_before_message_dispatch(keep)) << keep;
    EXPECT_TRUE(monero_key_image_active()) << keep;
  }
  /* Ping is answered, but it ends the sync. */
  EXPECT_TRUE(keepkey_before_message_dispatch(MessageType_MessageType_Ping));
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());

  /* A step without a session is refused as stale. */
  EXPECT_FALSE(keepkey_before_message_dispatch(
      MessageType_MessageType_MoneroKeyImageSyncStepRequest));
  EXPECT_FALSE(keepkey_before_message_dispatch(
      MessageType_MessageType_MoneroKeyImageSyncFinalRequest));

  /* Any other top-level request ends it too, before its handler runs. */
  ASSERT_TRUE(monero_key_image_begin(cases[0]->key_seed, &init));
  EXPECT_TRUE(
      keepkey_before_message_dispatch(MessageType_MessageType_GetAddress));
  EXPECT_FALSE(monero_key_image_active());
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, BeginPublishesOnlyInitializedState) {
  const auto& c = monero_core_cases[0];
  auto init = init_request({transfer(c, true)});
  advance_monero_test_clock(120001);
  monero_session_interrupt = [] {
    EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
    keepkey_user_activity();
    EXPECT_FALSE(fsm_workflowInProgress());
  };
  const bool ok = probe_monero_key_image_begin(c.key_seed, &init);
  monero_session_interrupt = nullptr;
  ASSERT_TRUE(ok);
  EXPECT_TRUE(monero_key_image_active());
  monero_session_abort();
  EXPECT_TRUE(signing_session_is_zero());
}

TEST_F(MoneroSession, ActivityDuringAnExpiringStepCannotWipeItsCountOrKeys) {
  const auto& c = monero_core_cases[0];
  const auto td = transfer(c, true);
  auto init = init_request({td});
  ASSERT_TRUE(monero_key_image_begin(c.key_seed, &init));
  monero_session_interrupt = [] {
    advance_monero_test_clock(120001);
    const auto before = signing_session_arena;
    EXPECT_FALSE(monero_key_image_active());
    keepkey_user_activity();
    EXPECT_EQ(SIGNING_SESSION_MONERO_KEY_IMAGE, signing_session_owner());
    EXPECT_EQ(0, memcmp(&before, &signing_session_arena, sizeof(before)));
    monero_session_interrupt = nullptr;
  };
  MoneroKeyImageSyncStepRequest step = {};
  step.tdis_count = 1;
  step.tdis[0] = td;
  MoneroKeyImageSyncStepAck ack = {};
  uint32_t permil = 0;
  ASSERT_TRUE(probe_monero_key_image_step(&step, &ack, &permil));
  monero_session_interrupt = nullptr;
  EXPECT_EQ(1000u, permil);
  uint8_t key[32];
  memset(key, 0xa5, sizeof(key));
  EXPECT_FALSE(monero_key_image_finish(key));
  EXPECT_TRUE(signing_session_is_zero());
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  for (auto b : key) EXPECT_EQ(0, b);
}

TEST_F(MoneroSession, ValidatedKeyImageStepDefersLockUntilProgressStalls) {
  const auto& c = monero_core_cases[0];
  const auto td = transfer(c, true);
  auto init = init_request({td});
  layoutHomeForced();
  ASSERT_TRUE(monero_key_image_begin(c.key_seed, &init));
  const uint32_t delay = storage_getAutoLockDelayMs();
  increment_idle_time(delay / 2);
  MoneroKeyImageSyncStepRequest step = {};
  step.tdis_count = 1;
  step.tdis[0] = td;
  fsm_msgMoneroKeyImageSyncStep(&step);
  increment_idle_time(delay - delay / 2);
  EXPECT_FALSE(auto_lock_if_due());
  EXPECT_TRUE(monero_key_image_active());
  increment_idle_time(delay / 2);
  EXPECT_TRUE(auto_lock_if_due());
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  layoutHomeForced();
  reset_idle_time();
}

TEST_F(MoneroSession, DispatchExpiresAnIdleKeyImageSession) {
  const auto& c = monero_core_cases[0];
  auto init = init_request({transfer(c, true)});
  ASSERT_TRUE(monero_key_image_begin(c.key_seed, &init));
  advance_monero_test_clock(120001);
  keepkey_user_activity();
  EXPECT_EQ(SIGNING_SESSION_MONERO_KEY_IMAGE, signing_session_owner());
  EXPECT_TRUE(keepkey_before_message_dispatch(MessageType_MessageType_GetFeatures));
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  EXPECT_TRUE(signing_session_is_zero());
}

TEST(SigningSession, UnpublishedReservationIsExclusiveAndCanBeWiped) {
  fsm_abort_signing_workflows();
  auto* arena = signing_session_prepare(SIGNING_SESSION_MONERO_TX);
  ASSERT_NE(nullptr, arena);
  memset(arena, 0xa5, sizeof(signing_session_arena));
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
  EXPECT_EQ(nullptr, signing_session_get(SIGNING_SESSION_MONERO_TX));
  EXPECT_EQ(nullptr, signing_session_claim(SIGNING_SESSION_ZCASH));
  monero_session_abort();
  EXPECT_TRUE(signing_session_is_zero());
  EXPECT_NE(nullptr, signing_session_claim(SIGNING_SESSION_ZCASH));
  signing_session_release(SIGNING_SESSION_ZCASH);
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
}

#if ZCASH_PRIVACY
TEST(SigningSession, ZcashActivityPredicateDoesNotModifyTheArena) {
  fsm_abort_signing_workflows();
  ASSERT_NE(nullptr, signing_session_claim(SIGNING_SESSION_ZCASH));
  signing_session_arena.zcash.active = true;
  const auto before = signing_session_arena;
  advance_monero_test_clock(MONERO_TX_SESSION_MS + 1);
  keepkey_user_activity();
  EXPECT_TRUE(zcash_signing_is_active());
  EXPECT_TRUE(fsm_workflowInProgress());
  EXPECT_EQ(0, memcmp(&before, &signing_session_arena, sizeof(before)));
  fsm_abort_signing_workflows();
}

#endif
