extern "C" {
#include "keepkey/board/memory.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/tron.h"
#include "keepkey/firmware/mayachain.h"
#include "storage.h"
}
#include "gtest/gtest.h"
#include <cstring>
#include <vector>

bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);

class ReviewHandlers : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous;
  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    previous = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    fsm_test_clearLastFailure();
  }
  void TearDown() override {
    fsm_abort_workflows();
    kkconfirm_drain();
    storage_wipe();
    storage_reset();
    emulator_flash_base = previous;
  }
};

TEST_F(ReviewHandlers, NewerWalletRefusesEveryMutationBeforeConsent) {
  char record[STORAGE_SECTOR_LEN] = {};
  memcpy(record, "stor", 4);
  record[44] = STORAGE_VERSION + 1;
  SessionState session = {};
  ConfigFlash shadow = {};
  ASSERT_EQ(SUS_TooNew, storage_fromFlash(&session, &shadow, record));
  std::fill(flash.begin(), flash.end(), 0xff);
  memcpy(flash.data() + 0x4000, record, sizeof(record));
  storage_init();
  ASSERT_TRUE(storage_isFirmwareTooOld());
  const auto unchanged = flash;
  ChangePin pin = {};
  ChangeWipeCode wipe_code = {};
  LoadDevice load = {};
  ResetDevice reset = {};
  ApplySettings settings = {};
  ApplyPolicies policies = {};
  RecoveryDevice recovery = {};
#define REFUSED(call)                                               \
  fsm_test_clearLastFailure();                                      \
  call;                                                             \
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode()); \
  EXPECT_EQ(unchanged, flash);                                      \
  EXPECT_FALSE(setup_isArmed())
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  REFUSED(fsm_msgChangePin(&pin));
  REFUSED(fsm_msgChangeWipeCode(&wipe_code));
  REFUSED(fsm_msgLoadDevice(&load));
  REFUSED(fsm_msgResetDevice(&reset));
  REFUSED(fsm_msgApplySettings(&settings));
  REFUSED(fsm_msgApplyPolicies(&policies));
  REFUSED(fsm_msgRecoveryDevice(&recovery));
  EXPECT_EQ(2, kkconfirm_drain());
#undef REFUSED
  // Wipe still requires consent, including when firmware cannot read the
  // wallet.
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  WipeDevice wipe = {};
  fsm_test_clearLastFailure();
  fsm_msgWipeDevice(&wipe);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(unchanged, flash);
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  fsm_test_clearLastFailure();
  fsm_msgWipeDevice(&wipe);
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_FALSE(storage_isFirmwareTooOld());
  EXPECT_NE(unchanged, flash);
  EXPECT_EQ(0, kkconfirm_drain());
}

#if !BITCOIN_ONLY
static TronSignMessage message(size_t size, bool binary) {
  TronSignMessage msg = {};
  msg.address_n_count = 3;
  msg.address_n[0] = 0x80000000 | 44;
  msg.address_n[1] = 0x80000000 | 195;
  msg.address_n[2] = 0x80000000;
  msg.has_message = true;
  msg.message.size = size;
  memset(msg.message.bytes, binary ? 0 : 'W', size);
  if (size) msg.message.bytes[size - 1] = 'Z';
  return msg;
}

TEST_F(ReviewHandlers, MissingAndEmptyTronMessageNeverRequestsConsent) {
  for (bool present : {false, true}) {
    auto msg = message(0, false);
    msg.has_message = present;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignMessage(&msg);
    EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

static int page_count(const uint8_t* bytes, size_t size) {
  int pages = 0;
  for (size_t offset = 0; offset < size; ++pages) {
    char page[BODY_CHAR_MAX];
    size_t n = confirm_bytes_format_page(bytes + offset, size - offset, page,
                                         sizeof(page));
    if (!n) return 0;
    offset += n;
  }
  return pages;
}

TEST_F(ReviewHandlers, RejectTronSignedAndVerifiedMessageTail) {
  for (bool binary : {false, true}) {
    auto msg = message(200, binary);
    const int pages = page_count(msg.message.bytes, msg.message.size);
    ASSERT_GT(pages, 1);
    ASSERT_TRUE(kkconfirm_preload(pages - 1, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignMessage(&msg);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_EQ(0, kkconfirm_drain());

    HDNode node = {};
    ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
    for (uint32_t step : {msg.address_n[0], msg.address_n[1], msg.address_n[2]})
      ASSERT_TRUE(hdnode_private_ckd(&node, step));
    hdnode_fill_public_key(&node);
    TronMessageSignature signature = {};
    ASSERT_TRUE(tron_message_sign(&node, &msg, &signature));
    TronVerifyMessage verify = {};
    verify.has_message = verify.has_signature = verify.has_address = true;
    verify.message.size = msg.message.size;
    memcpy(verify.message.bytes, msg.message.bytes, msg.message.size);
    verify.signature.size = signature.signature.size;
    memcpy(verify.signature.bytes, signature.signature.bytes,
           signature.signature.size);
    strcpy(verify.address, signature.address);
    ASSERT_EQ(0, tron_message_verify(&verify));
    ASSERT_TRUE(kkconfirm_preload(pages, 1));  // signer + all but final page
    fsm_test_clearLastFailure();
    fsm_msgTronVerifyMessage(&verify);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

TEST_F(ReviewHandlers, MayaDefaultDenomReachesConsentForMissingAndEmptyField) {
  for (bool present : {false, true}) {
    HDNode node = {};
    ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
    hdnode_fill_public_key(&node);
    MayachainSignTx tx = {};
    tx.has_chain_id = tx.has_msg_count = true;
    strcpy(tx.chain_id, "mayachain");
    tx.msg_count = 1;
    ASSERT_TRUE(mayachain_signTxInit(&node, &tx));
    MayachainMsgAck ack = {};
    ack.has_send = true;
    ack.send.has_to_address = ack.send.has_amount = true;
    ack.send.amount = 1;
    ack.send.has_denom = present;
    strcpy(ack.send.to_address, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k");
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    fsm_test_clearLastFailure();
    fsm_msgMayachainMsgAck(&ack);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_FALSE(mayachain_signingIsInited());
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

TEST_F(ReviewHandlers, MayaDepositGrammarRejectedBeforeConsent) {
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
  MayachainSignTx tx = {};
  tx.has_chain_id = tx.has_msg_count = true;
  strcpy(tx.chain_id, "mayachain");
  tx.msg_count = 1;
  ASSERT_TRUE(mayachain_signTxInit(&node, &tx));
  MayachainMsgAck ack = {};
  ack.has_deposit = true;
  ack.deposit.has_asset = ack.deposit.has_amount = ack.deposit.has_memo =
      ack.deposit.has_signer = true;
  strcpy(ack.deposit.asset, "MAYA:CACAO");
  strcpy(ack.deposit.signer, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k");
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  fsm_test_clearLastFailure();
  fsm_msgMayachainMsgAck(&ack);
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_EQ(2, kkconfirm_drain());
}
#endif
