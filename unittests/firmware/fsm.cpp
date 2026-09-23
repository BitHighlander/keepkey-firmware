extern "C" {
#include "keepkey/transport/interface.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"
#include "pb_encode.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/bip39.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/tendermint.h"
#include "keepkey/firmware/storage.h"
#include "storage.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/secp256k1.h"

bool keepkey_before_message_dispatch(MessageType msg_id);
}

#include "gtest/gtest.h"

#include <cstring>
#include <algorithm>
#include <vector>

// The shared bootstrap initializes the canvas and timer queues exactly once.
// Calling timer_init() again relinks the static runnable nodes into a cycle.
void kk_test_board_init(void);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Fsm, AuthenticatorCredentialSourceIsWipedOnEveryExit) {
  char credential[] = "site:user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  ASSERT_EQ(LARGESEED, addAuthAccount(credential));

  for (size_t i = 0; i < sizeof(credential); ++i) {
    EXPECT_EQ('\0', credential[i]);
  }
}

TEST(Fsm, ZcashPrivacyWireSurfaceMatchesBuildVariant) {
  fsm_init();
  const MessageType inbound[] = {MessageType_MessageType_ZcashSignPCZT,
                                 MessageType_MessageType_ZcashPCZTAction,
                                 MessageType_MessageType_ZcashGetOrchardFVK,
                                 MessageType_MessageType_ZcashTransparentOutput,
                                 MessageType_MessageType_ZcashTransparentInput,
                                 MessageType_MessageType_ZcashDisplayAddress};
  const MessageType outbound[] = {
      MessageType_MessageType_ZcashPCZTActionAck,
      MessageType_MessageType_ZcashSignedPCZT,
      MessageType_MessageType_ZcashOrchardFVK,
      MessageType_MessageType_ZcashTransparentSigned,
      MessageType_MessageType_ZcashAddress,
      MessageType_MessageType_ZcashTransparentAck};
  for (MessageType type : inbound) {
    EXPECT_EQ(ZCASH_PRIVACY != 0,
              message_fields(NORMAL_MSG, type, IN_MSG) != nullptr)
        << type;
  }
  for (MessageType type : outbound) {
    EXPECT_EQ(ZCASH_PRIVACY != 0,
              message_fields(NORMAL_MSG, type, OUT_MSG) != nullptr)
        << type;
  }
}

#if !BITCOIN_ONLY
static void expectSigningSessionsCleared(bool initialize) {
  HDNode node = {};
  node.curve = &secp256k1_info;

  BinanceSignTx binance = {};
  binance.has_msg_count = true;
  binance.msg_count = 1;
  binance.has_account_number = true;
  binance.has_chain_id = true;
  std::strcpy(binance.chain_id, "Binance-Chain-Nile");
  binance.has_sequence = true;
  binance.has_source = true;
  ASSERT_TRUE(binance_signTxInit(&node, &binance));

  TendermintSignTx tendermint = {};
  tendermint.has_msg_count = true;
  tendermint.msg_count = 1;
  tendermint.has_chain_id = true;
  std::strcpy(tendermint.chain_id, "chain-1");
  tendermint.has_chain_name = true;
  std::strcpy(tendermint.chain_name, "Cosmos");
  tendermint.has_denom = true;
  std::strcpy(tendermint.denom, "uatom");
  tendermint.has_message_type_prefix = true;
  std::strcpy(tendermint.message_type_prefix, "cosmos-sdk");
  ASSERT_TRUE(tendermint_signTxInit(&node, &tendermint, sizeof(tendermint),
                                    "uatom", TENDERMINT_SIGNING_GENERIC));

  OsmosisSignTx osmosis = {};
  osmosis.has_msg_count = true;
  osmosis.msg_count = 1;
  osmosis.has_chain_id = true;
  std::strcpy(osmosis.chain_id, "osmosis-1");
  ASSERT_TRUE(osmosis_signTxInit(&node, &osmosis));

  ThorchainSignTx thorchain = {};
  thorchain.has_msg_count = true;
  thorchain.msg_count = 1;
  thorchain.has_chain_id = true;
  std::strcpy(thorchain.chain_id, "thorchain-1");
  ASSERT_TRUE(thorchain_signTxInit(&node, &thorchain));

  MayachainSignTx mayachain = {};
  mayachain.has_msg_count = true;
  mayachain.msg_count = 1;
  mayachain.has_chain_id = true;
  std::strcpy(mayachain.chain_id, "mayachain-mainnet-v1");
  ASSERT_TRUE(mayachain_signTxInit(&node, &mayachain));

  uint8_t eos_chain_id[32] = {};
  EosTxHeader eos_header = {};
  uint32_t eos_path[8] = {};
  eos_signingInit(eos_chain_id, 1, &eos_header, &node, eos_path, 0);

  ASSERT_TRUE(binance_signingIsInited());
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  ASSERT_TRUE(osmosis_signingIsInited());
  ASSERT_TRUE(thorchain_signingIsInited());
  ASSERT_TRUE(mayachain_signingIsInited());
  ASSERT_TRUE(eos_signingIsInited());

  if (initialize) {
    kk_test_board_init();
    fsm_init();
    fsm_msgInitialize(nullptr);
  } else {
    fsm_abort_workflows();
  }

  EXPECT_FALSE(binance_signingIsInited());
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_FALSE(eos_signingIsInited());
}

TEST(Fsm, AbortWorkflowsClearsEveryObservableSigningSession) {
  expectSigningSessionsCleared(false);
}

TEST(Fsm, InitializeClearsEveryObservableSigningSession) {
  expectSigningSessionsCleared(true);
}

#endif

TEST(Fsm, MissingBitcoinAckPayloadTerminatesSigning) {
  fsm_init();

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);

  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  TxAck missing = {};
  fsm_msgTxAck(&missing);
  EXPECT_FALSE(signing_is_active());

  TxAck stale = {};
  stale.has_tx = true;
  fsm_msgTxAck(&stale);
  EXPECT_FALSE(signing_is_active());
}

TEST(Fsm, AutoLockTerminatesSigningWhileWaitingAwayFromHome) {
  /* Production initializes the OLED before the main loop can auto-lock. Use
   * the firmware suite's one-time board bootstrap to mirror that precondition
   * without reinitializing and corrupting the static timer queues. */
  kk_test_board_init();

  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  EXPECT_TRUE(signing_is_active());

  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());

  /* Restore a deterministic home state for subsequent tests. */
  layoutHomeForced();
}

/* The lock path aborts signing, and signing_abort() draws the home screen,
 * which resets the idle timer. If that reset stands, the very next tick sees
 * an idle device and replaces the screensaver with the home screen. */
TEST(Fsm, AutoLockKeepsTheScreensaverAfterAbortingSigning) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  ASSERT_FALSE(signing_is_active());
  ASSERT_EQ(SCREENSAVER, home_get_state());

  increment_idle_time(1000);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "a locked device must stay on the screensaver, not wake to home";

  layoutHomeForced();
}

namespace {
void receiveMessage(MessageType type, const pb_field_t* fields,
                    const void* msg) {
  uint8_t encoded[4096] = {};
  pb_ostream_t stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
  ASSERT_TRUE(pb_encode(&stream, fields, msg));
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = type >> 8;
  frame[4] = type & 0xff;
  const size_t size = stream.bytes_written;
  frame[5] = size >> 24;
  frame[6] = size >> 16;
  frame[7] = size >> 8;
  frame[8] = size;
  size_t sent = std::min(size, sizeof(frame) - 9);
  std::memcpy(frame + 9, encoded, sent);
  usb_test_receive(frame, sizeof(frame));
  while (sent < size) {
    std::memset(frame + 1, 0, sizeof(frame) - 1);
    const size_t chunk = std::min(size - sent, sizeof(frame) - 1);
    std::memcpy(frame + 1, encoded + sent, chunk);
    usb_test_receive(frame, sizeof(frame));
    sent += chunk;
  }
}

// firmware-unit never maps emulated flash; tests whose handlers commit storage
// borrow a zeroed image for their duration.
struct ScopedFlash {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  ScopedFlash() {
    emulator_flash_base = bytes.data();
    storage_init();
  }
  ~ScopedFlash() {
    storage_reset();
    emulator_flash_base = previous;
  }
};

class AutoLockProgress : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    setup_abort();
    layoutHomeForced();
    storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
    SignTx start = {};
    start.inputs_count = start.outputs_count = 1;
    HDNode root = {};
    const uint8_t seed[32] = {1};
    ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
    signing_init(&start, coinByName("Bitcoin"), &root);
    ASSERT_TRUE(signing_is_active());
    leave_home();
  }
  void TearDown() override {
    fsm_abort_workflows();
    setup_abort();
  }
};
}  // namespace

TEST_F(AutoLockProgress, FeaturePollingCannotKeepStalledSigningUnlocked) {
  GetFeatures poll = {};
  for (int i = 0; i < 4; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    ASSERT_EQ(AWAY_FROM_HOME, home_get_state());
    ASSERT_TRUE(signing_is_active());
    toggle_screensaver();
  }
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST(Fsm, DispatchScrubsDerivedKeyScratchAfterHandler) {
  fsm_init();
  fsm_test_seedDerivedNode();
  ASSERT_FALSE(fsm_test_derivedNodeIsZero());

  GetFeatures request = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &request);

  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
}

TEST(Fsm, InactiveBitcoinAckGetsATerminalResponse) {
  fsm_init();
  fsm_abort_workflows();
  fsm_test_clearLastFailure();

  TxAck stale = {};
  stale.has_tx = true;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &stale);

  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "silently dropping an inactive ACK leaves the host blocked";
  EXPECT_FALSE(signing_is_active());
}

TEST_F(AutoLockProgress, IncompleteFrameCannotKeepStalledSigningUnlocked) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  // Valid Ping header, but its 60-byte payload has not arrived in full.
  uint8_t frame[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 60};
  usb_test_receive(frame, sizeof(frame));
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  // Finish the pending transport message so it cannot affect later tests.
  uint8_t tail[64] = {'?'};
  usb_test_receive(tail, sizeof(tail));
}

TEST_F(AutoLockProgress, ValidBitcoinStreamProgressRenewsTheIdleDeadline) {
  TxAck ack = {};
  ack.has_tx = true;
  ack.tx.inputs_count = 1;
  ack.tx.inputs[0].prev_hash.size = 32;
  ack.tx.inputs[0].has_script_type = true;
  ack.tx.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());

  // Real next stage: supply metadata for the requested previous transaction.
  ack = {};
  ack.has_tx = true;
  ack.tx.has_inputs_cnt = ack.tx.has_outputs_cnt = true;
  ack.tx.inputs_cnt = ack.tx.outputs_cnt = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, FeaturePollingAtHomeDoesNotRenewTheIdleDeadline) {
  signing_abort();
  layoutHomeForced();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, PingCannotRenewAStalledSigningDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  Ping ping = {};
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, ProtectedPingCannotSuspendAnOlderSigningSession) {
  Ping ping = {};
  ping.has_pin_protection = true;
  ping.pin_protection = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);

  EXPECT_FALSE(signing_is_active());
}

TEST_F(AutoLockProgress, TopLevelConfirmationEndsAnOlderSigningSession) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  ChangePin request = {};
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_ChangePin, ChangePin_fields, &request);

  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(AutoLockProgress, TopLevelBoundaryEndsSigningButIsNotALock) {
  // AdvancedMode is the observable here: without a PIN, session_clear()
  // re-caches the empty PIN, so a PIN-cache check would pass even under a lock.
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  EXPECT_TRUE(
      keepkey_before_message_dispatch(MessageType_MessageType_ChangePin));
  EXPECT_FALSE(signing_is_active());

  EXPECT_TRUE(storage_isPolicyEnabled("AdvancedMode"))
      << "an ordinary request must not disarm AdvancedMode before signing";
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  storage_reset();
}

TEST_F(AutoLockProgress, NewSigningRequestCannotCoexistWithRecovery) {
  signing_abort();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  EXPECT_TRUE(keepkey_before_message_dispatch(MessageType_MessageType_SignTx));

  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(signing_is_active());
  layoutHomeForced();
}

TEST_F(AutoLockProgress, HostDrivenLayoutChangesDoNotRenewTheDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  layoutHome();
  leave_home();
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST(Fsm, SolanaCertificateIsRejectedAtTheProductionHandler) {
  kk_test_board_init();
  fsm_init();
  fsm_test_clearLastFailure();

  SolanaSignTx request = {};
  request.has_clearsign_certificate = true;
  request.clearsign_certificate.size = 1;
  request.clearsign_certificate.bytes[0] = 0x01;
  receiveMessage(MessageType_MessageType_SolanaSignTx, SolanaSignTx_fields,
                 &request);

  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "a decoded certificate must not fall through to ordinary signing";
  layoutHomeForced();
}
#endif

TEST_F(AutoLockProgress, InvalidBitcoinAckEndsTheStream) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TxAck invalid = {};
  invalid.has_tx = true;
  // Decodable protobuf, but the required 32-byte previous hash is missing.
  invalid.tx.inputs_count = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &invalid);
  EXPECT_FALSE(signing_is_active());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, RecoveryEditsRenewButPollingAndEmptyDeleteDoNot) {
  signing_abort();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "idle test", false,
                       STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(0, kkconfirm_drain());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  CharacterAck character = {};
  character.has_character = true;
  character.character[0] = 'a';  // Every a-z character belongs to the cipher.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  character = {};
  character.has_delete = character.del = true;
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  // The mnemonic is now empty: another delete makes no progress.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST_F(AutoLockProgress, EthereumChunksRenewButFeaturePollingDoesNot) {
  signing_abort();
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct RestorePolicy {
    ~RestorePolicy() { storage_setPolicy("AdvancedMode", false); }
  } restore;
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EthereumSignTx start = {};
  start.has_chain_id = true;
  start.chain_id = 1;
  start.has_gas_price = start.has_gas_limit = true;
  start.gas_price.size = start.gas_limit.size = 1;
  start.gas_price.bytes[0] = start.gas_limit.bytes[0] = 1;
  start.has_to = true;
  start.to.size = 20;
  start.to.bytes[0] = 1;
  start.has_data_initial_chunk = start.has_data_length = true;
  start.data_initial_chunk.size = 1;
  start.data_initial_chunk.bytes[0] = 1;
  start.data_length = 4096;
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
  ethereum_signing_init(&start, &node, false);
  ASSERT_TRUE(ethereum_signing_isInProgress());
  ASSERT_EQ(0, kkconfirm_drain());
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  for (int i = 0; i < 2; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    EthereumTxAck chunk = {};
    chunk.has_data_chunk = true;
    chunk.data_chunk.size = 128;  // Requires multiple USB frames.
    receiveMessage(MessageType_MessageType_EthereumTxAck, EthereumTxAck_fields,
                   &chunk);
    toggle_screensaver();
    ASSERT_TRUE(ethereum_signing_isInProgress());
  }
  GetFeatures poll = {};
  for (int i = 0; i < 4; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    toggle_screensaver();
  }
  EXPECT_FALSE(ethereum_signing_isInProgress());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, EosDataProgressRenewsButEmptyChunksDoNot) {
  signing_abort();
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct RestorePolicy {
    ~RestorePolicy() { storage_setPolicy("AdvancedMode", false); }
  } restore;
  HDNode node = {};
  node.curve = &secp256k1_info;
  uint8_t chain_id[32] = {};
  EosTxHeader header = {};
  uint32_t path[8] = {};
  eos_signingInit(chain_id, 1, &header, &node, path, 0);
  ASSERT_TRUE(eos_signingIsInited());
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  EosTxActionAck ack = {};
  ack.has_common = ack.has_unknown = true;
  ack.common.has_account = ack.common.has_name = true;
  ack.common.account = 0x1111;
  ack.common.name = 0x2222;
  ack.common.authorization_count = 1;
  ack.common.authorization[0].has_actor = true;
  ack.common.authorization[0].actor = 0x3333;
  ack.common.authorization[0].has_permission = true;
  ack.common.authorization[0].permission = 0x4444;
  ack.unknown.has_data_size = ack.unknown.has_data_chunk = true;
  ack.unknown.data_size = 256;
  ack.unknown.data_chunk.size = 1;
  for (int i = 0; i < 2; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_EosTxActionAck,
                   EosTxActionAck_fields, &ack);
    toggle_screensaver();
    ASSERT_TRUE(eos_signingIsInited());
  }
  ack.unknown.data_chunk.size = 0;
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_EosTxActionAck, EosTxActionAck_fields,
                 &ack);
  ASSERT_TRUE(eos_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(eos_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}
#endif

// Drive the real protobuf dispatch at the old deadline. Each initial request
// must buy a fresh interval; polling during the next interval must not.
TEST_F(AutoLockProgress, ResetEntropyRequestRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  storage_reset();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  ResetDevice start = {};
  start.has_strength = true;
  start.strength = 128;
  receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                 &start);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST_F(AutoLockProgress, BinanceStartRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  BinanceSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_source = true;
  std::strcpy(start.chain_id, "Binance-Chain-Nile");
  receiveMessage(MessageType_MessageType_BinanceSignTx, BinanceSignTx_fields,
                 &start);
  ASSERT_TRUE(binance_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(binance_signingIsInited());
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(binance_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(binance_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, CosmosStartRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  CosmosSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  receiveMessage(MessageType_MessageType_CosmosSignTx, CosmosSignTx_fields,
                 &start);
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

// Generic Tendermint is compiled but has no message-map entries. Do not
// enable a dormant protocol merely to exercise its internal renewal hook.
TEST_F(AutoLockProgress, UnregisteredTendermintCannotRenewTheDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TendermintSignTx start = {};
  receiveMessage(MessageType_MessageType_TendermintSignTx,
                 TendermintSignTx_fields, &start);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, OsmosisStartRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  OsmosisSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  receiveMessage(MessageType_MessageType_OsmosisSignTx, OsmosisSignTx_fields,
                 &start);
  ASSERT_TRUE(osmosis_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(osmosis_signingIsInited());
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(osmosis_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, ThorchainStartRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  ThorchainSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  receiveMessage(MessageType_MessageType_ThorchainSignTx,
                 ThorchainSignTx_fields, &start);
  ASSERT_TRUE(thorchain_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(thorchain_signingIsInited());
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(thorchain_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, MayachainStartRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  MayachainSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  receiveMessage(MessageType_MessageType_MayachainSignTx,
                 MayachainSignTx_fields, &start);
  ASSERT_TRUE(mayachain_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(mayachain_signingIsInited());
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(mayachain_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, BinanceContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  BinanceSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_source = true;
  std::strcpy(start.chain_id, "Binance-Chain-Nile");
  receiveMessage(MessageType_MessageType_BinanceSignTx, BinanceSignTx_fields,
                 &start);
  ASSERT_TRUE(binance_signingIsInited());
  HDNode signer = {};
  ASSERT_TRUE(storage_getRootNode("secp256k1", false, &signer));
  hdnode_fill_public_key(&signer);
  BinanceTransferMsg ack = {};
  ack.inputs_count = ack.outputs_count = 1;
  ack.inputs[0].has_address = ack.outputs[0].has_address = true;
  ASSERT_TRUE(tendermint_getAddress(&signer, "tbnb", ack.inputs[0].address));
  std::strcpy(ack.outputs[0].address,
              "tbnb1ss57e8sa7xnwq030k2ctr775uac9gjzglqhvpy");
  ack.inputs[0].coins_count = ack.outputs[0].coins_count = 1;
  ack.inputs[0].coins[0].has_amount = ack.outputs[0].coins[0].has_amount = true;
  ack.inputs[0].coins[0].amount = ack.outputs[0].coins[0].amount = 1;
  ack.inputs[0].coins[0].has_denom = ack.outputs[0].coins[0].has_denom = true;
  std::strcpy(ack.inputs[0].coins[0].denom, "BNB");
  std::strcpy(ack.outputs[0].coins[0].denom, "BNB");
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                   BinanceTransferMsg_fields, &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(binance_signingIsInited());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(binance_signingIsInited());
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                 BinanceTransferMsg_fields, &ack);
  EXPECT_FALSE(binance_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, CosmosContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  CosmosSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_fee_amount = start.has_gas = true;
  std::strcpy(start.chain_id, "chain-1");
  receiveMessage(MessageType_MessageType_CosmosSignTx, CosmosSignTx_fields,
                 &start);
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  HDNode recipient = {};
  const uint8_t seed[32] = {7};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &recipient));
  hdnode_fill_public_key(&recipient);
  CosmosMsgAck ack = {};
  ack.has_send = ack.send.has_to_address = ack.send.has_amount = true;
  ack.send.amount = 1;
  ASSERT_TRUE(tendermint_getAddress(&recipient, "cosmos", ack.send.to_address));
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                   &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                 &ack);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, OsmosisContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  OsmosisSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_fee_amount = start.has_gas = true;
  std::strcpy(start.chain_id, "chain-1");
  receiveMessage(MessageType_MessageType_OsmosisSignTx, OsmosisSignTx_fields,
                 &start);
  ASSERT_TRUE(osmosis_signingIsInited());
  HDNode recipient = {};
  const uint8_t seed[32] = {7};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &recipient));
  hdnode_fill_public_key(&recipient);
  OsmosisMsgAck ack = {};
  ack.has_send = ack.send.has_to_address = ack.send.has_amount = true;
  std::strcpy(ack.send.amount, "1");
  ASSERT_TRUE(tendermint_getAddress(&recipient, "osmo", ack.send.to_address));
  ack.send.has_denom = true;
  std::strcpy(ack.send.denom, "uosmo");
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_OsmosisMsgAck, OsmosisMsgAck_fields,
                   &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(osmosis_signingIsInited());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(osmosis_signingIsInited());
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_OsmosisMsgAck, OsmosisMsgAck_fields,
                 &ack);
  EXPECT_FALSE(osmosis_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, ThorchainContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  ThorchainSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_fee_amount = start.has_gas = true;
  std::strcpy(start.chain_id, "chain-1");
  receiveMessage(MessageType_MessageType_ThorchainSignTx,
                 ThorchainSignTx_fields, &start);
  ASSERT_TRUE(thorchain_signingIsInited());
  HDNode recipient = {};
  const uint8_t seed[32] = {7};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &recipient));
  hdnode_fill_public_key(&recipient);
  ThorchainMsgAck ack = {};
  ack.has_send = ack.send.has_to_address = ack.send.has_amount = true;
  ack.send.amount = 1;
  ASSERT_TRUE(tendermint_getAddress(&recipient, "thor", ack.send.to_address));
  ack.send.has_denom = true;
  std::strcpy(ack.send.denom, "rune");
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_ThorchainMsgAck,
                   ThorchainMsgAck_fields, &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(thorchain_signingIsInited());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(thorchain_signingIsInited());
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_ThorchainMsgAck,
                 ThorchainMsgAck_fields, &ack);
  EXPECT_FALSE(thorchain_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, MayachainContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  MayachainSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_fee_amount = start.has_gas = true;
  std::strcpy(start.chain_id, "chain-1");
  receiveMessage(MessageType_MessageType_MayachainSignTx,
                 MayachainSignTx_fields, &start);
  ASSERT_TRUE(mayachain_signingIsInited());
  HDNode recipient = {};
  const uint8_t seed[32] = {7};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &recipient));
  hdnode_fill_public_key(&recipient);
  MayachainMsgAck ack = {};
  ack.has_send = ack.send.has_to_address = ack.send.has_amount = true;
  ack.send.amount = 1;
  ASSERT_TRUE(tendermint_getAddress(&recipient, "maya", ack.send.to_address));
  ack.send.has_denom = true;
  std::strcpy(ack.send.denom, "cacao");
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_MayachainMsgAck,
                   MayachainMsgAck_fields, &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(mayachain_signingIsInited());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(mayachain_signingIsInited());
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_MayachainMsgAck,
                 MayachainMsgAck_fields, &ack);
  EXPECT_FALSE(mayachain_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, EosStartRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  EosSignTx start = {};
  start.has_chain_id = start.has_header = start.has_num_actions = true;
  start.chain_id.size = 32;
  start.num_actions = 2;
  receiveMessage(MessageType_MessageType_EosSignTx, EosSignTx_fields, &start);
  ASSERT_TRUE(eos_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(eos_signingIsInited());
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(eos_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(eos_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#endif

// This integration-style case remaps emulator flash and drives the address
// failure UI. Keep it last in the fixture group so its process-global layout
// state cannot contaminate the setup of another AutoLockProgress case.
TEST_F(AutoLockProgress, MalformedMultisigAddressCannotRenewTheDeadline) {
  ScopedFlash flash;

  signing_abort();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
  signing_init(&start, coinByName("Bitcoin"), &root);
  ASSERT_TRUE(signing_is_active());
  leave_home();

  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetAddress malformed = {};
  malformed.has_multisig = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_GetAddress, GetAddress_fields,
                 &malformed);
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode())
      << "the request must reach the multisig rejection, not an earlier gate";
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

/* Clearing PIN authorization revokes signing, but must not discard a staged
 * setup ceremony: recovery stages before it prompts for the PIN, and every
 * routine PIN entry lands here through the wipe-code probe. */
TEST(Fsm, PinRevocationKeepsAStagedCeremony) {
  fsm_init();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "dry run", 0, 0, false));

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, /*clear_pin=*/true);

  setup_arm(SETUP_RECOVERY);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY))
      << "the PIN prompt must not disarm the ceremony it was asked for";

  setup_abort();
}

/* ... while the paths that really do end a session still discard it. */
TEST(Fsm, SessionClearDiscardsAStagedCeremony) {
  fsm_init();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  fsm_abort_workflows();
  EXPECT_FALSE(setup_isArmedAs(SETUP_RESET));

  setup_abort();
}

TEST(Fsm, InvalidSecondBitcoinStartTerminatesOldSigning) {
  fsm_init();

  SignTx first = {};
  first.inputs_count = 1;
  first.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);

  signing_init(&first, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SignTx invalid = {};
  fsm_msgSignTx(&invalid);
  EXPECT_FALSE(signing_is_active());

  TxAck stale = {};
  stale.has_tx = true;
  fsm_msgTxAck(&stale);
  EXPECT_FALSE(signing_is_active());
}

#if !BITCOIN_ONLY
TEST(Fsm, CrossWorkflowAcknowledgementsTerminateTheActiveSigner) {
  fsm_init();
  HDNode node = {};
  node.curve = &secp256k1_info;

  BinanceSignTx binance = {};
  binance.has_msg_count = true;
  binance.msg_count = 1;
  binance.has_account_number = true;
  binance.has_chain_id = true;
  std::strcpy(binance.chain_id, "Binance-Chain-Nile");
  binance.has_sequence = true;
  binance.has_source = true;
  ASSERT_TRUE(binance_signTxInit(&node, &binance));
  ASSERT_TRUE(binance_signingIsInited());

  CosmosMsgAck cosmos_ack = {};
  receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                 &cosmos_ack);
  EXPECT_FALSE(binance_signingIsInited());

  TendermintSignTx cosmos = {};
  cosmos.has_msg_count = true;
  cosmos.msg_count = 1;
  cosmos.has_chain_id = true;
  std::strcpy(cosmos.chain_id, "cosmoshub-4");
  ASSERT_TRUE(tendermint_signTxInit(&node, &cosmos, sizeof(cosmos), "uatom",
                                    TENDERMINT_SIGNING_COSMOS));
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));

  BinanceTransferMsg binance_ack = {};
  receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                 BinanceTransferMsg_fields, &binance_ack);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
}

TEST(Fsm, StaleEthereumAckCannotReplaceARecoveryCeremony) {
  kk_test_board_init();
  fsm_init();
  setup_abort();
  fsm_test_clearLastFailure();

  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  EthereumTxAck stale = {};
  receiveMessage(MessageType_MessageType_EthereumTxAck, EthereumTxAck_fields,
                 &stale);

  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "the stale ACK was dropped without a terminal host response";

  setup_abort();
  layoutHomeForced();
}

TEST(Fsm, PaddedZeroUnlimitedApprovalReachesTheGlobalRefusal) {
  kk_test_board_init();
  fsm_init();
  fsm_test_clearLastFailure();
  kkconfirm_drain();
  ASSERT_TRUE(kkconfirm_preload(0, 1));

  EthereumSignTx msg = {};
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_gas_price = msg.has_gas_limit = true;
  msg.gas_price.size = msg.gas_limit.size = 1;
  msg.gas_price.bytes[0] = msg.gas_limit.bytes[0] = 1;
  msg.has_to = true;
  msg.to.size = 20;
  msg.to.bytes[0] = 1;
  msg.has_value = true;
  msg.value.size = 32;  // Non-canonical spelling of zero.
  msg.has_data_length = msg.has_data_initial_chunk = true;
  msg.data_length = msg.data_initial_chunk.size = 68;
  memcpy(msg.data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4);
  memset(msg.data_initial_chunk.bytes + 36, 0xff, 32);

  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
  ethereum_signing_init(&msg, &node, false);

  EXPECT_FALSE(ethereum_signing_isInProgress());
  EXPECT_EQ(0u, msg.value.size)
      << "the global ERC-20 classifier never saw canonical zero";
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(2, kkconfirm_drain())
      << "a generic-signing confirmation ran before the global refusal";
}
#endif

#if !BITCOIN_ONLY
TEST(Fsm, MissingEosCommonTerminatesSigning) {
  fsm_init();

  HDNode root = {};
  uint8_t chain_id[32] = {};
  EosTxHeader header = {};
  uint32_t path[8] = {};
  eos_signingInit(chain_id, 1, &header, &root, path, 0);
  ASSERT_TRUE(eos_signingIsInited());

  EosTxActionAck missing = {};
  fsm_msgEosTxActionAck(&missing);
  EXPECT_FALSE(eos_signingIsInited());

  EosTxActionAck stale = {};
  stale.has_common = true;
  stale.has_transfer = true;
  fsm_msgEosTxActionAck(&stale);
  EXPECT_FALSE(eos_signingIsInited());
}
#endif

TEST(Fsm, LowLevelPinRevocationTerminatesSigning) {
  fsm_init();
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, true);
  EXPECT_FALSE(signing_is_active());
  signing_abort();
}

TEST(Fsm, LowLevelSoftClearPreservesSigning) {
  fsm_init();
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, false);
  EXPECT_TRUE(signing_is_active());
  signing_abort();
}

/* A rejected frame must not be able to resume a signing session -- but it must
 * not be able to destroy a setup ceremony either. Every unmapped message id
 * reaches the same handler, and on bitcoin-only firmware that is every
 * multi-chain message a host probes with, so a routine EthereumGetAddress
 * would otherwise memzero a recovery the user is 20 words into. */
TEST(Fsm, TransportFailureEndsSigningButKeepsRecoveryCeremony) {
  kk_test_board_init();
  fsm_init();
  setup_abort();

  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  // Exactly what lib/board/messages.c does for a message id that is not in
  // the map, via the handler fsm_init() installed.
  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Unknown message");

  EXPECT_FALSE(signing_is_active())
      << "a rejected frame left a signing session a later ack could resume";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY))
      << "an unmapped host probe tore down the ceremony the user was in";

  setup_abort();
  layoutHomeForced();
}

TEST(Fsm, TransportFailureDisarmsResetBeforeAStaleEntropyAck) {
  kk_test_board_init();
  fsm_init();
  setup_abort();

  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Malformed frame");

  EXPECT_FALSE(setup_isArmed())
      << "a rejected frame left reset armed for a stale EntropyAck";
  layoutHomeForced();
}

TEST(Fsm, UnrelatedGetFeaturesDoesNotDeferAnActiveSigningAutoLock) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  uint8_t get_features[64] = {'?', '#', '#'};
  get_features[3] =
      static_cast<uint8_t>(MessageType_MessageType_GetFeatures >> 8);
  get_features[4] = static_cast<uint8_t>(MessageType_MessageType_GetFeatures);
  handle_usb_rx(get_features, sizeof(get_features));
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());

  layoutHomeForced();
}

TEST(Fsm, WorkflowResponseAtHomeDoesNotDeferTheAutoLock) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TxRequest next = {};
  ASSERT_TRUE(msg_write(MessageType_MessageType_TxRequest, &next));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());

  layoutHomeForced();
}

extern "C" {
void reset_probe_begin(int abort_phase);
void reset_probe_end(void);
unsigned reset_probe_seen(void);
unsigned reset_probe_errors(void);
const char* reset_probe_entropy_words(void);
const char* reset_probe_backup_words(void);
}
namespace {
struct ResetProbeScope {
  explicit ResetProbeScope(int abort_phase) { reset_probe_begin(abort_phase); }
  ~ResetProbeScope() { reset_probe_end(); }
};
}  // namespace

TEST(DiceCeremonyPrivacy,
     Mixed128DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 50.
  const uint8_t expected_seed[32] = {
      0xd7, 0x17, 0xae, 0xc4, 0x8f, 0x55, 0x58, 0x59, 0x5a, 0x60, 0x62,
      0xd1, 0xec, 0x03, 0xf9, 0x72, 0x24, 0x63, 0x62, 0x24, 0x56, 0xc6,
      0x31, 0x12, 0x37, 0xdd, 0x95, 0x82, 0x53, 0xf6, 0x24, 0x87};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 16);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(128, false, false, "english", "privacy", false, 0, 0, true, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(expected_entropy_words, reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(126u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy,
     Mixed256DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 99.
  const uint8_t expected_seed[32] = {
      0x2d, 0xf1, 0x8b, 0xfa, 0x9b, 0x97, 0xb3, 0x84, 0xb8, 0xd3, 0x05,
      0xcf, 0x7b, 0xe0, 0xa9, 0x98, 0x23, 0x04, 0x51, 0xce, 0x42, 0x5b,
      0xf4, 0x8d, 0xd9, 0x25, 0xf8, 0xb8, 0x70, 0x81, 0x1f, 0x58};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 32);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(256, false, false, "english", "privacy", false, 0, 0, true, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(expected_entropy_words, reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(126u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy,
     Only128DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 50.
  const uint8_t expected_seed[32] = {
      0xee, 0x72, 0xae, 0x91, 0x5a, 0x4e, 0x6e, 0xa7, 0xcc, 0xbe, 0xb8,
      0xe5, 0xe5, 0xee, 0xce, 0xf2, 0x9a, 0x1d, 0x0d, 0x90, 0xf0, 0x53,
      0x18, 0x37, 0x26, 0xa4, 0x24, 0xb6, 0xd3, 0xb0, 0x73, 0x25};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 16);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(128, false, false, "english", "privacy", false, 0, 0, true, true);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(std::string(), reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(122u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy,
     Only256DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 99.
  const uint8_t expected_seed[32] = {
      0x55, 0x88, 0xd3, 0x63, 0x0b, 0xd1, 0x9f, 0x63, 0x75, 0xb7, 0xbd,
      0x92, 0x24, 0x57, 0xaf, 0x34, 0xea, 0x9c, 0x74, 0xf0, 0x08, 0x07,
      0x56, 0x6a, 0x1c, 0xf8, 0x08, 0xe4, 0x45, 0xdc, 0x8c, 0x20};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 32);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(256, false, false, "english", "privacy", false, 0, 0, true, true);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(std::string(), reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(122u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy, AbortAtEveryPhaseWipesAndAllowsOrdinaryRestart) {
  kk_test_board_init();
  fsm_init();
  for (int phase = 1; phase <= 6; ++phase) {
    SCOPED_TRACE(phase);
    ScopedFlash flash;
    ResetProbeScope probe(phase);
    reset_init(128, false, false, "english", "abort", false, 0, 0, true, false);
    if (setup_isArmed()) {
      const uint8_t external[32] = {1};
      reset_entropy(external, sizeof(external));
    }
    EXPECT_NE(0u, reset_probe_seen() & (1u << phase));
    EXPECT_EQ(0u, reset_probe_errors());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(reset_debug_is_private());
    EXPECT_FALSE(storage_hasMnemonic());
    EXPECT_STREQ("", reset_get_word());
    uint8_t bytes[32] = {};
    EXPECT_EQ(32u, reset_get_int_entropy(bytes));
    for (uint8_t byte : bytes) EXPECT_EQ(0, byte);
    EXPECT_EQ(0u, reset_get_dice_digest(bytes));
    reset_init(128, false, false, "english", "ordinary", false, 0, 0, false,
               false);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    EXPECT_FALSE(reset_debug_is_private());
    ASSERT_EQ(32u, reset_get_int_entropy(bytes));
    for (unsigned i = 0; i < 32; ++i) EXPECT_EQ(i, bytes[i]);
  }
}

TEST(DiceCeremonyPrivacy, AbortClearsCanvasBeforeDiagnosticsResume) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  reset_init(128, false, false, "english", "canvas", false, 0, 0, true, false);
  ASSERT_TRUE(reset_debug_is_private());
  Canvas* canvas = display_canvas();
  ASSERT_NE(nullptr, canvas->buffer);
  const size_t size = canvas->width * canvas->height;
  std::memset(canvas->buffer, 0xa5, size);
  DebugLinkFlashDump dump = {};
  dump.has_address = dump.has_length = true;
  dump.address = 0x20000000;
  dump.length = 32;
  fsm_test_clearLastFailure();
  fsm_msgDebugLinkFlashDump(&dump);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
  setup_abort();
  EXPECT_FALSE(reset_debug_is_private());
  for (size_t i = 0; i < size; ++i) ASSERT_EQ(0, canvas->buffer[i]);
}

TEST(Fsm, LockedStorageRefusesResetAndSetupCommitWithoutChangingFlash) {
  kk_test_board_init();
  fsm_init();
  const uint32_t versions[] = {
#if BITCOIN_ONLY
      STORAGE_VERSION_BTC_ONLY_BASE + STORAGE_VERSION + 1,
#else
      STORAGE_VERSION + 1,
      STORAGE_VERSION_BTC_ONLY_BASE + STORAGE_VERSION,
#endif
  };
  for (uint32_t version : versions) {
    SCOPED_TRACE(version);
    ScopedFlash flash;
    struct WipeOnExit {
      ~WipeOnExit() { storage_wipe(); }
    } cleanup;
    auto* active =
        reinterpret_cast<uint8_t*>(flash_write_helper(storage_getLocation()));
    std::memcpy(active + 44, &version, sizeof(version));
    storage_init();
    ASSERT_TRUE(storage_isFirmwareTooOld() || storage_isBitcoinOnlyLocked());
    const auto before = flash.bytes;
    ResetDevice reset = {};
    reset.has_strength = true;
    reset.strength = 128;
    fsm_test_clearLastFailure();
    receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                   &reset);
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage,
              fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    ASSERT_TRUE(setup_stage(false, "english", "blocked", 0, 0, false));
    setup_arm(SETUP_RESET);
    fsm_test_clearLastFailure();
    EXPECT_FALSE(setup_commit(
        SETUP_RESET, "all all all all all all all all all all all all", false));
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage,
              fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(storage_hasMnemonic());
    EXPECT_EQ(before, flash.bytes);
  }
}
