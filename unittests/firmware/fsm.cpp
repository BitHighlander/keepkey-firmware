extern "C" {
#include "keepkey/transport/interface.h"
#include "trezor/crypto/sha2.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/storage.h"
#include "storage.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"

#include <cstring>

// The shared bootstrap initializes the canvas and timer queues exactly once.
// Calling timer_init() again relinks the static runnable nodes into a cycle.
void kk_test_board_init(void);

// confirm() auto-accept driver, from confirm_test_utils.cpp. preload() queues
// nYes accepts, nNo rejections and a trailing rejection sentinel; drain()
// returns the sentinel-discounted surplus, so 0 means exactly the budgeted
// screens appeared and a negative value means a screen appeared that was not
// budgeted for.
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Fsm, AuthenticatorCredentialSourceIsWipedOnEveryExit) {
  char credential[] = "site:user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  ASSERT_EQ(LARGESEED, addAuthAccount(credential));

  for (size_t i = 0; i < sizeof(credential); ++i) {
    EXPECT_EQ('\0', credential[i]);
  }
}

#if !BITCOIN_ONLY
TEST(Fsm, AbortWorkflowsClearsEveryObservableSigningSession) {
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

  fsm_abort_workflows();

  EXPECT_FALSE(binance_signingIsInited());
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_FALSE(eos_signingIsInited());
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

/* Host traffic is activity: a ceremony or signing stream the user is still
 * working through outlasts the delay only because nothing else resets the
 * timer once the device has left the home screen. */
TEST(Fsm, HostActivityDefersTheAutoLockWhileStreaming) {
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
  note_host_activity();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  EXPECT_TRUE(signing_is_active())
      << "two sub-delay gaps around a host frame must not add up to a lock";

  // The lock still fires once the host really has stalled for the full delay.
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());

  layoutHomeForced();
}

/* The control: at the home screen the same frames must not hold the device
 * unlocked, or a polling host would defeat auto-lock entirely. */
TEST(Fsm, HostActivityAtHomeDoesNotDeferTheAutoLock) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  ASSERT_EQ(AT_HOME, home_get_state());

  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  note_host_activity();
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());

  layoutHomeForced();
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
TEST(Fsm, TransportFailureEndsSigningButKeepsASetupCeremony) {
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

/* THE LOCK, FROM THE HANDLER SIDE.
 *
 * A bitcoin-only wallet seen by this firmware leaves the device LOOKING
 * uninitialized -- the RAM shadow is reset, so storage_isInitialized() and
 * storage_hasPin() are both false -- while storage_commit() silently declines
 * to write. Every handler that only persists settings therefore used to run to
 * completion, consume an on-device confirmation, and answer Success for a
 * change that was gone at the next boot.
 *
 * Asserted through the confirm budget rather than the reply, because "refuse
 * before the user does the work" is the property: with no screens budgeted,
 * kkconfirm_drain() goes negative the moment a handler puts one up.
 *
 * The lock is reachable only through a real boot, so plant a wallet in the
 * emulated flash and call storage_init(). storage_wipe() at the end clears
 * btc_only_locked (its only exit) and leaves the rest of the binary an
 * ordinary erased device. */
TEST(Fsm, BitcoinOnlyLockRefusesSettingsHandlersBeforeAnyConfirm) {
  setup();  // maps the emulated flash; idempotent across test binaries
  kk_test_board_init();
  fsm_init();

  flash_erase_word(FLASH_STORAGE1);
  flash_erase_word(FLASH_STORAGE2);
  flash_erase_word(FLASH_STORAGE3);
#if BITCOIN_ONLY
  // In-band but NEWER than this build understands -- the only way a
  // bitcoin-only image reaches the same lock.
  const uint32_t version = STORAGE_VERSION_BTC_ONLY + 1;
#else
  const uint32_t version = STORAGE_VERSION_BTC_ONLY;
#endif
  ASSERT_TRUE(flash_write(FLASH_STORAGE1, 0, STORAGE_MAGIC_LEN,
                          (const uint8_t*)STORAGE_MAGIC_STR));
  // Offset 44: the version word, immediately after the 44-byte Metadata.
  ASSERT_TRUE(flash_write(FLASH_STORAGE1, 44, sizeof(version),
                          (const uint8_t*)&version));
  storage_init();
  ASSERT_TRUE(storage_isBitcoinOnlyLocked());
  ASSERT_FALSE(storage_isInitialized());

  ApplyPolicies policies = {};
  policies.policy_count = 1;
  policies.policy[0].has_policy_name = true;
  std::strcpy(policies.policy[0].policy_name, "AdvancedMode");
  policies.policy[0].has_enabled = true;
  policies.policy[0].enabled = true;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgApplyPolicies(&policies);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ApplyPolicies asked for a button press it could never persist";
  EXPECT_FALSE(storage_isPolicyEnabled("AdvancedMode"))
      << "the policy changed in RAM only, so this boot disagrees with flash";

  ApplySettings settings = {};
  settings.has_label = true;
  std::strcpy(settings.label, "locked");
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgApplySettings(&settings);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ApplySettings asked for a button press it could never persist";

  ChangePin pin = {};
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgChangePin(&pin);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ChangePin ran the Create PIN ceremony on a device it cannot write";

  storage_wipe();
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  layoutHomeForced();
}
