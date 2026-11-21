extern "C" {
// Select the firmware CTAPHID definitions before the board USB headers.
#include "keepkey/firmware/u2f/u2f_hid.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/ctap2/cbor.h"
#include "keepkey/firmware/ctap2.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/u2f.h"
#include "keepkey/firmware/u2f/u2f.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/nist256p1.h"
#include "trezor/crypto/sha2.h"
#include "u2f.h"
#include "u2f_knownapps.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <functional>
#include <string>
#include <vector>

TEST(U2F, WordsFromData) {
  const uint8_t buff1[32] = "123456789012345678901";
  ASSERT_EQ(std::string(words_from_data(buff1, 6)),
            "couple muscle snack heavy");

  const uint8_t buff2[32] = "keepkeykeepkeykeepkey";
  ASSERT_EQ(std::string(words_from_data(buff2, 6)),
            "hidden clinic foster strategy");

  ASSERT_EQ(std::string(u2f_well_known[6].appname), "Bitbucket");
  ASSERT_EQ(std::string(words_from_data(u2f_well_known[6].appid, 6)),
            "bar peace tonight cement");
}

TEST(U2F, ShapeShift) {
  ASSERT_EQ(U2F_SHAPESHIFT_COM->appname, std::string("ShapeShift"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO->appname, std::string("ShapeShift"));
  ASSERT_EQ(U2F_SHAPESHIFT_COM_STG->appname,
            std::string("ShapeShift (staging)"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO_STG->appname,
            std::string("ShapeShift (staging)"));
  ASSERT_EQ(U2F_SHAPESHIFT_COM_DEV->appname, std::string("ShapeShift (dev)"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO_DEV->appname, std::string("ShapeShift (dev)"));
}

extern "C" void set_msg_failure_handler(msg_failure_t failure_func);
void kk_test_set_message_hook(std::function<void(MessageType, const void*)>);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

namespace {

// Each step runs inside one usbPoll(), as a USB callback would on hardware.
std::deque<std::function<void()>> poll_script;
bool button_up;
std::vector<std::vector<uint8_t>> u2f_replies;
std::vector<uint8_t> u2f_reply_cmds;
size_t u2f_reply_len;

const uint32_t kCid = 0x01020304;

// A U2F_REGISTER APDU is 71 bytes: one init frame and one continuation.
void register_frames(uint8_t challenge, U2FHID_FRAME* init,
                     U2FHID_FRAME* cont) {
  uint8_t apdu[7 + sizeof(U2F_REGISTER_REQ)] = {
      0, U2F_REGISTER, 0, 0, 0, 0, sizeof(U2F_REGISTER_REQ)};
  memset(apdu + 7, challenge, U2F_CHAL_SIZE);
  memset(apdu + 7 + U2F_CHAL_SIZE, 0xa5, U2F_APPID_SIZE);
  *init = {};
  init->cid = kCid;
  init->init.cmd = U2FHID_MSG;
  init->init.bcntl = sizeof(apdu);
  memcpy(init->init.data, apdu, sizeof(init->init.data));
  *cont = {};
  cont->cid = kCid;
  memcpy(cont->cont.data, apdu + sizeof(init->init.data),
         sizeof(apdu) - sizeof(init->init.data));
}

// A request (or retry) arriving during the session, on the tiny U2F path.
void send_register(uint8_t challenge) {
  U2FHID_FRAME init, cont;
  register_frames(challenge, &init, &cont);
  u2fhid_read(1, &init);
  u2fhid_read(1, &cont);
}

void send_main(uint16_t id, const uint8_t* payload, uint8_t len) {
  uint8_t frame[64] = {'?', '#', '#', uint8_t(id >> 8), uint8_t(id & 0xff)};
  frame[8] = len;
  if (len) memcpy(frame + 9, payload, len);
  usb_test_receive(frame, sizeof(frame));
}

void hold(bool up, int polls) {
  for (int i = 0; i < polls; i++)
    poll_script.push_back([=] { button_up = up; });
}

uint16_t status(const std::vector<uint8_t>& reply) {
  return reply.size() < 2 ? 0 : reply[reply.size() - 2] << 8 | reply.back();
}

std::vector<uint16_t> statuses() {
  std::vector<uint16_t> out;
  for (const auto& reply : u2f_replies) out.push_back(status(reply));
  return out;
}

// Splits a request into one init frame and its continuations.
std::vector<U2FHID_FRAME> frames_for(const std::vector<uint8_t>& apdu,
                                    uint8_t command = U2FHID_MSG,
                                    uint32_t channel = kCid) {
  std::vector<U2FHID_FRAME> out(1);
  out[0] = {};
  out[0].cid = channel;
  out[0].init.cmd = command;
  out[0].init.bcnth = apdu.size() >> 8;
  out[0].init.bcntl = apdu.size() & 0xff;
  size_t off = std::min(apdu.size(), sizeof(out[0].init.data));
  memcpy(out[0].init.data, apdu.data(), off);
  for (uint8_t seq = 0; off < apdu.size(); seq++) {
    U2FHID_FRAME cont = {};
    cont.cid = channel;
    cont.cont.seq = seq;
    const size_t n = std::min(apdu.size() - off, sizeof(cont.cont.data));
    memcpy(cont.cont.data, apdu.data() + off, n);
    off += n;
    out.push_back(cont);
  }
  return out;
}

const uint8_t kAppId = 0xa5;      // register_frames() uses the same appId
const size_t kPubKeyLen = 65;     // uncompressed P-256 point
const size_t kKeyHandleLen = 64;  // key path + HMAC, as u2f.c builds it

std::vector<uint8_t> auth_apdu(const std::vector<uint8_t>& key_handle) {
  std::vector<uint8_t> apdu = {0, U2F_AUTHENTICATE, U2F_AUTH_ENFORCE, 0, 0, 0,
                               0};
  apdu.insert(apdu.end(), U2F_CHAL_SIZE, 0x11);
  apdu.insert(apdu.end(), U2F_APPID_SIZE, kAppId);
  apdu.push_back(key_handle.size());
  apdu.insert(apdu.end(), key_handle.begin(), key_handle.end());
  apdu[6] = apdu.size() - 7;
  return apdu;
}

// Queues each frame as its own USB callback through the U2F endpoint, so the
// frame sees usb.c's current tiny setting as on hardware.
void push_u2f(const std::vector<U2FHID_FRAME>& frames) {
  for (const auto& f : frames)
    poll_script.push_back([=] { usb_test_receive_u2f(&f); });
}

std::vector<uint8_t> screen() {
  const Canvas* c = layout_get_canvas();
  return std::vector<uint8_t>(c->buffer, c->buffer + c->width * c->height);
}

size_t count(uint8_t cmd, uint8_t err) {
  size_t n = 0;
  for (size_t i = 0; i < u2f_replies.size(); i++)
    if (u2f_reply_cmds[i] == cmd && !u2f_replies[i].empty() &&
        u2f_replies[i][0] == err)
      n++;
  return n;
}

int failures;
std::string failure_text;

struct U2FWait : ::testing::Test {
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = emulator_flash_base;

  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    storage_commit();
    usb_set_u2f_rx_callback(u2fhid_read);  // as u2fInit() does
    poll_script.clear();
    u2f_replies.clear();
    u2f_reply_cmds.clear();
    button_up = false;
    failures = 0;
    failure_text.clear();
    set_msg_failure_handler(+[](FailureType, const char* text) {
      failures++;
      failure_text = text;
    });
  }

  void TearDown() override {
    kk_test_set_message_hook({});
    poll_script.clear();
    button_up = false;
    fsm_init();  // restores the real failure handler
    storage_reset();
    emulator_flash_base = previous_flash;
  }

  // Runs one U2F session from the main loop until its wait ends.
  void run(uint8_t challenge) {
    U2FHID_FRAME init, cont;
    register_frames(challenge, &init, &cont);
    poll_script.push_front([=] { u2fhid_read(1, &cont); });
    u2fhid_read(0, &init);
  }
};

}  // namespace

size_t kk_test_u2f_reply_count(void) { return u2f_replies.size(); }
uint8_t kk_test_u2f_last_reply_command(void) { return u2f_reply_cmds.back(); }
void kk_test_poll(void);
extern "C" void emulatorPoll(void) {
  kk_test_poll();
  if (poll_script.empty()) return;
  auto step = poll_script.front();
  poll_script.pop_front();
  step();
}

extern "C" bool emulator_button_up(void) { return button_up; }

extern "C" void emulator_u2f_tx(const U2FHID_FRAME* f) {
  if (f->type & TYPE_INIT) {
    u2f_replies.emplace_back();
    u2f_reply_cmds.push_back(f->init.cmd);
    u2f_reply_len = MSG_LEN(*f);
    const size_t n = std::min(u2f_reply_len, sizeof(f->init.data));
    u2f_replies.back().assign(f->init.data, f->init.data + n);
  } else if (!u2f_replies.empty()) {
    auto& reply = u2f_replies.back();
    const size_t n =
        std::min(u2f_reply_len - reply.size(), sizeof(f->cont.data));
    reply.insert(reply.end(), f->cont.data, f->cont.data + n);
  }
}

// A normal message arriving while U2F waits for presence must not be
// dispatched: its confirm would replace the U2F prompt, and a press held for
// it would then count as U2F presence once the host cancels it.
TEST_F(U2FWait, NormalMessageIsNotDispatched) {
  const uint8_t ping[] = {0x10, 0x01};  // Ping.button_protection = true
  poll_script.push_back(
      [&] { send_main(MessageType_MessageType_Ping, ping, sizeof(ping)); });
  poll_script.push_back([] { send_register(1); });
  // If the Ping was dispatched, this Cancel unwinds its confirm.
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  kkconfirm_capture_start();
  run(1);
  const auto screens = kkconfirm_capture_finish();
  EXPECT_TRUE(screens.empty()) << "a nested confirm was drawn: " << screens[0];
  EXPECT_EQ(1, failures);
  EXPECT_EQ("Unknown message", failure_text);
  // Still armed: the retry is answered "not satisfied", not aborted.
  EXPECT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                                   U2F_SW_CONDITIONS_NOT_SATISFIED}),
            statuses());
}

// Read-only debug inspection must be answered in both receive and presence
// waits without replacing the prompt or granting presence.
TEST_F(U2FWait, DebugStateIsAnsweredWithoutChangingPromptOrPresence) {
  int replies = 0;
  kk_test_set_message_hook([&](MessageType id, const void* msg) {
    if (id != MessageType_MessageType_DebugLinkState) return;
    ++replies;
    const auto* state = static_cast<const DebugLinkState*>(msg);
    EXPECT_TRUE(state->has_layout);
    EXPECT_EQ(2048u, state->layout.size);
  });
  const auto get_state = [] {
    const uint16_t id = MessageType_MessageType_DebugLinkGetState;
    uint8_t frame[64] = {'?', '#', '#', uint8_t(id >> 8), uint8_t(id)};
    handle_debug_usb_rx(frame, sizeof(frame));
  };
  U2FHID_FRAME init, cont;
  register_frames(1, &init, &cont);
  poll_script.push_back(get_state);
  poll_script.push_back([&] {
    EXPECT_EQ(1, replies) << "no state reply while receiving the U2F request";
    u2fhid_read(1, &cont);
  });
  std::vector<uint8_t> prompt;
  poll_script.push_back([&] {
    prompt = screen();
    get_state();
  });
  poll_script.push_back([&] {
    EXPECT_EQ(2, replies) << "no state reply during the presence prompt";
    EXPECT_EQ(prompt, screen());
    send_register(1);
  });
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  u2fhid_read(0, &init);
  EXPECT_EQ(2, replies);
  EXPECT_EQ(0, failures);
  EXPECT_TRUE(poll_script.empty());
  EXPECT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                                   U2F_SW_CONDITIONS_NOT_SATISFIED}),
            statuses());
}

// Initialize and Cancel from a wallet host end the session and get their
// usual answer. The tiny reader used to store them, and nothing read them.
TEST_F(U2FWait, InitializeAndCancelEndTheSessionAndAreAnswered) {
  size_t size = 0;
  auto* features = reinterpret_cast<Features*>(fsm_test_responseArena(&size));
  for (uint16_t id :
       {MessageType_MessageType_Initialize, MessageType_MessageType_Cancel}) {
    SCOPED_TRACE(id);
    memset(features, 0, sizeof(*features));
    fsm_test_clearLastFailure();
    u2f_replies.clear();
    u2f_reply_cmds.clear();
    poll_script.clear();
    int polls_after = 0;
    poll_script.push_back([=] { send_main(id, nullptr, 0); });
    poll_script.push_back([&] { polls_after++; });
    run(1);
    EXPECT_EQ(0, polls_after) << "the session went on waiting";
    EXPECT_EQ(std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED},
              statuses());
    if (id == MessageType_MessageType_Initialize) {
      EXPECT_STREQ("keepkey.com", features->vendor);
    } else {
      EXPECT_EQ(FailureType_Failure_ActionCancelled,
                fsm_test_lastFailureCode());
    }
  }
}

// The same while a request is still being received drops that request, so
// its sender is told rather than left to time out.
TEST_F(U2FWait, InitializeDuringReceiveAnswersU2FBusy) {
  U2FHID_FRAME init, cont;
  register_frames(1, &init, &cont);
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Initialize, nullptr, 0); });
  u2fhid_read(0, &init);
  EXPECT_EQ(1u, count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(1u, u2f_replies.size());
}

// Presence is a press and release that starts after the prompt is drawn.
TEST_F(U2FWait, PresenceNeedsFreshPressAndRelease) {
  hold(false, 5);  // held since before the prompt
  poll_script.push_back([] { send_register(2); });
  hold(true, 5);
  hold(false, 5);  // pressed, not yet released
  poll_script.push_back([] { send_register(2); });
  poll_script.push_back([] { send_register(3); });  // new prompt
  hold(true, 5);  // releasing a press that began before this prompt
  poll_script.push_back([] { send_register(3); });
  hold(false, 5);
  hold(true, 5);
  poll_script.push_back([] { send_register(3); });
  run(2);
  EXPECT_EQ((std::vector<uint16_t>{
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // first request
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // held through the prompt
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // pressed, not released
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // new request, new prompt
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // stale press released
                U2F_SW_NO_ERROR}),                // fresh press and release
            statuses());
  EXPECT_TRUE(poll_script.empty());
}

// Chrome's CTAP 2.0 "touch your security key" request is a makeCredential or
// getAssertion with an empty pinAuth. The device must wait for a press and
// then report whether a passkey PIN is set.
TEST_F(U2FWait, EmptyPinAuthWaitsForTouch) {
  // makeCredential {1: hash, 2: {"id": ".dummy"}, 3: {"id": h'01', "name":
  // "dummy"}, 4: [{"alg": -7, "type": "public-key"}], 8: h'', 9: 1} and
  // getAssertion {1: ".dummy", 2: hash, 6: h'', 7: 1}, as Chrome sends them.
  std::vector<uint8_t> hash(32, 0x11);
  std::vector<uint8_t> make = {CTAP2_CMD_MAKE_CREDENTIAL, 0xa6, 0x01, 0x58,
                               0x20};
  make.insert(make.end(), hash.begin(), hash.end());
  make.insert(
      make.end(),
      {0x02, 0xa1, 0x62, 'i', 'd', 0x66, '.',  'd',  'u',  'm',  'm', 'y',
       0x03, 0xa2, 0x62, 'i', 'd', 0x41, 0x01, 0x64, 'n',  'a',  'm', 'e',
       0x65, 'd',  'u',  'm', 'm', 'y',  0x04, 0x81, 0xa2, 0x63, 'a', 'l',
       'g',  0x26, 0x64, 't', 'y', 'p',  'e',  0x6a, 'p',  'u',  'b', 'l',
       'i',  'c',  '-',  'k', 'e', 'y',  0x08, 0x40, 0x09, 0x01});
  std::vector<uint8_t> get = {CTAP2_CMD_GET_ASSERTION, 0xa4};
  get.insert(get.end(),
             {0x01, 0x66, '.', 'd', 'u', 'm', 'm', 'y', 0x02, 0x58, 0x20});
  get.insert(get.end(), hash.begin(), hash.end());
  get.insert(get.end(), {0x06, 0x40, 0x07, 0x01});
  PasskeyStorage passkeys;
  storage_getPasskeyData(&passkeys);
  for (bool pin_set : {false, true}) {
    passkeys.pin_set = pin_set;
    storage_setPasskeyData(&passkeys);
    for (const auto& request : {make, get}) {
      SCOPED_TRACE(::testing::Message()
                   << "command=" << int(request[0]) << " pin_set=" << pin_set);
      ctap2_init();
      hold(true, 2);
      hold(false, 1);  // confirm on the fresh press
      uint8_t response[64] = {0};
      size_t response_length = 0;
      ctap2_handle(request.data(), request.size(), response, sizeof(response),
                   &response_length);
      EXPECT_EQ(1u, response_length);
      EXPECT_EQ(pin_set ? CTAP2_ERR_PIN_INVALID : CTAP2_ERR_PIN_NOT_SET,
                response[0]);
      EXPECT_TRUE(poll_script.empty())
          << "answered without waiting for a press";
      poll_script.clear();
    }
  }
}

TEST_F(U2FWait, CtapPresenceEndsWhenItsDisplayIsReplaced) {
  for (const char* rp : {static_cast<const char*>(nullptr), "example.com"}) {
    for (bool registration : {false, true}) {
      SCOPED_TRACE(::testing::Message() << "rp=" << (rp ? rp : "none")
                                        << " registration=" << registration);
      button_up = true;
      poll_script.push_back([] {
        layout_clear();
        button_up = false;
      });
      EXPECT_FALSE(ctap2_request_user_presence(rp, registration));
      EXPECT_TRUE(poll_script.empty());
    }
  }
}

TEST_F(U2FWait, CancelledResetPreservesPasskeysAndAnswersBothHosts) {
  ctap2_init();
  PasskeyStorage before;
  storage_getPasskeyData(&before);
  before.pin_set = true;
  storage_setPasskeyData(&before);
  U2FHID_FRAME reset = {};
  reset.cid = kCid;
  reset.init.cmd = U2FHID_CBOR;
  reset.init.bcntl = 1;
  reset.init.data[0] = CTAP2_CMD_RESET;
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  fsm_test_clearLastFailure();
  u2fhid_read(0, &reset);
  EXPECT_EQ(1u, count(U2FHID_CBOR, CTAP2_ERR_KEEPALIVE_CANCEL));
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  PasskeyStorage after;
  storage_getPasskeyData(&after);
  EXPECT_EQ(0, memcmp(&before, &after, sizeof(after)));
}

// Every exit of a U2F session forgets the request. A session ended by the
// data timeout used to keep it armed, with its presence progress, so the next
// identical request was not prompted and a single release completed presence.
TEST_F(U2FWait, DataTimeoutForgetsPromptAndPresence) {
  std::vector<uint8_t> prompt, home, resent;
  U2FHID_FRAME init, cont;
  register_frames(7, &init, &cont);
  poll_script.push_back([&] { prompt = screen(); });
  hold(true, 3);
  hold(false, 3);  // pressed: presence needs only the release now
  // A new message that never completes ends the session by the data timeout.
  poll_script.push_back([=] { u2fhid_read(1, &init); });
  run(7);
  EXPECT_EQ(1u, count(U2FHID_ERROR, ERR_MSG_TIMEOUT));
  home = screen();
  EXPECT_NE(prompt, home);

  u2f_replies.clear();
  u2f_reply_cmds.clear();
  poll_script.push_back([&] { resent = screen(); });
  hold(true, 3);  // the release of the earlier press
  poll_script.push_back([] { send_register(7); });
  run(7);
  EXPECT_EQ(prompt, resent) << "the resent request was not prompted";
  EXPECT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                                   U2F_SW_CONDITIONS_NOT_SATISFIED}),
            statuses());
}

// A U2F request arriving while a confirm waits gets the busy reply. It used to
// start a nested U2F session that, for a request armed by an earlier session,
// left the confirm on screen and took the press made for it as U2F presence.
TEST_F(U2FWait, ConfirmAnswersU2FBusy) {
  // Register to obtain a valid key handle for kAppId.
  hold(true, 3);
  hold(false, 3);
  hold(true, 3);
  poll_script.push_back([] { send_register(5); });
  run(5);
  ASSERT_EQ(
      (std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED, U2F_SW_NO_ERROR}),
      statuses());
  const auto& reg = u2f_replies[1];
  ASSERT_EQ(kKeyHandleLen, reg[1 + kPubKeyLen]);
  const std::vector<uint8_t> handle(
      reg.begin() + 2 + kPubKeyLen,
      reg.begin() + 2 + kPubKeyLen + kKeyHandleLen);
  const auto auth = frames_for(auth_apdu(handle));

  // Arm AUTH, then end the session by the data timeout.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  push_u2f(std::vector<U2FHID_FRAME>(auth.begin() + 1, auth.end()));
  push_u2f({auth[0]});  // never completed
  u2fhid_read(0, &auth[0]);
  ASSERT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED}),
            std::vector<uint16_t>{status(u2f_replies[0])});
  ASSERT_EQ(1u, count(U2FHID_ERROR, ERR_MSG_TIMEOUT));

  // Resend the identical AUTH while a Ping confirm waits, press and release
  // for the confirm, resend again, then cancel the confirm.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  push_u2f(auth);
  hold(true, 3);
  hold(false, 3);
  hold(true, 3);
  push_u2f(auth);
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  const uint8_t ping[] = {0x10, 0x01};  // Ping.button_protection = true
  kkconfirm_capture_start();
  send_main(MessageType_MessageType_Ping, ping, sizeof(ping));
  EXPECT_EQ(1u, kkconfirm_capture_finish().size());
  EXPECT_TRUE(poll_script.empty());
  EXPECT_EQ(2 * auth.size(), count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(2 * auth.size(), u2f_replies.size()) << "U2F ran in the confirm";
  for (uint16_t sw : statuses())
    EXPECT_NE(U2F_SW_NO_ERROR, sw) << "the confirm's press was U2F presence";

  // After the confirm the same request is prompted afresh.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  push_u2f(std::vector<U2FHID_FRAME>(auth.begin() + 1, auth.end()));
  u2fhid_read(0, &auth[0]);
  EXPECT_EQ(std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED},
            std::vector<uint16_t>{status(u2f_replies.at(0))});
}

// A rejected normal message is answered through the real failure handler,
// which draws home over the prompt. Presence must not count until the prompt
// is drawn again.
TEST_F(U2FWait, RejectedMessageForgetsPrompt) {
  fsm_init();  // the real failure handler, which redraws the screen
  std::vector<uint8_t> prompt, after, redrawn;
  const uint8_t ping[] = {0x10, 0x01};
  poll_script.push_back([&] { prompt = screen(); });
  poll_script.push_back(
      [&] { send_main(MessageType_MessageType_Ping, ping, sizeof(ping)); });
  poll_script.push_back([&] { after = screen(); });
  hold(true, 3);
  hold(false, 3);
  hold(true, 3);  // a whole press and release while the prompt is gone
  poll_script.push_back([] { send_register(9); });
  poll_script.push_back([&] { redrawn = screen(); });
  hold(false, 3);
  hold(true, 3);
  poll_script.push_back([] { send_register(9); });
  run(9);
  EXPECT_NE(prompt, after) << "the failure did not draw over the prompt";
  EXPECT_EQ(prompt, redrawn);
  EXPECT_EQ(
      (std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                             U2F_SW_CONDITIONS_NOT_SATISFIED, U2F_SW_NO_ERROR}),
      statuses());
  EXPECT_TRUE(poll_script.empty());
}

namespace {

void settle() {
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
}

// Arms a recovery and returns the cipher it drew.
std::vector<uint8_t> arm_recovery() {
  EXPECT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "recovery", true, 0, 0,
                       false);
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  settle();
  return screen();
}

U2FHID_FRAME ping_frame() {
  U2FHID_FRAME f = {};
  f.cid = kCid;
  f.init.cmd = U2FHID_PING;
  f.init.bcntl = 4;
  memcpy(f.init.data, "ping", 4);
  return f;
}

}  // namespace

// While a ceremony waits in the main loop, U2F frames get the busy reply and
// draw nothing. A session used to end on the home screen with the recovery
// still armed, taking CharacterAcks with no cipher shown.
TEST_F(U2FWait, ArmedRecoveryAnswersU2FBusy) {
  const auto cipher = arm_recovery();
  const U2FHID_FRAME ping = ping_frame();
  U2FHID_FRAME init, cont;
  register_frames(1, &init, &cont);
  usb_test_receive_u2f(&ping);
  usb_test_receive_u2f(&init);
  usb_test_receive_u2f(&cont);
  settle();
  EXPECT_EQ(3u, count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(3u, u2f_replies.size()) << "a U2F session ran";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher, screen()) << "the cipher was drawn over";
  setup_abort();
}

TEST_F(U2FWait, ArmedResetAnswersU2FBusy) {
  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  const auto before = screen();
  const U2FHID_FRAME ping = ping_frame();
  U2FHID_FRAME init, cont;
  register_frames(1, &init, &cont);
  usb_test_receive_u2f(&ping);
  usb_test_receive_u2f(&init);
  usb_test_receive_u2f(&cont);
  EXPECT_EQ(3u, count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(3u, u2f_replies.size()) << "a U2F session ran";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_EQ(before, screen());
  setup_abort();

  // Outside a ceremony U2F is served as before.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  usb_test_receive_u2f(&ping);
  ASSERT_EQ(1u, u2f_replies.size());
  EXPECT_EQ(U2FHID_PING, u2f_reply_cmds[0]);
  EXPECT_EQ(std::vector<uint8_t>({'p', 'i', 'n', 'g'}), u2f_replies[0]);
}

// Defence in depth: a session that ends with a recovery armed restores the
// cipher instead of going home.
TEST_F(U2FWait, SessionEndRestoresArmedCipher) {
  std::vector<uint8_t> cipher;
  poll_script.push_back([&] { cipher = arm_recovery(); });
  run(4);
  settle();
  ASSERT_FALSE(cipher.empty());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher, screen()) << "the session went home over the cipher";
  setup_abort();
}

TEST(U2F, AuthenticatorResetGenerationInvalidatesNewAndLegacyHandles) {
  uint8_t private_key[32], app_id[32], handle[64];
  uint8_t generation_before[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  uint8_t generation_after[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  memset(private_key, 0x11, sizeof(private_key));
  memset(app_id, 0x22, sizeof(app_id));
  memset(handle, 0x80, 32);  // public hardened derivation path
  memset(generation_before, 0x33, sizeof(generation_before));
  memset(generation_after, 0x44, sizeof(generation_after));

  uint8_t generation_keybase[32 + 32 + PASSKEY_CREDENTIAL_GENERATION_SIZE];
  memcpy(generation_keybase, app_id, 32);
  memcpy(generation_keybase + 32, handle, 32);
  memcpy(generation_keybase + 64, generation_before, sizeof(generation_before));
  hmac_sha256(private_key, sizeof(private_key), generation_keybase,
              sizeof(generation_keybase), handle + 32);
  EXPECT_TRUE(u2f_key_handle_authenticator_is_valid(private_key, app_id, handle,
                                                    generation_before, false));
  EXPECT_FALSE(u2f_key_handle_authenticator_is_valid(
      private_key, app_id, handle, generation_after, false));

  uint8_t legacy_keybase[64];
  memcpy(legacy_keybase, app_id, 32);
  memcpy(legacy_keybase + 32, handle, 32);
  hmac_sha256(private_key, sizeof(private_key), legacy_keybase,
              sizeof(legacy_keybase), handle + 32);
  EXPECT_TRUE(u2f_key_handle_authenticator_is_valid(private_key, app_id, handle,
                                                    generation_before, true));
  EXPECT_FALSE(u2f_key_handle_authenticator_is_valid(
      private_key, app_id, handle, generation_after, false));
}

namespace {
std::vector<uint8_t> ctap_call(const std::vector<uint8_t>& request,
                               uint32_t channel = kCid) {
  auto frames = frames_for(request, U2FHID_CBOR, channel);
  for (size_t i = frames.size(); i > 1; --i) {
    poll_script.push_front([frame = frames[i - 1]] {
      usb_test_receive_u2f(&frame);
    });
  }
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  u2fhid_read(0, &frames[0]);
  if (u2f_reply_cmds.empty() || u2f_reply_cmds.back() != U2FHID_CBOR) {
    ADD_FAILURE() << "Expected CTAPHID_CBOR reply";
    return {0xff};
  }
  return u2f_replies.back();
}

CborValue response_field(const std::vector<uint8_t>& response, int key) {
  CborValue result = {};
  EXPECT_GT(response.size(), 1u);
  if (response.size() > 1)
    EXPECT_TRUE(cbor_map_find(response.data() + 1, response.size() - 1, nullptr,
                              key, &result, nullptr, nullptr));
  return result;
}

void pin_exchange(uint8_t command, const char* pin, uint8_t permission,
                  uint8_t expected, uint8_t token[32]) {
  const auto info = ctap_call({6, 0xa2, 1, 1, 2, 2});
  ASSERT_EQ(CTAP2_OK, info.at(0));
  const CborValue key = response_field(info, 1);
  ASSERT_EQ(CBOR_TYPE_MAP, key.type);
  const uint8_t* cose;
  size_t cose_length;
  CborValue x, y, ignored;
  ASSERT_TRUE(cbor_map_find(info.data() + 1, info.size() - 1, nullptr, 1,
                            &ignored, &cose, &cose_length));
  ASSERT_TRUE(cbor_map_find(cose, cose_length, nullptr, -2, &x, nullptr, nullptr));
  ASSERT_TRUE(cbor_map_find(cose, cose_length, nullptr, -3, &y, nullptr, nullptr));
  ASSERT_EQ(32u, x.length);
  ASSERT_EQ(32u, y.length);
  uint8_t device[65] = {4}, client[65], shared[65], secret[32];
  memcpy(device + 1, x.data, 32);
  memcpy(device + 33, y.data, 32);
  uint8_t client_key[32] = {};
  client_key[31] = 2;
  ASSERT_EQ(0, ecdsa_get_public_key65(&nist256p1, client_key, client));
  ASSERT_EQ(0, ecdh_multiply(&nist256p1, client_key, device, shared));
  sha256_Raw(shared + 1, 32, secret);

  uint8_t pin_material[64] = {};
  size_t pin_length = 16;
  if (command == 3) {
    memcpy(pin_material, pin, strlen(pin));
    pin_length = sizeof(pin_material);
  } else {
    sha256_Raw(reinterpret_cast<const uint8_t*>(pin), strlen(pin), pin_material);
  }
  uint8_t encrypted[64], iv[16] = {};
  aes_encrypt_ctx encrypt;
  aes_encrypt_key256(secret, &encrypt);
  aes_cbc_encrypt(pin_material, encrypted, pin_length, iv, &encrypt);
  uint8_t auth[32];
  hmac_sha256(secret, 32, encrypted, pin_length, auth);

  uint8_t wire[256] = {CTAP2_CMD_CLIENT_PIN};
  CborEncoder e;
  cbor_encoder_init(&e, wire + 1, sizeof(wire) - 1);
  cbor_encode_map(&e, command == 5 ? 4 : 5);
  cbor_encode_uint(&e, 1);
  cbor_encode_uint(&e, 1);
  cbor_encode_uint(&e, 2);
  cbor_encode_uint(&e, command);
  cbor_encode_uint(&e, 3);
  cbor_encode_map(&e, 5);
  cbor_encode_uint(&e, 1);
  cbor_encode_uint(&e, 2);
  cbor_encode_uint(&e, 3);
  cbor_encode_int(&e, -25);
  cbor_encode_int(&e, -1);
  cbor_encode_uint(&e, 1);
  cbor_encode_int(&e, -2);
  cbor_encode_bytes(&e, client + 1, 32);
  cbor_encode_int(&e, -3);
  cbor_encode_bytes(&e, client + 33, 32);
  if (command == 3) {
    cbor_encode_uint(&e, 4);
    cbor_encode_bytes(&e, auth, 16);
  }
  cbor_encode_uint(&e, command == 3 ? 5 : 6);
  cbor_encode_bytes(&e, encrypted, pin_length);
  if (command == 9) {
    cbor_encode_uint(&e, 9);
    cbor_encode_uint(&e, permission);
  }
  const auto response = ctap_call({wire, wire + 1 + cbor_encoder_size(&e)});
  ASSERT_EQ(expected, response.at(0));
  if (expected == CTAP2_OK && command != 3) {
    const auto encrypted_token = response_field(response, 2);
    ASSERT_EQ(32u, encrypted_token.length);
    memset(iv, 0, sizeof(iv));
    aes_decrypt_ctx decrypt;
    aes_decrypt_key256(secret, &decrypt);
    aes_cbc_decrypt(encrypted_token.data, token, 32, iv, &decrypt);
  }
}

std::vector<uint8_t> management(uint8_t command, const uint8_t token[32],
                                const std::vector<uint8_t>& params = {},
                                uint32_t channel = kCid) {
  std::vector<uint8_t> auth_data = {command};
  auth_data.insert(auth_data.end(), params.begin(), params.end());
  uint8_t auth[32];
  hmac_sha256(token, 32, auth_data.data(), auth_data.size(), auth);
  std::vector<uint8_t> wire = {CTAP2_CMD_CREDENTIAL_MANAGEMENT,
                               static_cast<uint8_t>(params.empty() ? 0xa3 : 0xa4),
                               1, command};
  if (!params.empty()) {
    wire.push_back(2);
    wire.insert(wire.end(), params.begin(), params.end());
  }
  wire.insert(wire.end(), {3, 1, 4, 0x50});
  wire.insert(wire.end(), auth, auth + 16);
  return ctap_call(wire, channel);
}

PasskeyCredential fixture_credential(const char* rp, bool resident) {
  PasskeyCredential credential = {};
  credential.occupied = true;
  credential.resident_only = resident;
  sha256_Raw(reinterpret_cast<const uint8_t*>(rp), strlen(rp),
             credential.rp_id_hash);
  credential.user_id_length = 1;
  credential.user_id[0] = 1;
  strcpy(credential.user_name, "QA account");
  uint8_t secret[32], public_key[65];
  EXPECT_TRUE(u2f_generate_credential(credential.rp_id_hash, resident,
                                     credential.credential_id, secret, public_key));
  return credential;
}

bool can_use_credential(const PasskeyCredential& credential) {
  uint8_t secret[32], public_key[65];
  return u2f_load_credential(credential.rp_id_hash, credential.credential_id,
                             secret, public_key);
}

std::vector<uint8_t> delete_params(const PasskeyCredential& credential) {
  std::vector<uint8_t> params = {0xa1, 2, 0xa2, 0x62, 'i', 'd', 0x58, 64};
  params.insert(params.end(), credential.credential_id,
                credential.credential_id + sizeof(credential.credential_id));
  params.insert(params.end(), {0x64, 't', 'y', 'p', 'e', 0x6a});
  const std::string type = "public-key";
  params.insert(params.end(), type.begin(), type.end());
  return params;
}

uint8_t explicit_sign_in(const char* rp, const PasskeyCredential& credential) {
  uint8_t wire[256] = {CTAP2_CMD_GET_ASSERTION};
  uint8_t challenge[32] = {};
  CborEncoder e;
  cbor_encoder_init(&e, wire + 1, sizeof(wire) - 1);
  cbor_encode_map(&e, 3);
  cbor_encode_uint(&e, 1);
  cbor_encode_text(&e, rp, strlen(rp));
  cbor_encode_uint(&e, 2);
  cbor_encode_bytes(&e, challenge, sizeof(challenge));
  cbor_encode_uint(&e, 3);
  cbor_encode_array(&e, 1);
  cbor_encode_map(&e, 2);
  cbor_encode_text(&e, "id", 2);
  cbor_encode_bytes(&e, credential.credential_id, sizeof(credential.credential_id));
  cbor_encode_text(&e, "type", 4);
  cbor_encode_text(&e, "public-key", 10);
  button_up = true;
  EXPECT_TRUE(poll_script.empty());
  poll_script.push_back([] { button_up = false; });
  const auto response = ctap_call({wire, wire + 1 + cbor_encoder_size(&e)});
  poll_script.clear();
  return response.at(0);
}

void register_into_freed_slot(const char* rp, const uint8_t token[32],
                              PasskeyCredential* replacement) {
  uint8_t request[256] = {CTAP2_CMD_MAKE_CREDENTIAL};
  uint8_t client_hash[32] = {}, auth[32];
  hmac_sha256(token, 32, client_hash, sizeof(client_hash), auth);
  CborEncoder e;
  cbor_encoder_init(&e, request + 1, sizeof(request) - 1);
  cbor_encode_map(&e, 7);
  cbor_encode_uint(&e, 1);
  cbor_encode_bytes(&e, client_hash, sizeof(client_hash));
  cbor_encode_uint(&e, 2);
  cbor_encode_map(&e, 1);
  cbor_encode_text(&e, "id", 2);
  cbor_encode_text(&e, rp, strlen(rp));
  cbor_encode_uint(&e, 3);
  cbor_encode_map(&e, 1);
  cbor_encode_text(&e, "id", 2);
  const uint8_t user = 1;
  cbor_encode_bytes(&e, &user, 1);
  cbor_encode_uint(&e, 4);
  cbor_encode_array(&e, 1);
  cbor_encode_map(&e, 2);
  cbor_encode_text(&e, "alg", 3);
  cbor_encode_int(&e, -7);
  cbor_encode_text(&e, "type", 4);
  cbor_encode_text(&e, "public-key", 10);
  cbor_encode_uint(&e, 7);
  cbor_encode_map(&e, 1);
  cbor_encode_text(&e, "rk", 2);
  cbor_encode_bool(&e, true);
  cbor_encode_uint(&e, 8);
  cbor_encode_bytes(&e, auth, 16);
  cbor_encode_uint(&e, 9);
  cbor_encode_uint(&e, 1);
  button_up = true;
  poll_script.push_back([] { button_up = false; });
  const auto response = ctap_call({request, request + 1 + cbor_encoder_size(&e)});
  ASSERT_EQ(CTAP2_OK, response.at(0));
  ASSERT_TRUE(storage_getPasskeySlot(0, replacement));
  EXPECT_TRUE(replacement->resident_only);
}

void hold_for_management() {
  button_up = true;
  poll_script.push_back([] { button_up = false; });
  poll_script.push_back([] {
    for (unsigned i = 0; i < 1600; ++i) timerisr_usr();
  });
}
}

TEST_F(U2FWait, ManagementRequiresTheCorrectPinAndPermission) {
  ctap2_init();
  ctap2_set_transport_channel(kCid);
  uint8_t token[32] = {};
  pin_exchange(9, "1234", 4, CTAP2_ERR_PIN_NOT_SET, token);
  pin_exchange(3, "1234", 0, CTAP2_OK, token);
  pin_exchange(9, "4321", 4, CTAP2_ERR_PIN_INVALID, token);
  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  EXPECT_EQ(PASSKEY_PIN_RETRIES - 1, storage.pin_retries);

  pin_exchange(5, "1234", 0, CTAP2_OK, token);
  EXPECT_EQ(CTAP2_ERR_PIN_AUTH_INVALID, management(1, token).at(0));
  pin_exchange(9, "1234", 4, CTAP2_OK, token);
  const auto metadata = management(1, token);
  EXPECT_EQ(CTAP2_OK, metadata.at(0));
  EXPECT_EQ(0u, response_field(metadata, 1).value);
  EXPECT_EQ(4u, response_field(metadata, 2).value);
  EXPECT_EQ(CTAP2_ERR_PIN_AUTH_INVALID, management(1, token, {}, kCid + 1).at(0));
}

TEST_F(U2FWait, ManagementEnumeratesAndRetiresOnlyTheSelectedHandle) {
  ctap2_init();
  ctap2_set_transport_channel(kCid);
  uint8_t token[32] = {};
  pin_exchange(3, "1234", 0, CTAP2_OK, token);
  const auto created = fixture_credential("example.com", true);
  const auto prerelease = fixture_credential("example.org", false);
  PasskeyStorage storage;
  storage_getPasskeyData(&storage);
  storage.credentials[0] = created;
  storage.credentials[1] = prerelease;
  storage_setPasskeyData(&storage);
  ASSERT_EQ(CTAP2_OK, explicit_sign_in("example.com", created));
  ASSERT_EQ(CTAP2_OK, explicit_sign_in("example.org", prerelease));

  pin_exchange(9, "1234", 4, CTAP2_OK, token);
  const auto rps = management(2, token);
  ASSERT_EQ(CTAP2_OK, rps.at(0));
  EXPECT_EQ(2u, response_field(rps, 5).value);
  const auto next_rp = ctap_call({0x0a, 0xa1, 1, 3});
  ASSERT_EQ(CTAP2_OK, next_rp.at(0));
  const auto hash = response_field(next_rp, 4);
  ASSERT_EQ(32u, hash.length);
  EXPECT_EQ(0, memcmp(hash.data, prerelease.rp_id_hash, 32));
  EXPECT_EQ(CTAP2_ERR_NO_CREDENTIALS, ctap_call({0x0a, 0xa1, 1, 3}).at(0));
  std::vector<uint8_t> params = {0xa1, 1, 0x58, 32};
  params.insert(params.end(), prerelease.rp_id_hash, prerelease.rp_id_hash + 32);
  const auto credentials = management(4, token, params);
  ASSERT_EQ(CTAP2_OK, credentials.at(0));
  EXPECT_EQ(1u, response_field(credentials, 9).value);
  EXPECT_EQ(CBOR_TYPE_MAP, response_field(credentials, 8).type);

  button_up = true;
  poll_script.push_back([] { button_up = false; });
  poll_script.push_back([] { button_up = true; });
  poll_script.push_back([] { layoutHome(); });
  EXPECT_EQ(CTAP2_ERR_OPERATION_DENIED,
            management(6, token, delete_params(created)).at(0));
  EXPECT_TRUE(can_use_credential(created));
  hold_for_management();
  ASSERT_EQ(CTAP2_OK, management(6, token, delete_params(created)).at(0));
  EXPECT_EQ(CTAP2_ERR_NO_CREDENTIALS, explicit_sign_in("example.com", created));
  EXPECT_EQ(CTAP2_OK, explicit_sign_in("example.org", prerelease));
  hold_for_management();
  ASSERT_EQ(CTAP2_OK, management(6, token, delete_params(prerelease)).at(0));
  EXPECT_FALSE(can_use_credential(prerelease));

  storage_init();
  EXPECT_FALSE(can_use_credential(created));
  EXPECT_FALSE(can_use_credential(prerelease));
  storage_getPasskeyData(&storage);
  ASSERT_FALSE(storage.credentials[0].occupied);
  pin_exchange(5, "1234", 0, CTAP2_OK, token);
  PasskeyCredential replacement;
  register_into_freed_slot("example.com", token, &replacement);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(CTAP2_ERR_NO_CREDENTIALS, explicit_sign_in("example.com", created));
  EXPECT_EQ(CTAP2_OK, explicit_sign_in("example.com", replacement));
}

TEST_F(U2FWait, ResetRequiresAHoldAndClearsThePinAndCredentials) {
  ctap2_init();
  uint8_t token[32] = {};
  pin_exchange(3, "1234", 0, CTAP2_OK, token);
  const auto credential = fixture_credential("example.com", true);
  ASSERT_TRUE(storage_storePasskeySlot(&credential));
  button_up = true;
  poll_script.push_back([] { button_up = false; });
  poll_script.push_back([] { button_up = true; });
  poll_script.push_back([] { layoutHome(); });
  EXPECT_EQ(CTAP2_ERR_OPERATION_DENIED, ctap_call({CTAP2_CMD_RESET}).at(0));
  EXPECT_TRUE(can_use_credential(credential));

  hold_for_management();
  ASSERT_EQ(CTAP2_OK, ctap_call({CTAP2_CMD_RESET}).at(0));
  EXPECT_EQ(CTAP2_ERR_NO_CREDENTIALS, explicit_sign_in("example.com", credential));
  pin_exchange(9, "1234", 4, CTAP2_ERR_PIN_NOT_SET, token);
  EXPECT_EQ(CTAP2_ERR_NOT_ALLOWED, ctap_call({CTAP2_CMD_RESET}).at(0));
}

TEST_F(U2FWait, CredentialListsRespectTheAdvertisedBound) {
  ctap2_init();
  std::vector<uint8_t> make = {CTAP2_CMD_MAKE_CREDENTIAL, 0xa5, 1, 0x58, 32};
  make.insert(make.end(), 32, 0);
  make.insert(make.end(), {2, 0xa0, 3, 0xa0, 4, 0x80, 5, 0x89});
  make.insert(make.end(), 9, 0xa0);
  EXPECT_EQ(CTAP2_ERR_LIMIT_EXCEEDED, ctap_call(make).at(0));

  std::vector<uint8_t> assertion = {CTAP2_CMD_GET_ASSERTION, 0xa3,
                                     1, 0x61, 'a', 2, 0x58, 32};
  assertion.insert(assertion.end(), 32, 0);
  assertion.insert(assertion.end(), {3, 0x89});
  assertion.insert(assertion.end(), 9, 0xa0);
  EXPECT_EQ(CTAP2_ERR_LIMIT_EXCEEDED, ctap_call(assertion).at(0));
}
