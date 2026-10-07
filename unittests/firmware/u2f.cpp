extern "C" {
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/u2f.h"
#include "keepkey/firmware/u2f/u2f.h"
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
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

namespace {

// Each step runs inside one usbPoll(), as a USB callback would on hardware.
std::deque<std::function<void()>> poll_script;
bool button_up;
std::vector<std::vector<uint8_t>> u2f_replies;
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
    poll_script.clear();
    u2f_replies.clear();
    button_up = false;
    failures = 0;
    failure_text.clear();
    set_msg_failure_handler(+[](FailureType, const char* text) {
      failures++;
      failure_text = text;
    });
  }

  void TearDown() override {
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

extern "C" void emulatorPoll(void) {
  if (poll_script.empty()) return;
  auto step = poll_script.front();
  poll_script.pop_front();
  step();
}

extern "C" bool emulator_button_up(void) { return button_up; }

extern "C" void emulator_u2f_tx(const U2FHID_FRAME* f) {
  if (f->type & TYPE_INIT) {
    u2f_replies.emplace_back();
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
  // If the Ping was dispatched, this Cancel unwinds its confirm.
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  poll_script.push_back([] { send_register(1); });
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
