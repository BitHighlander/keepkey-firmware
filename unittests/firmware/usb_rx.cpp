extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
}

#include "gtest/gtest.h"
#include <unistd.h>

extern "C" {
void usb_rx_helper(const void *buf, size_t length, MessageMapType type);
void set_msg_failure_handler(msg_failure_t failure_func);
}

static int failure_count;
static std::string message;

static void setup() {
  failure_count = 0;

  set_msg_failure_handler(+[](FailureType code, const char *text) {
    failure_count++;
    message = text;
  });
}

TEST(USBRX, Overflow) {
  fsm_init();
  setup();

  char msg[64];
  TrezorFrame *frame = (TrezorFrame *)msg;
  TrezorFrameFragment *frame_fragment = (TrezorFrameFragment *)msg;

  frame->usb_header.hid_type = '?';
  frame->header.pre1 = '#';
  frame->header.pre2 = '#';
  frame->header.id = __builtin_bswap16(MessageType_MessageType_Initialize);
  frame->header.len = __builtin_bswap32(0xffffffff);
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);

  frame->header.pre1 = '0';
  frame->header.pre2 = '0';

  // Send packets up until the point just before where the buffer internal to
  // usb_rx_helper would overflow. All of these should succeeed.
  for (unsigned i = 0; i < 1039; i++) {
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 0);
  }

  // Then on the last one, check that we detect the overflow before it happens:
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 1);
  ASSERT_EQ(message, "Malformed message");

  // And check that the state got cleared out afterward:
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 2);
  ASSERT_EQ(message, "Malformed packet");
}

TEST(USBRX, ErrorHandling) {
  fsm_init();
  setup();

  char msg[64];
  memset(msg, 0, sizeof(msg));

  // Missing '?'
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 1);
  ASSERT_EQ(message, "Malformed packet");

  msg[0] = '?';

  // Missing '#'
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 2);
  ASSERT_EQ(message, "Malformed packet");

  msg[1] = '#';

  // Missing '#'
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 3);
  ASSERT_EQ(message, "Malformed packet");

  msg[2] = '#';
  msg[3] = 0xff;
  msg[6] = 0xff;

  // Unknown msgId
  usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
  ASSERT_EQ(failure_count, 4);
  ASSERT_EQ(message, "Unknown message");
}

// msg_write() copied a fixed 63 bytes into every packet, so the last packet of
// a near-maximal frame read up to 62 bytes past the frame arena and sent them
// on the wire. The copy must stop at the end of the frame.
TEST(USBRX, FinalChunkNeverReadsPastTheFrame) {
  EXPECT_EQ(msg_write_chunk_len(9 + 12292, 1), 63u);
  EXPECT_EQ(msg_write_chunk_len(100, 64), 36u);
  EXPECT_EQ(msg_write_chunk_len(64, 1), 63u);
  EXPECT_EQ(msg_write_chunk_len(9 + 12292, 12286), 15u);
  EXPECT_EQ(msg_write_chunk_len(10, 10), 0u);
  EXPECT_EQ(msg_write_chunk_len(10, 11), 0u);
}

namespace {

int dispatch_count;

void count_dispatch(void *) { ++dispatch_count; }

void install_test_map(MessageMapType type) {
  static MessagesMap_t map[MessageType_MessageType_Initialize + 1];
  memset(map, 0, sizeof(map));
  map[MessageType_MessageType_Initialize] = {
      Initialize_fields,
      count_dispatch,
      PARSABLE,
      type,
      IN_MSG,
      MessageType_MessageType_Initialize,
  };
  msg_map_init(map, sizeof(map) / sizeof(map[0]));
}

void initialize_packet(uint8_t packet[64]) {
  memset(packet, 0, 64);
  packet[0] = '?';
  packet[1] = '#';
  packet[2] = '#';
  const uint16_t id = __builtin_bswap16(MessageType_MessageType_Initialize);
  memcpy(packet + 3, &id, sizeof(id));
}

}  // namespace

TEST(USBRX, MainPacketsStayTinyWhileU2fOwnsUserPresence) {
  fsm_init();
  setup();
  install_test_map(NORMAL_MSG);

  uint8_t packet[64];
  initialize_packet(packet);
  dispatch_count = 0;

  usbTiny(0);
  handle_usb_rx(packet, sizeof(packet));
  ASSERT_EQ(dispatch_count, 1);

  usbTiny(1);
  handle_usb_rx(packet, sizeof(packet));
  EXPECT_EQ(dispatch_count, 1);

  // Tiny messages are read during an active poll, not queued for a later poll.
  // This valid Initialize was accepted by the tiny decoder without dispatch.
  EXPECT_EQ(failure_count, 0);
  usbTiny(0);
  fsm_init();
}

#if DEBUG_LINK
TEST(USBRX, DebugPacketsStayTinyWhileU2fOwnsUserPresence) {
  fsm_init();
  setup();
  install_test_map(DEBUG_MSG);

  uint8_t packet[64];
  initialize_packet(packet);
  dispatch_count = 0;

  usbTiny(0);
  handle_debug_usb_rx(packet, sizeof(packet));
  ASSERT_EQ(dispatch_count, 1);

  usbTiny(1);
  handle_debug_usb_rx(packet, sizeof(packet));
  EXPECT_EQ(dispatch_count, 1);

  // Tiny messages are read during an active poll, not queued for a later poll.
  // This valid Initialize was accepted by the tiny decoder without dispatch.
  EXPECT_EQ(failure_count, 0);
  usbTiny(0);
  fsm_init();
}
#endif

extern bool kkconfirm_preload(int nYes, int nNo);

TEST(USBRX, EmulatorPollConsumesTinyPacketsWhileU2fOwnsInterface) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  usbTiny(1);
  auto poll = []() {
    uint8_t tiny[MSG_TINY_BFR_SZ];
    MessageType id = static_cast<MessageType>(MSG_TINY_TYPE_ERROR);
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
      id = check_for_tiny_msg(tiny);
      if (id != MSG_TINY_TYPE_ERROR) break;
      usleep(1000);
    }
    return id;
  };
  EXPECT_EQ(poll(), MessageType_MessageType_ButtonAck);
  EXPECT_EQ(poll(), MessageType_MessageType_DebugLinkDecision);
  usbTiny(0);
  fsm_init();
}
