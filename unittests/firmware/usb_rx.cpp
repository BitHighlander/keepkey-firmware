extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
}

#include "gtest/gtest.h"
#include <cstring>

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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

void kk_test_board_init(void);

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

static void init_test_usb() {
  static bool initialized = false;
  fsm_init();
  if (!initialized) {
    usbInit("");
    initialized = true;
  }
}

TEST(USBRX, TinyAcknowledgementDoesNotReusePreviousSecret) {
  init_test_usb();
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const char secret[] = "previous-passphrase-secret";
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = MessageType_MessageType_PassphraseAck >> 8;
  frame[4] = MessageType_MessageType_PassphraseAck & 0xff;
  frame[8] = sizeof(secret) + 1;
  frame[9] = 0x0a;
  frame[10] = sizeof(secret) - 1;
  memcpy(frame + 11, secret, sizeof(secret) - 1);
  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  uint8_t received[MSG_TINY_BFR_SZ] = {};
  uint16_t id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  EXPECT_EQ(MessageType_MessageType_PassphraseAck, id);
  EXPECT_STREQ(secret, reinterpret_cast<PassphraseAck *>(received)->passphrase);

  memset(frame, 0, sizeof(frame));
  frame[0] = '?';
  frame[1] = frame[2] = '#';
  frame[3] = MessageType_MessageType_ButtonAck >> 8;
  frame[4] = MessageType_MessageType_ButtonAck & 0xff;
  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  id = MSG_TINY_TYPE_ERROR;
  for (int attempt = 0; attempt < 1000 && id == MSG_TINY_TYPE_ERROR;
       ++attempt) {
    id = check_for_tiny_msg(received);
    if (id == MSG_TINY_TYPE_ERROR) usleep(1000);
  }
  close(fd);
  ASSERT_EQ(MessageType_MessageType_ButtonAck, id);
  for (uint8_t byte : received) EXPECT_EQ(0, byte);
}

static const uint8_t *observed_packet;
static size_t observed_length;
static void observe_packet(const void *packet, size_t length) {
  observed_packet = static_cast<const uint8_t *>(packet);
  observed_length = length;
  EXPECT_EQ(0x5a, observed_packet[20]);
}

TEST(USBRX, PacketStorageIsWipedAfterCallback) {
  init_test_usb();
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  uint8_t frame[64];
  memset(frame, 0x5a, sizeof(frame));
  observed_packet = nullptr;
  observed_length = 0;
  usb_set_rx_callback(observe_packet);
  EXPECT_EQ(sizeof(frame), sendto(fd, frame, sizeof(frame), 0,
                                  reinterpret_cast<struct sockaddr *>(&address),
                                  sizeof(address)));
  for (int attempt = 0; attempt < 1000 && !observed_packet; ++attempt) {
    usbPoll();
    if (!observed_packet) usleep(1000);
  }
  close(fd);
  fsm_init();  // Restore the real callback before any fatal assertion.
  ASSERT_NE(nullptr, observed_packet);
  ASSERT_EQ(sizeof(frame), observed_length);
  // The transport owns static storage; observe its lifetime after callback.
  for (size_t i = 0; i < sizeof(frame); ++i) EXPECT_EQ(0, observed_packet[i]);
}

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
}

TEST(Confirmation, BackupSubpagesConsumeTheirOwnAcknowledgements) {
  init_test_usb();
  if (layout_get_canvas() == nullptr) {
    timer_init();
    layout_init(display_canvas_init());
  }
  const char body[] = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n";
  size_t pages = 0;
  for (const char *cursor = body; *cursor;) {
    const size_t take = confirm_constant_power_subpage_take(cursor);
    ASSERT_GT(take, 0u);
    cursor += take;
    pages++;
  }
  ASSERT_GT(pages, 1u);
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(11044);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  auto send = [&](uint16_t id, bool decision, bool yes) {
    uint8_t frame[64] = {'?', '#', '#'};
    frame[3] = id >> 8;
    frame[4] = id & 0xff;
    if (decision) {
      frame[8] = 2;
      frame[9] = 0x08;
      frame[10] = yes;
    }
    EXPECT_EQ(
        sizeof(frame),
        sendto(fd, frame, sizeof(frame), 0,
               reinterpret_cast<struct sockaddr *>(&address), sizeof(address)));
  };
  // The debug decision may arrive before the main-channel acknowledgement.
  for (size_t page = 0; page < pages; page++) {
    send(MessageType_MessageType_DebugLinkDecision, true, true);
    send(MessageType_MessageType_ButtonAck, false, false);
  }
  // A rejection sentinel prevents an over-consuming implementation hanging.
  send(MessageType_MessageType_ButtonAck, false, false);
  send(MessageType_MessageType_DebugLinkDecision, true, false);
  close(fd);
  EXPECT_TRUE(confirm_constant_power_paged(
      ButtonRequestType_ButtonRequest_ConfirmWord, "Backup", body));
  int remaining = 0;
  uint8_t tiny[MSG_TINY_BFR_SZ];
  for (int idle = 0; idle < 200; idle++) {
    if (check_for_tiny_msg(tiny) != MSG_TINY_TYPE_ERROR) remaining++;
    usleep(1000);
  }
  EXPECT_EQ(2, remaining);  // Only the sentinel remains, never a page's Ack.
}

extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/signing.h"
void extract_input_bip32_path(const TxInputType* input);
bool check_change_bip32_path(const TxOutputType* output);
}
static constexpr uint32_t H(uint32_t i) { return 0x80000000 | i; }

TEST(Signing, MixedModeChangeMustPreserveLeadingPathComponents) {
  init_test_usb();
  if (layout_get_canvas() == nullptr) {
    timer_init();
    layout_init(display_canvas_init());
  }
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  for (uint32_t count = 5; count <= 8; ++count) {
    SignTx request = {};
    request.inputs_count = request.outputs_count = 1;
    request.version = 1;
    signing_init(&request, coin, nullptr);
    struct Abort {
      ~Abort() { signing_abort(); }
    } abort;
    TxInputType input = {};
    input.address_n_count = count;
    for (uint32_t i = 0; i < count - 5; ++i) input.address_n[i] = H(7 + i);
    const uint32_t tail[] = {H(44), H(0), H(0), 0, 0};
    std::memcpy(input.address_n + count - 5, tail, sizeof(tail));
    extract_input_bip32_path(&input);
    TxOutputType output = {};
    output.address_n_count = count;
    output.script_type = OutputScriptType_PAYTOWITNESS;
    std::memcpy(output.address_n, input.address_n, sizeof(input.address_n));
    output.address_n[count - 5] = H(84);
    output.address_n[count - 2] = 1;
    EXPECT_TRUE(check_change_bip32_path(&output));
    if (count > 5) {
      for (uint32_t i = 0; i < count - 5; ++i) {
        output.address_n[i]++;
        EXPECT_FALSE(check_change_bip32_path(&output));
        output.address_n[i]--;
      }
      // A second input from a different leading branch also disables change.
      input.address_n[0]++;
      extract_input_bip32_path(&input);
      EXPECT_FALSE(check_change_bip32_path(&output));
    }
  }
}

extern "C" {
#include "keepkey/firmware/transaction.h"
#include "keepkey/firmware/txin_check.h"
}

TEST(Transaction, ChangedInputsTriggerDuplicateOutputRefusal) {
  init_test_usb();
  if (layout_get_canvas() == nullptr) {
    timer_init();
    layout_init(display_canvas_init());
  }
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ASSERT_GE(fd, 0);
  struct CloseSocket {
    int fd;
    ~CloseSocket() { close(fd); }
  } close_socket{fd};
  auto preload = [&](int yes_count, int no_count) {
    uint8_t stale[MSG_TINY_BFR_SZ];
    while (check_for_tiny_msg(stale) != MSG_TINY_TYPE_ERROR) {}
    struct sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(11044);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int screen = 0; screen < yes_count + no_count + 1; ++screen) {
      for (uint16_t id : {uint16_t(MessageType_MessageType_ButtonAck),
                          uint16_t(MessageType_MessageType_DebugLinkDecision)}) {
        uint8_t frame[64] = {'?', '#', '#'};
        frame[3] = id >> 8;
        frame[4] = id & 0xff;
        if (id == MessageType_MessageType_DebugLinkDecision) {
          frame[8] = 2;
          frame[9] = 0x08;
          frame[10] = screen < yes_count;
        }
        if (sendto(fd, frame, sizeof(frame), 0,
                    reinterpret_cast<struct sockaddr*>(&address),
                    sizeof(address)) != sizeof(frame)) return false;
      }
    }
    return true;
  };
  auto drain = [&]() {
    int count = 0, idle = 0;
    uint8_t tiny[MSG_TINY_BFR_SZ];
    while (idle < 200) {
      if (check_for_tiny_msg(tiny) != MSG_TINY_TYPE_ERROR) {
        ++count;
        idle = 0;
      } else {
        usleep(1000);
        ++idle;
      }
    }
    return count - 2;  // Discount the trailing rejection sentinel.
  };
  // Initialize the queue before seeding transaction-history state.
  ASSERT_TRUE(preload(0, 0));
  ASSERT_EQ(0, drain());
  struct ClearHistory {
    ~ClearHistory() { txin_dgst_initialize(); }
  } clear_history;
  txin_dgst_initialize();
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  HDNode root = {};
  TxOutputType output = {};
  output.has_address = true;
  std::strcpy(output.address, "1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1");
  output.amount = 380000;
  output.script_type = OutputScriptType_PAYTOADDRESS;
  TxOutputBinType compiled = {};

  const uint8_t first_input[] = {1, 2, 3};
  txin_dgst_addto(first_input, sizeof(first_input));
  txin_dgst_final();
  ASSERT_TRUE(preload(1, 0));
  ASSERT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
  ASSERT_EQ(0, drain());

  // Signing initialization starts the next transaction's input hash.
  // Identical inputs and outputs remain a permitted repeat.
  txin_dgst_reset_current();
  txin_dgst_addto(first_input, sizeof(first_input));
  txin_dgst_final();
  ASSERT_TRUE(preload(1, 0));
  ASSERT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
  ASSERT_EQ(0, drain());

  // A different input digest with the same output reaches the real warning
  // and refuses compilation even when the user acknowledges both screens.
  const uint8_t changed_input[] = {4, 5, 6};
  txin_dgst_reset_current();
  txin_dgst_addto(changed_input, sizeof(changed_input));
  txin_dgst_final();
  ASSERT_TRUE(preload(2, 0));
  EXPECT_EQ(-1, compile_output(coin, &root, &output, &compiled, true));
  EXPECT_EQ(0, drain());

  // Refusing an output must not bless the rejected input set for a retry.
  for (int retry = 0; retry < 3; ++retry) {
    txin_dgst_reset_current();
    txin_dgst_addto(changed_input, sizeof(changed_input));
    txin_dgst_final();
    ASSERT_TRUE(preload(2, 0));
    EXPECT_EQ(-1, compile_output(coin, &root, &output, &compiled, true));
    EXPECT_EQ(0, drain());
  }
  // The original accepted transaction can still be retried afterward.
  txin_dgst_reset_current();
  txin_dgst_addto(first_input, sizeof(first_input));
  txin_dgst_final();
  ASSERT_TRUE(preload(1, 0));
  EXPECT_GT(compile_output(coin, &root, &output, &compiled, true), 0);
  EXPECT_EQ(0, drain());
}
