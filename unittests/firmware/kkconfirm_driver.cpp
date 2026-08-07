extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"

// From keepkey_board.h, which we can't include here: its shutdown(void)
// declaration clashes with sys/socket.h's shutdown(int, int).
void kk_board_init(void);
}

#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "kkconfirm_driver.h"

/*
 * confirm() auto-accept driver for unit tests.
 *
 * In the emulator/unittest build (always DEBUG_LINK), confirm_helper()
 * busy-polls the emulator's UDP "usb" port for tiny messages and returns
 * once it has seen a ButtonAck plus a DebugLinkDecision. Each confirm
 * screen therefore consumes exactly one ButtonAck + one DebugLinkDecision
 * from the socket queue. Preloading exactly N accept pairs before invoking
 * the code under test auto-accepts exactly N screens, and
 * kkconfirm_drain() == 0 afterwards proves exactly N screens were shown
 * (fewer screens leave packets queued; more screens would hang the test).
 */

static bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload,
                               uint8_t len) {
  static int fd = -1;
  if (fd < 0) fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return false;

  uint8_t frame[64] = {0};
  frame[0] = '?';
  frame[1] = '#';
  frame[2] = '#';
  frame[3] = msgId >> 8;
  frame[4] = msgId & 0xff;
  frame[8] = len;  // bytes 5..7 are the high bits of the big-endian size
  if (len) memcpy(&frame[9], payload, len);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(11044);  // emulator main "usb" port
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return sendto(fd, frame, sizeof(frame), 0, (struct sockaddr*)&addr,
                sizeof(addr)) == (ssize_t)sizeof(frame);
}

bool kkconfirm_preload(int nYes, int nNo) {
  static bool initialized = false;
  if (!initialized) {
    kk_board_init();  // canvas + runnable queues for confirm's draw path
    fsm_init();       // registers the usb rx callback + message maps
    usbInit("");      // binds the emulator UDP ports
    initialized = true;
  }

  static const uint8_t yes[] = {0x08, 0x01};  // DebugLinkDecision.yes_no
  static const uint8_t no[] = {0x08, 0x00};
  for (int i = 0; i < nYes + nNo; i++) {
    if (!kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, NULL, 0))
      return false;
    const uint8_t* decision = (i < nYes) ? yes : no;
    if (!kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision, decision,
                            2))
      return false;
  }
  return true;
}

int kkconfirm_drain(void) {
  uint8_t buf[MSG_TINY_BFR_SZ];
  int n = 0;
  for (;;) {
    // volatile: 0xFFFF (MSG_TINY_TYPE_ERROR) is outside the MessageType
    // enum range, so an unguarded comparison is a tautology the compiler
    // may fold away.
    volatile uint16_t id = (uint16_t)check_for_tiny_msg(buf);
    if (id == MSG_TINY_TYPE_ERROR) break;
    n++;
  }
  return n;
}
