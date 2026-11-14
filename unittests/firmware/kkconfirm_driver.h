// confirm() auto-accept driver for unit tests.
//
// Shared by every test that drives code through a confirmation screen
// (authenticator, ethereum, thorchain, mayachain, osmosis, ...). It lives in
// confirm_test_utils.cpp rather than inside one chain's test file so that
// adding a caller never depends on which chain-specific test happens to be
// listed in CMakeLists.txt.
#ifndef UNITTESTS_FIRMWARE_KKCONFIRM_DRIVER_H
#define UNITTESTS_FIRMWARE_KKCONFIRM_DRIVER_H

#include <stdint.h>

// The emulator's main UDP "usb" port the firmware under test listens on:
// KEEPKEY_UDP_PORT when set, else 11044. The debug port is this plus one.
uint16_t kkconfirm_main_port(void);

// Queue nYes accepted screens followed by nNo rejected screens. Performs the
// one-time board/usb initialization on first use.
bool kkconfirm_preload(int nYes, int nNo);

// As above without the trailing rejection sentinel; see confirm_test_utils.cpp.
bool kkconfirm_preload_no_sentinel(int nYes, int nNo);

// Consume and count any queued messages the code under test did not use.
// Zero proves exactly the preloaded number of screens was shown: fewer screens
// leave packets queued, more would hang the test.
int kkconfirm_drain(void);

#endif
