/* Optional research-only FFI entry, built into the real KeepKey emulator.
 * Run in host-driven single-thread mode on an anonymous erased flash buffer.
 * No new protobuf command or normal-wallet Monero capability is introduced.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bip32.h"
#include "bip39.h"
#include "memzero.h"
#include "emulator_derivation_vectors.h"
#include "keepkey/emulator/libkkemu.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/keepkey_display.h"

extern int monero_interop_run(void);
extern volatile uint32_t monero_checks;
extern volatile uint32_t monero_fail_line;
volatile uint32_t monero_wallet_derivation_checks;

static int wallet_derivations(void) {
  monero_wallet_derivation_checks = 0;
  for (size_t i = 0; i < MONERO_DERIVATION_CASE_COUNT; ++i) {
    const monero_derivation_case *v = &monero_derivation_cases[i];
    uint8_t seed[64];
    HDNode node;
    memset(&node, 0, sizeof(node));
    mnemonic_to_seed(v->mnemonic, "", seed, NULL);
    int ok = hdnode_from_seed(seed, sizeof(seed), "ed25519", &node) &&
             hdnode_private_ckd_prime(&node, 44) &&
             hdnode_private_ckd_prime(&node, 128) &&
             hdnode_private_ckd_prime(&node, v->account) &&
             memcmp(node.private_key, v->key_seed, 32) == 0;
    memzero(seed, sizeof(seed));
    memzero(&node, sizeof(node));
    if (!ok) return 0;
    ++monero_wallet_derivation_checks;
  }
  return 1;
}

__attribute__((visibility("default"))) int kkemu_monero_feasibility(void) {
  if (!kkemu_is_running()) return -1;
  layout_standard_notification("Monero experiment", "Checking public fixtures",
                               NOTIFICATION_INFO);
  display_refresh();
  int result = wallet_derivations() ? monero_interop_run() : 2;
  char body[96];
  if (result) {
    snprintf(body, sizeof(body), "FAIL line %lu\nChecks %lu",
             (unsigned long)monero_fail_line, (unsigned long)monero_checks);
  } else {
    snprintf(body, sizeof(body), "PASS 96 cases + 4 paths\n%lu checks",
             (unsigned long)monero_checks);
  }
  layout_standard_notification("Monero experiment", body, NOTIFICATION_INFO);
  display_refresh();
  return result;
}
