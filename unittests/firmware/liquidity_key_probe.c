/* Compile the real liquidity implementation with fault-injected dependencies.
 * The production archive member is not linked because this object supplies
 * the same public liquidity entry points. No seam enters the firmware build. */
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/bip32.h"

bool probe_storage_getRootNode(const char*, bool, HDNode*);
int probe_hdnode_private_ckd_cached(HDNode*, const uint32_t*, size_t,
                                    uint32_t*);

#define storage_getRootNode probe_storage_getRootNode
#define hdnode_private_ckd_cached probe_hdnode_private_ckd_cached
#include "../../lib/firmware/ethereum_contracts/zxliquidtx.c"
#undef storage_getRootNode
#undef hdnode_private_ckd_cached

static HDNode* observed_node;
static int fault_stage;

bool probe_storage_getRootNode(const char* curve, bool passphrase,
                               HDNode* node) {
  if (!fault_stage) return storage_getRootNode(curve, passphrase, node);
  observed_node = node;
  memset(node, 0xa5, sizeof(*node));
  return fault_stage != 1;
}

int probe_hdnode_private_ckd_cached(HDNode* node, const uint32_t* path,
                                    size_t count, uint32_t* fingerprint) {
  if (!fault_stage)
    return hdnode_private_ckd_cached(node, path, count, fingerprint);
  memset(node, 0x5a, sizeof(*node));
  return fault_stage != 2;
}

bool test_liquidity_failed_derivation_wipes(int stage) {
  fault_stage = stage;
  const uint32_t path[] = {0x8000002c, 0x8000003c};
  HDNode* result = zx_getDerivedNode(SECP256K1_NAME, path, 2, NULL);
  if (stage == 3) {
    if (!result) {
      fault_stage = 0;
      return false;
    }
    result = zx_getDerivedNode("invalid-curve", path, 2, NULL);
  }
  fault_stage = 0;
  if (result || !observed_node) return false;
  const uint8_t* bytes = (const uint8_t*)observed_node;
  for (size_t i = 0; i < sizeof(*observed_node); i++) {
    if (bytes[i] != 0) return false;
  }
  return true;
}
