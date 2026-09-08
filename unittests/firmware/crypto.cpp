extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/memzero.h"
void setup(void);
}
#include "gtest/gtest.h"
#include <cstring>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Crypto, Ed25519MessagePrefixIsDeterministic) {
  uint8_t seed[32] = {1};
  HDNode node = {};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), ED25519_NAME, &node));
  uint8_t sig[65];
  for (int i = 0; i < 8; ++i) {
    memset(sig, 0xa5, sizeof(sig));
    ASSERT_EQ(0, cryptoMessageSign(
                     coinByName("Bitcoin"), &node, InputScriptType_SPENDADDRESS,
                     reinterpret_cast<const uint8_t*>("identity"), 8, sig));
    EXPECT_EQ(31, sig[0]);
  }
  memzero(&node, sizeof(node));
}

TEST(Crypto, EcdsaMessageRetainsRecoverableSignature) {
  uint8_t seed[32] = {1};
  HDNode node = {};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  const CoinType* coin = coinByName("Bitcoin");
  uint8_t sig[65];
  const uint8_t message[] = "approved message";
  ASSERT_EQ(0, cryptoMessageSign(coin, &node, InputScriptType_SPENDADDRESS,
                                 message, sizeof(message) - 1, sig));
  char address[80];
  hdnode_fill_public_key(&node);
  hdnode_get_address(&node, coin->address_type, address, sizeof(address));
  EXPECT_EQ(
      0, cryptoMessageVerify(coin, message, sizeof(message) - 1, address, sig));
  memzero(&node, sizeof(node));
}

static void prepare_crypto_wallet(void) {
  if (storage_getLocation() == FLASH_INVALID) {
    setup();
    storage_init();
  }
  session_clear(true);
  storage_setMnemonic("all all all all all all all all all all all all");
  storage_setPassphraseProtected(false);
  fsm_init();
}

TEST(Crypto, FailedDerivationScrubsPartialPrivateNode) {
  prepare_crypto_wallet();
  GetPublicKey msg = GetPublicKey_init_zero;
  msg.has_ecdsa_curve_name = true;
  strcpy(msg.ecdsa_curve_name, ED25519_NAME);
  msg.address_n_count = 2;
  msg.address_n[0] = 0x80000000;
  msg.address_n[1] = 0;  // Ed25519 requires hardened child derivation.
  fsm_test_seedDerivedNode();
  fsm_msgGetPublicKey(&msg);
  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
}

TEST(Crypto, CipherOperationScrubsDerivedPrivateNode) {
  prepare_crypto_wallet();
  CipherKeyValue msg = CipherKeyValue_init_zero;
  msg.has_key = true;
  strcpy(msg.key, "test key");
  msg.has_value = true;
  msg.value.size = 16;
  msg.has_encrypt = true;
  msg.encrypt = true;
  fsm_msgCipherKeyValue(&msg);
  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
}
