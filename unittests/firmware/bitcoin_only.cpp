extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "variant.h"
}

#include "gtest/gtest.h"

#include <initializer_list>

static_assert(BITCOIN_ONLY == 1,
              "bitcoin-only test built for the wrong product");
static_assert(ZCASH_PRIVACY == 0,
              "bitcoin-only must compile out Zcash privacy");
static_assert(TOKENS_COUNT == 0, "bitcoin-only must compile out ERC-20 tokens");

TEST(BitcoinOnly, ProductAndCoinTableAreExact) {
  ASSERT_EQ(COINS_COUNT, 2);
  EXPECT_STREQ(coins[0].coin_name, "Bitcoin");
  EXPECT_STREQ(coins[1].coin_name, "Testnet");
  EXPECT_STREQ(variant_getName(), "EmulatorBTC");

  EXPECT_NE(coinByName("Bitcoin"), nullptr);
  EXPECT_NE(coinByName("Testnet"), nullptr);
  for (const char* name : {"BitcoinCash", "Litecoin", "Dogecoin", "Zcash",
                           "Ethereum", "Solana", "THORChain", "MAYAChain"}) {
    EXPECT_EQ(coinByName(name), nullptr) << name;
  }
}
