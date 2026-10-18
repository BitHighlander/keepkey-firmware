/* Certified contacts for SignTx coins (docs/design/certified-contacts-utxo.md).
 * Vectors come from scripts/clearsign/gen_contact_book_utxo_vectors.py, which
 * builds them from the formats alone. */
extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/contact_book.h"
#include "keepkey/firmware/contact_book_utxo.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/transaction.h"
#include "keepkey/firmware/txin_check.h"
#include "trezor/crypto/ecdsa.h"
}

#include "contact_book_utxo_vectors.h"
#include "contact_book_vectors.h"
#include "kkconfirm_driver.h"
#include "gtest/gtest.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

namespace {

std::vector<uint8_t> hex(const char* value) {
  std::vector<uint8_t> out;
  for (size_t i = 0; value[i] && value[i + 1]; i += 2) {
    unsigned byte = 0;
    sscanf(value + i, "%2x", &byte);
    out.push_back(static_cast<uint8_t>(byte));
  }
  return out;
}

const char kBitcoin[] = "bip122:000000000019d6689c085ae165831e93";
const char kAlice[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const char kBob[] =
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

class UtxoContacts : public ::testing::Test {
 protected:
  std::vector<uint8_t> key = hex(ATTESTOR_PUBKEY_ALL);
  void TearDown() override { contact_book_clear(); }

  bool accept(const char* coin, const char* proof) {
    const auto bytes = hex(proof);
    return contact_book_utxo_accept_proof(coinByName(coin), bytes.data(),
                                          bytes.size(), key.data());
  }

  static TxOutputType toAddress(const char* address, uint64_t amount,
                                OutputScriptType type) {
    TxOutputType out = {};
    out.has_address = true;
    std::strncpy(out.address, address, sizeof(out.address) - 1);
    out.amount = amount;
    out.script_type = type;
    return out;
  }

  /* The label an output gets after compile_output() builds its script. */
  static const char* labelFor(const char* coin_name, TxOutputType out) {
    const CoinType* coin = coinByName(coin_name);
    HDNode root = {};
    TxOutputBinType bin = {};
    if (compile_output(coin, &root, &out, &bin, false) <= 0) return "?";
    return contact_book_utxo_label(coin, &out, bin.script_pubkey.bytes,
                                   bin.script_pubkey.size);
  }

  /* The screens compile_output() shows for `out`, all accepted. */
  static std::vector<std::string> review(const char* coin_name,
                                         TxOutputType out) {
    txin_dgst_initialize();
    HDNode root = {};
    TxOutputBinType bin = {};
    EXPECT_TRUE(kkconfirm_preload(1, 0));
    kkconfirm_capture_start();
    EXPECT_GT(compile_output(coinByName(coin_name), &root, &out, &bin, true),
              0);
    auto screens = kkconfirm_capture_finish();
    EXPECT_EQ(0, kkconfirm_drain());
    txin_dgst_initialize();
    return screens;
  }
};

TEST_F(UtxoContacts, EachNetworkNamesExactlyOneCoin) {
  const CoinType* btc = coinByName("Bitcoin");
  ASSERT_NE(nullptr, btc);
  EXPECT_STREQ(kBitcoin, contact_book_utxo_network(btc));
  EXPECT_EQ(btc, contact_book_utxo_coin(kBitcoin));
  EXPECT_EQ(coinByName("Testnet"),
            contact_book_utxo_coin("bip122:000000000933ea01ad0ee984209779ba"));
  for (const char* network :
       {"eip155:1", "bip122:000000000019d6689c085ae165831e9",
        "bip122:000000000019d6689c085ae165831e93 ", "BIP122:000000000019d6689c085ae165831e93",
        ""}) {
    EXPECT_EQ(nullptr, contact_book_utxo_coin(network)) << network;
  }
  EXPECT_EQ(nullptr, contact_book_utxo_coin(nullptr));
  EXPECT_EQ(nullptr, contact_book_utxo_network(nullptr));
#if !BITCOIN_ONLY
  struct {
    const char* coin;
    const char* network;
  } const bound[] = {
      {"Litecoin", "bip122:12a765e31ffd4059bada1e25190f6e98"},
      {"Dogecoin", "bip122:00000000001a91e3dace36e2be3bf030"},
      {"BitcoinCash", "bip122:000000000000000000651ef99cb9fcbe"},
      {"Dash", "bip122:000007d91d1254d60e2dd1ae58038307"},
      {"Zcash", "bip122:00040fe8ec8471911baa1db1266ea15d"},
      {"DigiByte", "bip122:4da631f2ac1bed857bd968c67c913978"},
  };
  for (const auto& b : bound) {
    const CoinType* coin = coinByName(b.coin);
    ASSERT_NE(nullptr, coin) << b.coin;
    EXPECT_STREQ(b.network, contact_book_utxo_network(coin));
    EXPECT_EQ(coin, contact_book_utxo_coin(b.network));
  }
  /* Signed by the firmware, but not named by Desktop: never bound. */
  for (const char* coin : {"BitcoinGold", "Namecoin", "Zcash Testnet",
                           "LTC Testnet", "BCH Testnet", "Ethereum"}) {
    if (coinByName(coin))
      EXPECT_EQ(nullptr, contact_book_utxo_network(coinByName(coin))) << coin;
  }
#else
  /* The bitcoin-only image has no other coin to bind. */
  EXPECT_EQ(nullptr,
            contact_book_utxo_coin("bip122:12a765e31ffd4059bada1e25190f6e98"));
#endif
}

/* The address shown at certification is the one the send screen decodes back
 * to the same script, for every script type and coin in this build. */
TEST_F(UtxoContacts, RendersEveryStandardScriptAsTheSendScreenDecodesIt) {
  size_t checked = 0;
  for (const auto& v : UTXO_ADDRESSES) {
    const CoinType* coin = coinByName(v.coin);
    if (!coin) continue; /* not in this build */
    SCOPED_TRACE(std::string(v.coin) + " " + v.address);
    const auto script = hex(v.script);
    char address[MAX_ADDR_SIZE];
    ASSERT_TRUE(contact_book_utxo_address(coin, script.data(), script.size(),
                                          address, sizeof(address)));
    EXPECT_STREQ(v.address, address);

    TxOutputType out = toAddress(v.address, 1000,
                                 OutputScriptType_PAYTOADDRESS);
    HDNode root = {};
    TxOutputBinType bin = {};
    ASSERT_GT(compile_output(coin, &root, &out, &bin, false), 0);
    EXPECT_EQ(script, std::vector<uint8_t>(bin.script_pubkey.bytes,
                                           bin.script_pubkey.bytes +
                                               bin.script_pubkey.size));
    checked++;
  }
#if BITCOIN_ONLY
  EXPECT_EQ(9u, checked);
#else
  EXPECT_EQ(sizeof(UTXO_ADDRESSES) / sizeof(UTXO_ADDRESSES[0]), checked);
#endif
}

TEST_F(UtxoContacts, RefusesScriptsItCannotShowAsAnAddress) {
  const CoinType* btc = coinByName("Bitcoin");
  char address[MAX_ADDR_SIZE];
  const char* refused[] = {
      "6a0568656c6c6f",                                   /* OP_RETURN */
      "21" "02f2ffb8489096035d8bc25201ea7439379fa3dd55a6ed781bf7a94213408ed015" "ac", /* P2PK */
      "76a914751e76e8199196d454941c45d1b3a323f1433bd688",   /* short P2PKH */
      "76a914751e76e8199196d454941c45d1b3a323f1433bd688ad", /* wrong opcode */
      "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb88",     /* P2SH, OP_EQUALV */
      "0015751e76e8199196d454941c45d1b3a323f1433bd600",     /* v0, 21 bytes */
      "5214751e76e8199196d454941c45d1b3a323f1433bd6",       /* v2 */
      "5114751e76e8199196d454941c45d1b3a323f1433bd6",       /* v1, 20 bytes */
      "00",
  };
  for (const char* script_hex : refused) {
    const auto script = hex(script_hex);
    EXPECT_FALSE(contact_book_utxo_address(btc, script.data(), script.size(),
                                           address, sizeof(address)))
        << script_hex;
  }
  const auto good = hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
  EXPECT_FALSE(contact_book_utxo_address(btc, good.data(), good.size(),
                                         address, MAX_ADDR_SIZE - 1))
      << "a short buffer is refused, not truncated";
#if !BITCOIN_ONLY
  /* Dogecoin has no bech32 prefix: a witness script has no Dogecoin address. */
  EXPECT_FALSE(contact_book_utxo_address(coinByName("Dogecoin"), good.data(),
                                         good.size(), address,
                                         sizeof(address)));
#endif
}

/* Only a valid UTXO proof for the coin being signed is kept; anything else is
 * dropped, and so is a proof held from before. */
TEST_F(UtxoContacts, KeepsOnlyAValidProofForTheCoinBeingSigned) {
  ASSERT_TRUE(accept("Bitcoin", UPROOF_BTC_0));
  EXPECT_STREQ("Alice", contact_book_label());

  const char* const dropped[][2] = {
      {"Testnet", UPROOF_BTC_0},              /* a Bitcoin contact */
      {"Bitcoin", UPROOF_BTC_5},              /* a Testnet contact */
      {"Bitcoin", UPROOF_BTC_0_OTHER_KEY},    /* another wallet's book */
      {"Bitcoin", UPROOF_BTC_0_TAMPERED},     /* one bit of the name */
      {"Bitcoin", PROOF3_0},                  /* an EVM contact */
      {"Bitcoin", "4b4b414250524631"},        /* truncated */
  };
  for (const auto& d : dropped) {
    ASSERT_TRUE(accept("Bitcoin", UPROOF_BTC_0));
    EXPECT_FALSE(accept(d[0], d[1])) << d[0] << " " << d[1];
    EXPECT_EQ(nullptr, contact_book_label());
  }
  /* A coin no network names keeps nothing, even a valid proof. */
  const auto bytes = hex(UPROOF_BTC_0);
  EXPECT_FALSE(contact_book_utxo_accept_proof(nullptr, bytes.data(),
                                              bytes.size(), key.data()));
#if !BITCOIN_ONLY
  EXPECT_FALSE(accept("Litecoin", UPROOF_BTC_0));
  EXPECT_FALSE(accept("Namecoin", UPROOF_BTC_0));
  ASSERT_TRUE(accept("Litecoin", UPROOF_MIXED_6));
  EXPECT_STREQ("Alice", contact_book_label());
#endif
}

/* Every script type is matched on its exact bytes, and names only itself. */
TEST_F(UtxoContacts, EveryScriptTypeNamesOnlyItsOwnOutput) {
  struct {
    const char* proof;
    const char* label;
    const char* address;
    OutputScriptType type;
  } const book[] = {
      {UPROOF_BTC_0, "Alice", kAlice, OutputScriptType_PAYTOWITNESS},
      {UPROOF_BTC_1, "Bob", kBob, OutputScriptType_PAYTOTAPROOT},
      {UPROOF_BTC_2, "Carol", "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
       OutputScriptType_PAYTOADDRESS},
      {UPROOF_BTC_3, "Dave", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
       OutputScriptType_PAYTOSCRIPTHASH},
      {UPROOF_BTC_4, "Erin",
       "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
       OutputScriptType_PAYTOWITNESS},
  };
  for (const auto& held : book) {
    SCOPED_TRACE(held.label);
    ASSERT_TRUE(accept("Bitcoin", held.proof));
    for (const auto& out : book) {
      const char* label = labelFor("Bitcoin", toAddress(out.address, 1000, out.type));
      if (&out == &held) {
        EXPECT_STREQ(held.label, label);
      } else {
        EXPECT_EQ(nullptr, label) << out.address;
      }
    }
  }
}

TEST_F(UtxoContacts, NeverNamesChangeDataOrAnotherCoin) {
  ASSERT_TRUE(accept("Bitcoin", UPROOF_BTC_0));
  const auto script = hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
  const CoinType* btc = coinByName("Bitcoin");

  TxOutputType out = toAddress(kAlice, 1000, OutputScriptType_PAYTOWITNESS);
  EXPECT_STREQ("Alice", contact_book_utxo_label(btc, &out, script.data(),
                                                script.size()));

  /* Change and own-account transfers are given by path. */
  TxOutputType change = out;
  change.has_address = false;
  change.address_n_count = 5;
  EXPECT_EQ(nullptr, contact_book_utxo_label(btc, &change, script.data(),
                                             script.size()));
  change.has_address = true; /* signing refuses this shape anyway */
  EXPECT_EQ(nullptr, contact_book_utxo_label(btc, &change, script.data(),
                                             script.size()));

  TxOutputType data = out;
  data.script_type = OutputScriptType_PAYTOOPRETURN;
  EXPECT_EQ(nullptr, contact_book_utxo_label(btc, &data, script.data(),
                                             script.size()));

  /* The same script on Testnet is another network. */
  EXPECT_EQ(nullptr,
            labelFor("Testnet", toAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                                          1000, OutputScriptType_PAYTOWITNESS)));
#if !BITCOIN_ONLY
  /* Carol's BTC and BCH entries share one script. Each proof names only its
   * own coin. */
  const char kCarolBtc[] = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu";
  const char kCarolBch[] = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
  ASSERT_TRUE(accept("Bitcoin", UPROOF_MIXED_2));
  EXPECT_STREQ("Carol", labelFor("Bitcoin", toAddress(kCarolBtc, 1000,
                                                      OutputScriptType_PAYTOADDRESS)));
  EXPECT_EQ(nullptr, labelFor("BitcoinCash",
                              toAddress(kCarolBch, 1000, OutputScriptType_PAYTOADDRESS)));
  ASSERT_TRUE(accept("BitcoinCash", UPROOF_MIXED_7));
  EXPECT_STREQ("Carol cash",
               labelFor("BitcoinCash",
                        toAddress(kCarolBch, 1000, OutputScriptType_PAYTOADDRESS)));
  EXPECT_EQ(nullptr, labelFor("Bitcoin", toAddress(kCarolBtc, 1000,
                                                   OutputScriptType_PAYTOADDRESS)));

  /* Dogecoin and DigiByte share a P2PKH version byte, so one script is the
   * same "D..." address on both. A Dogecoin contact never names DigiByte. */
  const char kDoge[] = "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE";
  ASSERT_TRUE(accept("Dogecoin", UPROOF_MIXED_8));
  EXPECT_STREQ("Doge", labelFor("Dogecoin", toAddress(kDoge, 1000,
                                                      OutputScriptType_PAYTOADDRESS)));
  EXPECT_EQ(nullptr, labelFor("DigiByte", toAddress(kDoge, 1000,
                                                    OutputScriptType_PAYTOADDRESS)));

  /* Transparent Zcash. */
  ASSERT_TRUE(accept("Zcash", UPROOF_MIXED_10));
  EXPECT_STREQ("Zed", labelFor("Zcash", toAddress("t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs",
                                                  1000, OutputScriptType_PAYTOADDRESS)));
#endif
}

/* signing_abort() ends a SignTx proof but not the EVM proof that an
 * EthereumSignTx's engine reset passes through it on the way to. */
TEST_F(UtxoContacts, EndOfSigningDropsOnlyAUtxoProof) {
  ASSERT_TRUE(accept("Bitcoin", UPROOF_BTC_0));
  signing_abort();
  EXPECT_EQ(nullptr, contact_book_label());

  const auto evm = hex(PROOF3_0);
  ASSERT_TRUE(contact_book_process_proof(evm.data(), evm.size(), key.data()));
  signing_abort();
  EXPECT_STREQ("Alice", contact_book_label());
  contact_book_clear_type(CONTACT_BOOK_DEST_UTXO_SCRIPT);
  EXPECT_STREQ("Alice", contact_book_label());
  contact_book_clear_type(CONTACT_BOOK_DEST_EVM_ADDRESS);
  EXPECT_EQ(nullptr, contact_book_label());
}

/* The send screen adds the name and keeps the whole address. */
TEST_F(UtxoContacts, OutputScreenNamesTheContactBesideTheFullAddress) {
  const auto plain =
      review("Bitcoin", toAddress(kAlice, 100000, OutputScriptType_PAYTOWITNESS));
  ASSERT_EQ(1u, plain.size());
  EXPECT_EQ(std::string("Send 0.001 BTC to\n") + kAlice, plain[0]);

  ASSERT_TRUE(accept("Bitcoin", UPROOF_BTC_0));
  const auto named =
      review("Bitcoin", toAddress(kAlice, 100000, OutputScriptType_PAYTOWITNESS));
  ASSERT_EQ(1u, named.size()) << "the same number of screens";
  EXPECT_EQ(std::string("Send 0.001 BTC to Alice\n") + kAlice, named[0]);

  /* Several outputs: each one paying Alice is named, the others are not. */
  const auto bob =
      review("Bitcoin", toAddress(kBob, 5000, OutputScriptType_PAYTOTAPROOT));
  ASSERT_EQ(1u, bob.size());
  EXPECT_EQ(std::string("Send 0.00005 BTC to\n") + kBob, bob[0]);
  const auto again =
      review("Bitcoin", toAddress(kAlice, 2500, OutputScriptType_PAYTOWITNESS));
  ASSERT_EQ(1u, again.size());
  EXPECT_EQ(std::string("Send 0.000025 BTC to Alice\n") + kAlice, again[0]);
#if !BITCOIN_ONLY
  /* CashAddr: the same form as the unnamed screen, prefix included. */
  ASSERT_TRUE(accept("BitcoinCash", UPROOF_MIXED_7));
  const auto bch = review(
      "BitcoinCash",
      toAddress("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
                100000, OutputScriptType_PAYTOADDRESS));
  ASSERT_EQ(1u, bch.size());
  EXPECT_EQ("Send 0.001 BCH to Carol cash\n"
            "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            bch[0]);
#endif
}

}  // namespace
