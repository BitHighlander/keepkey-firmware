extern "C" {
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_settle.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

// What a typed-data order pays the signer (7.17), on the values of real
// OpenSea listings (Seaport 1.6 fills, ~/keepkey-audit-rigs batch6 fixtures)
// and of the phishing orders derived from them. Each item is fed as the
// review shows its fields: type, identifier, start and end amount, recipient.

namespace {

std::vector<uint8_t> word(const char* decimal) {
  std::vector<uint8_t> out(32, 0);
  for (const char* c = decimal; *c; c++) {
    unsigned carry = (unsigned)(*c - '0');
    for (int i = 31; i >= 0; i--) {
      carry += out[i] * 10u;
      out[i] = (uint8_t)carry;
      carry >>= 8;
    }
  }
  return out;
}

std::vector<uint8_t> address(const char* hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    unsigned value = 0;
    sscanf(hex + i, "%2x", &value);
    out.push_back((uint8_t)value);
  }
  return out;
}

const char* kZero = "0000000000000000000000000000000000000000";
const char* kWeth = "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const char* kPolygonWeth = "7ceb23fd6bc0add59e62ac25578270cff1b9f619";
const char* kWorthless = "1111111111111111111111111111111111111111";
const char* kNft = "387c41b0b2f1128de44db1bcf8baad085f26392c";

struct Order {
  Erc7730Settle settle{};

  // offer[]: the definition marks one field of each item GIVE.
  Order& give() {
    erc7730_settle_give(&settle);
    erc7730_settle_end_item(&settle);
    return *this;
  }
  // consideration[]: itemType, identifierOrCriteria, startAmount, endAmount,
  // recipient, then the element ends.
  Order& pay(unsigned type, const char* token, const char* start,
             const char* end, bool to_signer, const char* id = "0") {
    const auto type_word = word(std::to_string(type).c_str());
    erc7730_settle_type(&settle, type_word.data());
    erc7730_settle_id(&settle, word(id).data());
    const auto t = address(token);
    const bool native = std::strcmp(token, kZero) == 0;
    erc7730_settle_amount(&settle, word(start).data(), t.data(), native);
    erc7730_settle_amount(&settle, word(end).data(), t.data(), native);
    erc7730_settle_to(&settle, to_signer);
    erc7730_settle_end_item(&settle);
    return *this;
  }
  Order& pay(unsigned type, const char* token, const char* amount,
             bool to_signer) {
    return pay(type, token, amount, amount, to_signer);
  }

  std::string review(uint64_t chain, Erc7730SettleVerdict expected) {
    Erc7730SettleVerdict verdict = ERC7730_SETTLE_CALM;
    char body[512];
    if (!erc7730_settle_review(&settle, chain, &verdict, body, sizeof(body)))
      return "<refused>";
    EXPECT_EQ(verdict, expected) << body;
    return body;
  }
};

const char* kDust = "This wallet gets only unknown tokens, NFTs or dust:\n";

}  // namespace

// Real listings, as the seller signs them: the NFT given, the seller paid in
// the native coin, the marketplace and creator fees paid to others.
TEST(Erc7730Settle, RealListingShowsWhatTheSellerReceives) {
  // mainnet tx 0x1dfb30c9...: seller, OpenSea fee, creator fee
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "19740000000000000", true)
                .pay(0, kZero, "210000000000000", false)
                .pay(0, kZero, "1050000000000000", false)
                .review(1, ERC7730_SETTLE_CALM),
            "0.01974 ETH");
  // Base: the cheapest real listing, 0.000025 ETH, is not dust.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "25000000000000", true)
                .review(8453, ERC7730_SETTLE_CALM),
            "0.000025 ETH");
  // Avalanche, ERC-1155 x2.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "55242000000000000", true)
                .pay(0, kZero, "558000000000000", false)
                .review(43114, ERC7730_SETTLE_CALM),
            "0.055242 AVAX");
  // Paid in a token the table knows.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            "0.5 WETH");
}

// Phishing: the victim's NFT for nothing paid to the victim.
TEST(Erc7730Settle, NothingPaidToThisWalletWarns) {
  const char* nothing = "Nothing in this order is paid to this wallet.";
  // 1 wei to a stranger.
  EXPECT_EQ(Order().give().pay(0, kZero, "1", false).review(
                1, ERC7730_SETTLE_NOTHING),
            nothing);
  // The real creator-fee listing with the seller's payment redirected.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "19740000000000000", false)
                .pay(0, kZero, "210000000000000", false)
                .pay(0, kZero, "1050000000000000", false)
                .review(1, ERC7730_SETTLE_NOTHING),
            nothing);
  // No payment at all.
  EXPECT_EQ(Order().give().review(1, ERC7730_SETTLE_NOTHING), nothing);
}

// A payment that makes a phishing order look paid: dust or a worthless token.
TEST(Erc7730Settle, OnlyDustOrUnknownTokensForWhatIsGivenWarns) {
  EXPECT_EQ(Order().give().pay(0, kZero, "1", true).review(
                1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) + "1 Wei");
  // A worthless token the attacker made.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWorthless, "1000000000000000000000", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) +
                "1000000000000000000000\nunknown token\n"
                "0x1111111111111111111111111111111111111111");
  // Dust of a known token: under a millionth of one WETH.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "999999999999", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) + "0.000000999999999999 WETH");
  // A millionth of one is no longer dust.
  Order().give().pay(1, kWeth, "1000000000000", true).review(
      1, ERC7730_SETTLE_CALM);
  // Dust from two payments stays dust.
  Order()
      .give()
      .pay(0, kZero, "1", true)
      .pay(0, kZero, "1", true)
      .review(1, ERC7730_SETTLE_UNVALUED);
  // The device has no NFT prices: an NFT for an NFT warns.
  EXPECT_EQ(
      Order()
          .give()
          .pay(2, kNft, "1", "1", true, "5318")
          .review(1, ERC7730_SETTLE_UNVALUED),
      std::string(kDust) +
          "NFT ID 5318\n0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C");
  // Without anything given, the same receipt is not a warning.
  Order().pay(1, kWorthless, "5", true).review(1, ERC7730_SETTLE_CALM);
}

// The smaller of the start and end amounts counts: a Dutch auction that ends
// at 1 wei pays 1 wei.
TEST(Erc7730Settle, DutchAuctionCountsItsSmallerAmount) {
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1000000000000000000", "1", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) + "1 Wei");
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1", "1000000000000000000", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) + "1 Wei");
}

// Seaport moves an item by its type: an ERC-721 item whose token is WETH
// moves "identifier" wei, so it is never counted as WETH.
TEST(Erc7730Settle, ItemTypeDecidesWhatIsReceived) {
  EXPECT_EQ(Order()
                .give()
                .pay(2, kWeth, "1", "1", true, "1")
                .review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) +
                "NFT ID 1\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
  // A native item with a token, an ERC-20 at 0x0, an unknown type: unread.
  for (const auto& c : {std::make_pair(0u, kWeth), std::make_pair(1u, kZero),
                        std::make_pair(6u, kZero)}) {
    EXPECT_EQ(Order()
                  .give()
                  .pay(c.first, c.second, "1000000000000000000", true)
                  .review(1, ERC7730_SETTLE_UNVALUED),
              std::string(kDust) + "+ items not listed here")
        << c.first;
  }
  // Start and end in two tokens: unread.
  Order order;
  order.give();
  const auto type = word("0");
  erc7730_settle_type(&order.settle, type.data());
  erc7730_settle_amount(&order.settle, word("1000000000000000000").data(),
                        address(kZero).data(), true);
  erc7730_settle_amount(&order.settle, word("1000000000000000000").data(),
                        address(kWeth).data(), false);
  erc7730_settle_to(&order.settle, true);
  erc7730_settle_end_item(&order.settle);
  order.review(1, ERC7730_SETTLE_UNVALUED);
}

TEST(Erc7730Settle, NftsAndTotalsAreListed) {
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1000000000000000", true)
                .pay(0, kZero, "2000000000000000", true)
                .pay(3, kNft, "4", "4", true, "7")
                .review(1, ERC7730_SETTLE_CALM),
            "0.003 ETH\n4 of NFT ID 7\n"
            "0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C");
  EXPECT_EQ(Order()
                .pay(4, kNft, "1", "1", true, "12345")
                .review(1, ERC7730_SETTLE_CALM),
            "1 NFT by criteria\n0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C");
  // More distinct items than the device lists: summed up, never valued.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWorthless, "1", true)
                .pay(2, kNft, "1", "1", true, "1")
                .pay(0, kZero, "1000000000000000000", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) +
                "1\nunknown token\n0x1111111111111111111111111111111111111111"
                "\nNFT ID 1\n0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C\n"
                "+ items not listed here");
  // A total that overflows is not listed.
  const char* max =
      "115792089237316195423570985008687907853269984665640564039457584007913"
      "129639935";
  EXPECT_EQ(Order()
                .pay(0, kZero, max, true)
                .pay(0, kZero, "1", true)
                .review(1, ERC7730_SETTLE_CALM)
                .find("+ items not listed here") != std::string::npos,
            true);
}

// The table knows tokens per chain: WETH on Polygon is not in it, so a real
// Polygon listing paid in WETH warns (a firmware table limit, stated).
TEST(Erc7730Settle, TokensUnknownOnTheChainAreNotValued) {
  EXPECT_EQ(Order()
                .give()
                .pay(1, kPolygonWeth, "3613500000000000", true)
                .pay(1, kPolygonWeth, "36500000000000", false)
                .review(137, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) +
                "3613500000000000\nunknown token\n"
                "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619");
  // Mainnet WETH's address on another chain is not WETH.
  Order().give().pay(1, kWeth, "500000000000000000", true).review(
      8453, ERC7730_SETTLE_UNVALUED);
}

// Items paid to others never reach the summary, and an element's values never
// leak into the next element.
TEST(Erc7730Settle, EachItemEndsWithItsElement) {
  Order order;
  order.give();
  const auto type = word("0");
  erc7730_settle_type(&order.settle, type.data());
  erc7730_settle_amount(&order.settle, word("5000000000000000000").data(),
                        address(kZero).data(), true);
  erc7730_settle_to(&order.settle, false);
  erc7730_settle_end_item(&order.settle);
  // The next element has no amount of its own.
  erc7730_settle_to(&order.settle, true);
  erc7730_settle_end_item(&order.settle);
  EXPECT_EQ(order.review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) + "+ items not listed here");
}

// The flags each formatter kind may carry: one SETTLE role at most, on the
// kinds that can hold its value; never on embedded calldata.
TEST(Erc7730Settle, FormatterKindsCarryTheirRoles) {
  EXPECT_EQ(erc7730_cap_formatter_flags(1),
            ERC7730_FORMATTER_FLAG_SETTLE_GIVE |
                ERC7730_FORMATTER_FLAG_SETTLE_TYPE |
                ERC7730_FORMATTER_FLAG_SETTLE_ID);
  EXPECT_EQ(erc7730_cap_formatter_flags(3),
            ERC7730_FORMATTER_FLAG_SETTLE_GIVE |
                ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT);
  EXPECT_EQ(erc7730_cap_formatter_flags(8),
            ERC7730_FORMATTER_FLAG_SETTLE_GIVE |
                ERC7730_FORMATTER_FLAG_SETTLE_TYPE);
  EXPECT_EQ(erc7730_cap_formatter_flags(10),
            ERC7730_FORMATTER_FLAG_SETTLE_GIVE |
                ERC7730_FORMATTER_FLAG_RECIPIENT |
                ERC7730_FORMATTER_FLAG_SETTLE_TO);
  EXPECT_EQ(erc7730_cap_formatter_flags(2),
            ERC7730_FORMATTER_FLAG_SETTLE_GIVE |
                ERC7730_FORMATTER_FLAG_TX_VALUE);
  EXPECT_EQ(erc7730_cap_formatter_flags(13), 0u);
}

namespace {

// An item's amount as the review shows it (erc7730_settle_format_nft_amount
// for an NFT item, else a token amount), after its type and identifier.
std::string shown_amount(Erc7730Settle* settle, unsigned type, const char* id,
                         const char* amount, const char* token,
                         uint64_t chain = 1) {
  const auto type_word = word(std::to_string(type).c_str());
  erc7730_settle_type(settle, type_word.data());
  if (id) erc7730_settle_id(settle, word(id).data());
  if (erc7730_settle_item_is_coin(settle)) return "<coin>";
  char out[512];
  if (!erc7730_settle_format_nft_amount(settle, word(amount).data(),
                                        address(token).data(), chain, out,
                                        sizeof(out))) {
    EXPECT_EQ(out[0], '\0');
    return "<refused>";
  }
  return out;
}

// offer[] the way batch 6-D marks it: type, identifier and amounts, no GIVE.
Order& give_item(Order& order, unsigned type, const char* token,
                 const char* amount, const char* id = "0") {
  shown_amount(&order.settle, type, id, amount, token);
  const auto t = address(token);
  erc7730_settle_amount(&order.settle, word(amount).data(), t.data(),
                        std::strcmp(token, kZero) == 0);
  erc7730_settle_end_item(&order.settle);
  return order;
}

const char* kCoinWeth =
    "An NFT item names the token WETH: Seaport moves its ID as an amount of "
    "WETH.\n";

}  // namespace

// Seaport moves an NFT item by its identifier: its amount is a count of that
// NFT, never an amount of its token. Coins keep their token amount.
TEST(Erc7730Settle, NftAmountsAreShownAsSeaportMovesThem) {
  const std::string nft = "\n0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C";
  Erc7730Settle s{};
  EXPECT_EQ(shown_amount(&s, 2, "446", "1", kNft), "NFT ID 446" + nft);
  s = {};
  // Seaport refuses an ERC-721 amount other than 1; it reads as a count.
  EXPECT_EQ(shown_amount(&s, 2, "446", "3", kNft), "3 of NFT ID 446" + nft);
  s = {};
  EXPECT_EQ(shown_amount(&s, 3, "650", "2", kNft), "2 of NFT ID 650" + nft);
  s = {};
  EXPECT_EQ(shown_amount(&s, 4, "0", "1", kNft), "1 NFT by criteria" + nft);
  s = {};
  EXPECT_EQ(shown_amount(&s, 5, "77", "7", kNft), "7 NFT by criteria" + nft);
  // Coins, and items with no type shown, are token amounts.
  for (unsigned type : {0u, 1u}) {
    s = {};
    EXPECT_EQ(shown_amount(&s, type, "0", "5", kWeth), "<coin>") << type;
  }
  s = {};
  EXPECT_TRUE(erc7730_settle_item_is_coin(&s));
  // A type beyond Seaport's, or an NFT whose identifier was not shown first.
  s = {};
  EXPECT_EQ(shown_amount(&s, 6, "0", "1", kNft), "<refused>");
  s = {};
  EXPECT_EQ(shown_amount(&s, 2, nullptr, "1", kNft), "<refused>");
  s = {};
  EXPECT_EQ(shown_amount(&s, 3, nullptr, "1", kNft), "<refused>");
  // Criteria items need no identifier: the criteria is its own screen.
  s = {};
  EXPECT_EQ(shown_amount(&s, 4, nullptr, "1", kNft), "1 NFT by criteria" + nft);
  EXPECT_EQ(s.coin_as_nft, nullptr);
}

// The re-review's drain: an ERC-721 (or by-criteria) item whose token is WETH
// moves "identifier" wei of WETH. The amount reads as an NFT, and the last
// screen warns, whatever the order pays.
TEST(Erc7730Settle, AnNftItemNamingACoinWarns) {
  {
    Order order;
    give_item(order, 4, kWeth, "1", "0");
    EXPECT_EQ(order.settle.coin_as_nft != nullptr, true);
    EXPECT_EQ(order.pay(0, kZero, "500000000000000000", true)
                  .review(1, ERC7730_SETTLE_COIN_AS_NFT),
              std::string(kCoinWeth) + "You receive:\n0.5 ETH");
  }
  {
    Order order;
    give_item(order, 2, kWeth, "1", "50000000000000000000");
    EXPECT_EQ(order.pay(0, kZero, "1", false)
                  .review(1, ERC7730_SETTLE_COIN_AS_NFT),
              std::string(kCoinWeth) +
                  "Nothing in this order is paid to this wallet.");
  }
  {
    Order order;
    give_item(order, 2, kWeth, "1", "1");
    EXPECT_EQ(order.pay(0, kZero, "1", true)
                  .review(1, ERC7730_SETTLE_COIN_AS_NFT),
              std::string(kCoinWeth) + kDust + "1 Wei");
  }
  // The same address on a chain whose table does not list it: no warning
  // (the device cannot tell an NFT contract from a token it does not list).
  Erc7730Settle s{};
  shown_amount(&s, 2, "1", "1", kWeth, 8453);
  EXPECT_EQ(s.coin_as_nft, nullptr);
  // A real NFT collection: no warning.
  Order order;
  give_item(order, 2, kNft, "1", "5318");
  EXPECT_EQ(order.settle.coin_as_nft, nullptr);
  EXPECT_EQ(order.pay(0, kZero, "19740000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            "0.01974 ETH");
}

// An item described by type and amount with no recipient is given away, the
// same as a GIVE: 1 wei back for it warns.
TEST(Erc7730Settle, AnItemWithoutRecipientIsGiven) {
  Order order;
  give_item(order, 2, kNft, "1", "5318");
  EXPECT_TRUE(order.settle.gives);
  EXPECT_EQ(order.pay(0, kZero, "1", true).review(1, ERC7730_SETTLE_UNVALUED),
            std::string(kDust) + "1 Wei");
  // Control: nothing given, the same receipt is calm.
  EXPECT_EQ(Order().pay(0, kZero, "1", true).review(1, ERC7730_SETTLE_CALM),
            "1 Wei");
}
