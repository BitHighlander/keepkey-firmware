extern "C" {
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_settle.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

// What a typed-data order gives and pays the signer (7.17), on the values of
// real OpenSea listings (Seaport 1.6 fills, ~/keepkey-audit-rigs batch6
// fixtures) and of the phishing orders derived from them. Each item is fed as
// the review shows its fields: type, identifier, start and end amount (an
// NFT item's amount through erc7730_settle_format_nft_amount, as the device
// shows it), recipient.

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
const char* kEeee = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const char* kMax =
    "115792089237316195423570985008687907853269984665640564039457584007913"
    "129639935";

struct Order {
  Erc7730Settle settle{};
  uint64_t chain = 1;
  bool refused = false;

  // One item as the review shows it: type, identifier, then each amount
  // (an NFT item's through erc7730_settle_format_nft_amount, which the
  // device fails the review on), the recipient when there is one.
  Order& item(unsigned type, const char* token, const char* start,
              const char* end, const char* id, int to_signer) {
    const auto type_word = word(std::to_string(type).c_str());
    erc7730_settle_type(&settle, type_word.data());
    if (id) erc7730_settle_id(&settle, word(id).data());
    const auto t = address(token);
    const bool native = std::strcmp(token, kZero) == 0;
    for (const char* amount : {start, end}) {
      if (!erc7730_settle_item_is_coin(&settle)) {
        char shown[256];
        if (!erc7730_settle_format_nft_amount(&settle, word(amount).data(),
                                              t.data(), chain, shown,
                                              sizeof(shown)))
          refused = true;
      }
      erc7730_settle_amount(&settle, word(amount).data(), t.data(), native);
    }
    if (to_signer >= 0) erc7730_settle_to(&settle, to_signer == 1);
    erc7730_settle_end_item(&settle, chain);
    return *this;
  }
  // offer[]: an item with no recipient, given away. By default the seller's
  // NFT.
  Order& give(unsigned type = 2, const char* token = kNft,
              const char* start = "1", const char* end = nullptr,
              const char* id = "5318") {
    return item(type, token, start, end ? end : start, id, -1);
  }
  // consideration[]: itemType, identifierOrCriteria, startAmount, endAmount,
  // recipient, then the element ends.
  Order& pay(unsigned type, const char* token, const char* start,
             const char* end, bool to_signer, const char* id = "0") {
    return item(type, token, start, end, id, to_signer ? 1 : 0);
  }
  Order& pay(unsigned type, const char* token, const char* amount,
             bool to_signer) {
    return pay(type, token, amount, amount, to_signer);
  }

  std::string review(uint64_t chain, Erc7730SettleVerdict expected) {
    if (refused) return "<refused>";
    Erc7730SettleVerdict verdict = ERC7730_SETTLE_CALM;
    char body[ERC7730_SETTLE_BODY_MAX];
    if (!erc7730_settle_review(&settle, chain, &verdict, body, sizeof(body)))
      return "<refused>";
    EXPECT_EQ(verdict, expected) << body;
    return body;
  }
};

// The settlement screen: its warning lines, then both sides.
std::string screen(const std::vector<std::string>& warnings,
                   const std::string& give, const std::string& receive) {
  std::string out;
  for (const auto& line : warnings) out += line + "\n";
  return out + "You give:\n" + give + "\nYou receive:\n" + receive;
}

const char* kNftAddress = "0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C";
const std::string kSellerNft = std::string("NFT ID 5318\n") + kNftAddress;
const char* kNothing = "Nothing in this order is paid to this wallet.";
const char* kBack = "This wallet gets back no more than it gives.";
const char* kUnknown = "This wallet gets only unknown tokens or NFTs.";
const char* kUnderEth = "This wallet gets under 0.0001 ETH.";
const char* kCriteria =
    "This wallet gives an item by criteria: the buyer picks its ID (on a "
    "token, the ID is an amount).";
const char* kMoreItems = "This wallet gives more items than this screen lists.";

}  // namespace

// Real listings, as the seller signs them: the NFT given, the seller paid in
// the native coin, the marketplace and creator fees paid to others. The
// screen is neutral and shows both sides.
TEST(Erc7730Settle, RealListingShowsBothSides) {
  // mainnet tx 0x1dfb30c9...: seller, OpenSea fee, creator fee
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "19740000000000000", true)
                .pay(0, kZero, "210000000000000", false)
                .pay(0, kZero, "1050000000000000", false)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "0.01974 ETH"));
  // Avalanche, ERC-1155 x2.
  EXPECT_EQ(Order()
                .give(3, kNft, "2", nullptr, "650")
                .pay(0, kZero, "55242000000000000", true)
                .pay(0, kZero, "558000000000000", false)
                .review(43114, ERC7730_SETTLE_CALM),
            screen({}, std::string("2 of NFT ID 650\n") + kNftAddress,
                   "0.055242 AVAX"));
  // Paid in a token the table knows.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "0.5 WETH"));
  // Base: the cheapest real listing, 0.000025 ETH, is under the floor. The
  // line is a fact, not a price; the listing still shows both sides.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "25000000000000", true)
                .review(8453, ERC7730_SETTLE_DUST),
            screen({kUnderEth}, kSellerNft, "0.000025 ETH"));
}

// Phishing: the victim's NFT for nothing paid to the victim.
TEST(Erc7730Settle, NothingPaidToThisWalletWarns) {
  const std::string nothing = screen({kNothing}, kSellerNft, "Nothing");
  // 1 wei to a stranger.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1", false)
                .review(1, ERC7730_SETTLE_NOTHING),
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

// A payment that makes a phishing order look paid: a worthless token or an
// NFT, which the device cannot tell from a real one.
TEST(Erc7730Settle, OnlyUnknownTokensOrNftsForWhatIsGivenWarns) {
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWorthless, "1000000000000000000000", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, kSellerNft,
                   "1000000000000000000000\nunknown token\n"
                   "0x1111111111111111111111111111111111111111"));
  // The device has no NFT prices: an NFT for an NFT warns.
  EXPECT_EQ(
      Order()
          .give()
          .pay(2, kNft, "1", "1", true, "7")
          .review(1, ERC7730_SETTLE_UNVALUED),
      screen({kUnknown}, kSellerNft, std::string("NFT ID 7\n") + kNftAddress));
  // Without anything given, the same receipt is not a warning.
  EXPECT_EQ(
      Order().pay(1, kWorthless, "5", true).review(1, ERC7730_SETTLE_CALM),
      screen({}, "Nothing",
             "5\nunknown token\n"
             "0x1111111111111111111111111111111111111111"));
}

// Dust is a fact the device states, never a reason to be calm: a coin under
// 0.0001 of one (0.01 for six decimals or fewer, one unit below two) adds a
// line, and paying above it only removes that line.
TEST(Erc7730Settle, DustIsALineNotAPrice) {
  EXPECT_EQ(
      Order().give().pay(0, kZero, "1", true).review(1, ERC7730_SETTLE_DUST),
      screen({kUnderEth}, kSellerNft, "1 Wei"));
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "99999999999999", true)
                .review(1, ERC7730_SETTLE_DUST),
            screen({"This wallet gets under 0.0001 WETH."}, kSellerNft,
                   "0.000099999999999999 WETH"));
  // 0.0001 of one is no longer dust; both sides are still shown.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "100000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "0.0001 WETH"));
  // Dust from two payments stays dust.
  Order()
      .give()
      .pay(0, kZero, "1", true)
      .pay(0, kZero, "1", true)
      .review(1, ERC7730_SETTLE_DUST);
  // One coin above the floor is enough; the dusty one is still listed.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1", true)
                .pay(1, kWeth, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "1 Wei\n0.5 WETH"));
}

// Review r1 (HIGH): an NFT for a millionth of one ETH (1e12 wei) read as a
// calm "You receive: 0.000001 ETH". It now warns, and shows what is given.
TEST(Erc7730Settle, ReviewDustFloorNftForAMillionthOfAnEthWarns) {
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1000000000000", true)
                .review(1, ERC7730_SETTLE_DUST),
            screen({kUnderEth}, kSellerNft, "0.000001 ETH"));
}

// The smaller of the start and end amounts counts: a Dutch auction that ends
// at 1 wei pays 1 wei.
TEST(Erc7730Settle, DutchAuctionCountsItsSmallerAmount) {
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1000000000000000000", "1", true)
                .review(1, ERC7730_SETTLE_DUST),
            screen({kUnderEth}, kSellerNft, "1 Wei"));
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1", "1000000000000000000", true)
                .review(1, ERC7730_SETTLE_DUST),
            screen({kUnderEth}, kSellerNft, "1 Wei"));
}

// Seaport moves an item by its type: an ERC-721 item whose token is WETH
// moves "identifier" wei, so it is never counted as WETH, and it warns.
TEST(Erc7730Settle, ItemTypeDecidesWhatIsReceived) {
  EXPECT_EQ(Order()
                .give()
                .pay(2, kWeth, "1", "1", true, "1")
                .review(1, ERC7730_SETTLE_COIN_AS_NFT),
            screen({"An NFT item names the token WETH: Seaport moves its ID "
                    "as an amount of WETH.",
                    kUnknown},
                   kSellerNft,
                   "NFT ID 1\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"));
  // A native item with a token, an ERC-20 at 0x0: unread.
  for (const auto& c : {std::make_pair(0u, kWeth), std::make_pair(1u, kZero)}) {
    EXPECT_EQ(Order()
                  .give()
                  .pay(c.first, c.second, "1000000000000000000", true)
                  .review(1, ERC7730_SETTLE_UNVALUED),
              screen({kUnknown}, kSellerNft, "+ items not listed here"))
        << c.first;
  }
  // A type beyond Seaport's: its amount screen refuses the review.
  EXPECT_EQ(Order()
                .give()
                .pay(6, kZero, "1000000000000000000", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            "<refused>");
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
  erc7730_settle_end_item(&order.settle, order.chain);
  order.review(1, ERC7730_SETTLE_UNVALUED);
}

TEST(Erc7730Settle, NftsAndTotalsAreListed) {
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "1000000000000000", true)
                .pay(0, kZero, "2000000000000000", true)
                .pay(3, kNft, "4", "4", true, "7")
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft,
                   std::string("0.003 ETH\n4 of NFT ID 7\n") + kNftAddress));
  EXPECT_EQ(
      Order()
          .pay(4, kNft, "1", "1", true, "12345")
          .review(1, ERC7730_SETTLE_CALM),
      screen({}, "Nothing", std::string("1 NFT by criteria\n") + kNftAddress));
  // More distinct items than the device lists: summed up, never valued.
  EXPECT_EQ(
      Order()
          .give()
          .pay(1, kWorthless, "1", true)
          .pay(2, kNft, "1", "1", true, "1")
          .pay(0, kZero, "1000000000000000000", true)
          .review(1, ERC7730_SETTLE_UNVALUED),
      screen({kUnknown}, kSellerNft,
             "1\nunknown token\n0x1111111111111111111111111111111111111111"
             "\nNFT ID 1\n" +
                 std::string(kNftAddress) + "\n+ items not listed here"));
  // A total that overflows is not listed.
  EXPECT_NE(Order()
                .pay(0, kZero, kMax, true)
                .pay(0, kZero, "1", true)
                .review(1, ERC7730_SETTLE_CALM)
                .find("+ items not listed here"),
            std::string::npos);
}

// Every NFT given is listed, by ID and contract: two of them, then a count.
TEST(Erc7730Settle, EveryNftGivenIsListed) {
  const std::string pay = "0.5 ETH";
  EXPECT_EQ(Order()
                .give(2, kNft, "1", nullptr, "1")
                .give(3, kNft, "2", nullptr, "3")
                .pay(0, kZero, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({},
                   std::string("NFT ID 1\n") + kNftAddress +
                       "\n2 of NFT ID 3\n" + kNftAddress,
                   pay));
  // The same NFT twice is one line; a third and fourth are counted, and
  // the screen says it does not list everything given (review r2).
  EXPECT_EQ(Order()
                .give(2, kNft, "1", nullptr, "1")
                .give(3, kNft, "1", nullptr, "3")
                .give(3, kNft, "1", nullptr, "3")
                .give(2, kNft, "1", nullptr, "4")
                .give(2, kNft, "1", nullptr, "5")
                .pay(0, kZero, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_GIVEN_UNLISTED),
            screen({kMoreItems},
                   std::string("NFT ID 1\n") + kNftAddress +
                       "\n2 of NFT ID 3\n" + kNftAddress + "\n+ 2 more NFTs",
                   pay));
  // NFTs and coins given: NFTs first.
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "100000000000000000")
                .pay(0, kZero, "600000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft + "\n0.1 WETH", "0.5 ETH"));
}

// The table knows tokens per chain: WETH on Polygon is not in it, so a real
// Polygon listing paid in WETH warns (a firmware table limit, stated).
TEST(Erc7730Settle, TokensUnknownOnTheChainAreNotValued) {
  EXPECT_EQ(Order()
                .give()
                .pay(1, kPolygonWeth, "3613500000000000", true)
                .pay(1, kPolygonWeth, "36500000000000", false)
                .review(137, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, kSellerNft,
                   "3613500000000000\nunknown token\n"
                   "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"));
  // Mainnet WETH's address on another chain is not WETH.
  Order()
      .give()
      .pay(1, kWeth, "500000000000000000", true)
      .review(8453, ERC7730_SETTLE_UNVALUED);
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
  erc7730_settle_end_item(&order.settle, order.chain);
  // The next element has no amount of its own.
  erc7730_settle_to(&order.settle, true);
  erc7730_settle_end_item(&order.settle, order.chain);
  EXPECT_EQ(order.review(1, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, kSellerNft, "+ items not listed here"));
}

// The flags each formatter kind may carry: one SETTLE role at most, on the
// kinds that can hold its value; never on embedded calldata.
TEST(Erc7730Settle, FormatterKindsCarryTheirRoles) {
  EXPECT_EQ(
      erc7730_cap_formatter_flags(1),
      ERC7730_FORMATTER_FLAG_SETTLE_TYPE | ERC7730_FORMATTER_FLAG_SETTLE_ID);
  EXPECT_EQ(erc7730_cap_formatter_flags(3),
            ERC7730_FORMATTER_FLAG_SETTLE_AMOUNT);
  EXPECT_EQ(erc7730_cap_formatter_flags(8), ERC7730_FORMATTER_FLAG_SETTLE_TYPE);
  EXPECT_EQ(
      erc7730_cap_formatter_flags(10),
      ERC7730_FORMATTER_FLAG_RECIPIENT | ERC7730_FORMATTER_FLAG_SETTLE_TO);
  EXPECT_EQ(erc7730_cap_formatter_flags(2), ERC7730_FORMATTER_FLAG_TX_VALUE);
  // Flag 4 (a "give" role in an earlier draft) is no role: an item is
  // given when it has no recipient, and must be read like a payment.
  for (unsigned kind = 0; kind < 32; kind++)
    EXPECT_EQ(erc7730_cap_formatter_flags((uint8_t)kind) & 4u, 0u) << kind;
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

const char* kCoinWeth =
    "An NFT item names the token WETH: Seaport moves its ID as an amount of "
    "WETH.";

}  // namespace

// Seaport moves an NFT item by its identifier: its amount is a count of that
// NFT, never an amount of its token. Coins keep their token amount.
TEST(Erc7730Settle, NftAmountsAreShownAsSeaportMovesThem) {
  const std::string nft = std::string("\n") + kNftAddress;
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
  const std::string weth_nft =
      "1 NFT by criteria\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
  EXPECT_EQ(Order()
                .give(4, kWeth, "1", nullptr, "0")
                .pay(0, kZero, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_COIN_AS_NFT),
            screen({kCoinWeth, kCriteria}, weth_nft, "0.5 ETH"));
  EXPECT_EQ(Order()
                .give(2, kWeth, "1", nullptr, "50000000000000000000")
                .pay(0, kZero, "1", false)
                .review(1, ERC7730_SETTLE_COIN_AS_NFT),
            screen({kCoinWeth, kNothing},
                   "NFT ID 50000000000000000000\n"
                   "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                   "Nothing"));
  // The same address on a chain whose table does not list it: no coin
  // warning (the device cannot tell an NFT contract from a token it does
  // not list; the ID is under 2^64).
  Erc7730Settle s{};
  shown_amount(&s, 2, "1", "1", kWeth, 8453);
  EXPECT_EQ(s.coin_as_nft, nullptr);
  // A real NFT collection: no warning.
  EXPECT_EQ(Order()
                .give()
                .pay(0, kZero, "19740000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "0.01974 ETH"));
}

// An item described by type and amount with no recipient is given away.
TEST(Erc7730Settle, AnItemWithoutRecipientIsGiven) {
  Order order;
  order.give();
  EXPECT_TRUE(order.settle.gives);
  EXPECT_EQ(order.pay(0, kZero, "1", true).review(1, ERC7730_SETTLE_DUST),
            screen({kUnderEth}, kSellerNft, "1 Wei"));
  // Control: nothing given, the same receipt is not a warning.
  EXPECT_EQ(Order().pay(0, kZero, "1", true).review(1, ERC7730_SETTLE_CALM),
            screen({}, "Nothing", "1 Wei"));
}

namespace {

const char* kBayc = "bc4ca0eda7647a8ab7c2061c2e118a18a936f13d";
const char* kUsdc = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const char* kGusd = "056fd409e1d7a124bd7017459dfea2f387b6d5cd";
const char* kDcn = "08d32b0da63e2c3bcf8019c9c5d849d7a9d791e6";
const char* kUsde = "4c9edd5852cd905f086c759e8383e09bff1e68b3";
// Lido DAO: an ERC-20 the token table does not list, and no list names.
const char* kLdo = "5a98fcbea516cf06857215779fd812ca3bef1b32";
const char* kBaseUsdc = "833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const char* kEns = "57f1887a8bf19b14fc0df6fd9b2acc9af147ea85";
const char* kGivesUnknown =
    "This wallet gives a token the device does not know: if it is an NFT "
    "collection, Seaport moves the NFT whose ID is the amount.";
const char* kLargeId =
    "An NFT ID is 2^64 or more: if its contract is a token, Seaport moves "
    "that many units of it.";
const std::string kBaycGiven =
    "1234\nunknown token\n0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D";

}  // namespace

// Seaport moves an ERC-20 item with transferFrom(from, to, amount), which an
// ERC-721 answers too: an ERC-20 item naming BAYC gives BAYC #1234. An
// ERC-20 the order gives away that the table does not list warns.
TEST(Erc7730Settle, GivingAnUnknownErc20Warns) {
  {
    Order order;
    order.give(1, kBayc, "1234");
    EXPECT_TRUE(order.settle.gives_unknown_token);
    EXPECT_EQ(order.pay(0, kZero, "1000000000000000", true)
                  .review(1, ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN),
              screen({kGivesUnknown}, kBaycGiven, "0.001 ETH"));
  }
  EXPECT_EQ(Order()
                .give(1, kBayc, "1234")
                .pay(0, kZero, "1", false)
                .review(1, ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN),
            screen({kGivesUnknown, kNothing}, kBaycGiven, "Nothing"));
  // With an NFT item naming a coin too: both lines, then both sides.
  EXPECT_EQ(Order()
                .give(2, kWeth, "1", nullptr, "5")
                .give(1, kBayc, "7")
                .pay(0, kZero, "1000000000000000", true)
                .review(1, ERC7730_SETTLE_COIN_AS_NFT),
            screen({kCoinWeth, kGivesUnknown},
                   "NFT ID 5\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n7\n"
                   "unknown token\n0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
                   "0.001 ETH"));
  {
    // Mainnet WETH is not in the table on Base: the same order warns there.
    Order order;
    order.chain = 8453;
    order.give(1, kWeth, "500000000000000000");
    EXPECT_TRUE(order.settle.gives_unknown_token);
  }
  // Controls: a token the table lists, the native coin, an NFT given, and an
  // unknown token paid out, not given.
  {
    Order order;
    order.give(1, kWeth, "500000000000000000");
    EXPECT_FALSE(order.settle.gives_unknown_token);
    // WETH given nets against the ETH paid back.
    EXPECT_EQ(order.pay(0, kZero, "600000000000000000", true)
                  .review(1, ERC7730_SETTLE_CALM),
              screen({}, "0.5 WETH", "0.1 ETH"));
  }
  EXPECT_FALSE(
      Order().give(0, kZero, "500000000000000000").settle.gives_unknown_token);
  EXPECT_FALSE(Order().give().settle.gives_unknown_token);
  EXPECT_FALSE(
      Order().give().pay(1, kWorthless, "5", false).settle.gives_unknown_token);
}

// The floor in units of the coin: 0.01 of one for six decimals or fewer (one
// base unit of USDC is dust), one unit below two.
TEST(Erc7730Settle, StablecoinDustWarns) {
  const char* under = "This wallet gets under 0.01 USDC.";
  EXPECT_EQ(
      Order().give().pay(1, kUsdc, "1", true).review(1, ERC7730_SETTLE_DUST),
      screen({under}, kSellerNft, "0.000001 USDC"));
  EXPECT_EQ(
      Order().give().pay(1, kUsdc, "9999", true).review(1, ERC7730_SETTLE_DUST),
      screen({under}, kSellerNft, "0.009999 USDC"));
  EXPECT_EQ(Order()
                .give()
                .pay(1, kUsdc, "10000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "0.01 USDC"));
  // Two decimals: a hundredth is one base unit.
  EXPECT_EQ(
      Order().give().pay(1, kGusd, "1", true).review(1, ERC7730_SETTLE_CALM),
      screen({}, kSellerNft, "0.01 GUSD"));
}

// Review r1 (HIGH): a coin the table lists but nobody values (Dentacoin, no
// decimals) is above any floor in units. The device cannot tell; the screen
// is neutral, never "You receive", and shows what is given.
TEST(Erc7730Settle, ReviewDeadTableTokenShowsWhatIsGiven) {
  const std::string body = Order()
                               .give()
                               .pay(1, kDcn, "1000000", true)
                               .review(1, ERC7730_SETTLE_CALM);
  EXPECT_EQ(body, screen({}, kSellerNft, "1000000 DCN"));
  for (const char* word : {"fair", "price", "safe", "value"})
    EXPECT_EQ(body.find(word), std::string::npos) << word;
  // One unit is its floor: under it, there is none; at it, no line.
  EXPECT_EQ(
      Order().give().pay(1, kDcn, "1", true).review(1, ERC7730_SETTLE_CALM),
      screen({}, kSellerNft, "1 DCN"));
}

// A total that overflows keeps the first amount: the summary never shows a
// wrapped sum (2^255 + 2^255 + 10^18 would wrap to 1 ETH).
TEST(Erc7730Settle, AnOverflowingTotalIsNotWrapped) {
  EXPECT_EQ(
      Order()
          .give()
          .pay(0, kZero,
               "578960446186580977117854925043439539266349923328202820197287"
               "92003956564819968",
               true)
          .pay(0, kZero,
               "578960446186580977117854925043439539266349923328202820197297"
               "92003956564819968",
               true)
          .review(1, ERC7730_SETTLE_CALM),
      screen({}, kSellerNft,
             "57896044618658097711785492504343953926634992332820282019728."
             "792003956564819968 ETH\n+ items not listed here"));
}

// The re-review's drain: this wallet gives an NFT and 2 WETH and is paid the
// same 2 WETH back. The filler flash-loans the payment and keeps the NFT, so
// the wallet is paid nothing. What it receives is net of what it gives of the
// same coin.
TEST(Erc7730Settle, WhatIsReceivedIsNetOfWhatIsGiven) {
  const std::string nft_weth = kSellerNft + "\n2 WETH";
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "2000000000000000000")
                .pay(1, kWeth, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_NOTHING),
            screen({kBack}, nft_weth, "Nothing"));
  // Control: the same payment for the NFT alone.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "2 WETH"));
  // More back than given: the difference. The native coin nets the same.
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "2000000000000000000")
                .pay(1, kWeth, "3000000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, nft_weth, "1 WETH"));
  EXPECT_EQ(Order()
                .give()
                .give(0, kZero, "1000000000000000000")
                .pay(0, kZero, "1500000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft + "\n1 ETH", "0.5 ETH"));
  // Back plus one wei: dust.
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "2000000000000000000")
                .pay(1, kWeth, "2000000000000000001", true)
                .review(1, ERC7730_SETTLE_DUST),
            screen({"This wallet gets under 0.0001 WETH."}, nft_weth,
                   "0.000000000000000001 WETH"));
  // A given item counts its larger amount, two given items add up, and a
  // payment split in two adds up before netting.
  Order()
      .give()
      .give(1, kWeth, "1000000000000000000", "2000000000000000000")
      .pay(1, kWeth, "1000000000000000000", true)
      .pay(1, kWeth, "1000000000000000000", true)
      .review(1, ERC7730_SETTLE_NOTHING);
  EXPECT_EQ(Order()
                .give(1, kWeth, "1000000000000000000")
                .give(1, kWeth, "1000000000000000000")
                .pay(1, kWeth, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_NOTHING),
            screen({kBack}, "2 WETH", "Nothing"));
  // An NFT is never netted: one given and paid back is listed (and alone
  // warns).
  EXPECT_EQ(Order()
                .give()
                .pay(2, kNft, "1", "1", true, "5318")
                .review(1, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, kSellerNft, kSellerNft));
}

// Review r1 (HIGH): the flash-loan drain paid in the native coin. This
// wallet gives its NFT and 2 WETH and is paid 2 ETH: the filler unwraps the
// WETH it takes. WETH and ETH net as one coin.
TEST(Erc7730Settle, ReviewFlashLoanDrainViaTheNativeCoinWarns) {
  const std::string nft_weth = kSellerNft + "\n2 WETH";
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "2000000000000000000")
                .pay(0, kZero, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_NOTHING),
            screen({kBack}, nft_weth, "Nothing"));
  // The other way round: ETH given, WETH paid back.
  EXPECT_EQ(Order()
                .give()
                .give(0, kZero, "2000000000000000000")
                .pay(1, kWeth, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_NOTHING),
            screen({kBack}, kSellerNft + "\n2 ETH", "Nothing"));
  // Split across both coins: each is netted against all that is given.
  Order()
      .give()
      .give(1, kWeth, "2000000000000000000")
      .pay(0, kZero, "1000000000000000000", true)
      .pay(1, kWeth, "1000000000000000000", true)
      .review(1, ERC7730_SETTLE_NOTHING);
  // Controls: more ETH back than WETH given is the difference; another
  // coin (USDC) does not net against ETH.
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "2000000000000000000")
                .pay(0, kZero, "2500000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, nft_weth, "0.5 ETH"));
  EXPECT_EQ(Order()
                .give()
                .give(1, kUsdc, "2000000")
                .pay(0, kZero, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft + "\n2 USDC", "2 ETH"));
}

// What is given must be read to be netted: an item with no type, an amount
// shown before its type, an NFT with no identifier, or more distinct coins
// than the device keeps, make the last screen a warning.
TEST(Erc7730Settle, AGivenItemTheDeviceCannotReadWarns) {
  const char* unread = "This wallet gives an item the device cannot read.";
  {
    // The finding's "give-only" layout: the offer's amount with no type.
    Order order;
    erc7730_settle_amount(&order.settle, word("2000000000000000000").data(),
                          address(kWeth).data(), false);
    erc7730_settle_end_item(&order.settle, order.chain);
    EXPECT_TRUE(order.settle.given_unread);
    EXPECT_EQ(order.pay(1, kWeth, "2000000000000000000", true)
                  .review(1, ERC7730_SETTLE_GIVEN_UNREAD),
              screen({unread}, "+ items not listed here", "2 WETH"));
  }
  {
    // A type and no amount.
    Order order;
    erc7730_settle_type(&order.settle, word("1").data());
    erc7730_settle_end_item(&order.settle, order.chain);
    order.review(1, ERC7730_SETTLE_GIVEN_UNREAD);
  }
  {
    // The type after the amount.
    Order order;
    erc7730_settle_amount(&order.settle, word("1").data(),
                          address(kWeth).data(), false);
    erc7730_settle_type(&order.settle, word("1").data());
    erc7730_settle_end_item(&order.settle, order.chain);
    order.review(1, ERC7730_SETTLE_GIVEN_UNREAD);
  }
  {
    // An NFT with no identifier shown: its amount screen refuses.
    EXPECT_EQ(Order()
                  .give(2, kNft, "1", nullptr, nullptr)
                  .pay(0, kZero, "1000000000000000000", true)
                  .review(1, ERC7730_SETTLE_GIVEN_UNREAD),
              "<refused>");
    // Without the amount screen (a definition that never shows it).
    Order order;
    erc7730_settle_type(&order.settle, word("2").data());
    erc7730_settle_amount(&order.settle, word("1").data(), address(kNft).data(),
                          false);
    erc7730_settle_end_item(&order.settle, order.chain);
    order.pay(0, kZero, "1000000000000000000", true)
        .review(1, ERC7730_SETTLE_GIVEN_UNREAD);
  }
  // Three distinct coins given: the third is not kept.
  EXPECT_EQ(Order()
                .give(0, kZero, "1")
                .give(1, kUsdc, "1000000")
                .give(1, kWeth, "2000000000000000000")
                .pay(1, kWeth, "2000000000000000000", true)
                .review(1, ERC7730_SETTLE_GIVEN_UNREAD),
            screen({unread}, "1 Wei\n1 USDC\n+ items not listed here",
                   "1.999999999999999999 WETH"));
  // Control: a bundle of NFTs and one coin, all read and listed; the same
  // payment nets to nothing.
  Order()
      .give(2, kNft, "1", nullptr, "1")
      .give(3, kNft, "2", nullptr, "3")
      .give(1, kWeth, "2000000000000000000")
      .pay(1, kWeth, "2000000000000000000", true)
      .review(1, ERC7730_SETTLE_NOTHING);
  // A payment with no type is not read either: never listed or valued.
  Order untyped;
  untyped.give();
  erc7730_settle_amount(&untyped.settle, word("1000000000000000000").data(),
                        address(kZero).data(), true);
  erc7730_settle_to(&untyped.settle, true);
  erc7730_settle_end_item(&untyped.settle, untyped.chain);
  EXPECT_EQ(untyped.review(1, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, kSellerNft, "+ items not listed here"));
}

// 0xEeee...EEeE is the token table's mainnet "ETH" sentinel, not a contract:
// an ERC-20 item naming it is not read, never valued as ETH.
TEST(Erc7730Settle, TheNativePlaceholderIsNoToken) {
  EXPECT_EQ(Order()
                .give()
                .pay(1, kEeee, "1000000000000000000", true)
                .review(1, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, kSellerNft, "+ items not listed here"));
  // Control: WETH, the same amount.
  EXPECT_EQ(Order()
                .give()
                .pay(1, kWeth, "1000000000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft, "1 WETH"));
}

// Review r1 (LOW): an NFT item naming 0xEeee...EEeE said "names the token
// ETH: Seaport moves its ID as an amount of ETH", which is not what happens
// (it is no contract). It now says what it is.
TEST(Erc7730Settle, ReviewAnNftItemNamingThePlaceholderSaysWhatItIs) {
  const std::string eeee_nft =
      "NFT ID 7\n0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
  const std::string body = Order()
                               .give(2, kEeee, "1", nullptr, "7")
                               .pay(0, kZero, "500000000000000000", true)
                               .review(1, ERC7730_SETTLE_NFT_PLACEHOLDER);
  EXPECT_EQ(body, screen({"An NFT item names 0xEeee...EEeE, the native "
                          "coin's placeholder: it is not an NFT contract."},
                         eeee_nft, "0.5 ETH"));
  EXPECT_EQ(body.find("ETH:"), std::string::npos);
  // Review r4: with an ID of 2^64 or more, the same one line. The table
  // answers 0xEeee as ETH on chain 1, so the 2^64 line skips it like any
  // coin (Desktop's prediction matches this).
  EXPECT_EQ(Order()
                .give(2, kEeee, "1", nullptr, "18446744073709551616")
                .pay(0, kZero, "500000000000000000", true)
                .review(1, ERC7730_SETTLE_NFT_PLACEHOLDER),
            screen({"An NFT item names 0xEeee...EEeE, the native "
                    "coin's placeholder: it is not an NFT contract."},
                   "NFT ID 18446744073709551616\n"
                   "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
                   "0.5 ETH"));
  // On a chain whose table has no sentinel, the same.
  Order other;
  other.chain = 8453;
  other.give(2, kEeee, "1", nullptr, "7")
      .pay(0, kZero, "500000000000000000", true)
      .review(8453, ERC7730_SETTLE_NFT_PLACEHOLDER);
  EXPECT_EQ(other.settle.coin_as_nft, nullptr);
}

// Review r1 (MEDIUM): an ERC-721 item naming an ERC-20 the table does not
// list moves "ID" units of it. An ID of 2^64 or more is no collection's but
// a hashed one's: it warns, given or received, and the item is shown by its
// raw contract and ID.
TEST(Erc7730Settle, ReviewAnErc721NamingAnUnlistedTokenWarns) {
  // LDO on mainnet: 10,000 LDO as "NFT ID 10^22", for 0.01 ETH (the review
  // used USDe, which never_nft now names: see ReviewR3NeverAnNft).
  EXPECT_EQ(Order()
                .give(2, kLdo, "1", nullptr, "10000000000000000000000")
                .pay(0, kZero, "10000000000000000", true)
                .review(1, ERC7730_SETTLE_LARGE_NFT_ID),
            screen({kLargeId},
                   "NFT ID 10000000000000000000000\n"
                   "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32",
                   "0.01 ETH"));
  // Received: the order pays an "NFT" that is a token amount.
  Order()
      .pay(2, kLdo, "1", "1", true, "18446744073709551616")
      .review(1, ERC7730_SETTLE_LARGE_NFT_ID);
  // USDC on Base (six decimals): 10,000 USDC is ID 10^10, under 2^64, so
  // the device cannot tell it from an NFT. The 1e12 wei paid is under the
  // floor; Desktop checks the contract (supportsInterface, decimals) before
  // the device.
  Order base;
  base.chain = 8453;
  EXPECT_EQ(base.give(2, kBaseUsdc, "1", nullptr, "10000000000")
                .pay(0, kZero, "1000000000000", true)
                .review(8453, ERC7730_SETTLE_DUST),
            screen({kUnderEth},
                   "NFT ID 10000000000\n"
                   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                   "0.000001 ETH"));
  // Controls: 2^64 - 1; a hashed-ID collection (ENS); ERC-1155 (Seaport
  // calls safeTransferFrom, which an ERC-20 does not answer); by criteria
  // (its identifier is a root: the criteria warning, not this one).
  Order()
      .give(2, kLdo, "1", nullptr, "18446744073709551615")
      .pay(0, kZero, "10000000000000000", true)
      .review(1, ERC7730_SETTLE_CALM);
  Order()
      .give(2, kEns, "1", nullptr, kMax)
      .pay(0, kZero, "10000000000000000", true)
      .review(1, ERC7730_SETTLE_CALM);
  Order()
      .give(3, kLdo, "1", nullptr, "10000000000000000000000")
      .pay(0, kZero, "10000000000000000", true)
      .review(1, ERC7730_SETTLE_CALM);
  Order()
      .give(4, kLdo, "1", nullptr, kMax)
      .pay(0, kZero, "10000000000000000", true)
      .review(1, ERC7730_SETTLE_GIVES_BY_CRITERIA);
  // ENS's address on another chain is not ENS.
  Order other;
  other.chain = 8453;
  other.give(2, kEns, "1", nullptr, kMax)
      .pay(0, kZero, "10000000000000000", true)
      .review(8453, ERC7730_SETTLE_LARGE_NFT_ID);
}

// Review r1: a line too long for the screen refuses the review (fails
// closed), never a cut-off line.
TEST(Erc7730Settle, ReviewALongNftLineFailsClosed) {
  EXPECT_EQ(Order()
                .pay(3, kNft, kMax, kMax, true, kMax)
                .review(1, ERC7730_SETTLE_CALM),
            "<refused>");
}

// The screen never words an order as a good one: its calm title is the
// neutral "Order summary" (fsm), and no body says fair, price or safe.
TEST(Erc7730Settle, TheScreenNeverReassures) {
  std::vector<std::string> bodies = {
      Order()
          .give()
          .pay(0, kZero, "19740000000000000", true)
          .review(1, ERC7730_SETTLE_CALM),
      Order().give().pay(0, kZero, "1", true).review(1, ERC7730_SETTLE_DUST),
      Order()
          .give()
          .pay(0, kZero, "1", false)
          .review(1, ERC7730_SETTLE_NOTHING),
      Order()
          .give()
          .pay(1, kWorthless, "5", true)
          .review(1, ERC7730_SETTLE_UNVALUED),
  };
  for (const auto& body : bodies) {
    EXPECT_EQ(body.find("You give:\n"), body.rfind("You give:\n")) << body;
    EXPECT_NE(body.find("You give:\n"), std::string::npos) << body;
    EXPECT_NE(body.find("\nYou receive:\n"), std::string::npos) << body;
    for (const char* word : {"fair", "price", "safe", "good"})
      EXPECT_EQ(body.find(word), std::string::npos) << word << ": " << body;
  }
}

namespace {

const char* kReth = "ae78736cd615f374d3085123a210448e74fc6393";
const char* kUd = "049aba7510f45ba5b64ea9e658e342f904db358d";
const char* kUdNamehash =
    "538974463791641374324267330513076226333073735129812319168380132343720"
    "94094706";
const char* kCent = "10000000000000000";  // 0.01 ETH

}  // namespace

// Review r2 (HIGH): an item given by criteria names no ID; Seaport takes
// the one the filler supplies (any, with a zero root; any in the tree
// otherwise). On an ERC-20 the table does not list, transferFrom(victim,
// filler, ID) takes that many units; on a real collection the filler picks
// which of the wallet's NFTs. OpenSea listings never give by criteria.
TEST(Erc7730Settle, ReviewR2GivingByCriteriaWarns) {
  // LDO, wildcard root.
  EXPECT_EQ(Order()
                .give(4, kLdo, "1", nullptr, "0")
                .pay(0, kZero, kCent, true)
                .review(1, ERC7730_SETTLE_GIVES_BY_CRITERIA),
            screen({kCriteria},
                   "1 NFT by criteria\n"
                   "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32",
                   "0.01 ETH"));
  // rETH, a non-zero root.
  EXPECT_EQ(Order()
                .give(4, kReth, "1", nullptr, "12345678901234567890123456789")
                .pay(0, kZero, kCent, true)
                .review(1, ERC7730_SETTLE_GIVES_BY_CRITERIA),
            screen({kCriteria},
                   "1 NFT by criteria\n"
                   "0xae78736Cd615f374D3085123A210448E74Fc6393",
                   "0.01 ETH"));
  // A real collection, wildcard: the filler picks the wallet's best NFT.
  EXPECT_EQ(
      Order()
          .give(4, kNft, "1", nullptr, "0")
          .pay(0, kZero, kCent, true)
          .review(1, ERC7730_SETTLE_GIVES_BY_CRITERIA),
      screen({kCriteria}, std::string("1 NFT by criteria\n") + kNftAddress,
             "0.01 ETH"));
  // ERC-1155 by criteria.
  Order()
      .give(5, kNft, "3", nullptr, "0")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_GIVES_BY_CRITERIA);
  // Controls: the same collection by ID is calm; an item by criteria the
  // wallet receives (its own collection offer) has no criteria line.
  Order()
      .give(2, kNft, "1", nullptr, "1")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_CALM);
  EXPECT_EQ(Order()
                .give(1, kWeth, "500000000000000000")
                .pay(4, kNft, "1", "1", true, "0")
                .review(1, ERC7730_SETTLE_UNVALUED),
            screen({kUnknown}, "0.5 WETH",
                   std::string("1 NFT by criteria\n") + kNftAddress));
}

// Review r2 (MEDIUM): NFTs given past the two the screen lists were only
// counted, so the item that drains could hide behind "+ N more NFTs". The
// screen now says it does not list everything given; an item that warns on
// its own still does when it is not listed.
TEST(Erc7730Settle, ReviewR2NftsPastTheListWarn) {
  const std::string two =
      std::string("NFT ID 1\n") + kNftAddress + "\nNFT ID 2\n" + kNftAddress;
  // Three real NFTs, then an ERC-721 item naming LDO (ID 1000, under
  // 2^64).
  EXPECT_EQ(Order()
                .give(2, kNft, "1", nullptr, "1")
                .give(2, kNft, "1", nullptr, "2")
                .give(2, kNft, "1", nullptr, "3")
                .give(2, kLdo, "1", nullptr, "1000")
                .pay(0, kZero, kCent, true)
                .review(1, ERC7730_SETTLE_GIVEN_UNLISTED),
            screen({kMoreItems}, two + "\n+ 2 more NFTs", "0.01 ETH"));
  // A criteria item past the list.
  EXPECT_EQ(
      Order()
          .give(2, kNft, "1", nullptr, "1")
          .give(2, kNft, "1", nullptr, "2")
          .give(4, kLdo, "1", nullptr, "0")
          .pay(0, kZero, kCent, true)
          .review(1, ERC7730_SETTLE_GIVES_BY_CRITERIA),
      screen({kCriteria, kMoreItems}, two + "\n+ 1 more NFT", "0.01 ETH"));
  // A coin as an NFT, and a large ID, past the list.
  Order()
      .give(2, kNft, "1", nullptr, "1")
      .give(2, kNft, "1", nullptr, "2")
      .give(2, kWeth, "1", nullptr, "1000000000000000000")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_COIN_AS_NFT);
  Order()
      .give(2, kNft, "1", nullptr, "1")
      .give(2, kNft, "1", nullptr, "2")
      .give(2, kLdo, "1", nullptr, "1000000000000000000000")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_LARGE_NFT_ID);
  // Control: two NFTs, both listed, are calm.
  EXPECT_EQ(Order()
                .give(2, kNft, "1", nullptr, "1")
                .give(2, kNft, "1", nullptr, "2")
                .pay(0, kZero, kCent, true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, two, "0.01 ETH"));
}

// Review r2 (LOW): Unstoppable Domains' ERC-721 on Ethereum uses namehash
// IDs, like ENS: a real listing is calm. Its address elsewhere is not it.
TEST(Erc7730Settle, ReviewR2HashedIdCollections) {
  EXPECT_EQ(Order()
                .give(2, kUd, "1", nullptr, kUdNamehash)
                .pay(0, kZero, "50000000000000000", true)
                .pay(0, kZero, "1250000000000000", false)
                .review(1, ERC7730_SETTLE_CALM),
            screen({},
                   std::string("NFT ID ") + kUdNamehash +
                       "\n0x049aba7510f45BA5b64ea9E658E342F904DB358D",
                   "0.05 ETH"));
  Order()
      .give(2, kEns, "1", nullptr, kUdNamehash)
      .pay(0, kZero, "50000000000000000", true)
      .review(1, ERC7730_SETTLE_CALM);
  Order base;
  base.chain = 8453;
  base.give(2, kUd, "1", nullptr, kUdNamehash)
      .pay(0, kZero, "50000000000000000", true)
      .review(8453, ERC7730_SETTLE_LARGE_NFT_ID);
}

// Review r2: an ERC-721 item naming an ERC-20 the table does not list, with
// an ID under 2^64 (18.4 LDO), reads like an NFT: the device cannot tell
// the contract apart (a stated limit). It shows the raw contract and ID;
// Desktop asks the contract what it is before the device.
TEST(Erc7730Settle, ReviewR2SmallIdOnAnUnlistedTokenIsAHostCheck) {
  EXPECT_EQ(Order()
                .give(2, kLdo, "1", nullptr, "18446744073709551615")
                .pay(0, kZero, kCent, true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({},
                   "NFT ID 18446744073709551615\n"
                   "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32",
                   "0.01 ETH"));
}

// The rest of review r2's attacks, each a warning (or, for the last ones,
// the calm a real listing needs).
TEST(Erc7730Settle, ReviewR2Attacks) {
  // An ERC-20 item naming an NFT collection: moves NFT ID 5318.
  Order()
      .give(1, kNft, "5318")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN);
  // 2 WETH given, 2 ETH paid back in two items.
  Order()
      .give()
      .give(1, kWeth, "2000000000000000000")
      .pay(0, kZero, "1000000000000000000", true)
      .pay(0, kZero, "1000000000000000000", true)
      .review(1, ERC7730_SETTLE_NOTHING);
  // 2 WETH given, 1 ETH and 1 WETH paid back: each nets against all given.
  Order()
      .give()
      .give(1, kWeth, "2000000000000000000")
      .pay(0, kZero, "1000000000000000000", true)
      .pay(1, kWeth, "1000000000000000000", true)
      .review(1, ERC7730_SETTLE_NOTHING);
  // Three coins paid back: the third is not listed and not valued.
  Order()
      .give()
      .give(1, kWeth, "2000000000000000000")
      .pay(1, kWeth, "2000000000000000000", true)
      .pay(1, kUsdc, "1", true)
      .pay(0, kZero, "2000000000000000000", true)
      .review(1, ERC7730_SETTLE_DUST);
  // 1 WETH and 1 ETH given, 2.0001 ETH paid back: 0.0001 ETH net, at the
  // floor, shown with both sides.
  EXPECT_EQ(Order()
                .give()
                .give(1, kWeth, "1000000000000000000")
                .give(0, kZero, "1000000000000000000")
                .pay(0, kZero, "2000100000000000000", true)
                .review(1, ERC7730_SETTLE_CALM),
            screen({}, kSellerNft + "\n1 WETH\n1 ETH", "0.0001 ETH"));
  // A Dutch auction that ends at 0.
  Order()
      .give()
      .pay(0, kZero, "1000000000000000000", "0", true)
      .review(1, ERC7730_SETTLE_DUST);
  // Two payments that overflow 2^256 together: not a total.
  const char* half =
      "578960446186580977117854925043439539266349923328202820197287920039565"
      "64819968";
  Order()
      .give()
      .pay(0, kZero, half, true)
      .pay(0, kZero, half, true)
      .review(1, ERC7730_SETTLE_CALM)
      .find("+ items not listed here");
  // ERC-1155 naming an unlisted ERC-20: Seaport calls safeTransferFrom,
  // which an ERC-20 does not answer.
  Order()
      .give(3, kLdo, "1", nullptr, "1000000")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_CALM);
  // A real listing paid in WETH, with the fee to OpenSea.
  Order()
      .give()
      .pay(1, kWeth, "500000000000000000", true)
      .pay(1, kWeth, "12500000000000000", false)
      .review(1, ERC7730_SETTLE_CALM);
}

namespace {

// Chain-1 ERC-721 collections whose live IDs are all 2^64 or more (review r3;
// ~/keepkey-audit-rigs/issuer/batch6/sources/hashed-ids-onchain-6d.json: ERC-165
// says ERC-721, and each of their 50 latest transfers has such an ID). Each
// with an ID one of them moved on chain, and its address as the device shows
// it.
struct Collection {
  const char* name;
  const char* token;
  const char* shown;
  const char* id;
};
const Collection kHashed[] = {
    {"Unstoppable Domains .crypto (CNS)",
     "d1e5b0ff1287aa9f9a268759062e4ab08b9dacbe",
     "0xD1E5b0FF1287aA9f9A268759062E4Ab08b9Dacbe",
     "2640479375954687368405108873679577913755247171701477055198822272924474"
     "546773"},
    {"Decentraland LAND", "f87e31492faf9a91b02ee0deaad50d51d56d5d4d",
     "0xF87E31492Faf9A91B02Ee0dEAAd50d51d56D5d4d",
     "1157920892373161954235709850086879078505477257302730563317505871484589"
     "83948410"},
    {"Decentraland Names", "2a187453064356c898cae034eaed119e1663acb8",
     "0x2A187453064356c898cAe034EAed119E1663ACb8",
     "1104886426554971316873225178934451429952489820850483521117029452396656"
     "89743296"},
    {"Sorare", "629a673a8242c2ac4b7b8c5d8735fbeac21a6205",
     "0x629A673A8242c2AC4B7B8C5D8735fbeac21A6205",
     "8486410100290593993614660320003782926703175571181795977402868013196166"
     "933584"},
    {"Rarible", "f6793da657495ffeff9ee6350824910abc21356c",
     "0xF6793dA657495ffeFF9Ee6350824910Abc21356C",
     "4198952414451092601333812763749611905246708960792447852956960428300143"
     "1130114"},
};

// Review r4: the hashed-ID list from real data. Every ERC-721 that Seaport 1.6
// moved on chain 1 with an ID of 2^64 or more over blocks 26263701-26313700
// (63,287 OrderFulfilled events), read on chain (ERC-165 ERC-721, not
// ERC-1155, decimals() reverts); these are the eight with the most listings
// (~/keepkey-audit-rigs/issuer/batch6/sources/hashed-ids-from-fills-6d.json).
// Each ID is one a real listing of it sold.
const Collection kHashedR4[] = {
    {"ENS Commemorative", "20262e3433306a4ff250a64d20a8e0f09b2c7f68",
     "0x20262e3433306a4FF250a64d20a8E0F09B2C7F68",
     "4800339746304215113505442909383013170834154924283749081808552991793306"
     "7218499"},
    {"Unetwork Operator Software License",
     "0bfa9aff76fd91756f837ab47e11bd99e04c15bd",
     "0x0bfa9AFF76FD91756F837Ab47e11BD99e04C15bD",
     "4576591384459525819354822824087780623876878923053159931781766556648552"
     "9869688"},
    {"Gucci", "572e33ffa523865791ab1c26b42a86ac244df784",
     "0x572E33FFa523865791aB1C26B42a86aC244Df784",
     "340282366920938542673693659940582850561"},
    {"Zer0 Name Service (0x51bd)", "51bd5948cf84a1041d2720f56ded5e173396fc95",
     "0x51bd5948CF84a1041d2720F56DEd5e173396FC95",
     "7956835364388832789985426334073616726165905345450434453319174395065344"
     "2050388"},
    {"Zer0 Name Service (0x05f8)", "05f81f870cbca79e9171f22886b58b5597a603aa",
     "0x05F81F870cBca79E9171f22886b58b5597A603AA",
     "1889289441097877424889029978620228441072846434811872990092939913119975"
     "2586985"},
    {"OKX AI NFT", "741512954cb6f8e5d3cd9321c07462b05b7cc8d5",
     "0x741512954Cb6f8e5d3cD9321c07462b05B7cC8D5",
     "4894621097800733791606173110553506964654181500179553434699681112865701"
     "7831425"},
    {"Zero Name Service (0xc2e9)", "c2e9678a71e50e5aed036e00e9c5caeb1ac5987d",
     "0xc2e9678A71e50E5AEd036e00e9c5caeb1aC5987D",
     "5804190919614418592259370525208415466303453209166590916760934043604458"
     "3769244"},
    {"Rarible (0xc915)", "c9154424b823b10579895ccbe442d41b9abd96ed",
     "0xc9154424B823b10579895cCBE442d41b9Abd96Ed",
     "2826039867819840215306711511831437299585336968281979299548049622915281"
     "322105"},
};

// ERC-20s the token table does not list, on chain 1 (never_nft[]): symbol and
// decimals read on chain, no ERC-721 or ERC-1155 interface.
struct Coin {
  const char* ticker;
  const char* token;
  const char* shown;
};
const Coin kNeverNft[] = {
    {"cbBTC", "cbb7c0000ab88b473b1f5afd9ef808440eed33bf",
     "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"},
    {"PYUSD", "6c3ea9036406852006290770bedfcaba0e23a0e8",
     "0x6c3ea9036406852006290770BEdFcAbA0e23A0e8"},
    {"XAUt", "68749665ff8d2d112fa859aa293f07a622782f38",
     "0x68749665FF8D2d112Fa859AA293F07A622782F38"},
    {"EURC", "1abaea1f7c830bd89acc67ec4af516284b1bc33c",
     "0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c"},
    {"stETH", "ae7ab96520de3a18e5e111b5eaab095312d7fe84",
     "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"},
    {"wstETH", "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
     "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"},
    {"USDe", "4c9edd5852cd905f086c759e8383e09bff1e68b3",
     "0x4c9EDD5852cd905f086C759E8383e09bff1E68B3"},
    {"APE", "4d224452801aced8b2f0aebe155379bb5d594381",
     "0x4d224452801ACEd8B2F0aebE155379bb5D594381"},
};

std::string coinAsNft(const char* ticker) {
  return std::string("An NFT item names the token ") + ticker +
         ": Seaport moves its ID as an amount of " + ticker + ".";
}

}  // namespace

// Review r3 (MEDIUM): a real chain-1 listing of a collection with hashed or
// packed IDs read "An NFT ID is 2^64 or more". Each is calm, and shows its ID
// and contract. Its address on another chain is not it.
TEST(Erc7730Settle, ReviewR3HashedIdCollections) {
  for (const auto& c : kHashed) {
    SCOPED_TRACE(c.name);
    EXPECT_EQ(Order()
                  .give(2, c.token, "1", nullptr, c.id)
                  .pay(0, kZero, "50000000000000000", true)
                  .pay(0, kZero, "1250000000000000", false)
                  .review(1, ERC7730_SETTLE_CALM),
              screen({}, std::string("NFT ID ") + c.id + "\n" + c.shown,
                     "0.05 ETH"));
    Order base;
    base.chain = 8453;
    EXPECT_EQ(base.give(2, c.token, "1", nullptr, c.id)
                  .pay(0, kZero, "50000000000000000", true)
                  .review(8453, ERC7730_SETTLE_LARGE_NFT_ID),
              screen({kLargeId},
                     std::string("NFT ID ") + c.id + "\n" + c.shown,
                     "0.05 ETH"));
  }
}

// Review r4 (MEDIUM): the r3 list was hand-picked; real listings of these
// collections read "An NFT ID is 2^64 or more" (1.14% of the window's chain-1
// listings, 0.063% after). Each is calm, and shows its ID and contract; its
// address on another chain is not it. A mutant removing any one entry fails
// here, under its name.
TEST(Erc7730Settle, ReviewR4HashedIdCollectionsFromRealFills) {
  for (const auto& c : kHashedR4) {
    SCOPED_TRACE(c.name);
    EXPECT_EQ(Order()
                  .give(2, c.token, "1", nullptr, c.id)
                  .pay(0, kZero, "50000000000000000", true)
                  .pay(0, kZero, "1250000000000000", false)
                  .review(1, ERC7730_SETTLE_CALM),
              screen({}, std::string("NFT ID ") + c.id + "\n" + c.shown,
                     "0.05 ETH"));
    Order base;
    base.chain = 8453;
    EXPECT_EQ(base.give(2, c.token, "1", nullptr, c.id)
                  .pay(0, kZero, "50000000000000000", true)
                  .review(8453, ERC7730_SETTLE_LARGE_NFT_ID),
              screen({kLargeId},
                     std::string("NFT ID ") + c.id + "\n" + c.shown,
                     "0.05 ETH"));
  }
}

// Review r3 (LOW): an ERC-721 item naming an ERC-20 the table does not list,
// with an ID under 2^64, read as an NFT (for a 6- or 8-decimal token that is
// any amount). The ERC-20s an NFT item is most likely to name that way warn
// like a table coin, by criteria too, and with an ID of 2^64 or more say the
// coin, not the ID. Elsewhere they are not these tokens.
TEST(Erc7730Settle, ReviewR3NeverAnNft) {
  for (const auto& c : kNeverNft) {
    SCOPED_TRACE(c.ticker);
    EXPECT_EQ(Order()
                  .give(2, c.token, "1", nullptr, "1000000")
                  .pay(0, kZero, kCent, true)
                  .review(1, ERC7730_SETTLE_COIN_AS_NFT),
              screen({coinAsNft(c.ticker)},
                     std::string("NFT ID 1000000\n") + c.shown, "0.01 ETH"));
    EXPECT_EQ(Order()
                  .give(2, c.token, "1", nullptr, "10000000000000000000000")
                  .pay(0, kZero, kCent, true)
                  .review(1, ERC7730_SETTLE_COIN_AS_NFT),
              screen({coinAsNft(c.ticker)},
                     std::string("NFT ID 10000000000000000000000\n") + c.shown,
                     "0.01 ETH"));
    EXPECT_EQ(Order()
                  .give(4, c.token, "1", nullptr, "0")
                  .pay(0, kZero, kCent, true)
                  .review(1, ERC7730_SETTLE_COIN_AS_NFT),
              screen({coinAsNft(c.ticker), kCriteria},
                     std::string("1 NFT by criteria\n") + c.shown,
                     "0.01 ETH"));
    // Received as an NFT, too.
    Order()
        .give(1, kWeth, "500000000000000000")
        .pay(2, c.token, "1", "1", true, "7")
        .review(1, ERC7730_SETTLE_COIN_AS_NFT);
    Order base;
    base.chain = 8453;
    base.give(2, c.token, "1", nullptr, "1000000")
        .pay(0, kZero, kCent, true)
        .review(8453, ERC7730_SETTLE_CALM);
  }
  // CONTROL: an ERC-20 on no list (LDO) still reads as an NFT under 2^64.
  Order()
      .give(2, kLdo, "1", nullptr, "1000000")
      .pay(0, kZero, kCent, true)
      .review(1, ERC7730_SETTLE_CALM);
}
