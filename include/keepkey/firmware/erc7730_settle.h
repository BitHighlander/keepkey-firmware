#ifndef KEEPKEY_FIRMWARE_ERC7730_SETTLE_H
#define KEEPKEY_FIRMWARE_ERC7730_SETTLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What the signer of a typed-data order gives and receives (7.17).
 *
 * A definition opts in with program header flag ERC7730_PROGRAM_FLAG_SETTLEMENT
 * and marks the fields of every item of the order with
 * ERC7730_FORMATTER_FLAG_SETTLE_*: its TYPE, ID and AMOUNT (start and end)
 * and, for an item paid out, its recipient TO (Seaport: offer[] and
 * consideration[]). An item without TO is one the order gives away. As the
 * review shows those fields, the device keeps what is paid to the signing
 * address it derived itself and what it gives. After the definition's last
 * field it shows both sides on a screen the definition cannot change or skip:
 * "You give:" (every item given: NFTs by ID and contract, coins with their
 * amounts) and "You receive:" (net of the same coin given; the chain's
 * wrapped native coin nets as the native coin). The device has no prices, so
 * that screen never says an order is fair: it is a warning only on what the
 * device can tell from the order itself, one line each:
 *  - nothing is received net, or only unknown tokens or NFTs, for what is
 *    given, or every known coin received is under a floor (0.0001 of one for
 *    more than six decimals, 0.01 for three to six, one unit below that);
 *  - a given item the device could not read;
 *  - an NFT item naming a coin of the firmware's table, or of a short list
 *    of ERC-20s the table does not list (chain 1: cbBTC, PYUSD, XAUt, EURC,
 *    stETH, wstETH, USDe, APE), or 0xEeee...EEeE;
 *  - giving an item by criteria (types 4 and 5): the filler picks its
 *    identifier, any NFT of the collection or, on a token, any amount;
 *  - an ERC-721 item outside the collections the device knows with an ID of
 *    2^64 or more (an ERC-20 at that contract would move that many units;
 *    chain 1: ENS, Unstoppable Domains, Decentraland LAND and Names, Sorare,
 *    Rarible use such IDs);
 *  - giving an ERC-20 the table does not list on the chain;
 *  - giving more NFTs than the screen lists.
 *
 * TYPE is a Seaport item type: 0 the native coin, 1 an ERC-20, 2 ERC-721,
 * 3 ERC-1155, 4 and 5 the same "by criteria". An item is read only when its
 * TYPE comes before its AMOUNT, and an NFT item's ID too. A received item
 * counts the smaller of its start and end amounts, a given item the larger.
 *
 * An item is shown as Seaport moves it: the AMOUNT of an NFT item (types 2
 * to 5) reads as its identifier and count, never as an amount of its token,
 * because Seaport moves an ERC-721 item by its identifier whatever its token
 * is (an ERC-721 item naming WETH moves "identifier" wei of WETH).
 *
 * The other way round, Seaport moves an ERC-20 item with transferFrom(from,
 * to, amount), which an ERC-721 contract also answers: an ERC-20 item naming
 * an NFT collection gives the NFT whose ID is the amount. */

#define ERC7730_SETTLE_NATIVE 0u
#define ERC7730_SETTLE_ERC20 1u
#define ERC7730_SETTLE_ERC721 2u
#define ERC7730_SETTLE_ERC1155 3u
#define ERC7730_SETTLE_CRITERIA_MAX 5u
/* Items paid to the signer this many distinct (kind, token, id) at most are
 * listed; more are summed up in one line and never valued. As many distinct
 * coins given are kept to net against them; more make the last screen a
 * warning. As many distinct NFTs given are listed; more are counted, and
 * make it a warning too. */
#define ERC7730_SETTLE_SLOTS 2u
/* The settlement screen's body, warnings and both sides. */
#define ERC7730_SETTLE_BODY_MAX 768u

typedef struct {
  uint8_t amount[32]; /* big-endian */
  uint8_t id[32];     /* an NFT's identifier or criteria; 0 for coins */
  uint8_t token[20];
  uint8_t kind;
} Erc7730SettleItem;

typedef struct {
  Erc7730SettleItem item; /* the item being reviewed */
  uint8_t item_max[32];   /* the larger of the item's two amounts */
  Erc7730SettleItem received[ERC7730_SETTLE_SLOTS];
  Erc7730SettleItem given[ERC7730_SETTLE_SLOTS];     /* coins only */
  Erc7730SettleItem given_nft[ERC7730_SETTLE_SLOTS]; /* NFTs only */
  uint8_t received_count;
  uint8_t given_count;
  uint8_t given_nft_count;
  uint8_t given_nft_more; /* NFTs given past given_nft[] (saturates) */
  uint8_t item_seen;      /* ERC7730_FORMATTER_FLAG_SETTLE_* this item showed */
  bool item_native;
  bool item_to_signer;
  bool item_unreadable;
  bool gives;
  bool given_unread; /* a given item not read, or not kept */
  bool received_any;
  bool unlisted; /* paid to the signer, not in received[] */
  /* An item given away is an ERC-20 the table does not list on the chain. */
  bool gives_unknown_token;
  /* An item given away is by criteria: the filler picks its identifier. */
  bool gives_by_criteria;
  /* An ERC-721 item outside the known collections has an ID of 2^64 or
   * more. */
  bool large_nft_id;
  /* An NFT item names 0xEeee...EEeE, the native coin's placeholder. */
  bool nft_placeholder;
  /* An NFT item names this token of the firmware's table, or NULL. */
  const char* coin_as_nft;
} Erc7730Settle;

/* The screen's title: CALM is the neutral "Order summary", any other is a
 * WARNING; the verdict names its first warning line. */
typedef enum {
  ERC7730_SETTLE_CALM = 0,
  ERC7730_SETTLE_NOTHING,             /* nothing is paid to this wallet */
  ERC7730_SETTLE_UNVALUED,            /* only unknown tokens or NFTs */
  ERC7730_SETTLE_GIVEN_UNREAD,        /* a given item the device did not read */
  ERC7730_SETTLE_COIN_AS_NFT,         /* an NFT item names a coin's contract */
  ERC7730_SETTLE_GIVES_UNKNOWN_TOKEN, /* gives an ERC-20 the table lacks */
  ERC7730_SETTLE_DUST,                /* every known coin is under the floor */
  ERC7730_SETTLE_LARGE_NFT_ID,        /* an ERC-721 ID of 2^64 or more */
  ERC7730_SETTLE_NFT_PLACEHOLDER,     /* an NFT item names 0xEeee...EEeE */
  ERC7730_SETTLE_GIVES_BY_CRITERIA,   /* the filler picks an ID given */
  ERC7730_SETTLE_GIVEN_UNLISTED,      /* more NFTs given than listed */
} Erc7730SettleVerdict;

/* One shown field's value, by the SETTLE flag it carries. A word is a whole
 * 32-byte ABI word; `native` says the definition names `token` as the chain's
 * native coin. */
void erc7730_settle_type(Erc7730Settle* settle, const uint8_t word[32]);
void erc7730_settle_id(Erc7730Settle* settle, const uint8_t word[32]);
void erc7730_settle_amount(Erc7730Settle* settle, const uint8_t amount[32],
                           const uint8_t token[20], bool native);
void erc7730_settle_to(Erc7730Settle* settle, bool signer);
/* A value the device could not read where a role expected a word. */
void erc7730_settle_unreadable(Erc7730Settle* settle);
/* True when the item being reviewed is a coin, or showed no TYPE (it is
 * then not read): its AMOUNT is a token amount. */
bool erc7730_settle_item_is_coin(const Erc7730Settle* settle);
/* An AMOUNT of an NFT item, as Seaport moves it: "NFT ID 7", "4 of NFT ID
 * 7" or "1 NFT by criteria", then the collection. False (and `out` empty)
 * for an item type beyond Seaport's, or an ERC-721 or ERC-1155 item whose ID
 * was not shown first. */
bool erc7730_settle_format_nft_amount(Erc7730Settle* settle,
                                      const uint8_t amount[32],
                                      const uint8_t token[20],
                                      uint64_t chain_id, char* out,
                                      size_t size);
/* The item's last field was shown (the end of an iteration element, or of
 * the program): keep it when it is paid to the signer or given. */
void erc7730_settle_end_item(Erc7730Settle* settle, uint64_t chain_id);

/* The screen after the definition's last field: the verdict, which picks
 * its title, and its body: the warning lines, then "You give:" and "You
 * receive:" (net of what is given) with one item per line. */
bool erc7730_settle_review(const Erc7730Settle* settle, uint64_t chain_id,
                           Erc7730SettleVerdict* verdict, char* body,
                           size_t body_size);

#endif
