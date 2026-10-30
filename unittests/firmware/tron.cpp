extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tron.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/sha3.h"
#include "storage.h"
}

#include "tron_vectors.h"

#include "gtest/gtest.h"
#include <cstring>
#include <string>
#include <vector>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
bool kkconfirm_readResponse(uint16_t expected, const pb_field_t* fields,
                            void* result);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_capture_titles(void);

TEST(Tron, LongBinaryMemoRequiresApprovalOfEveryPage) {
  std::vector<uint8_t> memo(114, 'W');
  memo[40] = 0;
  memo.back() = 'Z';

  size_t offset = 0;
  int pages = 0;
  while (offset < memo.size()) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        memo.data() + offset, memo.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    pages++;
  }
  ASSERT_GT(pages, 1);

  ASSERT_TRUE(kkconfirm_preload(pages - 1, 1));
  EXPECT_FALSE(confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo,
                             "Memo", memo.data(), memo.size()));
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(kkconfirm_preload(pages, 0));
  EXPECT_TRUE(confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, "Memo",
                            memo.data(), memo.size()));
  EXPECT_EQ(0, kkconfirm_drain());
}

/* ------------------------------------------------------------------ */
/*  Minimal protobuf wire-format writer for building raw_data vectors  */
/* ------------------------------------------------------------------ */

namespace {

void putVarint(std::vector<uint8_t>& out, uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<uint8_t>(v) | 0x80);
    v >>= 7;
  }
  out.push_back(static_cast<uint8_t>(v));
}

void putKey(std::vector<uint8_t>& out, uint32_t field, uint8_t wire) {
  putVarint(out, (static_cast<uint64_t>(field) << 3) | wire);
}

void putVarintField(std::vector<uint8_t>& out, uint32_t field, uint64_t v) {
  putKey(out, field, 0);
  putVarint(out, v);
}

void putBytesField(std::vector<uint8_t>& out, uint32_t field,
                   const std::vector<uint8_t>& bytes) {
  putKey(out, field, 2);
  putVarint(out, bytes.size());
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void putStringField(std::vector<uint8_t>& out, uint32_t field,
                    const char* str) {
  putBytesField(out, field,
                std::vector<uint8_t>(str, str + strlen(str)));
}

/* A 10-byte varint whose final byte's payload has bits above bit 0 set.
 * Bytes 1-9 carry `low` as continuations, so the "value" this would decode
 * to (if truncation were allowed) is `low`: the 2 << 63 is silently dropped
 * by a naive shift. A correct reader must reject this outright rather than
 * accept the truncated value. */
void putOverlongVarintValue(std::vector<uint8_t>& out, uint64_t low = 0) {
  for (int i = 0; i < 9; i++)
    out.push_back(0x80 | static_cast<uint8_t>((low >> (7 * i)) & 0x7f));
  out.push_back(0x02);
}

void putOverlongVarintField(std::vector<uint8_t>& out, uint32_t field) {
  putKey(out, field, 0);
  putOverlongVarintValue(out);
}

std::vector<uint8_t> tronAddr(uint8_t fill) {
  std::vector<uint8_t> a(21, fill);
  a[0] = 0x41;
  return a;
}

/* protocol.TransferContract { owner=1, to=2, amount=3 } */
std::vector<uint8_t> transferContractValue(const std::vector<uint8_t>& owner,
                                           const std::vector<uint8_t>& to,
                                           uint64_t amount) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, owner);
  putBytesField(v, 2, to);
  putVarintField(v, 3, amount);
  return v;
}

/* TRC-20 transfer(address,uint256) calldata */
std::vector<uint8_t> trc20Calldata(const std::vector<uint8_t>& to21,
                                   uint64_t amount, bool tronStylePrefix) {
  std::vector<uint8_t> d = {0xa9, 0x05, 0x9c, 0xbb};
  /* address word */
  for (int i = 0; i < 11; i++) d.push_back(0);
  d.push_back(tronStylePrefix ? 0x41 : 0x00);
  d.insert(d.end(), to21.begin() + 1, to21.end()); /* low 20 bytes */
  /* amount word: big-endian uint256 */
  for (int i = 0; i < 24; i++) d.push_back(0);
  for (int i = 7; i >= 0; i--)
    d.push_back(static_cast<uint8_t>(amount >> (8 * i)));
  return d;
}

/* protocol.TriggerSmartContract { owner=1, contract=2, call_value=3, data=4 } */
std::vector<uint8_t> triggerContractValue(const std::vector<uint8_t>& owner,
                                          const std::vector<uint8_t>& contract,
                                          const std::vector<uint8_t>& data) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, owner);
  putBytesField(v, 2, contract);
  putBytesField(v, 4, data);
  return v;
}

/* Transaction.Contract { type=1, parameter=2 (Any{type_url=1, value=2}) } */
std::vector<uint8_t> contractMsg(uint64_t type, const char* type_url,
                                 const std::vector<uint8_t>& value) {
  std::vector<uint8_t> any;
  putStringField(any, 1, type_url);
  putBytesField(any, 2, value);

  std::vector<uint8_t> c;
  putVarintField(c, 1, type);
  putBytesField(c, 2, any);
  return c;
}

/* Transaction.raw with typical TronGrid framing */
std::vector<uint8_t> rawTx(const std::vector<uint8_t>& contract,
                           const char* memo, uint64_t fee_limit) {
  std::vector<uint8_t> raw;
  putBytesField(raw, 1, {0xab, 0xcd});                     /* ref_block_bytes */
  putBytesField(raw, 4, std::vector<uint8_t>(8, 0x5a));    /* ref_block_hash */
  putVarintField(raw, 8, 1750000000000ULL);                /* expiration */
  if (memo) putStringField(raw, 10, memo);
  putBytesField(raw, 11, contract);
  putVarintField(raw, 14, 1749999000000ULL);               /* timestamp */
  if (fee_limit) putVarintField(raw, 18, fee_limit);
  return raw;
}

const char* TRANSFER_URL = "type.googleapis.com/protocol.TransferContract";
const char* TRIGGER_URL = "type.googleapis.com/protocol.TriggerSmartContract";

}  // namespace

TEST(Tron, RejectingFinalMemoPageCancelsSignHandler) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  // The native binary has no mapped flash unless a test supplies one.
  struct ScopedFlash {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
    uint8_t* previous = emulator_flash_base;
    ScopedFlash() {
      emulator_flash_base = bytes.data();
      storage_init();
    }
    ~ScopedFlash() {
      storage_reset();
      emulator_flash_base = previous;
    }
  } flash;
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);

  const uint32_t path[] = {0x80000000 | 44, 0x80000000 | 195, 0x80000000};
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
  for (uint32_t step : path) ASSERT_TRUE(hdnode_private_ckd(&node, step));
  hdnode_fill_public_key(&node);
  char address[TRON_ADDRESS_MAX_LEN];
  ASSERT_TRUE(tron_getAddress(node.public_key, address, sizeof(address)));
  std::vector<uint8_t> owner(TRON_RAW_ADDRESS_SIZE);
  ASSERT_EQ(
      TRON_RAW_ADDRESS_SIZE,
      base58_decode_check(address, HASHER_SHA2D, owner.data(), owner.size()));

  std::string memo(114, 'W');
  memo.back() = 'Z';
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(owner, tronAddr(0x22), 1)),
                   memo.c_str(), 0);
  TronSignTx tx = {};
  tx.address_n_count = 3;
  std::memcpy(tx.address_n, path, sizeof(path));
  tx.has_raw_data = true;
  ASSERT_LE(raw.size(), sizeof(tx.raw_data.bytes));
  tx.raw_data.size = raw.size();
  std::memcpy(tx.raw_data.bytes, raw.data(), raw.size());

  TronParsedTx parsed;
  ASSERT_EQ(TRON_TX_TRANSFER, tron_parseRawTx(raw.data(), raw.size(), &parsed));
  ASSERT_EQ(memo.size(), parsed.memo_len);
  size_t offset = 0;
  int pages = 0;
  while (offset < parsed.memo_len) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        parsed.memo + offset, parsed.memo_len - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    pages++;
  }
  ASSERT_GT(pages, 1);

  // Accept the transaction and prior memo pages; decline the signed tail.
  ASSERT_TRUE(kkconfirm_preload(pages, 1));
  fsm_test_clearLastFailure();
  fsm_msgTronSignTx(&tx);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
  EXPECT_EQ(0, kkconfirm_drain());
}

// TIP-712 typed hashes are blind: without AdvancedMode the handler refuses
// before any screen or key derivation; with it, the blind-sign prompt is the
// first thing that runs (control).
TEST(Tron, TypedHashIsRefusedBeforeAnyScreenWithoutAdvancedMode) {
  struct ScopedFlash {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
    uint8_t* previous = emulator_flash_base;
    ScopedFlash() {
      emulator_flash_base = bytes.data();
      storage_init();
    }
    ~ScopedFlash() {
      storage_reset();
      emulator_flash_base = previous;
    }
  } flash;
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);

  TronSignTypedHash msg = {};
  const uint32_t path[] = {0x80000000 | 44, 0x80000000 | 195, 0x80000000};
  msg.address_n_count = 3;
  std::memcpy(msg.address_n, path, sizeof(path));
  msg.domain_separator_hash.size = 32;
  std::memset(msg.domain_separator_hash.bytes, 0x11, 32);

  for (bool advanced : {false, true}) {
    SCOPED_TRACE(advanced ? "AdvancedMode on (control)" : "AdvancedMode off");
    ASSERT_TRUE(storage_setPolicy("AdvancedMode", advanced));
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignTypedHash(&msg);
    if (advanced) {
      EXPECT_EQ(FailureType_Failure_ActionCancelled,
                fsm_test_lastFailureCode());
      EXPECT_EQ(0, kkconfirm_drain()) << "the blind-sign prompt did not run";
    } else {
      EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
      EXPECT_STREQ("Enable AdvancedMode to blind-sign typed hashes",
                   fsm_test_lastFailureMessage());
      EXPECT_EQ(2, kkconfirm_drain()) << "a screen ran before the refusal";
    }
    EXPECT_TRUE(fsm_test_derivedNodeIsZero());
  }
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

namespace {
// Seeded device whose m/44'/195'/0' account owns the transactions below.
struct TronSignFixture {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  std::vector<uint8_t> owner = std::vector<uint8_t>(TRON_RAW_ADDRESS_SIZE);
  const uint32_t path[3] = {0x80000000 | 44, 0x80000000 | 195, 0x80000000};
  TronSignFixture() {
    emulator_flash_base = bytes.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic,
                "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    HDNode node = {};
    storage_getRootNode("secp256k1", true, &node);
    for (uint32_t step : path) hdnode_private_ckd(&node, step);
    hdnode_fill_public_key(&node);
    char address[TRON_ADDRESS_MAX_LEN];
    tron_getAddress(node.public_key, address, sizeof(address));
    base58_decode_check(address, HASHER_SHA2D, owner.data(), owner.size());
  }
  ~TronSignFixture() {
    storage_setPolicy("AdvancedMode", false);
    storage_reset();
    emulator_flash_base = previous;
  }
  TronSignTx request(const std::vector<uint8_t>& raw) const {
    TronSignTx tx = {};
    tx.address_n_count = 3;
    std::memcpy(tx.address_n, path, sizeof(path));
    tx.has_raw_data = true;
    tx.raw_data.size = raw.size();
    std::memcpy(tx.raw_data.bytes, raw.data(), raw.size());
    return tx;
  }
};
}  // namespace

// The transfer selector does not prove what an arbitrary contract executes,
// so a TRC-20 call to a contract outside the trusted table meets the
// blind-sign gate; native TRX does not (control).
TEST(Tron, Trc20TransferRequiresAdvancedModeBlindSign) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  TronSignFixture f;
  TronSignTx trc20 = f.request(
      rawTx(contractMsg(
                31, TRIGGER_URL,
                triggerContractValue(f.owner, tronAddr(0x33),
                                     trc20Calldata(tronAddr(0x22), 42, false))),
            nullptr, 0));
  TronSignTx native = f.request(
      rawTx(contractMsg(1, TRANSFER_URL,
                        transferContractValue(f.owner, tronAddr(0x22), 1)),
            nullptr, 0));

  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  fsm_test_clearLastFailure();
  fsm_msgTronSignTx(&trc20);
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
  EXPECT_STREQ("Enable AdvancedMode to blind-sign",
               fsm_test_lastFailureMessage());
  EXPECT_EQ(2, kkconfirm_drain()) << "a screen ran before the refusal";

  ASSERT_TRUE(kkconfirm_preload(0, 1));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgTronSignTx(&native);
  auto screens = kkconfirm_capture_finish();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  ASSERT_EQ(1u, screens.size());
  EXPECT_EQ(0u, screens[0].find("Send ")) << screens[0];
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgTronSignTx(&trc20);
  screens = kkconfirm_capture_finish();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  ASSERT_EQ(1u, screens.size());
  EXPECT_NE(std::string::npos, screens[0].find("TRON transaction"))
      << screens[0];
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
}

// fee_limit caps smart-contract energy only. The screen must say so, and never
// present it as a cap on a native transfer's fee.
TEST(Tron, FeeLimitIsShownAsAnEnergyLimit) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  TronSignFixture f;
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct Case {
    std::vector<uint8_t> contract;
    int screens; /* the fee screen is last */
    const char* expected;
  };
  const Case cases[] = {
      {contractMsg(1, TRANSFER_URL,
                   transferContractValue(f.owner, tronAddr(0x22), 1)),
       2, "Energy fee limit 5 TRX\nNot used by TRX transfers"},
      {contractMsg(
           31, TRIGGER_URL,
           triggerContractValue(f.owner, tronAddr(0x33),
                                trc20Calldata(tronAddr(0x22), 42, false))),
       4, "Energy fee limit 5 TRX\nBandwidth fees are extra"},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.expected);
    TronSignTx tx = f.request(rawTx(c.contract, nullptr, 5000000));
    ASSERT_TRUE(kkconfirm_preload(c.screens - 1, 1));
    kkconfirm_capture_start();
    fsm_test_clearLastFailure();
    fsm_msgTronSignTx(&tx);
    const auto screens = kkconfirm_capture_finish();
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    ASSERT_EQ((size_t)c.screens, screens.size());
    EXPECT_EQ(c.expected, screens.back());
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

namespace {
std::vector<uint8_t> decodeTronAddress(const char* base58) {
  std::vector<uint8_t> raw(TRON_RAW_ADDRESS_SIZE);
  if (base58_decode_check(base58, HASHER_SHA2D, raw.data(), raw.size()) !=
      TRON_RAW_ADDRESS_SIZE)
    raw.clear();
  return raw;
}
std::vector<uint8_t> amountWord(uint64_t high, uint64_t low) {
  std::vector<uint8_t> word(32, 0);
  for (int i = 0; i < 8; i++) {
    word[16 + i] = static_cast<uint8_t>(high >> (8 * (7 - i)));
    word[24 + i] = static_cast<uint8_t>(low >> (8 * (7 - i)));
  }
  return word;
}
}  // namespace

// Issuer-published mainnet contracts with the symbol and decimals their
// contracts report; a lookalike or superseded contract is not trusted.
TEST(Tron, KnownTokenTableMatchesIssuerContracts) {
  struct Case {
    const char* address;
    const char* symbol; /* nullptr: must not be trusted */
    int decimals;
  };
  const Case cases[] = {
      {"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "USDT", 6},
      {"TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz", "USDD", 18},
      {"TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR", "WTRX", 6},
      /* USDD OLD reports the same on-chain symbol as USDD 2.0. */
      {"TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn", nullptr, 0},
      /* Circle's TRON USDC, discontinued. */
      {"TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", nullptr, 0},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.address);
    const auto raw = decodeTronAddress(c.address);
    ASSERT_EQ(TRON_RAW_ADDRESS_SIZE, raw.size());
    const TronToken* token = tron_knownToken(raw.data());
    if (!c.symbol) {
      EXPECT_EQ(nullptr, token);
      continue;
    }
    ASSERT_NE(nullptr, token);
    EXPECT_STREQ(c.symbol, token->symbol);
    EXPECT_EQ(c.decimals, token->decimals);
    auto lookalike = raw;
    lookalike[20] ^= 1;
    EXPECT_EQ(nullptr, tron_knownToken(lookalike.data()));
  }

  const TronToken* usdd = tron_knownToken(
      decodeTronAddress("TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz").data());
  ASSERT_NE(nullptr, usdd);
  char buf[96];
  /* 1.5e18 base units of an 18-decimal token */
  ASSERT_TRUE(tron_formatTrc20Amount(
      amountWord(0, 1500000000000000000ULL).data(), usdd, buf, sizeof(buf)));
  EXPECT_STREQ("1.5 USDD", buf);
  /* the uint256 maximum still fits the buffer */
  std::vector<uint8_t> max(32, 0xff);
  ASSERT_TRUE(tron_formatTrc20Amount(max.data(), usdd, buf, sizeof(buf)));
}

// A transfer on a trusted contract clear-signs without AdvancedMode: one
// screen with the amount in token units and the full recipient, taken from
// the signed raw_data.
TEST(Tron, KnownTrc20TransferClearSignsWithoutAdvancedMode) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  TronSignFixture f;
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  const auto usdt = decodeTronAddress("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
  ASSERT_EQ(TRON_RAW_ADDRESS_SIZE, usdt.size());
  const auto to = tronAddr(0x22);
  char to_str[TRON_ADDRESS_MAX_LEN];
  ASSERT_TRUE(tron_addressFromBytes(to.data(), to_str, sizeof(to_str)));
  TronSignTx tx = f.request(
      rawTx(contractMsg(31, TRIGGER_URL,
                        triggerContractValue(
                            f.owner, usdt, trc20Calldata(to, 1500000, false))),
            nullptr, 0));

  for (bool approve : {false, true}) {
    SCOPED_TRACE(approve ? "approve" : "reject");
    ASSERT_TRUE(kkconfirm_preload(approve ? 1 : 0, approve ? 0 : 1));
    kkconfirm_capture_start();
    fsm_test_clearLastFailure();
    fsm_msgTronSignTx(&tx);
    const auto screens = kkconfirm_capture_finish();
    EXPECT_EQ(approve ? 0 : FailureType_Failure_ActionCancelled,
              fsm_test_lastFailureCode());
    ASSERT_EQ(1u, screens.size());
    EXPECT_EQ(std::string("Send 1.5 USDT to ") + to_str + "?", screens[0]);
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

// Hosts and tests tell trusted-TRC-20 builds apart by this capability.
TEST(Tron, FeaturesReportTrc20Review) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  TronSignFixture f;
  GetFeatures request = {};
  fsm_msgGetFeatures(&request);
  static Features features;
  features = Features{};
  ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_Features,
                                     Features_fields, &features));
  bool reported = false;
  for (pb_size_t i = 0; i < features.capabilities_count; i++)
    reported = reported || features.capabilities[i] ==
                               Features_Capability_CAPABILITY_TRON_TRC20_REVIEW;
  EXPECT_TRUE(reported);
}

TEST(Tron, ParseNativeTransfer) {
  auto owner = tronAddr(0x11);
  auto to = tronAddr(0x22);
  auto raw = rawTx(
      contractMsg(1, TRANSFER_URL, transferContractValue(owner, to, 1000000)),
      nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRANSFER);
  EXPECT_EQ(memcmp(parsed.owner, owner.data(), 21), 0);
  EXPECT_EQ(memcmp(parsed.to, to.data(), 21), 0);
  EXPECT_EQ(parsed.amount, 1000000u);
  EXPECT_FALSE(parsed.has_fee_limit);
  EXPECT_EQ(parsed.memo_len, 0);
}

TEST(Tron, ParseNativeTransferWithSwapMemo) {
  const char* memo = "=:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:0/1/0:kk:75";
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 5000000)),
                   memo, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRANSFER);
  ASSERT_EQ(parsed.memo_len, strlen(memo));
  EXPECT_EQ(memcmp(parsed.memo, memo, parsed.memo_len), 0);
}

TEST(Tron, ParseTrc20Transfer) {
  auto owner = tronAddr(0x11);
  auto to = tronAddr(0x22);
  auto token = tronAddr(0x33);
  for (bool tronStyle : {false, true}) {
    auto raw = rawTx(
        contractMsg(31, TRIGGER_URL,
                    triggerContractValue(
                        owner, token, trc20Calldata(to, 123456789, tronStyle))),
        nullptr, 100000000 /* 100 TRX fee_limit */);

    TronParsedTx parsed;
    EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
              TRON_TX_TRC20_TRANSFER);
    EXPECT_EQ(memcmp(parsed.owner, owner.data(), 21), 0);
    EXPECT_EQ(memcmp(parsed.to, to.data(), 21), 0);
    EXPECT_EQ(memcmp(parsed.contract, token.data(), 21), 0);
    EXPECT_TRUE(parsed.has_fee_limit);
    EXPECT_EQ(parsed.fee_limit, 100000000u);

    char amount[90];
    ASSERT_TRUE(tron_formatTrc20Amount(parsed.trc20_amount, nullptr, amount,
                                       sizeof(amount)));
    EXPECT_STREQ(amount, "123456789");
  }
}

TEST(Tron, ParseTrc20TransferWithMemo) {
  /* Vault splices THORChain swap memos into raw_data.data for TRC-20 swaps */
  const char* memo = "=:e:0x1234:0:kk:75";
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(
                                   tronAddr(0x11), tronAddr(0x33),
                                   trc20Calldata(tronAddr(0x22), 42, false))),
                   memo, 30000000);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRC20_TRANSFER);
  ASSERT_EQ(parsed.memo_len, strlen(memo));
  EXPECT_EQ(memcmp(parsed.memo, memo, parsed.memo_len), 0);
}

TEST(Tron, RejectWrongSelector) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  data[0] = 0x09; /* approve(address,uint256) = 0x095ea7b3... not transfer */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(tronAddr(0x11),
                                                    tronAddr(0x33), data)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectDirtyAddressWord) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  data[4 + 3] = 0x01; /* junk in the high bytes of the address word */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(tronAddr(0x11),
                                                    tronAddr(0x33), data)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectCalldataLengthMismatch) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  data.push_back(0x00); /* trailing byte — could smuggle params */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(tronAddr(0x11),
                                                    tronAddr(0x33), data)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectNonzeroCallValue) {
  auto value = triggerContractValue(tronAddr(0x11), tronAddr(0x33),
                                    trc20Calldata(tronAddr(0x22), 42, false));
  std::vector<uint8_t> withCallValue;
  putBytesField(withCallValue, 1, tronAddr(0x11));
  putBytesField(withCallValue, 2, tronAddr(0x33));
  putVarintField(withCallValue, 3, 7 /* nonzero TRX attached */);
  putBytesField(withCallValue, 4, trc20Calldata(tronAddr(0x22), 42, false));
  auto raw = rawTx(contractMsg(31, TRIGGER_URL, withCallValue), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);

  /* zero call_value explicitly present is fine */
  std::vector<uint8_t> zeroCallValue;
  putBytesField(zeroCallValue, 1, tronAddr(0x11));
  putBytesField(zeroCallValue, 2, tronAddr(0x33));
  putVarintField(zeroCallValue, 3, 0);
  putBytesField(zeroCallValue, 4, trc20Calldata(tronAddr(0x22), 42, false));
  raw = rawTx(contractMsg(31, TRIGGER_URL, zeroCallValue), nullptr, 0);
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRC20_TRANSFER);
}

TEST(Tron, RejectTrc10Fields) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, tronAddr(0x11));
  putBytesField(v, 2, tronAddr(0x33));
  putBytesField(v, 4, trc20Calldata(tronAddr(0x22), 42, false));
  putVarintField(v, 5, 1000001); /* call_token_value / token_id territory */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL, v), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectMultipleContracts) {
  auto contract = contractMsg(
      1, TRANSFER_URL,
      transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  std::vector<uint8_t> raw;
  putBytesField(raw, 11, contract);
  putBytesField(raw, 11, contract);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectUnknownTopLevelField) {
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 1)),
                   nullptr, 0);
  putBytesField(raw, 9, {0x01}); /* auths — permission delegation */

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectExtraFieldInTransferContract) {
  auto value = transferContractValue(tronAddr(0x11), tronAddr(0x22), 1);
  putVarintField(value, 4, 99);
  auto raw = rawTx(contractMsg(1, TRANSFER_URL, value), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectPermissionId) {
  std::vector<uint8_t> any;
  putStringField(any, 1, TRANSFER_URL);
  putBytesField(any, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  std::vector<uint8_t> c;
  putVarintField(c, 1, 1);
  putBytesField(c, 2, any);
  putVarintField(c, 5, 2); /* Permission_id — multisig account slot */
  auto raw = rawTx(c, nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectDuplicateAnyFields) {
  /* Two type_urls in the Any wrapper — last-wins ambiguity, refuse. */
  std::vector<uint8_t> any;
  putStringField(any, 1, TRIGGER_URL);
  putStringField(any, 1, TRANSFER_URL);
  putBytesField(any, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  std::vector<uint8_t> c;
  putVarintField(c, 1, 1);
  putBytesField(c, 2, any);
  auto raw = rawTx(c, nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);

  /* Two value fields likewise */
  std::vector<uint8_t> any2;
  putStringField(any2, 1, TRANSFER_URL);
  putBytesField(any2, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  putBytesField(any2, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x33), 2));
  std::vector<uint8_t> c2;
  putVarintField(c2, 1, 1);
  putBytesField(c2, 2, any2);
  raw = rawTx(c2, nullptr, 0);
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectTypeUrlEnumMismatch) {
  /* enum says TransferContract, Any says TriggerSmartContract */
  auto raw = rawTx(contractMsg(1, TRIGGER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 1)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectBadOwnerAddress) {
  auto owner = tronAddr(0x11);
  owner[0] = 0x42; /* wrong network prefix */
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(owner, tronAddr(0x22), 1)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectOverlongKeyVarint) {
  /* A valid transfer whose contract key (field 11, length-delimited) is an
   * overlong varint. Truncated, the key reads as field 11 and the whole
   * transaction verifies, so only the overflow check can refuse it. */
  auto contract = contractMsg(
      1, TRANSFER_URL, transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  TronParsedTx parsed;

  std::vector<uint8_t> good;
  putBytesField(good, 11, contract);
  ASSERT_EQ(tron_parseRawTx(good.data(), good.size(), &parsed),
            TRON_TX_TRANSFER);

  std::vector<uint8_t> raw;
  putOverlongVarintValue(raw, (11 << 3) | 2);
  putVarint(raw, contract.size());
  raw.insert(raw.end(), contract.begin(), contract.end());
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectOverlongLengthVarint) {
  /* A valid transfer whose contract length is an overlong varint. Truncated,
   * the length reads as the real contract size and the whole transaction
   * verifies, so only the overflow check can refuse it. */
  auto contract = contractMsg(
      1, TRANSFER_URL, transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  TronParsedTx parsed;

  std::vector<uint8_t> good;
  putBytesField(good, 11, contract);
  ASSERT_EQ(tron_parseRawTx(good.data(), good.size(), &parsed),
            TRON_TX_TRANSFER);

  std::vector<uint8_t> raw;
  putKey(raw, 11, 2);
  putOverlongVarintValue(raw, contract.size());
  raw.insert(raw.end(), contract.begin(), contract.end());
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectOverlongAmountVarint) {
  /* TransferContract.amount (field 3) encoded as an overlong varint. */
  std::vector<uint8_t> value;
  putBytesField(value, 1, tronAddr(0x11));
  putBytesField(value, 2, tronAddr(0x22));
  putOverlongVarintField(value, 3);
  auto raw = rawTx(contractMsg(1, TRANSFER_URL, value), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectOverlongFeeLimitVarint) {
  /* Top-level fee_limit (field 18) encoded as an overlong varint. */
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 1)),
                   nullptr, 0);
  putOverlongVarintField(raw, 18);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectTruncated) {
  /* Build with the contract as the LAST field: any truncation then either
   * cuts into a field (parse failure) or drops the contract entirely —
   * both must be UNVERIFIED. (Truncation at a field boundary that only
   * drops benign trailing fields like timestamp is legal protobuf and
   * stays verified — that case is exercised by the parse tests above.) */
  std::vector<uint8_t> raw;
  putBytesField(raw, 1, {0xab, 0xcd});
  putVarintField(raw, 8, 1750000000000ULL);
  putBytesField(raw, 11,
                contractMsg(1, TRANSFER_URL,
                            transferContractValue(tronAddr(0x11),
                                                  tronAddr(0x22), 1000000)));
  TronParsedTx sanity;
  ASSERT_EQ(tron_parseRawTx(raw.data(), raw.size(), &sanity),
            TRON_TX_TRANSFER);

  for (size_t cut = 1; cut < raw.size(); cut++) {
    TronParsedTx parsed;
    EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size() - cut, &parsed),
              TRON_TX_UNVERIFIED)
        << "cut=" << cut;
  }

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(nullptr, 0, &parsed), TRON_TX_UNVERIFIED);
}

TEST(Tron, FormatTrc20AmountUint256) {
  uint8_t amount[32] = {0};
  amount[31] = 0x01;
  char buf[90];
  ASSERT_TRUE(tron_formatTrc20Amount(amount, nullptr, buf, sizeof(buf)));
  EXPECT_STREQ(buf, "1");

  /* 10^18 — an 18-decimals token unit */
  uint8_t big[32] = {0};
  const uint64_t e18 = 1000000000000000000ULL;
  for (int i = 0; i < 8; i++)
    big[24 + i] = static_cast<uint8_t>(e18 >> (8 * (7 - i)));
  ASSERT_TRUE(tron_formatTrc20Amount(big, nullptr, buf, sizeof(buf)));
  EXPECT_STREQ(buf, "1000000000000000000");
}

TEST(Tron, AddressFromBytes) {
  /* Base58Check of 41 + 20 bytes must round-trip through the display helper */
  uint8_t addr[21];
  memset(addr, 0x11, sizeof(addr));
  addr[0] = 0x41;
  char out[64];
  ASSERT_TRUE(tron_addressFromBytes(addr, out, sizeof(out)));
  EXPECT_EQ(out[0], 'T'); /* mainnet addresses render as T... */
  EXPECT_GE(strlen(out), 33u);
}

/* ------------------------------------------------------------------ */
/*  7.17: TRC-20 approve, Stake 2.0 and votes, on real mainnet bytes   */
/*  (tron_vectors.h, from scripts/tron_vectors.py; expected values are */
/*  TronGrid's own decode of each transaction).                        */
/* ------------------------------------------------------------------ */

namespace {
std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
    out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr,
                                                  16)));
  return out;
}

const tronv::Vec& vec(const char* name) {
  for (const auto& v : tronv::all())
    if (v.name == name) return v;
  ADD_FAILURE() << "no vector " << name;
  return tronv::all()[0];
}

TronTxType expectedType(const tronv::Vec& v) {
  if (v.permission_id) return TRON_TX_UNVERIFIED; /* multisig account slot */
  if (v.type == "TriggerSmartContract")
    return v.data.compare(0, 8, "095ea7b3") == 0 ? TRON_TX_TRC20_APPROVE
                                                 : TRON_TX_UNVERIFIED;
  if (v.type == "FreezeBalanceV2Contract") return TRON_TX_FREEZE_V2;
  if (v.type == "UnfreezeBalanceV2Contract") return TRON_TX_UNFREEZE_V2;
  if (v.type == "VoteWitnessContract") return TRON_TX_VOTE_WITNESS;
  return TRON_TX_UNVERIFIED;
}

/* The real transaction with its single owner_address replaced by `owner`:
 * same length, so every protobuf length prefix stays valid. */
std::vector<uint8_t> withOwner(const tronv::Vec& v,
                               const std::vector<uint8_t>& owner) {
  auto raw = fromHex(v.raw_hex);
  const auto from = fromHex(v.owner);
  size_t found = 0, at = 0;
  for (size_t i = 0; i + from.size() <= raw.size(); i++) {
    if (std::equal(from.begin(), from.end(), raw.begin() + i)) {
      found++;
      at = i;
    }
  }
  EXPECT_EQ(1u, found) << v.name;
  std::copy(owner.begin(), owner.end(), raw.begin() + at);
  return raw;
}
}  // namespace

// Every captured transaction is the exact byte string the chain accepted
// (sha256(raw_data) is its txID), and the parser reads it as TronGrid did.
TEST(Tron, RealTransactionsParseAsTronGridDecodesThem) {
  for (const auto& v : tronv::all()) {
    SCOPED_TRACE(v.name);
    const auto raw = fromHex(v.raw_hex);
    uint8_t digest[32];
    sha256_Raw(raw.data(), raw.size(), digest);
    ASSERT_EQ(v.txid, [&] {
      std::string hex;
      char b[3];
      for (uint8_t c : digest) {
        snprintf(b, sizeof(b), "%02x", c);
        hex += b;
      }
      return hex;
    }());

    TronParsedTx parsed;
    const TronTxType type = tron_parseRawTx(raw.data(), raw.size(), &parsed);
    ASSERT_EQ(expectedType(v), type);
    if (type == TRON_TX_UNVERIFIED) continue;
    EXPECT_EQ(fromHex(v.owner),
              std::vector<uint8_t>(parsed.owner, parsed.owner + 21));
    EXPECT_EQ(v.fee_limit, parsed.has_fee_limit);

    if (type == TRON_TX_TRC20_APPROVE) {
      const auto data = fromHex(v.data);
      std::vector<uint8_t> spender = {0x41};
      spender.insert(spender.end(), data.begin() + 16, data.begin() + 36);
      EXPECT_EQ(fromHex(v.contract),
                std::vector<uint8_t>(parsed.contract, parsed.contract + 21));
      EXPECT_EQ(spender, std::vector<uint8_t>(parsed.to, parsed.to + 21));
      EXPECT_EQ(std::vector<uint8_t>(data.begin() + 36, data.end()),
                std::vector<uint8_t>(parsed.trc20_amount,
                                     parsed.trc20_amount + 32));
    } else if (type == TRON_TX_VOTE_WITNESS) {
      ASSERT_EQ(v.votes.size(), parsed.vote_count);
      for (uint8_t i = 0; i < parsed.vote_count; i++) {
        uint8_t sr[21];
        uint64_t count = 0;
        ASSERT_TRUE(tron_voteAt(&parsed, i, sr, &count));
        EXPECT_EQ(fromHex(v.votes[i].address),
                  std::vector<uint8_t>(sr, sr + 21));
        EXPECT_EQ(v.votes[i].count, count);
      }
      uint8_t sr[21];
      uint64_t count;
      EXPECT_FALSE(tron_voteAt(&parsed, parsed.vote_count, sr, &count));
    } else {
      EXPECT_EQ(v.stake_amount, parsed.amount);
      EXPECT_EQ(v.resource, parsed.resource);
    }
  }
}

// Each real approve, stake, unstake and vote clear-signs on its own screens,
// with every value spelled out (expected text computed from TronGrid's decode,
// not by the firmware), and signs sha256(raw_data) with the account's key.
// TRC-20 calls to a contract outside the trusted table keep needing
// AdvancedMode, and then name the contract first.
TEST(Tron, RealApprovesStakesAndVotesShowEveryValue) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  TronSignFixture f;
  struct Case {
    const char* name;
    std::vector<std::pair<std::string, std::string>> screens;
  };
  const Case cases[] = {
      {"usdt_approve_unlimited",
       {{"UNLIMITED approval",
         "Allow TKwNfJYb2iyouByKpNdxQ6tryXK8KhTPT9 to spend ALL your USDT?"},
        {"TRON", "Energy fee limit 150 TRX\nBandwidth fees are extra"}}},
      {"usdt_approve_unlimited_41_word",
       {{"UNLIMITED approval",
         "Allow TJ4KeiGTvTX4wRUgLARiwr8rGLaurmVkdZ to spend ALL your USDT?"},
        {"TRON", "Energy fee limit 9.9827 TRX\nBandwidth fees are extra"}}},
      {"usdt_approve_100",
       {{"TRC-20 Approve",
         "Allow TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax to spend up to 100 USDT?"},
        {"TRON", "Energy fee limit 50 TRX\nBandwidth fees are extra"}}},
      {"usdt_approve_100_41_word",
       {{"TRC-20 Approve",
         "Allow TJ4KeiGTvTX4wRUgLARiwr8rGLaurmVkdZ to spend up to 100 USDT?"},
        {"TRON", "Energy fee limit 9.9827 TRX\nBandwidth fees are extra"}}},
      {"usdt_approve_revoke",
       {{"TRC-20 Approve",
         "Remove approval for TTJxU3P8rHycAyFY4kVtGNfmnMH4ezcuM9 to spend "
         "your USDT?"},
        {"TRON", "Energy fee limit 100 TRX\nBandwidth fees are extra"}}},
      {"usdd_approve",
       {{"TRC-20 Approve",
         "Allow TBXW4hS5KYjjbJXDpnrPf4zhkLwrpUjbyz to spend up to "
         "60000.00000028 USDD?"},
        {"TRON", "Energy fee limit 1.24215 TRX\nBandwidth fees are extra"}}},
      {"usdd_approve_unlimited",
       {{"UNLIMITED approval",
         "Allow TTJxU3P8rHycAyFY4kVtGNfmnMH4ezcuM9 to spend ALL your USDD?"},
        {"TRON", "Energy fee limit 100 TRX\nBandwidth fees are extra"}}},
      {"unlisted_contract_approve",
       {{"TRON Blind Sign", ""},
        {"TRC-20 Approve", "Token contract TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9"},
        {"TRC-20 Approve",
         "Allow TDH4dhmVQQNc1ZNudJwWzBcs2h6ahhWrpp to spend up to 57066 base "
         "units?"},
        {"TRON", "Energy fee limit 200 TRX\nBandwidth fees are extra"}}},
      {"unlisted_contract_approve_unlimited",
       {{"TRON Blind Sign", ""},
        {"TRC-20 Approve", "Token contract TSSMHYeV2uE9qYH95DqyoCuNCzEL1NvU3S"},
        {"UNLIMITED approval",
         "Allow TTJxU3P8rHycAyFY4kVtGNfmnMH4ezcuM9 to spend ALL your tokens?"},
        {"TRON", "Energy fee limit 150 TRX\nBandwidth fees are extra"}}},
      {"freeze_energy", {{"TRON Stake", "Stake 13 TRX for ENERGY?"}}},
      {"freeze_bandwidth",
       {{"TRON Stake", "Stake 2.993143 TRX for BANDWIDTH?"}}},
      {"freeze_with_fee_limit",
       {{"TRON Stake", "Stake 909 TRX for ENERGY?"},
        {"TRON", "Energy fee limit 100 TRX\nNot used by this transaction"}}},
      {"unfreeze_energy", {{"TRON Unstake", "Unstake 24 TRX from ENERGY?"}}},
      {"unfreeze_bandwidth",
       {{"TRON Unstake", "Unstake 18 TRX from BANDWIDTH?"}}},
      {"vote_1",
       {{"TRON Vote", "Vote for 1 SR? This replaces all your current votes."},
        {"Vote 1/1", "2498 votes for TFqEaQBVpJmc6y6sbvXgzu9zsXL1pTKw47"}}},
      {"vote_3",
       {{"TRON Vote", "Vote for 3 SRs? This replaces all your current votes."},
        {"Vote 1/3", "83306 votes for TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF"},
        {"Vote 2/3", "83304 votes for TNeEwWHXLLUgEtfzTnYN8wtVenGxuMzZCE"},
        {"Vote 3/3", "83304 votes for TTMNxTmRpBZnjtUnohX84j25NLkTqDga7j"}}},
      {"vote_7",
       {{"TRON Vote", "Vote for 7 SRs? This replaces all your current votes."},
        {"Vote 1/7", "6400 votes for TVFKwzE8qeETLaZEHMx2tjEsdnujAgAWaA"},
        {"Vote 2/7", "1631 votes for TDpt9adA6QidL1B1sy3D8NC717C6L5JxFo"},
        {"Vote 3/7", "1200 votes for TJvaAeFb8Lykt9RQcVyyTFN2iDvGMuyD4M"},
        {"Vote 4/7", "652 votes for TTMNxTmRpBZnjtUnohX84j25NLkTqDga7j"},
        {"Vote 5/7", "614 votes for TQopP5GM68QoqLzpz8YReDfSoCMkvwcZYd"},
        {"Vote 6/7", "334 votes for TFXHSwdMruwXk18r8s5LpJuMiiPxUn2XMV"},
        {"Vote 7/7", "223 votes for TNajWcLPBuxKmCVT8DZh7Xs4X9Bkme9poG"}}},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    const auto raw = withOwner(vec(c.name), f.owner);
    TronSignTx tx = f.request(raw);
    const bool blind = c.screens[0].first == "TRON Blind Sign";
    const int n = (int)c.screens.size();

    ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
    if (blind) { /* refused before any screen without AdvancedMode */
      ASSERT_TRUE(kkconfirm_preload(0, 1));
      fsm_test_clearLastFailure();
      fsm_msgTronSignTx(&tx);
      EXPECT_STREQ("Enable AdvancedMode to blind-sign",
                   fsm_test_lastFailureMessage());
      EXPECT_EQ(2, kkconfirm_drain());
      ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
    }

    /* Declining the last screen cancels: no screen is decoration. */
    ASSERT_TRUE(kkconfirm_preload(n - 1, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignTx(&tx);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_EQ(0, kkconfirm_drain());

    ASSERT_TRUE(kkconfirm_preload(n, 0));
    kkconfirm_capture_start();
    fsm_test_clearLastFailure();
    fsm_msgTronSignTx(&tx);
    const auto titles = kkconfirm_capture_titles();
    const auto bodies = kkconfirm_capture_finish();
    EXPECT_EQ(0, fsm_test_lastFailureCode());
    static TronSignedTx signed_tx;
    signed_tx = TronSignedTx{};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_TronSignedTx,
                                       TronSignedTx_fields, &signed_tx));
    EXPECT_EQ(0, kkconfirm_drain());
    ASSERT_EQ((size_t)n, bodies.size());
    for (int i = 0; i < n; i++) {
      EXPECT_EQ(c.screens[i].first, titles[i]) << i;
      if (!(blind && i == 0)) EXPECT_EQ(c.screens[i].second, bodies[i]) << i;
    }

    uint8_t digest[32], pub[65], hash[32];
    sha256_Raw(raw.data(), raw.size(), digest);
    ASSERT_EQ(65, signed_tx.signature.size);
    ASSERT_EQ(0, ecdsa_recover_pub_from_sig(&secp256k1, pub,
                                            signed_tx.signature.bytes, digest,
                                            signed_tx.signature.bytes[64]));
    keccak_256(pub + 1, 64, hash);
    EXPECT_EQ(0, memcmp(hash + 12, f.owner.data() + 1, 20));
    EXPECT_TRUE(fsm_test_derivedNodeIsZero());
  }
}

// A multisig Permission_id still leaves the device unable to say whose
// authority signs, so those real stakes and votes stay blind-sign only.
TEST(Tron, RealMultisigStakeAndVoteStayBlind) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  TronSignFixture f;
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  for (const char* name :
       {"freeze_multisig_permission", "vote_multisig_permission"}) {
    SCOPED_TRACE(name);
    TronSignTx tx = f.request(withOwner(vec(name), f.owner));
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignTx(&tx);
    EXPECT_STREQ("Enable AdvancedMode to blind-sign",
                 fsm_test_lastFailureMessage());
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

namespace {
/* VoteWitnessContract { owner=1, votes=2 { address=1, count=2 } } */
std::vector<uint8_t> voteValue(size_t n, uint64_t count) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, tronAddr(0x11));
  for (size_t i = 0; i < n; i++) {
    std::vector<uint8_t> vote;
    putBytesField(vote, 1, tronAddr(0x30 + (uint8_t)i));
    putVarintField(vote, 2, count);
    putBytesField(v, 2, vote);
  }
  return v;
}

/* FreezeBalanceV2Contract { owner=1, frozen_balance=2, resource=3 } */
std::vector<uint8_t> stakeValue(uint64_t amount, int resource) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, tronAddr(0x11));
  putVarintField(v, 2, amount);
  if (resource >= 0) putVarintField(v, 3, (uint64_t)resource);
  return v;
}

TronTxType parseOnly(uint64_t type, const char* url,
                     const std::vector<uint8_t>& value) {
  auto raw = rawTx(contractMsg(type, url, value), nullptr, 0);
  TronParsedTx parsed;
  return tron_parseRawTx(raw.data(), raw.size(), &parsed);
}

const char* VOTE_URL = "type.googleapis.com/protocol.VoteWitnessContract";
const char* FREEZE_URL = "type.googleapis.com/protocol.FreezeBalanceV2Contract";
const char* UNFREEZE_URL =
    "type.googleapis.com/protocol.UnfreezeBalanceV2Contract";
}  // namespace

// Anything outside what the chain accepts, or what the screens can state,
// stays blind: the boundaries next to the accepted shapes.
TEST(Tron, StakeAndVoteBoundariesFailClosed) {
  EXPECT_EQ(TRON_TX_VOTE_WITNESS, parseOnly(4, VOTE_URL, voteValue(1, 1)));
  EXPECT_EQ(TRON_TX_VOTE_WITNESS,
            parseOnly(4, VOTE_URL, voteValue(TRON_MAX_VOTES, 5)));
  EXPECT_EQ(TRON_TX_UNVERIFIED,
            parseOnly(4, VOTE_URL, voteValue(TRON_MAX_VOTES + 1, 5)));
  EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(4, VOTE_URL, voteValue(0, 5)));
  EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(4, VOTE_URL, voteValue(2, 0)));
  auto support = voteValue(1, 1);
  putVarintField(support, 3, 1); /* VoteWitnessContract.support */
  EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(4, VOTE_URL, support));
  EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(54, VOTE_URL, voteValue(1, 1)));

  for (uint64_t type : {54, 55}) {
    const char* url = type == 54 ? FREEZE_URL : UNFREEZE_URL;
    const TronTxType ok = type == 54 ? TRON_TX_FREEZE_V2 : TRON_TX_UNFREEZE_V2;
    EXPECT_EQ(ok, parseOnly(type, url, stakeValue(1000000, -1)));
    EXPECT_EQ(ok, parseOnly(type, url, stakeValue(1000000, 2)));
    EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(type, url, stakeValue(1000000, 3)));
    EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(type, url, stakeValue(0, 1)));
    auto receiver = stakeValue(1000000, 1);
    putBytesField(receiver, 4, tronAddr(0x22)); /* not a V2 field */
    EXPECT_EQ(TRON_TX_UNVERIFIED, parseOnly(type, url, receiver));
  }
  /* FreezeBalanceContract (v1, type 11) is not decoded. */
  EXPECT_EQ(TRON_TX_UNVERIFIED,
            parseOnly(11, "type.googleapis.com/protocol.FreezeBalanceContract",
                      stakeValue(1000000, 1)));

  /* No truncation of a real vote reads as a shorter vote list. */
  const auto raw = fromHex(vec("vote_7").raw_hex);
  for (size_t cut = 1; cut < raw.size(); cut++) {
    TronParsedTx parsed;
    const TronTxType type =
        tron_parseRawTx(raw.data(), raw.size() - cut, &parsed);
    /* Dropping only trailing timestamp/expiration fields is legal. */
    if (type != TRON_TX_UNVERIFIED) {
      EXPECT_EQ(TRON_TX_VOTE_WITNESS, type);
      EXPECT_EQ(7, parsed.vote_count) << "cut=" << cut;
    }
  }
}

// approve() calldata gets the same exact-shape checks as transfer().
TEST(Tron, ApproveCalldataMustBeExact) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  const uint8_t approve[4] = {0x09, 0x5e, 0xa7, 0xb3};
  std::copy(approve, approve + 4, data.begin());
  EXPECT_EQ(TRON_TX_TRC20_APPROVE,
            parseOnly(31, TRIGGER_URL,
                      triggerContractValue(tronAddr(0x11), tronAddr(0x33),
                                           data)));
  auto dirty = data;
  dirty[4 + 3] = 0x01;
  EXPECT_EQ(TRON_TX_UNVERIFIED,
            parseOnly(31, TRIGGER_URL,
                      triggerContractValue(tronAddr(0x11), tronAddr(0x33),
                                           dirty)));
  auto longer = data;
  longer.push_back(0);
  EXPECT_EQ(TRON_TX_UNVERIFIED,
            parseOnly(31, TRIGGER_URL,
                      triggerContractValue(tronAddr(0x11), tronAddr(0x33),
                                           longer)));
  /* increaseAllowance(address,uint256) is not decoded. */
  auto increase = data;
  const uint8_t inc[4] = {0x39, 0x50, 0x93, 0x51};
  std::copy(inc, inc + 4, increase.begin());
  EXPECT_EQ(TRON_TX_UNVERIFIED,
            parseOnly(31, TRIGGER_URL,
                      triggerContractValue(tronAddr(0x11), tronAddr(0x33),
                                           increase)));
}
