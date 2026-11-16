extern "C" {
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/monero.h"
#include "keepkey/firmware/monero_tx.h"
#include "keepkey/firmware/signing_session.h"
#include "keepkey/firmware/storage.h"
#include "monero_probe.h"
#include "monero_test_rng.h"
#include "monero_tx_probe.h"

bool keepkey_before_message_dispatch(MessageType msg_id);
}

#include "gtest/gtest.h"
#include "test_board.h"
#include "generated/monero_core_vectors.h"
#include "monero_tx_vectors.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

/* Drives the streamed signer (lib/firmware/monero_tx.c) in process, the way
 * a host would, and assembles the transaction from what the device returns.
 *
 * MONERO CORE. Every positive case's transaction is checked by unmodified
 * Monero Core v0.18.5.4 when the vectors are generated
 * (monero_tx_vectors_gen.sh): with KK_XMR_TX_RECORDS set, each case writes a
 * record, monero_tx_core_verify.cpp parses the transaction, verifies the
 * range proof, the balance and every CLSAG against the ring, recomputes the
 * prefix hash and the CLSAG message, checks every key image, and scans every
 * output as its recipient. Only then is the transaction's Keccak written to
 * monero_tx_vectors.h. A normal run rebuilds the same transaction (the RNG
 * draws are replayed) and requires that exact digest, so the bytes tested
 * here are bytes Core accepted. Tampered copies are recorded too, and Core
 * must reject them.
 *
 * Wallets come from the Core fixtures (monero_core_vectors.h): "abandon"
 * signs, "trezor" receives. */

namespace {

using Bytes = std::vector<uint8_t>;

const MoneroCoreCase& fixture(const std::string& label) {
  for (size_t i = 0; i < MONERO_CORE_CASE_COUNT; ++i)
    if (label == monero_core_cases[i].label) return monero_core_cases[i];
  ADD_FAILURE() << "no fixture " << label;
  return monero_core_cases[0];
}

const MoneroCoreCase& signer_wallet() {
  return fixture("abandon-account0-sub0-0-output0");
}
const MoneroCoreCase& other_wallet() {
  return fixture("trezor-account0-sub0-0-output0");
}

void put_varint(Bytes& out, uint64_t v) {
  while (v >= 0x80) {
    out.push_back((uint8_t)(v | 0x80));
    v >>= 7;
  }
  out.push_back((uint8_t)v);
}

void append(Bytes& out, const uint8_t* p, size_t n) {
  out.insert(out.end(), p, p + n);
}

void put_le64(Bytes& out, uint64_t v) {
  for (int i = 0; i < 8; ++i) out.push_back((uint8_t)(v >> (8 * i)));
}

Bytes keccak(const Bytes& data) {
  Bytes out(32);
  monero_probe_keccak(data.data(), data.size(), out.data());
  return out;
}

std::string hex(const uint8_t* p, size_t n) {
  static const char digits[] = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; ++i) {
    s += digits[p[i] >> 4];
    s += digits[p[i] & 15];
  }
  return s;
}

alignas(8) uint8_t scratch[XMR_FRAME_ARENA_FLOOR_BYTES];

struct Recipient {
  uint8_t keys[64];        /* spend and view public keys of the address */
  uint8_t view_secret[32]; /* the wallet's view secret, to scan as recipient */
  bool subaddress = false;
};

Recipient own_address(uint32_t account) {
  Recipient r;
  const MoneroCoreCase& w = signer_wallet();
  monero_tx_probe_address_keys(w.spend_secret, w.view_secret, account, 0,
                               r.keys);
  memcpy(r.view_secret, w.view_secret, 32);
  r.subaddress = account != 0;
  return r;
}

Recipient other_address(uint32_t major, uint32_t minor) {
  Recipient r;
  const MoneroCoreCase& w = other_wallet();
  monero_tx_probe_address_keys(w.spend_secret, w.view_secret, major, minor,
                               r.keys);
  memcpy(r.view_secret, w.view_secret, 32);
  r.subaddress = major || minor;
  return r;
}

MoneroTxDestination destination(const Recipient& to, uint64_t amount,
                                bool integrated = false) {
  MoneroTxDestination d = {};
  d.has_amount = true;
  d.amount = amount;
  d.has_spend_public_key = d.has_view_public_key = true;
  d.spend_public_key.size = d.view_public_key.size = 32;
  memcpy(d.spend_public_key.bytes, to.keys, 32);
  memcpy(d.view_public_key.bytes, to.keys + 32, 32);
  d.has_is_subaddress = true;
  d.is_subaddress = to.subaddress;
  d.has_is_integrated = true;
  d.is_integrated = integrated;
  return d;
}

struct Input {
  MoneroTxSourceEntry src;
  uint8_t secret[32];
};

/* An input the signer wallet really owns, at `real` in a ring of decoys. */
Input owned_input(uint32_t account, uint32_t minor, uint64_t amount,
                  unsigned real, uint32_t tag, bool via_additional = false) {
  Input in = {};
  MoneroTxProbeOwned owned;
  const MoneroCoreCase& w = signer_wallet();
  const uint32_t index = tag % 3;
  monero_tx_probe_owned(w.spend_secret, w.view_secret, account, minor, index,
                        amount, via_additional, "owned", tag, &owned);
  MoneroTxSourceEntry& s = in.src;
  s.ring_count = 16;
  for (unsigned i = 0; i < 16; ++i) {
    MoneroTxRingMember& m = s.ring[i];
    m.has_global_index = m.has_dest = m.has_commitment = true;
    m.global_index = 1000000u + tag * 100000u + i * 977u + (i * i) % 13u;
    m.dest.size = m.commitment.size = 32;
    monero_tx_probe_point(m.dest.bytes, "decoy-dest", tag * 16 + i);
    monero_tx_probe_point(m.commitment.bytes, "decoy-commit", tag * 16 + i);
  }
  memcpy(s.ring[real].dest.bytes, owned.out_key, 32);
  memcpy(s.ring[real].commitment.bytes, owned.commitment, 32);
  s.has_real_index = true;
  s.real_index = real;
  s.has_real_out_tx_key = true;
  s.real_out_tx_key.size = 32;
  memcpy(s.real_out_tx_key.bytes, owned.tx_pub, 32);
  if (via_additional) {
    s.has_real_out_additional_key = true;
    s.real_out_additional_key.size = 32;
    memcpy(s.real_out_additional_key.bytes, owned.additional, 32);
  }
  s.has_real_output_in_tx_index = true;
  s.real_output_in_tx_index = index;
  s.has_amount = true;
  s.amount = amount;
  s.has_mask = true;
  s.mask.size = 32;
  memcpy(s.mask.bytes, owned.mask, 32);
  s.has_sub_major = s.has_sub_minor = true;
  s.sub_major = account;
  s.sub_minor = minor;
  memcpy(in.secret, owned.secret, 32);
  return in;
}

struct Plan {
  std::string name;
  MoneroTxInitRequest init = {};
  std::vector<Input> inputs;
  Recipient to[2];
  bool has_pid = false;
  uint8_t pid[8] = {};
  uint8_t pid_view_secret[32] = {};
};

/* `recipient` paid `send`, change back to the wallet's (account, 0); the
 * change output is at `change_index`. Inputs must be added to match. */
Plan make_plan(const std::string& name, uint32_t account,
               const Recipient& recipient, uint64_t send, uint64_t change,
               uint64_t fee, unsigned change_index) {
  Plan p;
  p.name = name;
  MoneroTxInitRequest& m = p.init;
  m.address_n_count = 3;
  m.address_n[0] = 0x8000002c;
  m.address_n[1] = 0x80000080;
  m.address_n[2] = 0x80000000;
  m.has_tsx_data = true;
  MoneroTxData& t = m.tsx_data;
  const Recipient own = own_address(account);
  t.outputs_count = 2;
  t.outputs[change_index] = destination(own, change);
  t.outputs[1 - change_index] = destination(recipient, send);
  p.to[change_index] = own;
  p.to[1 - change_index] = recipient;
  t.has_change_dts = true;
  t.change_dts.has_amount = true;
  t.change_dts.amount = change;
  t.change_dts.has_spend_public_key = t.change_dts.has_view_public_key = true;
  t.change_dts.spend_public_key.size = t.change_dts.view_public_key.size = 32;
  memcpy(t.change_dts.spend_public_key.bytes, own.keys, 32);
  memcpy(t.change_dts.view_public_key.bytes, own.keys + 32, 32);
  t.change_dts.has_major = t.change_dts.has_minor = true;
  t.change_dts.major = account;
  t.change_dts.minor = 0;
  t.has_ring_size = true;
  t.ring_size = 16;
  t.has_fee = true;
  t.fee = fee;
  t.has_account = true;
  t.account = account;
  t.has_hard_fork = true;
  t.hard_fork = 16;
  t.has_bp_version = true;
  t.bp_version = 4;
  /* Core encrypts the (dummy) payment ID to the recipient's view key. */
  memcpy(p.pid_view_secret, recipient.view_secret, 32);
  return p;
}

void add_input(Plan& p, const Input& in) {
  p.inputs.push_back(in);
  p.init.tsx_data.has_num_inputs = true;
  p.init.tsx_data.num_inputs = (uint32_t)p.inputs.size();
}

void set_payment_id(Plan& p, unsigned output, uint8_t fill) {
  p.has_pid = true;
  memset(p.pid, fill, 8);
  p.pid[0] = 0x01;
  p.init.tsx_data.has_payment_id = true;
  p.init.tsx_data.payment_id.size = 8;
  memcpy(p.init.tsx_data.payment_id.bytes, p.pid, 8);
  p.init.tsx_data.outputs[output].is_integrated = true;
}

/* 1 input, a standard recipient, change last. */
Plan simple_plan() {
  Plan p = make_plan("1in-2out-standard", 0, other_address(0, 0),
                     1500000000000ull, 499969000000ull, 31000000ull, 1);
  add_input(p, owned_input(0, 0, 2000000000000ull, 5, 1));
  return p;
}

/* 2 inputs (one received on a subaddress, one through an additional key),
 * a subaddress recipient (so R = r*D), change first. */
Plan two_input_plan() {
  Plan p = make_plan("2in-2out-subaddress", 0, other_address(0, 1),
                     700000000001ull, 1299968999999ull, 31000000ull, 0);
  add_input(p, owned_input(0, 3, 1500000000000ull, 0, 2));
  add_input(p, owned_input(0, 0, 500000000000ull, 15, 3, true));
  return p;
}

struct Flow {
  Plan plan;
  MoneroTxReview review = {};
  MoneroTxInitAck init_ack = {};
  std::vector<MoneroTxSetInputAck> in_acks;
  std::vector<uint32_t> order; /* sorted position -> plan index */
  MoneroTxSetOutputAck out_acks[2] = {};
  MoneroTxAllOutSetAck all_out = {};
  std::vector<MoneroTxSignInputAck> sign_acks;
  MoneroTxFinalAck final_ack = {};

  explicit Flow(const Plan& p) : plan(p) {}

  const uint8_t* node_key() const { return signer_wallet().key_seed; }

  MoneroTxResult begin() {
    MoneroTxResult r = monero_tx_review(node_key(), &plan.init, &review);
    if (r != MONERO_TX_OK) return r;
    return monero_tx_begin(node_key(), &plan.init, review.digest, &init_ack);
  }

  MoneroTxResult set_inputs() {
    for (const Input& in : plan.inputs) {
      MoneroTxSetInputRequest req = {};
      req.has_src = true;
      req.src = in.src;
      MoneroTxSetInputAck ack = {};
      const MoneroTxResult r = monero_tx_set_input(&req, &ack);
      if (r != MONERO_TX_OK) return r;
      in_acks.push_back(ack);
    }
    /* Core's order: key images descending. */
    order.clear();
    for (uint32_t i = 0; i < in_acks.size(); ++i) order.push_back(i);
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
      return memcmp(key_image(a), key_image(b), 32) > 0;
    });
    return MONERO_TX_OK;
  }

  const uint8_t* key_image(uint32_t index) const {
    const MoneroTxSetInputAck& a = in_acks[index];
    return a.vini.bytes + a.vini.size - 32;
  }

  MoneroTxInputViniRequest vini_request(uint32_t index) const {
    MoneroTxInputViniRequest req = {};
    req.has_vini = req.has_vini_hmac = req.has_orig_idx = true;
    req.vini.size = in_acks[index].vini.size;
    memcpy(req.vini.bytes, in_acks[index].vini.bytes, req.vini.size);
    req.vini_hmac.size = 32;
    memcpy(req.vini_hmac.bytes, in_acks[index].vini_hmac.bytes, 32);
    req.orig_idx = index;
    return req;
  }

  MoneroTxResult vinis() {
    for (uint32_t index : order) {
      const MoneroTxInputViniRequest req = vini_request(index);
      const MoneroTxResult r = monero_tx_input_vini(&req);
      if (r != MONERO_TX_OK) return r;
    }
    return monero_tx_all_inputs_set();
  }

  MoneroTxSetOutputRequest output_request(unsigned j) const {
    MoneroTxSetOutputRequest req = {};
    req.has_dst = req.has_dst_hmac = true;
    req.dst = plan.init.tsx_data.outputs[j];
    req.dst_hmac.size = 32;
    memcpy(req.dst_hmac.bytes, init_ack.dst_hmacs[j].bytes, 32);
    return req;
  }

  MoneroTxResult output(unsigned j, xmr_progress_fn progress = nullptr,
                        void* ctx = nullptr) {
    const MoneroTxSetOutputRequest req = output_request(j);
    return monero_tx_set_output(&req, &out_acks[j], scratch, sizeof(scratch),
                                progress, ctx);
  }

  MoneroTxResult outputs() {
    for (unsigned j = 0; j < 2; ++j) {
      const MoneroTxResult r = output(j);
      if (r != MONERO_TX_OK) return r;
    }
    return monero_tx_all_out_set(&all_out);
  }

  MoneroTxSignInputRequest sign_request(uint32_t index) const {
    MoneroTxSignInputRequest req = {};
    req.has_src = req.has_vini = req.has_vini_hmac = true;
    req.has_pseudo_out = req.has_pseudo_out_hmac = req.has_orig_idx = true;
    req.src = plan.inputs[index].src;
    const MoneroTxSetInputAck& a = in_acks[index];
    req.vini.size = a.vini.size;
    memcpy(req.vini.bytes, a.vini.bytes, a.vini.size);
    req.vini_hmac.size = req.pseudo_out.size = req.pseudo_out_hmac.size = 32;
    memcpy(req.vini_hmac.bytes, a.vini_hmac.bytes, 32);
    memcpy(req.pseudo_out.bytes, a.pseudo_out.bytes, 32);
    memcpy(req.pseudo_out_hmac.bytes, a.pseudo_out_hmac.bytes, 32);
    req.orig_idx = index;
    return req;
  }

  MoneroTxResult sign(uint32_t index, xmr_progress_fn progress = nullptr,
                      void* ctx = nullptr) {
    const MoneroTxSignInputRequest req = sign_request(index);
    MoneroTxSignInputAck ack = {};
    const MoneroTxResult r = monero_tx_sign_input(
        &req, &ack, scratch, sizeof(scratch), progress, ctx);
    if (r == MONERO_TX_OK) sign_acks.push_back(ack);
    return r;
  }

  MoneroTxResult signs() {
    for (uint32_t index : order) {
      const MoneroTxResult r = sign(index);
      if (r != MONERO_TX_OK) return r;
    }
    return MONERO_TX_OK;
  }

  /* The whole session up to and including all_out_set. */
  MoneroTxResult to_signing() {
    MoneroTxResult r = begin();
    if (r == MONERO_TX_OK) r = set_inputs();
    if (r == MONERO_TX_OK) r = vinis();
    if (r == MONERO_TX_OK) r = outputs();
    return r;
  }

  MoneroTxResult run() {
    MoneroTxResult r = to_signing();
    if (r == MONERO_TX_OK) r = signs();
    if (r == MONERO_TX_OK) r = monero_tx_final(&final_ack);
    return r;
  }

  Bytes prefix() const {
    Bytes tx;
    const MoneroTxData& t = plan.init.tsx_data;
    put_varint(tx, 2);
    put_varint(tx, t.has_unlock_time ? t.unlock_time : 0);
    put_varint(tx, in_acks.size());
    for (uint32_t index : order)
      append(tx, in_acks[index].vini.bytes, in_acks[index].vini.size);
    put_varint(tx, 2);
    for (unsigned j = 0; j < 2; ++j)
      append(tx, out_acks[j].tx_out.bytes, out_acks[j].tx_out.size);
    put_varint(tx, all_out.extra.size);
    append(tx, all_out.extra.bytes, all_out.extra.size);
    return tx;
  }

  /* The complete transaction, as a host assembles it for relay. */
  Bytes assemble() const {
    Bytes tx = prefix();
    tx.push_back((uint8_t)all_out.rct_type);
    put_varint(tx, all_out.fee);
    for (unsigned j = 0; j < 2; ++j)
      append(tx, out_acks[j].ecdh_info.bytes, 8);
    for (unsigned j = 0; j < 2; ++j)
      append(tx, out_acks[j].out_pk.bytes + 32, 32);
    put_varint(tx, 1); /* one aggregate BP+ proof */
    append(tx, out_acks[1].bp_plus.bytes, out_acks[1].bp_plus.size);
    for (size_t k = 0; k < sign_acks.size(); ++k) {
      uint8_t plain[18 * 32];
      EXPECT_EQ(sizeof(plain) + 16, sign_acks[k].clsag_enc.size);
      EXPECT_TRUE(monero_tx_probe_open(final_ack.opening_key.bytes,
                                       (uint32_t)k,
                                       sign_acks[k].clsag_enc.bytes,
                                       sign_acks[k].clsag_enc.size, plain));
      append(tx, plain, sizeof(plain));
    }
    for (const auto& ack : sign_acks) append(tx, ack.pseudo_out.bytes, 32);
    return tx;
  }
};

/* ---- Core records and vectors ---- */

void write_record(const Flow& f, const std::string& name, const Bytes& tx,
                  bool expect) {
  const char* path = getenv("KK_XMR_TX_RECORDS");
  if (!path) return;
  Bytes r;
  r.push_back('T');
  r.push_back(expect ? 1 : 0);
  r.push_back((uint8_t)name.size());
  append(r, (const uint8_t*)name.data(), name.size());
  for (int i = 0; i < 4; ++i) r.push_back((uint8_t)(tx.size() >> (8 * i)));
  append(r, tx.data(), tx.size());
  append(r, f.all_out.tx_prefix_hash.bytes, 32);
  append(r, f.all_out.full_message_hash.bytes, 32);
  put_le64(r, f.all_out.fee);
  r.push_back((uint8_t)f.order.size());
  for (uint32_t index : f.order) {
    const Input& in = f.plan.inputs[index];
    for (unsigned i = 0; i < 16; ++i) {
      put_le64(r, in.src.ring[i].global_index);
      append(r, in.src.ring[i].dest.bytes, 32);
      append(r, in.src.ring[i].commitment.bytes, 32);
    }
    append(r, in.secret, 32);
  }
  for (unsigned j = 0; j < 2; ++j) {
    put_le64(r, f.plan.init.tsx_data.outputs[j].amount);
    append(r, f.plan.to[j].view_secret, 32);
    append(r, f.plan.to[j].keys, 32);
  }
  append(r, f.plan.pid, 8); /* zero when the payment ID is Core's dummy */
  append(r, f.plan.pid_view_secret, 32);
  FILE* out = fopen(path, "ab");
  ASSERT_NE(nullptr, out);
  ASSERT_EQ(r.size(), fwrite(r.data(), 1, r.size(), out));
  fclose(out);
}

/* The transaction must be, byte for byte, one Monero Core verified. */
void expect_core_verified(const Flow& f, const Bytes& tx) {
  write_record(f, f.plan.name, tx, true);
  if (getenv("KK_XMR_TX_RECORDS")) return; /* generating: Core decides */
  const Bytes digest = keccak(tx);
  for (size_t i = 0; i < MONERO_TX_VECTOR_COUNT; ++i) {
    if (f.plan.name != monero_tx_vectors[i].name) continue;
    EXPECT_EQ(monero_tx_vectors[i].size, tx.size()) << f.plan.name;
    EXPECT_EQ(hex(monero_tx_vectors[i].keccak, 32), hex(digest.data(), 32))
        << f.plan.name << ": not the transaction Monero Core verified; "
        << "rerun unittests/firmware/monero_tx_vectors_gen.sh";
    return;
  }
  ADD_FAILURE() << "no Core-verified vector for " << f.plan.name;
}

/* An address the device shows must be one Monero Core parses back to the
 * same keys, kind and payment ID. Checked by Core when the vectors are
 * generated; a normal run requires that exact string. */
void expect_core_address(const std::string& name, uint32_t network,
                         const MoneroTxReviewOutput& shown,
                         const uint8_t keys[64], const uint8_t* payment_id) {
  const std::string address = shown.address;
  if (const char* path = getenv("KK_XMR_TX_RECORDS")) {
    Bytes r;
    r.push_back('A');
    r.push_back(1);
    r.push_back((uint8_t)name.size());
    append(r, (const uint8_t*)name.data(), name.size());
    r.push_back((uint8_t)network);
    r.push_back((uint8_t)address.size());
    append(r, (const uint8_t*)address.data(), address.size());
    append(r, keys, 64);
    r.push_back(shown.is_subaddress ? 1 : 0);
    r.push_back(shown.is_integrated ? 1 : 0);
    static const uint8_t none[8] = {0};
    append(r, shown.is_integrated ? payment_id : none, 8);
    FILE* out = fopen(path, "ab");
    ASSERT_NE(nullptr, out);
    ASSERT_EQ(r.size(), fwrite(r.data(), 1, r.size(), out));
    fclose(out);
    return;
  }
  for (size_t i = 0; i < MONERO_TX_ADDRESS_VECTOR_COUNT; ++i) {
    if (name != monero_tx_address_vectors[i].name) continue;
    EXPECT_EQ(std::string(monero_tx_address_vectors[i].address), address)
        << name;
    return;
  }
  ADD_FAILURE() << "no Core-verified address for " << name;
}

void replay_rng(const std::string& name) {
  uint8_t seed[32] = {0};
  memcpy(seed, name.data(), std::min<size_t>(name.size(), 32));
  xmr_test_rng_replay(seed);
}

Flow signed_flow(const Plan& plan) {
  replay_rng(plan.name);
  Flow f(plan);
  EXPECT_EQ(MONERO_TX_OK, f.run()) << plan.name;
  return f;
}

class MoneroTx : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    keepkey_user_activity();
    fsm_abort_signing_workflows();
    replay_rng("default");
  }
  void TearDown() override {
    fsm_abort_signing_workflows();
    xmr_test_rng_checked();
  }
};

/* A failure ends the session and leaves nothing behind. */
::testing::AssertionResult ended(MoneroTxResult expected, MoneroTxResult got) {
  if (got != expected)
    return ::testing::AssertionFailure()
           << "result " << got << " (" << monero_tx_result_text(got)
           << "), expected " << expected;
  if (monero_tx_active() || signing_session_owner() != SIGNING_SESSION_FREE)
    return ::testing::AssertionFailure() << "the session is still open";
  if (!signing_session_is_zero())
    return ::testing::AssertionFailure() << "the session was not wiped";
  return ::testing::AssertionSuccess();
}
#define EXPECT_ENDED(expected, call) EXPECT_TRUE(ended((expected), (call)))

}  // namespace

/* ------------------------------------------------ whole transactions */

TEST_F(MoneroTx, OneInputTwoOutputsVerifiesWithMoneroCore) {
  const Flow f = signed_flow(simple_plan());
  ASSERT_FALSE(::testing::Test::HasFailure());
  const Bytes tx = f.assemble();
  EXPECT_EQ(hex(keccak(f.prefix()).data(), 32),
            hex(f.all_out.tx_prefix_hash.bytes, 32));
  EXPECT_EQ(MONERO_TX_RCT_TYPE, f.all_out.rct_type);
  EXPECT_EQ(f.plan.init.tsx_data.fee, f.all_out.fee);
  /* extra: R, then the encrypted (dummy) payment ID. No additional keys. */
  ASSERT_EQ(44u, f.all_out.extra.size);
  EXPECT_EQ(0x01, f.all_out.extra.bytes[0]);
  EXPECT_EQ(0x02, f.all_out.extra.bytes[33]);
  EXPECT_EQ(0x09, f.all_out.extra.bytes[34]);
  EXPECT_EQ(0x01, f.all_out.extra.bytes[35]);
  EXPECT_EQ(642u, f.out_acks[1].bp_plus.size);
  EXPECT_FALSE(f.out_acks[0].has_bp_plus);
  EXPECT_EQ(0u, f.init_ack.rsig_mode);
  expect_core_verified(f, tx);
  /* The session is gone once the key is out. */
  EXPECT_FALSE(monero_tx_active());
  EXPECT_TRUE(signing_session_is_zero());

  /* Core must reject every tampered copy. */
  Bytes bad = tx;
  bad[bad.size() - 32 - 64 - 5] ^= 1; /* a CLSAG response scalar */
  write_record(f, "1in-tampered-clsag", bad, false);
  bad = tx;
  bad[f.prefix().size() + 1] ^= 1; /* the fee */
  write_record(f, "1in-tampered-fee", bad, false);
  bad = tx;
  bad[f.prefix().size() + 1 + 4 + 3] ^= 1; /* an encrypted amount */
  write_record(f, "1in-tampered-ecdh", bad, false);
  bad = tx;
  bad[f.prefix().size() - 44 - 1 - 35 + 5] ^= 1; /* an output key */
  write_record(f, "1in-tampered-output-key", bad, false);
  bad = tx;
  bad[bad.size() - 1] ^= 1; /* the pseudo-output */
  write_record(f, "1in-tampered-pseudo-out", bad, false);
}

TEST_F(MoneroTx, TwoInputsTwoOutputsVerifiesWithMoneroCore) {
  const Flow f = signed_flow(two_input_plan());
  ASSERT_FALSE(::testing::Test::HasFailure());
  const Bytes tx = f.assemble();
  EXPECT_EQ(hex(keccak(f.prefix()).data(), 32),
            hex(f.all_out.tx_prefix_hash.bytes, 32));
  /* Key images strictly decreasing, as Core orders inputs. */
  ASSERT_EQ(2u, f.order.size());
  EXPECT_GT(memcmp(f.key_image(f.order[0]), f.key_image(f.order[1]), 32), 0);
  /* Only the last-signed pseudo-output differs from the one first shown. */
  EXPECT_EQ(0, memcmp(f.sign_acks[0].pseudo_out.bytes,
                      f.in_acks[f.order[0]].pseudo_out.bytes, 32));
  EXPECT_NE(0, memcmp(f.sign_acks[1].pseudo_out.bytes,
                      f.in_acks[f.order[1]].pseudo_out.bytes, 32));
  expect_core_verified(f, tx);
  expect_core_address("subaddress-mainnet", 0, f.review.outputs[1],
                      f.plan.to[1].keys, nullptr);

  Bytes bad = tx;
  bad[bad.size() - 64 - 2 * 18 * 32 + 7] ^= 0x10; /* first CLSAG */
  write_record(f, "2in-tampered-first-clsag", bad, false);
  bad = tx;
  bad[bad.size() - 64 - 2 * 18 * 32 - 40] ^= 1; /* the range proof */
  write_record(f, "2in-tampered-range-proof", bad, false);
}

TEST_F(MoneroTx, IntegratedRecipientVerifiesWithMoneroCore) {
  Plan p = make_plan("1in-2out-integrated", 0, other_address(0, 0),
                     250000000000ull, 749950000000ull, 50000000ull, 1);
  add_input(p, owned_input(0, 0, 1000000000000ull, 9, 4));
  set_payment_id(p, 0, 0xa5);
  const Flow f = signed_flow(p);
  ASSERT_FALSE(::testing::Test::HasFailure());
  EXPECT_TRUE(f.review.has_payment_id);
  EXPECT_TRUE(f.review.outputs[0].is_integrated);
  /* The payment ID in the extra is encrypted, never the clear one. */
  EXPECT_NE(0, memcmp(f.all_out.extra.bytes + 36, p.pid, 8));
  expect_core_verified(f, f.assemble());
  expect_core_address("integrated-mainnet", 0, f.review.outputs[0],
                      p.to[0].keys, p.pid);
  expect_core_address("own-mainnet", 0, f.review.outputs[1], p.to[1].keys,
                      nullptr);

  /* The same recipient as testnet and stagenet would show it. */
  for (uint32_t network : {1u, 2u}) {
    Plan q = p;
    q.init.has_network_type = true;
    q.init.network_type = (MoneroNetworkType)network;
    MoneroTxReview review;
    ASSERT_EQ(MONERO_TX_OK,
              monero_tx_review(signer_wallet().key_seed, &q.init, &review));
    expect_core_address(network == 1 ? "integrated-testnet"
                                     : "integrated-stagenet",
                        network, review.outputs[0], p.to[0].keys, p.pid);
  }
}

TEST_F(MoneroTx, SubaddressAccountChangeVerifiesWithMoneroCore) {
  /* Account 1: the change address (1, 0) is itself a subaddress, and so are
   * the addresses that received the inputs. */
  Plan p = make_plan("3in-2out-account1", 1, other_address(0, 0),
                     42000000000ull, 2957940000000ull, 60000000ull, 0);
  add_input(p, owned_input(1, 0, 1000000000000ull, 3, 5));
  add_input(p, owned_input(1, 2, 1500000000000ull, 8, 6));
  add_input(p, owned_input(1, 7, 500000000000ull, 12, 7));
  const Flow f = signed_flow(p);
  ASSERT_FALSE(::testing::Test::HasFailure());
  EXPECT_TRUE(f.review.outputs[0].is_change);
  EXPECT_TRUE(f.review.outputs[0].is_subaddress);
  EXPECT_EQ(std::string(fixture("abandon-account0-sub1-0-output0").address),
            f.review.outputs[0].address);
  expect_core_verified(f, f.assemble());
  expect_core_address("own-account1-mainnet", 0, f.review.outputs[0],
                      f.plan.to[0].keys, nullptr);
}

TEST_F(MoneroTx, SendToOwnAddressWithLockVerifiesWithMoneroCore) {
  /* Both outputs pay the wallet's own address. Exactly one is change (the
   * one with the declared change amount); the other is shown as a recipient.
   * Core derives both with a*R and encrypts the dummy payment ID to the
   * wallet's own view key. */
  Plan p = make_plan("1in-2out-self-locked", 0, own_address(0), 111ull,
                     999999999889ull - 20000000ull, 20000000ull, 1);
  add_input(p, owned_input(0, 1, 999999999999ull + 1ull, 2, 8));
  p.init.tsx_data.has_unlock_time = true;
  p.init.tsx_data.unlock_time = 3500000;
  memcpy(p.pid_view_secret, signer_wallet().view_secret, 32);
  const Flow f = signed_flow(p);
  ASSERT_FALSE(::testing::Test::HasFailure());
  EXPECT_FALSE(f.review.outputs[0].is_change);
  EXPECT_TRUE(f.review.outputs[1].is_change);
  EXPECT_EQ(111ull + 20000000ull, f.review.total);
  EXPECT_EQ(3500000ull, f.review.unlock_time);
  expect_core_verified(f, f.assemble());
}

TEST_F(MoneroTx, EveryVectorWasVerifiedByMoneroCore) {
  /* The header is written only by monero_tx_vectors_gen.sh, and only after
   * Core agreed with every record. */
  EXPECT_EQ(5u, (unsigned)MONERO_TX_VECTOR_COUNT);
  EXPECT_STREQ("v0.18.5.4", MONERO_TX_VECTORS_CORE);
  EXPECT_EQ(7u, (unsigned)MONERO_TX_VECTORS_CORE_REJECTED);
  EXPECT_EQ(6u, (unsigned)MONERO_TX_ADDRESS_VECTOR_COUNT);
}

TEST_F(MoneroTx, FreshRandomnessGivesAFreshSession) {
  /* A different RNG draw gives a different master key: every MAC, the tx
   * key and so every output key change. */
  replay_rng("session-a");
  Flow a(simple_plan());
  ASSERT_EQ(MONERO_TX_OK, a.to_signing());
  fsm_abort_signing_workflows();
  replay_rng("session-b");
  Flow b(simple_plan());
  ASSERT_EQ(MONERO_TX_OK, b.to_signing());
  EXPECT_NE(0, memcmp(a.init_ack.dst_hmacs[0].bytes,
                      b.init_ack.dst_hmacs[0].bytes, 32));
  EXPECT_NE(0, memcmp(a.all_out.extra.bytes, b.all_out.extra.bytes, 44));
  EXPECT_NE(0, memcmp(a.out_acks[0].tx_out.bytes, b.out_acks[0].tx_out.bytes,
                      35));
  /* The key image is the output's, not the session's. */
  EXPECT_EQ(0, memcmp(a.key_image(0), b.key_image(0), 32));
}

/* ----------------------------------------------------------- review */

TEST_F(MoneroTx, ReviewShowsDeviceEncodedAddressesAndItsOwnClassification) {
  Plan p = simple_plan();
  MoneroTxReview review;
  ASSERT_EQ(MONERO_TX_OK,
            monero_tx_review(signer_wallet().key_seed, &p.init, &review));
  EXPECT_FALSE(review.outputs[0].is_change);
  EXPECT_TRUE(review.outputs[1].is_change);
  EXPECT_EQ(std::string(other_wallet().address), review.outputs[0].address);
  EXPECT_EQ(std::string(signer_wallet().address), review.outputs[1].address);
  EXPECT_EQ(1500000000000ull, review.outputs[0].amount);
  EXPECT_EQ(499969000000ull, review.outputs[1].amount);
  EXPECT_EQ(31000000ull, review.fee);
  EXPECT_EQ(1500000000000ull + 31000000ull, review.total);
  EXPECT_EQ(1u, review.num_inputs);
  /* Review opens no session. */
  EXPECT_FALSE(monero_tx_active());
  EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());

  /* Subaddress recipient: the device encodes the subaddress form. */
  p = two_input_plan();
  ASSERT_EQ(MONERO_TX_OK,
            monero_tx_review(signer_wallet().key_seed, &p.init, &review));
  EXPECT_TRUE(review.outputs[0].is_change);
  EXPECT_EQ(std::string(fixture("trezor-account0-sub0-1-output0").address),
            review.outputs[1].address);
  EXPECT_TRUE(review.outputs[1].is_subaddress);

  /* Networks use their own prefixes. */
  p = simple_plan();
  p.init.has_network_type = true;
  p.init.network_type = MoneroNetworkType_MONERO_NETWORK_STAGENET;
  ASSERT_EQ(MONERO_TX_OK,
            monero_tx_review(signer_wallet().key_seed, &p.init, &review));
  uint64_t tag = 0;
  uint8_t data[80];
  size_t size = sizeof(data);
  ASSERT_TRUE(monero_tx_probe_decode_address(review.outputs[0].address, &tag,
                                             data, &size));
  EXPECT_EQ(24u, tag);
  EXPECT_EQ(64u, size);
  EXPECT_EQ(0, memcmp(data, p.to[0].keys, 64));
}

TEST_F(MoneroTx, IntegratedAddressIsEncodedWithItsPaymentId) {
  Plan p = simple_plan();
  set_payment_id(p, 0, 0x77);
  MoneroTxReview review;
  ASSERT_EQ(MONERO_TX_OK,
            monero_tx_review(signer_wallet().key_seed, &p.init, &review));
  EXPECT_EQ(106u, strlen(review.outputs[0].address));
  uint64_t tag = 0;
  uint8_t data[80];
  size_t size = sizeof(data);
  ASSERT_TRUE(monero_tx_probe_decode_address(review.outputs[0].address, &tag,
                                             data, &size));
  EXPECT_EQ(19u, tag);
  ASSERT_EQ(72u, size);
  EXPECT_EQ(0, memcmp(data, p.to[0].keys, 64));
  EXPECT_EQ(0, memcmp(data + 64, p.pid, 8));
  EXPECT_EQ(0, memcmp(review.payment_id, p.pid, 8));
}

TEST_F(MoneroTx, ZeroAmountIntegratedDestinationIsRejectedBeforeReview) {
  const uint8_t* key = signer_wallet().key_seed;
  for (unsigned recipient = 0; recipient < 2; ++recipient) {
    Plan p = make_plan("zero-integrated", 0, other_address(0, 0), 0,
                       999969000000ull, 31000000ull, 1 - recipient);
    add_input(p, owned_input(0, 0, 1000000000000ull, 5, 1));
    set_payment_id(p, recipient, 0x11);
    MoneroTxReview review, zero_review = {};
    MoneroTxInitAck ack, zero_ack = {};
    memset(&review, 0xa5, sizeof(review));
    memset(&ack, 0xa5, sizeof(ack));
    replay_rng(p.name);
    EXPECT_EQ(MONERO_TX_ERR_REQUEST, monero_tx_review(key, &p.init, &review));
    EXPECT_EQ(0, memcmp(&review, &zero_review, sizeof(review)));
    EXPECT_ENDED(MONERO_TX_ERR_REQUEST,
                 monero_tx_begin(key, &p.init, review.digest, &ack));
    EXPECT_EQ(0, memcmp(&ack, &zero_ack, sizeof(ack)));
    EXPECT_EQ(0u, xmr_test_rng_draws());
  }
}

TEST_F(MoneroTx, ChangeIsWhatTheDeviceDerivesNeverWhatTheHostDeclares) {
  const uint8_t* key = signer_wallet().key_seed;
  MoneroTxReview review;

  /* The host declares the recipient's address as "change". */
  Plan p = simple_plan();
  memcpy(p.init.tsx_data.change_dts.spend_public_key.bytes, p.to[0].keys, 32);
  memcpy(p.init.tsx_data.change_dts.view_public_key.bytes, p.to[0].keys + 32,
         32);
  p.init.tsx_data.change_dts.amount = p.init.tsx_data.outputs[0].amount;
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));

  /* No change declared at all. */
  p = simple_plan();
  p.init.tsx_data.has_change_dts = false;
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));

  /* Change declared for another account or a minor index. */
  p = simple_plan();
  p.init.tsx_data.change_dts.major = 1;
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));
  p = simple_plan();
  p.init.tsx_data.change_dts.minor = 1;
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));

  /* The declared change amount matches no output to the own address. */
  p = simple_plan();
  p.init.tsx_data.change_dts.amount += 1;
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));

  /* No output pays the wallet: nothing can be change. */
  p = simple_plan();
  p.init.tsx_data.outputs[1] =
      destination(other_address(0, 1), p.init.tsx_data.outputs[1].amount);
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));

  /* Account 1's change address is not account 0's. */
  p = simple_plan();
  p.init.tsx_data.account = 1;
  p.init.tsx_data.change_dts.major = 1;
  EXPECT_EQ(MONERO_TX_ERR_CHANGE, monero_tx_review(key, &p.init, &review));

  /* The own address flagged as the wrong kind is a lie about it. */
  p = simple_plan();
  p.init.tsx_data.outputs[1].is_subaddress = true;
  EXPECT_EQ(MONERO_TX_ERR_REQUEST, monero_tx_review(key, &p.init, &review));
  EXPECT_FALSE(monero_tx_active());
}

/* ------------------------------------------------- refusals at init */

TEST_F(MoneroTx, InitRefusesWhatSevenSeventeenDoesNotSign) {
  const uint8_t* key = signer_wallet().key_seed;
  MoneroTxReview review;
  MoneroTxInitAck ack;
  uint8_t digest[32] = {0};
  struct Case {
    MoneroTxResult expected;
    std::function<void(MoneroTxInitRequest&)> change;
  };
  const Recipient third = other_address(0, 2);
  const std::vector<Case> cases = {
      {MONERO_TX_ERR_OUTPUT_COUNT,
       [](MoneroTxInitRequest& m) { m.tsx_data.outputs_count = 1; }},
      {MONERO_TX_ERR_OUTPUT_COUNT,
       [&](MoneroTxInitRequest& m) {
         m.tsx_data.outputs_count = 3;
         m.tsx_data.outputs[2] = destination(third, 1);
       }},
      {MONERO_TX_ERR_OUTPUT_COUNT,
       [&](MoneroTxInitRequest& m) {
         m.tsx_data.outputs_count = 16;
         for (int j = 2; j < 16; ++j)
           m.tsx_data.outputs[j] = destination(third, 1);
       }},
      {MONERO_TX_ERR_OUTPUT_COUNT,
       [](MoneroTxInitRequest& m) { m.tsx_data.outputs_count = 0; }},
      {MONERO_TX_ERR_RING_SIZE,
       [](MoneroTxInitRequest& m) { m.tsx_data.ring_size = 11; }},
      {MONERO_TX_ERR_RING_SIZE,
       [](MoneroTxInitRequest& m) { m.tsx_data.ring_size = 15; }},
      {MONERO_TX_ERR_RING_SIZE,
       [](MoneroTxInitRequest& m) { m.tsx_data.ring_size = 17; }},
      {MONERO_TX_ERR_RING_SIZE,
       [](MoneroTxInitRequest& m) { m.tsx_data.has_ring_size = false; }},
      {MONERO_TX_ERR_HARD_FORK,
       [](MoneroTxInitRequest& m) { m.tsx_data.hard_fork = 15; }},
      {MONERO_TX_ERR_HARD_FORK,
       [](MoneroTxInitRequest& m) { m.tsx_data.has_hard_fork = false; }},
      {MONERO_TX_ERR_RCT_TYPE,
       [](MoneroTxInitRequest& m) { m.tsx_data.bp_version = 3; }},
      {MONERO_TX_ERR_RCT_TYPE,
       [](MoneroTxInitRequest& m) { m.tsx_data.has_bp_version = false; }},
      {MONERO_TX_ERR_INPUT_COUNT,
       [](MoneroTxInitRequest& m) { m.tsx_data.num_inputs = 0; }},
      {MONERO_TX_ERR_INPUT_COUNT,
       [](MoneroTxInitRequest& m) { m.tsx_data.num_inputs = 65; }},
      {MONERO_TX_ERR_INTEGRATED,
       [](MoneroTxInitRequest& m) {
         m.tsx_data.has_payment_id = true;
         m.tsx_data.payment_id.size = 8;
         m.tsx_data.outputs[0].is_integrated = true;
         m.tsx_data.outputs[1].is_integrated = true;
       }},
      {MONERO_TX_ERR_PAYMENT_ID,
       [](MoneroTxInitRequest& m) {
         m.tsx_data.has_payment_id = true;
         m.tsx_data.payment_id.size = 7;
         m.tsx_data.outputs[0].is_integrated = true;
       }},
      {MONERO_TX_ERR_PAYMENT_ID,
       [](MoneroTxInitRequest& m) {
         m.tsx_data.has_payment_id = true;
         m.tsx_data.payment_id.size = 0;
         m.tsx_data.outputs[0].is_integrated = true;
       }},
      {MONERO_TX_ERR_PAYMENT_ID, /* a payment ID nobody receives */
       [](MoneroTxInitRequest& m) {
         m.tsx_data.has_payment_id = true;
         m.tsx_data.payment_id.size = 8;
       }},
      {MONERO_TX_ERR_PAYMENT_ID, /* integrated without its payment ID */
       [](MoneroTxInitRequest& m) {
         m.tsx_data.outputs[0].is_integrated = true;
       }},
      {MONERO_TX_ERR_REQUEST, /* there is no integrated subaddress */
       [](MoneroTxInitRequest& m) {
         m.tsx_data.has_payment_id = true;
         m.tsx_data.payment_id.size = 8;
         m.tsx_data.outputs[0].is_integrated = true;
         m.tsx_data.outputs[0].is_subaddress = true;
       }},
      {MONERO_TX_ERR_AMOUNT,
       [](MoneroTxInitRequest& m) {
         m.tsx_data.outputs[0].amount = UINT64_MAX - 5;
       }},
      {MONERO_TX_ERR_AMOUNT,
       [](MoneroTxInitRequest& m) { m.tsx_data.fee = UINT64_MAX; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) { m.tsx_data.has_fee = false; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) { m.has_tsx_data = false; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) { m.address_n[1] = 0x80000000 | 133; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) { m.address_n_count = 5; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) {
         m.has_network_type = true;
         m.network_type = (MoneroNetworkType)3;
       }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) {
         m.tsx_data.outputs[0].spend_public_key.size = 31;
       }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInitRequest& m) {
         m.tsx_data.outputs[0].has_amount = false;
       }},
  };
  for (size_t i = 0; i < cases.size(); ++i) {
    Plan p = simple_plan();
    cases[i].change(p.init);
    EXPECT_EQ(cases[i].expected, monero_tx_review(key, &p.init, &review))
        << "case " << i;
    /* begin validates for itself: an approval digest does not bypass it. */
    EXPECT_ENDED(cases[i].expected,
                 monero_tx_begin(key, &p.init, digest, &ack));
  }
}

TEST_F(MoneroTx, InitRefusesKeysThatAreNotCleanPoints) {
  const uint8_t* key = signer_wallet().key_seed;
  uint8_t small_order[32], torsioned[32], noncanonical[32];
  const uint8_t identity[32] = {1};
  monero_tx_probe_bad_points(small_order, torsioned, noncanonical);
  const uint8_t* bad[] = {small_order, torsioned, noncanonical, identity};
  for (const uint8_t* point : bad) {
    for (int which = 0; which < 2; ++which) {
      Plan p = simple_plan();
      MoneroTxDestination& d = p.init.tsx_data.outputs[0];
      memcpy(which ? d.view_public_key.bytes : d.spend_public_key.bytes,
             point, 32);
      MoneroTxReview review;
      EXPECT_EQ(MONERO_TX_ERR_POINT, monero_tx_review(key, &p.init, &review));
      EXPECT_FALSE(monero_tx_active());
    }
  }
}

TEST_F(MoneroTx, BeginOpensOnlyThePlanThatWasReviewed) {
  const uint8_t* key = signer_wallet().key_seed;
  Plan p = simple_plan();
  MoneroTxReview review;
  MoneroTxInitAck ack;
  ASSERT_EQ(MONERO_TX_OK, monero_tx_review(key, &p.init, &review));
  /* Anything reviewed differs: amount, fee, recipient, lock, inputs. */
  const std::vector<std::function<void(MoneroTxInitRequest&)>> changes = {
      [](MoneroTxInitRequest& m) {
        m.tsx_data.outputs[0].amount += 1;
        m.tsx_data.fee -= 1;
      },
      [](MoneroTxInitRequest& m) {
        m.tsx_data.outputs[0] = destination(other_address(0, 5),
                                            m.tsx_data.outputs[0].amount);
      },
      [](MoneroTxInitRequest& m) {
        m.tsx_data.has_unlock_time = true;
        m.tsx_data.unlock_time = 9;
      },
      [](MoneroTxInitRequest& m) { m.tsx_data.num_inputs = 2; },
      [](MoneroTxInitRequest& m) { m.tsx_data.hard_fork = 17; },
      [](MoneroTxInitRequest& m) {
        m.has_network_type = true;
        m.network_type = MoneroNetworkType_MONERO_NETWORK_TESTNET;
      },
  };
  for (size_t i = 0; i < changes.size(); ++i) {
    Plan changed = simple_plan();
    changes[i](changed.init);
    EXPECT_ENDED(MONERO_TX_ERR_APPROVAL,
                 monero_tx_begin(key, &changed.init, review.digest, &ack))
        << "change " << i;
  }
  /* Another wallet cannot use this approval either. */
  EXPECT_NE(MONERO_TX_OK, monero_tx_begin(other_wallet().key_seed, &p.init,
                                          review.digest, &ack));
  EXPECT_FALSE(monero_tx_active());
  EXPECT_EQ(MONERO_TX_OK, monero_tx_begin(key, &p.init, review.digest, &ack));
  EXPECT_TRUE(monero_tx_active());
}

/* ------------------------------------------------------------ inputs */

TEST_F(MoneroTx, SetInputRefusesBadRingsAndForeignOutputs) {
  struct Case {
    MoneroTxResult expected;
    std::function<void(MoneroTxSourceEntry&)> change;
  };
  uint8_t small_order[32], torsioned[32], noncanonical[32];
  monero_tx_probe_bad_points(small_order, torsioned, noncanonical);
  const Input foreign = owned_input(1, 0, 2000000000000ull, 5, 1);
  const std::vector<Case> cases = {
      {MONERO_TX_ERR_RING, [](MoneroTxSourceEntry& s) { s.ring_count = 15; }},
      {MONERO_TX_ERR_RING, [](MoneroTxSourceEntry& s) { s.ring_count = 11; }},
      {MONERO_TX_ERR_RING, /* unsorted */
       [](MoneroTxSourceEntry& s) {
         std::swap(s.ring[2].global_index, s.ring[3].global_index);
       }},
      {MONERO_TX_ERR_RING, /* duplicate member */
       [](MoneroTxSourceEntry& s) {
         s.ring[8].global_index = s.ring[7].global_index;
       }},
      {MONERO_TX_ERR_RING,
       [](MoneroTxSourceEntry& s) { s.real_index = 16; }},
      {MONERO_TX_ERR_RING,
       [](MoneroTxSourceEntry& s) { s.ring[4].dest.size = 31; }},
      {MONERO_TX_ERR_RING,
       [](MoneroTxSourceEntry& s) { s.ring[4].has_commitment = false; }},
      {MONERO_TX_ERR_SCALAR, /* mask >= l */
       [](MoneroTxSourceEntry& s) { memset(s.mask.bytes, 0xff, 32); }},
      {MONERO_TX_ERR_SCALAR, /* mask == l */
       [](MoneroTxSourceEntry& s) {
         static const uint8_t l[32] = {
             0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
             0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
             0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
         memcpy(s.mask.bytes, l, 32);
       }},
      {MONERO_TX_ERR_POINT,
       [&](MoneroTxSourceEntry& s) {
         memcpy(s.real_out_tx_key.bytes, small_order, 32);
       }},
      {MONERO_TX_ERR_POINT,
       [&](MoneroTxSourceEntry& s) {
         memcpy(s.real_out_tx_key.bytes, torsioned, 32);
       }},
      {MONERO_TX_ERR_POINT,
       [&](MoneroTxSourceEntry& s) {
         memcpy(s.real_out_tx_key.bytes, noncanonical, 32);
       }},
      {MONERO_TX_ERR_POINT, /* a clean R, but a torsioned additional key */
       [&](MoneroTxSourceEntry& s) {
         s.has_real_out_additional_key = true;
         s.real_out_additional_key.size = 32;
         memcpy(s.real_out_additional_key.bytes, torsioned, 32);
       }},
      {MONERO_TX_ERR_POINT, /* decoy key that is no canonical point */
       [&](MoneroTxSourceEntry& s) {
         memcpy(s.ring[9].dest.bytes, noncanonical, 32);
       }},
      {MONERO_TX_ERR_POINT,
       [&](MoneroTxSourceEntry& s) {
         memcpy(s.ring[10].commitment.bytes, noncanonical, 32);
       }},
      {MONERO_TX_ERR_NOT_OWNED, /* another account's output */
       [&](MoneroTxSourceEntry& s) {
         s = foreign.src;
         s.sub_major = 0;
       }},
      {MONERO_TX_ERR_NOT_OWNED, /* a decoy claimed as the real one */
       [](MoneroTxSourceEntry& s) { s.real_index = 6; }},
      {MONERO_TX_ERR_NOT_OWNED,
       [](MoneroTxSourceEntry& s) { s.real_output_in_tx_index += 1; }},
      {MONERO_TX_ERR_NOT_OWNED,
       [](MoneroTxSourceEntry& s) { s.sub_minor = 4; }},
      {MONERO_TX_ERR_REQUEST, /* an input of another account */
       [](MoneroTxSourceEntry& s) { s.sub_major = 1; }},
      {MONERO_TX_ERR_COMMITMENT, /* claims more than the output holds */
       [](MoneroTxSourceEntry& s) { s.amount += 1; }},
      {MONERO_TX_ERR_COMMITMENT,
       [](MoneroTxSourceEntry& s) { s.mask.bytes[0] ^= 1; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxSourceEntry& s) { s.has_amount = false; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxSourceEntry& s) { s.real_out_tx_key.size = 0; }},
  };
  for (size_t i = 0; i < cases.size(); ++i) {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    MoneroTxSetInputRequest req = {};
    req.has_src = true;
    req.src = f.plan.inputs[0].src;
    cases[i].change(req.src);
    MoneroTxSetInputAck ack;
    EXPECT_ENDED(cases[i].expected, monero_tx_set_input(&req, &ack))
        << "case " << i;
    static const MoneroTxSetInputAck empty = {};
    EXPECT_EQ(0, memcmp(&ack, &empty, sizeof(ack))) << "case " << i;
  }
}

TEST_F(MoneroTx, ViniMustComeBackUnchangedOnceAndInKeyImageOrder) {
  /* Tampering with each MAC'd field. */
  struct Case {
    MoneroTxResult expected;
    std::function<void(MoneroTxInputViniRequest&)> change;
  };
  const std::vector<Case> cases = {
      {MONERO_TX_ERR_MAC, /* the key image */
       [](MoneroTxInputViniRequest& r) { r.vini.bytes[r.vini.size - 1] ^= 1; }},
      {MONERO_TX_ERR_MAC, /* a ring offset */
       [](MoneroTxInputViniRequest& r) { r.vini.bytes[5] ^= 1; }},
      {MONERO_TX_ERR_MAC, /* the amount byte */
       [](MoneroTxInputViniRequest& r) { r.vini.bytes[1] = 1; }},
      {MONERO_TX_ERR_MAC,
       [](MoneroTxInputViniRequest& r) { r.vini_hmac.bytes[31] ^= 0x80; }},
      {MONERO_TX_ERR_MAC, /* truncated */
       [](MoneroTxInputViniRequest& r) { r.vini.size -= 1; }},
      {MONERO_TX_ERR_MAC, /* another slot's index */
       [](MoneroTxInputViniRequest& r) { r.orig_idx ^= 1; }},
      {MONERO_TX_ERR_ORDER,
       [](MoneroTxInputViniRequest& r) { r.orig_idx = 2; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInputViniRequest& r) { r.vini_hmac.size = 16; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxInputViniRequest& r) { r.has_orig_idx = false; }},
  };
  for (size_t i = 0; i < cases.size(); ++i) {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    MoneroTxInputViniRequest req = f.vini_request(f.order[0]);
    cases[i].change(req);
    EXPECT_ENDED(cases[i].expected, monero_tx_input_vini(&req))
        << "case " << i;
  }

  /* Ascending key images. */
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    MoneroTxInputViniRequest req = f.vini_request(f.order[1]);
    ASSERT_EQ(MONERO_TX_OK, monero_tx_input_vini(&req));
    req = f.vini_request(f.order[0]);
    EXPECT_ENDED(MONERO_TX_ERR_ORDER, monero_tx_input_vini(&req));
  }
  /* The same input twice. */
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    MoneroTxInputViniRequest req = f.vini_request(f.order[0]);
    ASSERT_EQ(MONERO_TX_OK, monero_tx_input_vini(&req));
    EXPECT_ENDED(MONERO_TX_ERR_ORDER, monero_tx_input_vini(&req));
  }
  /* An input left out. */
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    MoneroTxInputViniRequest req = f.vini_request(f.order[0]);
    ASSERT_EQ(MONERO_TX_OK, monero_tx_input_vini(&req));
    EXPECT_ENDED(MONERO_TX_ERR_STEP, monero_tx_all_inputs_set());
  }
  /* The same output spent twice in one plan has one key image. */
  {
    Plan p = two_input_plan();
    p.inputs[1] = p.inputs[0];
    Flow f(p);
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    MoneroTxInputViniRequest req = f.vini_request(0);
    ASSERT_EQ(MONERO_TX_OK, monero_tx_input_vini(&req));
    req = f.vini_request(1);
    EXPECT_ENDED(MONERO_TX_ERR_ORDER, monero_tx_input_vini(&req));
  }
}

/* ----------------------------------------------------------- outputs */

TEST_F(MoneroTx, OutputsMustBeTheReviewedOnesInTheirSlots) {
  struct Case {
    std::function<void(MoneroTxSetOutputRequest&)> change;
  };
  const Recipient thief = other_address(3, 3);
  const std::vector<Case> cases = {
      {[](MoneroTxSetOutputRequest& r) { r.dst.amount += 1; }},
      {[](MoneroTxSetOutputRequest& r) { r.dst.amount = 0; }},
      {[&](MoneroTxSetOutputRequest& r) {
        memcpy(r.dst.spend_public_key.bytes, thief.keys, 32);
      }},
      {[&](MoneroTxSetOutputRequest& r) {
        memcpy(r.dst.view_public_key.bytes, thief.keys + 32, 32);
      }},
      {[](MoneroTxSetOutputRequest& r) { r.dst.is_subaddress = true; }},
      {[](MoneroTxSetOutputRequest& r) { r.dst.is_integrated = true; }},
      {[](MoneroTxSetOutputRequest& r) { r.dst_hmac.bytes[0] ^= 1; }},
      {[](MoneroTxSetOutputRequest& r) { memset(r.dst_hmac.bytes, 0, 32); }},
  };
  for (unsigned slot = 0; slot < 2; ++slot) {
    for (size_t i = 0; i < cases.size(); ++i) {
      Flow f(simple_plan());
      ASSERT_EQ(MONERO_TX_OK, f.begin());
      ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
      ASSERT_EQ(MONERO_TX_OK, f.vinis());
      if (slot) ASSERT_EQ(MONERO_TX_OK, f.output(0));
      MoneroTxSetOutputRequest req = f.output_request(slot);
      cases[i].change(req);
      MoneroTxSetOutputAck ack;
      EXPECT_ENDED(MONERO_TX_ERR_MAC,
                   monero_tx_set_output(&req, &ack, scratch, sizeof(scratch),
                                        nullptr, nullptr))
          << "slot " << slot << " case " << i;
      EXPECT_FALSE(ack.has_tx_out);
    }
  }
  /* A reviewed output in the other slot. */
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    ASSERT_EQ(MONERO_TX_OK, f.vinis());
    const MoneroTxSetOutputRequest req = f.output_request(1);
    MoneroTxSetOutputAck ack;
    EXPECT_ENDED(MONERO_TX_ERR_MAC,
                 monero_tx_set_output(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr));
  }
  /* An input's MAC offered as an output's: the purpose is inside the MAC. */
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    ASSERT_EQ(MONERO_TX_OK, f.vinis());
    MoneroTxSetOutputRequest req = f.output_request(0);
    memcpy(req.dst_hmac.bytes, f.in_acks[0].vini_hmac.bytes, 32);
    MoneroTxSetOutputAck ack;
    EXPECT_ENDED(MONERO_TX_ERR_MAC,
                 monero_tx_set_output(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr));
  }
}

TEST_F(MoneroTx, FeeMustBeExactlyInputsMinusOutputs) {
  for (int delta : {-1, 1}) {
    Plan p = simple_plan();
    p.inputs[0] = owned_input(0, 0, 2000000000000ull + delta, 5, 1);
    Flow f(p);
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    ASSERT_EQ(MONERO_TX_OK, f.vinis());
    /* Refused before any signature exists. */
    EXPECT_ENDED(MONERO_TX_ERR_BALANCE, f.outputs());
    EXPECT_FALSE(f.all_out.has_full_message_hash);
  }
}

TEST_F(MoneroTx, InputAmountsMustNotOverflow) {
  Plan p = two_input_plan();
  p.inputs[0] = owned_input(0, 3, UINT64_MAX - 3, 0, 2);
  p.inputs[1] = owned_input(0, 0, 4, 15, 3);
  Flow f(p);
  ASSERT_EQ(MONERO_TX_OK, f.begin());
  EXPECT_ENDED(MONERO_TX_ERR_AMOUNT, f.set_inputs());
}

/* ----------------------------------------------------------- signing */

TEST_F(MoneroTx, SignInputAcceptsOnlyTheStateItIssued) {
  struct Case {
    MoneroTxResult expected;
    std::function<void(MoneroTxSignInputRequest&)> change;
  };
  const std::vector<Case> cases = {
      {MONERO_TX_ERR_MAC,
       [](MoneroTxSignInputRequest& r) { r.vini.bytes[r.vini.size - 2] ^= 4; }},
      {MONERO_TX_ERR_MAC,
       [](MoneroTxSignInputRequest& r) { r.vini_hmac.bytes[3] ^= 1; }},
      {MONERO_TX_ERR_MAC,
       [](MoneroTxSignInputRequest& r) { r.pseudo_out.bytes[0] ^= 1; }},
      {MONERO_TX_ERR_MAC,
       [](MoneroTxSignInputRequest& r) { r.pseudo_out_hmac.bytes[9] ^= 1; }},
      {MONERO_TX_ERR_MAC, /* the vini MAC in the commitment's place */
       [](MoneroTxSignInputRequest& r) {
         memcpy(r.pseudo_out_hmac.bytes, r.vini_hmac.bytes, 32);
       }},
      {MONERO_TX_ERR_ORDER, /* the other input's slot */
       [](MoneroTxSignInputRequest& r) { r.orig_idx ^= 1; }},
      {MONERO_TX_ERR_MAC, /* a different ring than the one in the prefix */
       [](MoneroTxSignInputRequest& r) { r.src.ring[15].global_index += 1; }},
      {MONERO_TX_ERR_COMMITMENT, /* a different amount */
       [](MoneroTxSignInputRequest& r) { r.src.amount -= 1; }},
      {MONERO_TX_ERR_NOT_OWNED,
       [](MoneroTxSignInputRequest& r) {
         r.src.real_index = (r.src.real_index + 1) % 16;
       }},
      {MONERO_TX_ERR_RING,
       [](MoneroTxSignInputRequest& r) { r.src.ring_count = 15; }},
      {MONERO_TX_ERR_REQUEST,
       [](MoneroTxSignInputRequest& r) { r.pseudo_out.size = 31; }},
  };
  replay_rng("sign-negative");
  for (size_t i = 0; i < cases.size(); ++i) {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    MoneroTxSignInputRequest req = f.sign_request(f.order[0]);
    cases[i].change(req);
    MoneroTxSignInputAck ack;
    EXPECT_ENDED(cases[i].expected,
                 monero_tx_sign_input(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr))
        << "case " << i;
    EXPECT_FALSE(ack.has_clsag_enc);
  }

  /* A decoy swapped after the vini: the ring signature is over the ring the
   * host supplies, so this only yields a transaction the network rejects;
   * a swapped real commitment is refused outright. */
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    MoneroTxSignInputRequest req = f.sign_request(f.order[0]);
    monero_tx_probe_point(req.src.ring[req.src.real_index].commitment.bytes,
                          "swap", 1);
    MoneroTxSignInputAck ack;
    EXPECT_ENDED(MONERO_TX_ERR_COMMITMENT,
                 monero_tx_sign_input(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr));
  }
  /* Out of order: the second input first. */
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    EXPECT_ENDED(MONERO_TX_ERR_ORDER, f.sign(f.order[1]));
  }
  /* The same input twice: one CLSAG per input per session. */
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    ASSERT_EQ(MONERO_TX_OK, f.sign(f.order[0]));
    EXPECT_ENDED(MONERO_TX_ERR_ORDER, f.sign(f.order[0]));
  }
}

TEST_F(MoneroTx, OpeningKeyIsReleasedOnlyAfterEveryInputIsSigned) {
  Flow f(two_input_plan());
  ASSERT_EQ(MONERO_TX_OK, f.to_signing());
  ASSERT_EQ(MONERO_TX_OK, f.sign(f.order[0]));
  MoneroTxFinalAck ack;
  EXPECT_ENDED(MONERO_TX_ERR_STEP, monero_tx_final(&ack));
  EXPECT_FALSE(ack.has_opening_key);
  /* Without the key the sealed CLSAG is opaque: it authenticates under no
   * key the host has. */
  uint8_t plain[18 * 32], zero_key[32] = {0};
  EXPECT_FALSE(monero_tx_probe_open(zero_key, 0, f.sign_acks[0].clsag_enc.bytes,
                                    f.sign_acks[0].clsag_enc.size, plain));
}

/* ------------------------------------------------- order and replay */

TEST_F(MoneroTx, EveryStepIsRefusedOutsideItsExactPlace) {
  enum Stage { BEGUN, INPUTS, VINIS, FIRST_OUT, OUTS, ALL_OUT, SIGNED };
  enum Call { SET_INPUT, VINI, ALL_IN, SET_OUTPUT, ALL_OUT_SET, SIGN, FINAL };
  const auto advance = [](Flow& f, Stage stage) {
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    if (stage == BEGUN) return;
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    if (stage == INPUTS) return;
    ASSERT_EQ(MONERO_TX_OK, f.vinis());
    if (stage == VINIS) return;
    ASSERT_EQ(MONERO_TX_OK, f.output(0));
    if (stage == FIRST_OUT) return;
    ASSERT_EQ(MONERO_TX_OK, f.output(1));
    if (stage == OUTS) return;
    ASSERT_EQ(MONERO_TX_OK, monero_tx_all_out_set(&f.all_out));
    if (stage == ALL_OUT) return;
    ASSERT_EQ(MONERO_TX_OK, f.signs());
  };
  const auto call = [](Flow& f, Call c) -> MoneroTxResult {
    switch (c) {
      case SET_INPUT: {
        MoneroTxSetInputRequest req = {};
        req.has_src = true;
        req.src = f.plan.inputs[0].src;
        MoneroTxSetInputAck ack;
        return monero_tx_set_input(&req, &ack);
      }
      case VINI: {
        if (f.in_acks.empty()) {
          MoneroTxInputViniRequest req = {};
          return monero_tx_input_vini(&req);
        }
        const MoneroTxInputViniRequest req = f.vini_request(0);
        return monero_tx_input_vini(&req);
      }
      case ALL_IN:
        return monero_tx_all_inputs_set();
      case SET_OUTPUT:
        return f.output(0);
      case ALL_OUT_SET:
        return monero_tx_all_out_set(&f.all_out);
      case SIGN:
        if (f.in_acks.empty()) {
          MoneroTxSignInputRequest req = {};
          MoneroTxSignInputAck ack;
          return monero_tx_sign_input(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr);
        }
        return f.sign(0);
      default: {
        MoneroTxFinalAck ack;
        return monero_tx_final(&ack);
      }
    }
  };
  /* The one call each stage accepts; every other one ends the session. */
  const Call accepted[] = {SET_INPUT, VINI, SET_OUTPUT, SET_OUTPUT,
                           ALL_OUT_SET, SIGN, FINAL};
  replay_rng("step-order");
  for (int stage = BEGUN; stage <= SIGNED; ++stage) {
    for (int c = SET_INPUT; c <= FINAL; ++c) {
      if (c == accepted[stage]) continue;
      Flow f(simple_plan());
      advance(f, (Stage)stage);
      if (::testing::Test::HasFatalFailure()) return;
      EXPECT_ENDED(MONERO_TX_ERR_STEP, call(f, (Call)c))
          << "stage " << stage << " call " << c;
    }
  }
  /* With no session at all every continuation is refused. */
  for (int c = SET_INPUT; c <= FINAL; ++c) {
    Flow f(simple_plan());
    EXPECT_ENDED(MONERO_TX_ERR_STEP, call(f, (Call)c)) << "call " << c;
  }
}

TEST_F(MoneroTx, StateFromAnotherSessionNeverVerifies) {
  replay_rng("old-session");
  Flow old(two_input_plan());
  ASSERT_EQ(MONERO_TX_OK, old.to_signing());
  fsm_abort_signing_workflows();

  /* The same plan again: a new master key, so nothing old verifies. */
  replay_rng("new-session");
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    const MoneroTxInputViniRequest req = old.vini_request(old.order[0]);
    EXPECT_ENDED(MONERO_TX_ERR_MAC, monero_tx_input_vini(&req));
  }
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    ASSERT_EQ(MONERO_TX_OK, f.vinis());
    const MoneroTxSetOutputRequest req = old.output_request(0);
    MoneroTxSetOutputAck ack;
    EXPECT_ENDED(MONERO_TX_ERR_MAC,
                 monero_tx_set_output(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr));
  }
  {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    const MoneroTxSignInputRequest req = old.sign_request(f.order[0]);
    MoneroTxSignInputAck ack;
    EXPECT_ENDED(MONERO_TX_ERR_MAC,
                 monero_tx_sign_input(&req, &ack, scratch, sizeof(scratch),
                                      nullptr, nullptr));
  }
  /* A second begin wipes the first session's state before it starts. */
  {
    Flow a(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, a.begin());
    ASSERT_EQ(MONERO_TX_OK, a.set_inputs());
    Flow b(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, b.begin());
    const MoneroTxInputViniRequest req = a.vini_request(0);
    EXPECT_ENDED(MONERO_TX_ERR_STEP, monero_tx_input_vini(&req));
  }
}

/* ------------------------------------------------- RNG and aborting */

TEST_F(MoneroTx, FailedRandomnessProducesNothing) {
  /* At begin. */
  {
    Flow f(simple_plan());
    xmr_test_rng_fail();
    EXPECT_ENDED(MONERO_TX_ERR_PROOF, f.begin());
    EXPECT_EQ(0u, f.init_ack.dst_hmacs_count);
  }
  /* At the range proof. */
  {
    replay_rng("rng-bpp");
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    ASSERT_EQ(MONERO_TX_OK, f.vinis());
    ASSERT_EQ(MONERO_TX_OK, f.output(0));
    xmr_test_rng_fail();
    EXPECT_ENDED(MONERO_TX_ERR_PROOF, f.output(1));
    EXPECT_FALSE(f.out_acks[1].has_bp_plus);
    EXPECT_FALSE(f.out_acks[1].has_tx_out);
  }
  /* At a CLSAG. */
  {
    replay_rng("rng-clsag");
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    xmr_test_rng_fail();
    EXPECT_ENDED(MONERO_TX_ERR_PROOF, f.sign(0));
    EXPECT_TRUE(f.sign_acks.empty());
  }
}

struct Interrupt {
  uint32_t after;
  uint32_t calls;
  bool end_session; /* what a stray message does through the dispatch gate */
};

bool interrupt_step(void* ctx, uint32_t, uint32_t) {
  Interrupt* in = (Interrupt*)ctx;
  if (++in->calls <= in->after) return true;
  /* A stray frame may overwrite the arena freely once the proof is told to
   * stop. The marker must still be there afterwards: nothing wrote to the
   * scratch again. */
  memset(scratch, 0xa7, sizeof(scratch));
  if (in->end_session) fsm_abort_signing_workflows();
  return false;
}

bool scratch_untouched() {
  for (uint8_t b : scratch)
    if (b != 0xa7) return false;
  return true;
}

TEST_F(MoneroTx, AbortedRangeProofEndsTheSessionAndLeavesTheArenaAlone) {
  for (bool end_session : {false, true}) {
    for (uint32_t after : {0u, 1u, 100u, 381u}) {
      replay_rng("abort-bpp");
      Flow f(simple_plan());
      ASSERT_EQ(MONERO_TX_OK, f.begin());
      ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
      ASSERT_EQ(MONERO_TX_OK, f.vinis());
      ASSERT_EQ(MONERO_TX_OK, f.output(0));
      Interrupt in = {after, 0, end_session};
      EXPECT_ENDED(MONERO_TX_ERR_PROOF, f.output(1, interrupt_step, &in));
      EXPECT_EQ(after + 1, in.calls);
      EXPECT_TRUE(scratch_untouched()) << "after " << after;
      EXPECT_FALSE(f.out_acks[1].has_bp_plus);
      EXPECT_FALSE(f.out_acks[1].has_out_pk);
      /* Nothing half-done: the next step finds no session. */
      EXPECT_ENDED(MONERO_TX_ERR_STEP, monero_tx_all_out_set(&f.all_out));
    }
  }
}

TEST_F(MoneroTx, AbortedClsagEndsTheSessionAndLeavesTheArenaAlone) {
  for (bool end_session : {false, true}) {
    for (uint32_t after : {0u, 7u, 14u}) {
      replay_rng("abort-clsag");
      Flow f(two_input_plan());
      ASSERT_EQ(MONERO_TX_OK, f.to_signing());
      ASSERT_EQ(MONERO_TX_OK, f.sign(f.order[0]));
      Interrupt in = {after, 0, end_session};
      EXPECT_ENDED(MONERO_TX_ERR_PROOF,
                   f.sign(f.order[1], interrupt_step, &in));
      EXPECT_EQ(after + 1, in.calls);
      EXPECT_TRUE(scratch_untouched()) << "after " << after;
      EXPECT_EQ(1u, f.sign_acks.size());
      /* The one CLSAG already returned stays sealed for ever. */
      MoneroTxFinalAck ack;
      EXPECT_ENDED(MONERO_TX_ERR_STEP, monero_tx_final(&ack));
      EXPECT_FALSE(ack.has_opening_key);
    }
  }
}

TEST_F(MoneroTx, ProvingNeedsItsScratch) {
  Flow f(simple_plan());
  ASSERT_EQ(MONERO_TX_OK, f.begin());
  ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
  ASSERT_EQ(MONERO_TX_OK, f.vinis());
  EXPECT_FALSE(monero_tx_next_output_proves());
  ASSERT_EQ(MONERO_TX_OK, f.output(0));
  EXPECT_TRUE(monero_tx_next_output_proves());
  const MoneroTxSetOutputRequest req = f.output_request(1);
  MoneroTxSetOutputAck ack;
  EXPECT_ENDED(MONERO_TX_ERR_INTERNAL,
               monero_tx_set_output(&req, &ack, scratch + 1,
                                    sizeof(scratch) - 1, nullptr, nullptr));
  EXPECT_FALSE(monero_tx_next_output_proves());
}

/* --------------------------------------------- session and dispatch */

TEST_F(MoneroTx, EveryRevocationWipesTheSession) {
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    EXPECT_TRUE(monero_tx_active());
    EXPECT_TRUE(fsm_workflowInProgress());
    EXPECT_EQ(SIGNING_SESSION_MONERO_TX, signing_session_owner());
    fsm_abort_signing_workflows();
    EXPECT_FALSE(monero_tx_active());
    EXPECT_TRUE(signing_session_is_zero());
    EXPECT_FALSE(fsm_workflowInProgress());
  }
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    session_clear(true); /* lock, PIN failure, Initialize, ClearSession */
    EXPECT_FALSE(monero_tx_active());
    EXPECT_TRUE(signing_session_is_zero());
  }
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    monero_session_abort();
    EXPECT_FALSE(monero_tx_active());
    EXPECT_TRUE(signing_session_is_zero());
  }
}

TEST_F(MoneroTx, SessionExpiresTenMinutesAfterBegin) {
  /* Ten minutes to the millisecond is still inside. */
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    timer_poll_ticks(MONERO_TX_SESSION_MS);
    EXPECT_TRUE(monero_tx_active());
    EXPECT_TRUE(fsm_workflowInProgress());
    EXPECT_EQ(MONERO_TX_OK, f.set_inputs());
    fsm_abort_signing_workflows();
  }
  /* One more and the session is over, wherever it stood: the step that
   * arrives is told so, and nothing of the session is left. */
  enum Stage { BEGUN, INPUTS, OUTPUTS, ONE_SIGNED, SIGNED };
  for (Stage stage : {BEGUN, INPUTS, OUTPUTS, ONE_SIGNED, SIGNED}) {
    Flow f(two_input_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    if (stage >= INPUTS) ASSERT_EQ(MONERO_TX_OK, f.set_inputs());
    if (stage >= OUTPUTS) {
      ASSERT_EQ(MONERO_TX_OK, f.vinis());
      ASSERT_EQ(MONERO_TX_OK, f.outputs());
    }
    if (stage >= ONE_SIGNED) ASSERT_EQ(MONERO_TX_OK, f.sign(f.order[0]));
    if (stage >= SIGNED) ASSERT_EQ(MONERO_TX_OK, f.sign(f.order[1]));
    timer_poll_ticks(MONERO_TX_SESSION_MS + 1);
    MoneroTxFinalAck final_ack;
    switch (stage) {
      case BEGUN:
        EXPECT_ENDED(MONERO_TX_ERR_EXPIRED, f.set_inputs());
        break;
      case INPUTS:
        EXPECT_ENDED(MONERO_TX_ERR_EXPIRED, f.vinis());
        break;
      case OUTPUTS:
        EXPECT_ENDED(MONERO_TX_ERR_EXPIRED, f.sign(f.order[0]));
        break;
      case ONE_SIGNED:
        EXPECT_ENDED(MONERO_TX_ERR_EXPIRED, f.sign(f.order[1]));
        break;
      case SIGNED:
        /* Every input is signed, and still the key that opens the
         * signatures is not released. */
        EXPECT_ENDED(MONERO_TX_ERR_EXPIRED, monero_tx_final(&final_ack));
        EXPECT_FALSE(final_ack.has_opening_key);
        break;
    }
    EXPECT_FALSE(fsm_workflowInProgress()) << stage;
  }
  /* The dispatch gate finds it expired before any handler runs. The user
   * is at the device, so this is the session's own limit, not the lock. */
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.to_signing());
    timer_poll_ticks(MONERO_TX_SESSION_MS + 1);
    keepkey_user_activity();
    EXPECT_FALSE(keepkey_before_message_dispatch(
        MessageType_MessageType_MoneroTxSignInputRequest));
    EXPECT_FALSE(monero_tx_active());
    EXPECT_TRUE(signing_session_is_zero());
  }
  /* A status request does not extend it either. */
  {
    Flow f(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, f.begin());
    timer_poll_ticks(MONERO_TX_SESSION_MS / 2);
    keepkey_user_activity();
    EXPECT_TRUE(
        keepkey_before_message_dispatch(MessageType_MessageType_GetFeatures));
    EXPECT_EQ(MONERO_TX_OK, f.set_inputs());
    timer_poll_ticks(MONERO_TX_SESSION_MS / 2 + 1);
    keepkey_user_activity();
    EXPECT_TRUE(
        keepkey_before_message_dispatch(MessageType_MessageType_GetFeatures));
    EXPECT_FALSE(monero_tx_active());
    EXPECT_TRUE(signing_session_is_zero());
  }
}

TEST_F(MoneroTx, DispatchGateKeepsOnlyOwnStepsAndStatusRequests) {
  const MessageType steps[] = {
      MessageType_MessageType_MoneroTxSetInputRequest,
      MessageType_MessageType_MoneroTxInputViniRequest,
      MessageType_MessageType_MoneroTxAllInputsSetRequest,
      MessageType_MessageType_MoneroTxSetOutputRequest,
      MessageType_MessageType_MoneroTxAllOutSetRequest,
      MessageType_MessageType_MoneroTxSignInputRequest,
      MessageType_MessageType_MoneroTxFinalRequest};
  /* Without a session every continuation is refused as stale. */
  for (MessageType step : steps)
    EXPECT_FALSE(keepkey_before_message_dispatch(step)) << step;

  Flow f(simple_plan());
  ASSERT_EQ(MONERO_TX_OK, f.begin());
  for (MessageType step : steps) {
    EXPECT_TRUE(keepkey_before_message_dispatch(step)) << step;
    EXPECT_TRUE(monero_tx_active()) << step;
  }
  for (MessageType keep : {MessageType_MessageType_GetFeatures,
                           MessageType_MessageType_GetCoinTable}) {
    EXPECT_TRUE(keepkey_before_message_dispatch(keep));
    EXPECT_TRUE(monero_tx_active());
  }

  /* Anything else ends it before its handler runs, Ping included. */
  const MessageType others[] = {
      MessageType_MessageType_Ping,
      MessageType_MessageType_GetAddress,
      MessageType_MessageType_MoneroGetAddress,
      MessageType_MessageType_MoneroGetWatchKey,
      MessageType_MessageType_MoneroKeyImageExportInitRequest,
      MessageType_MessageType_MoneroTxInitRequest,
      MessageType_MessageType_Initialize,
      MessageType_MessageType_Cancel,
      MessageType_MessageType_ClearSession,
      MessageType_MessageType_SignTx};
  for (MessageType other : others) {
    Flow g(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, g.begin());
    EXPECT_TRUE(keepkey_before_message_dispatch(other)) << other;
    EXPECT_FALSE(monero_tx_active()) << other;
    EXPECT_TRUE(signing_session_is_zero()) << other;
  }
  /* A key-image step during signing is stale, and ends the signing too. */
  for (MessageType other :
       {MessageType_MessageType_MoneroKeyImageSyncStepRequest,
        MessageType_MessageType_MoneroKeyImageSyncFinalRequest}) {
    Flow g(simple_plan());
    ASSERT_EQ(MONERO_TX_OK, g.begin());
    EXPECT_FALSE(keepkey_before_message_dispatch(other)) << other;
    EXPECT_FALSE(monero_tx_active()) << other;
    EXPECT_TRUE(signing_session_is_zero()) << other;
  }
}

TEST_F(MoneroTx, SessionFitsTheSharedArenaWithOneOwner) {
  Flow f(simple_plan());
  ASSERT_EQ(MONERO_TX_OK, f.begin());
  EXPECT_EQ(SIGNING_SESSION_MONERO_TX, signing_session_owner());
  /* The key-image session cannot be read or taken while signing owns it. */
  EXPECT_EQ(nullptr, signing_session_get(SIGNING_SESSION_MONERO_KEY_IMAGE));
  EXPECT_FALSE(monero_key_image_active());
#if ZCASH_PRIVACY
  EXPECT_EQ(nullptr, signing_session_claim(SIGNING_SESSION_ZCASH));
#endif
  EXPECT_TRUE(monero_tx_active());
}

/* ------------------------------------------------------------------
 * The same transaction through the wire handlers (lib/firmware/
 * fsm_msg_monero.h): the review screens, the progress polls and the
 * frame-arena scratch are real here. */

bool kkconfirm_preload(int, int);
bool kkconfirm_preload_no_sentinel(int, int);
bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload, uint8_t len);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_captured_titles(void);
void kk_test_set_message_hook(
    std::function<void(MessageType, const void*)> hook);

namespace {

class MoneroTxHandlers : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = nullptr;
  MessageType last = (MessageType)0;
  std::vector<MessageType> written;

  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    previous = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    /* The "abandon" fixture wallet: key_seed is its node at m/44'/128'/0'. */
    strcpy(load.mnemonic,
           "abandon abandon abandon abandon abandon abandon abandon abandon "
           "abandon abandon abandon about");
    storage_loadDevice(&load);
    keepkey_user_activity();
    fsm_test_clearLastFailure();
    replay_rng("default");
  }
  void TearDown() override {
    kk_test_set_message_hook(nullptr);
    fsm_abort_workflows();
    kkconfirm_drain();
    storage_wipe();
    storage_reset();
    emulator_flash_base = previous;
    xmr_test_rng_checked();
  }

  /* Calls a handler and copies its reply out of the response buffer. */
  template <class Ack>
  bool reply(MessageType id, Ack* ack, const std::function<void()>& call) {
    bool got = false;
    kk_test_set_message_hook([&](MessageType type, const void* msg) {
      written.push_back(type);
      last = type;
      if (type == id) {
        memcpy(ack, msg, sizeof(Ack));
        got = true;
      }
    });
    call();
    kk_test_set_message_hook(nullptr);
    return got;
  }

  /* The review as the user pages through it. */
  std::vector<std::string> titles, bodies;
  bool init(Flow& f, int accept, int reject = 0) {
    EXPECT_TRUE(reject ? kkconfirm_preload(accept, reject)
                       : kkconfirm_preload_no_sentinel(accept, 0));
    kkconfirm_capture_start();
    const bool ok =
        reply(MessageType_MessageType_MoneroTxInitAck, &f.init_ack,
              [&] { fsm_msgMoneroTxInit(&f.plan.init); });
    titles = kkconfirm_captured_titles();
    bodies = kkconfirm_capture_finish();
    if (getenv("KK_XMR_SHOW_SCREENS"))
      for (size_t i = 0; i < bodies.size(); ++i)
        printf("--- %s ---\n%s\n", titles[i].c_str(), bodies[i].c_str());
    return ok;
  }

  /* How many screens the review of this plan has. */
  int review_screens(const Plan& plan) {
    Flow f(plan);
    EXPECT_TRUE(kkconfirm_preload(40, 0));
    kkconfirm_capture_start();
    fsm_msgMoneroTxInit(&f.plan.init);
    const int screens = (int)kkconfirm_capture_finish().size();
    fsm_abort_workflows();
    kkconfirm_drain();
    fsm_test_clearLastFailure();
    return screens;
  }

  bool inputs_and_first_output(Flow& f) {
    for (const Input& in : f.plan.inputs) {
      MoneroTxSetInputRequest req = {};
      req.has_src = true;
      req.src = in.src;
      MoneroTxSetInputAck ack = {};
      if (!reply(MessageType_MessageType_MoneroTxSetInputAck, &ack,
                 [&] { fsm_msgMoneroTxSetInput(&req); }))
        return false;
      f.in_acks.push_back(ack);
    }
    for (uint32_t i = 0; i < f.in_acks.size(); ++i) f.order.push_back(i);
    std::sort(f.order.begin(), f.order.end(), [&](uint32_t a, uint32_t b) {
      return memcmp(f.key_image(a), f.key_image(b), 32) > 0;
    });
    for (uint32_t index : f.order) {
      const MoneroTxInputViniRequest req = f.vini_request(index);
      MoneroTxInputViniAck ack;
      if (!reply(MessageType_MessageType_MoneroTxInputViniAck, &ack,
                 [&] { fsm_msgMoneroTxInputVini(&req); }))
        return false;
    }
    MoneroTxAllInputsSetRequest all_in = {};
    MoneroTxAllInputsSetAck all_in_ack;
    if (!reply(MessageType_MessageType_MoneroTxAllInputsSetAck, &all_in_ack,
               [&] { fsm_msgMoneroTxAllInputsSet(&all_in); }))
      return false;
    return output(f, 0);
  }

  bool output(Flow& f, unsigned j) {
    const MoneroTxSetOutputRequest req = f.output_request(j);
    return reply(MessageType_MessageType_MoneroTxSetOutputAck, &f.out_acks[j],
                 [&] { fsm_msgMoneroTxSetOutput(&req); });
  }

  bool all_out(Flow& f) {
    MoneroTxAllOutSetRequest req = {};
    return reply(MessageType_MessageType_MoneroTxAllOutSetAck, &f.all_out,
                 [&] { fsm_msgMoneroTxAllOutSet(&req); });
  }

  bool sign(Flow& f, uint32_t index) {
    const MoneroTxSignInputRequest req = f.sign_request(index);
    MoneroTxSignInputAck ack = {};
    if (!reply(MessageType_MessageType_MoneroTxSignInputAck, &ack,
               [&] { fsm_msgMoneroTxSignInput(&req); }))
      return false;
    f.sign_acks.push_back(ack);
    return true;
  }

  void expect_wiped() {
    EXPECT_FALSE(monero_tx_active());
    EXPECT_EQ(SIGNING_SESSION_FREE, signing_session_owner());
    EXPECT_TRUE(signing_session_is_zero());
    EXPECT_FALSE(fsm_workflowInProgress());
  }
};

/* Every page of the screens with this title, joined; pages break the
 * address anywhere, so spaces and newlines are dropped. */
std::string joined(const std::vector<std::string>& titles,
                   const std::vector<std::string>& bodies,
                   const std::string& title) {
  std::string all;
  for (size_t i = 0; i < bodies.size(); ++i)
    if (titles[i].compare(0, title.size(), title) == 0)
      for (char c : bodies[i])
        if (!isspace((unsigned char)c)) all += c;
  return all;
}

}  // namespace

TEST_F(MoneroTxHandlers, ReviewThenSignTheCoreVerifiedTransaction) {
  const Plan plan = simple_plan();
  const int screens = review_screens(plan);
  ASSERT_GT(screens, 3);

  replay_rng(plan.name);
  Flow f(plan);
  ASSERT_TRUE(init(f, screens));
  ASSERT_EQ((size_t)screens, bodies.size());
  EXPECT_TRUE(monero_tx_active());
  EXPECT_TRUE(fsm_workflowInProgress());

  /* The recipient: full address, never shortened, and the exact amount. */
  const std::string send = joined(titles, bodies, "Monero send");
  EXPECT_NE(std::string::npos, send.find(other_wallet().address)) << send;
  EXPECT_NE(std::string::npos, send.find("Send1.500000000000XMR")) << send;
  EXPECT_NE(std::string::npos, send.find("standardaddress")) << send;
  /* Change, shown as change, with the wallet's own full address. */
  const std::string change = joined(titles, bodies, "Monero change");
  EXPECT_NE(std::string::npos, change.find(signer_wallet().address)) << change;
  EXPECT_NE(std::string::npos, change.find("Change0.499969000000XMR"))
      << change;
  EXPECT_EQ(std::string::npos, send.find(signer_wallet().address));
  /* Fee and total on the last screen, which is the one that is held. */
  EXPECT_EQ("Sign Monero", titles.back()); /* one page: not split */
  EXPECT_NE(std::string::npos,
            bodies.back().find("1 input(s), ring 16, about 20 s"))
      << bodies.back();
  const std::string last_screen = joined(titles, bodies, "Sign Monero");
  EXPECT_NE(std::string::npos, last_screen.find("Fee0.000031000000XMR"))
      << last_screen;
  EXPECT_NE(std::string::npos, last_screen.find("Total1.500031000000XMR"))
      << last_screen;
  /* No address is ever abbreviated. */
  for (const std::string& body : bodies)
    EXPECT_EQ(std::string::npos, body.find("...")) << body;

  ASSERT_TRUE(inputs_and_first_output(f));
  ASSERT_TRUE(output(f, 1));
  EXPECT_EQ(642u, f.out_acks[1].bp_plus.size);
  ASSERT_TRUE(all_out(f));
  for (uint32_t index : f.order) ASSERT_TRUE(sign(f, index));
  MoneroTxFinalRequest fin = {};
  ASSERT_TRUE(reply(MessageType_MessageType_MoneroTxFinalAck, &f.final_ack,
                    [&] { fsm_msgMoneroTxFinal(&fin); }));
  ASSERT_FALSE(::testing::Test::HasFailure());

  /* Byte for byte the transaction Monero Core verified for this plan. */
  const Bytes tx = f.assemble();
  const Bytes digest = keccak(tx);
  bool found = false;
  for (size_t i = 0; i < MONERO_TX_VECTOR_COUNT; ++i) {
    if (plan.name != monero_tx_vectors[i].name) continue;
    found = true;
    EXPECT_EQ(hex(monero_tx_vectors[i].keccak, 32), hex(digest.data(), 32));
  }
  EXPECT_TRUE(found);
  expect_wiped();
  EXPECT_EQ(0, kkconfirm_drain() + 2); /* no confirmation left over */
}

TEST_F(MoneroTxHandlers, TestnetAndWarningsAreOnTheScreens) {
  Plan plan = make_plan("review-only", 0, other_address(0, 0), 250000000000ull,
                        749950000000ull, 50000000ull, 1);
  add_input(plan, owned_input(0, 0, 1000000000000ull, 9, 4));
  set_payment_id(plan, 0, 0xa5);
  plan.init.has_network_type = true;
  plan.init.network_type = MoneroNetworkType_MONERO_NETWORK_TESTNET;
  plan.init.tsx_data.has_unlock_time = true;
  plan.init.tsx_data.unlock_time = 3500000;
  const int screens = review_screens(plan);
  Flow f(plan);
  ASSERT_TRUE(init(f, screens));
  /* Every screen names the network. */
  for (const std::string& title : titles)
    EXPECT_NE(std::string::npos, title.find("TESTNET")) << title;
  const std::string send = joined(titles, bodies, "Monero TESTNET send");
  EXPECT_NE(std::string::npos, send.find("integratedaddress")) << send;
  const std::string pid = joined(titles, bodies, "Monero TESTNET payment ID");
  EXPECT_NE(std::string::npos, pid.find("01a5a5a5a5a5a5a5")) << pid;
  const std::string warning = joined(titles, bodies, "Monero TESTNET WARNING");
  EXPECT_NE(std::string::npos, warning.find("3500000")) << warning;
  /* The integrated address, complete (106 characters). */
  MoneroTxReview review;
  ASSERT_EQ(MONERO_TX_OK,
            monero_tx_review(signer_wallet().key_seed, &plan.init, &review));
  EXPECT_EQ(106u, strlen(review.outputs[0].address));
  EXPECT_NE(std::string::npos, send.find(review.outputs[0].address)) << send;
}

TEST_F(MoneroTxHandlers, DecliningAnyReviewScreenOpensNoSession) {
  const Plan plan = simple_plan();
  const int screens = review_screens(plan);
  for (int accepted = 0; accepted < screens; ++accepted) {
    Flow f(plan);
    fsm_test_clearLastFailure();
    EXPECT_FALSE(init(f, accepted, 1)) << accepted;
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode())
        << accepted;
    EXPECT_EQ(0u, f.init_ack.dst_hmacs_count);
    EXPECT_FALSE(monero_tx_active());
    EXPECT_TRUE(signing_session_is_zero());
    kkconfirm_drain();
  }
}

TEST_F(MoneroTxHandlers, RefusalsAreClearFailuresBeforeAnyScreen) {
  Plan plan = simple_plan();
  plan.init.tsx_data.outputs_count = 3;
  plan.init.tsx_data.outputs[2] = destination(other_address(0, 2), 1);
  Flow f(plan);
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  kkconfirm_capture_start();
  EXPECT_FALSE(reply(MessageType_MessageType_MoneroTxInitAck, &f.init_ack,
                     [&] { fsm_msgMoneroTxInit(&f.plan.init); }));
  EXPECT_TRUE(kkconfirm_capture_finish().empty());
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_NE(nullptr,
            strstr(fsm_test_lastFailureMessage(), "exactly 2 outputs"));
  EXPECT_FALSE(monero_tx_active());

  /* A continuation with no session, straight at the handler. */
  fsm_test_clearLastFailure();
  MoneroTxAllOutSetRequest req = {};
  fsm_msgMoneroTxAllOutSet(&req);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());

  /* An uninitialized device signs nothing. */
  storage_wipe();
  storage_reset();
  fsm_test_clearLastFailure();
  Flow g(simple_plan());
  fsm_msgMoneroTxInit(&g.plan.init);
  EXPECT_EQ(FailureType_Failure_NotInitialized, fsm_test_lastFailureCode());
  EXPECT_FALSE(monero_tx_active());
}

TEST_F(MoneroTxHandlers, CancelDuringTheRangeProofEndsTheSession) {
  const Plan plan = simple_plan();
  const int screens = review_screens(plan);
  Flow f(plan);
  ASSERT_TRUE(init(f, screens));
  ASSERT_TRUE(inputs_and_first_output(f));
  /* The host cancels while the device proves. */
  ASSERT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_Cancel, NULL, 0));
  fsm_test_clearLastFailure();
  EXPECT_FALSE(output(f, 1));
  EXPECT_EQ(MessageType_MessageType_Failure, last);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_FALSE(f.out_acks[1].has_bp_plus);
  expect_wiped();
  /* Nothing half-done: the next step is stale. */
  EXPECT_FALSE(keepkey_before_message_dispatch(
      MessageType_MessageType_MoneroTxAllOutSetRequest));
}

TEST_F(MoneroTxHandlers, AnyOtherMessageDuringAProofEndsTheSession) {
  const Plan plan = simple_plan();
  const int screens = review_screens(plan);
  /* A message the tiny reader refuses (it answers through the arena), one
   * it accepts, and a stray acknowledgement: all end the proof. */
  const uint16_t strays[] = {MessageType_MessageType_Ping,
                             MessageType_MessageType_ButtonAck,
                             MessageType_MessageType_MoneroTxFinalRequest};
  for (uint16_t stray : strays) {
    replay_rng("stray");
    Flow f(plan);
    ASSERT_TRUE(init(f, screens));
    ASSERT_TRUE(inputs_and_first_output(f));
    ASSERT_TRUE(kkconfirm_sendTiny(stray, NULL, 0));
    written.clear();
    EXPECT_FALSE(output(f, 1)) << stray;
    /* Exactly one reply, and it is a Failure. */
    ASSERT_EQ(1u, written.size()) << stray;
    EXPECT_EQ(MessageType_MessageType_Failure, written[0]) << stray;
    expect_wiped();
    kkconfirm_drain();
  }

  /* The same while a CLSAG is being made. */
  for (uint16_t stray : strays) {
    replay_rng("stray");
    Flow f(plan);
    ASSERT_TRUE(init(f, screens));
    ASSERT_TRUE(inputs_and_first_output(f));
    ASSERT_TRUE(output(f, 1));
    ASSERT_TRUE(all_out(f));
    ASSERT_TRUE(kkconfirm_sendTiny(stray, NULL, 0));
    written.clear();
    EXPECT_FALSE(sign(f, f.order[0])) << stray;
    ASSERT_EQ(1u, written.size()) << stray;
    EXPECT_EQ(MessageType_MessageType_Failure, written[0]) << stray;
    expect_wiped();
    kkconfirm_drain();
  }
}

TEST_F(MoneroTxHandlers, InitializeDuringAProofResetsTheDevice) {
  const Plan plan = simple_plan();
  const int screens = review_screens(plan);
  Flow f(plan);
  ASSERT_TRUE(init(f, screens));
  ASSERT_TRUE(inputs_and_first_output(f));
  ASSERT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_Initialize, NULL, 0));
  written.clear();
  EXPECT_FALSE(output(f, 1));
  /* Initialize is answered with Features, as from any other prompt. */
  ASSERT_EQ(1u, written.size());
  EXPECT_EQ(MessageType_MessageType_Features, written[0]);
  expect_wiped();
}
