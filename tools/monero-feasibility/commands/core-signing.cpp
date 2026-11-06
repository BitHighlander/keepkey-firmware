/* Emulator-only transaction bridge to pinned Monero Core 0.18.5.4.
 * This native C++ dependency is not a port of the signer to STM32 firmware.
 */
#include "core-signing.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>
#include "crypto/crypto.h"
extern "C" {
#include "crypto/crypto-ops.h"
}
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "device/device.hpp"
#include "memwipe.h"
#include "ringct/rctSigs.h"

namespace {
std::mutex engine_mutex;

bool fail(char *error, const char *message) {
  if (error) {
    std::strncpy(error, message, MONERO_CORE_ERROR_CAPACITY - 1);
    error[MONERO_CORE_ERROR_CAPACITY - 1] = 0;
  }
  return false;
}

template<typename T> T pod(const uint8_t *bytes) {
  static_assert(sizeof(T) == 32, "expected a 32-byte Core value");
  T value;
  std::memcpy(&value, bytes, 32);
  return value;
}

bool point(const uint8_t bytes[32]) {
  ge_p3 decoded;
  uint8_t canonical[32];
  if (ge_frombytes_vartime(&decoded, bytes)) return false;
  ge_p3_tobytes(canonical, &decoded);
  if (std::memcmp(canonical, bytes, 32)) return false;
  const rct::key value = pod<rct::key>(bytes);
  return !(value == rct::identity()) && rct::isInMainSubgroup(value);
}

bool add_amount(uint64_t &total, uint64_t amount) {
  if (amount > std::numeric_limits<uint64_t>::max() - total) return false;
  total += amount;
  return true;
}

struct Prepared {
  cryptonote::account_keys keys;
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  std::vector<cryptonote::tx_source_entry> sources;
  std::vector<cryptonote::tx_destination_entry> destinations;
  boost::optional<cryptonote::account_public_address> change;
  monero_core_summary summary{};
  ~Prepared() {
    memwipe(&keys.m_spend_secret_key, sizeof(keys.m_spend_secret_key));
    memwipe(&keys.m_view_secret_key, sizeof(keys.m_view_secret_key));
    for (auto &source : sources) memwipe(&source.mask, sizeof(source.mask));
  }
};

void append_u64(std::vector<uint8_t> &out, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(value >> (8 * i)));
}
void append_bytes(std::vector<uint8_t> &out, const void *data, size_t size) {
  const auto *first = static_cast<const uint8_t *>(data);
  out.insert(out.end(), first, first + size);
}
void plan_hash(const monero_core_plan &plan, uint8_t hash[32]) {
  std::vector<uint8_t> bytes;
  const char domain[] = "KeepKey Monero emulator plan v1";
  append_bytes(bytes, domain, sizeof(domain));
  append_u64(bytes, plan.network); append_u64(bytes, plan.input_count);
  append_u64(bytes, plan.output_count); append_u64(bytes, plan.fee);
  for (unsigned i = 0; i < plan.input_count; ++i) {
    const auto &source = plan.sources[i];
    append_u64(bytes, source.amount); append_u64(bytes, source.real_member);
    append_u64(bytes, source.output_index); append_u64(bytes, source.subaddress_major);
    append_u64(bytes, source.subaddress_minor); append_bytes(bytes, source.tx_public_key, 32);
    append_bytes(bytes, source.mask, 32); append_u64(bytes, source.additional_key_count);
    for (unsigned j = 0; j < source.additional_key_count; ++j)
      append_bytes(bytes, source.additional_tx_public_keys[j], 32);
    for (const auto &member : source.ring) {
      append_u64(bytes, member.global_index); append_bytes(bytes, member.public_key, 32);
      append_bytes(bytes, member.commitment, 32);
    }
  }
  for (unsigned i = 0; i < plan.output_count; ++i) {
    const auto &dest = plan.destinations[i];
    append_u64(bytes, dest.amount); append_bytes(bytes, dest.address, 96);
    append_u64(bytes, dest.is_change); append_u64(bytes, dest.change_major);
    append_u64(bytes, dest.change_minor);
  }
  const crypto::hash digest = crypto::cn_fast_hash(bytes.data(), bytes.size());
  std::memcpy(hash, &digest, 32);
  memwipe(bytes.data(), bytes.size());
}

bool prepare(const monero_core_plan *request, const uint8_t node_key[32],
             Prepared &out, char *error) {
  if (!request || !node_key) return fail(error, "Missing signing plan or wallet key");
  const auto &plan = *request;
  if (plan.network > 2 || !plan.input_count || plan.input_count > MONERO_CORE_MAX_INPUTS ||
      plan.output_count < 2 || plan.output_count > MONERO_CORE_MAX_OUTPUTS)
    return fail(error, "Invalid network or input/output count");

  uint8_t spend[32];
  std::memcpy(spend, node_key, 32);
  sc_reduce32(spend);
  if (!std::memcmp(spend, rct::zero().bytes, 32)) {
    memwipe(spend, sizeof(spend));
    return fail(error, "Wallet spend scalar is zero");
  }
  std::memcpy(static_cast<void *>(&out.keys.m_spend_secret_key), spend, 32);
  crypto::ec_scalar view;
  crypto::hash_to_scalar(spend, 32, view);
  std::memcpy(static_cast<void *>(&out.keys.m_view_secret_key), &view, 32);
  memwipe(spend, sizeof(spend)); memwipe(&view, sizeof(view));
  if (!crypto::secret_key_to_public_key(out.keys.m_spend_secret_key, out.keys.m_account_address.m_spend_public_key) ||
      !crypto::secret_key_to_public_key(out.keys.m_view_secret_key, out.keys.m_account_address.m_view_public_key) ||
      !point(reinterpret_cast<const uint8_t *>(&out.keys.m_account_address.m_spend_public_key)) ||
      !point(reinterpret_cast<const uint8_t *>(&out.keys.m_account_address.m_view_public_key)))
    return fail(error, "Invalid wallet keys");
  auto &device = out.keys.get_device();
  out.subaddresses[out.keys.m_account_address.m_spend_public_key] = {0, 0};
  std::set<std::string> real_keys;
  std::set<std::string> key_images;
  std::map<uint64_t, std::pair<rct::key, rct::key>> indexed_outputs;
  for (unsigned i = 0; i < plan.input_count; ++i) {
    const auto &input = plan.sources[i];
    if (!input.amount || input.real_member >= MONERO_CORE_RING_SIZE ||
        input.additional_key_count > MONERO_CORE_MAX_ADDITIONAL_KEYS ||
        (input.additional_key_count && input.output_index >= input.additional_key_count) ||
        !point(input.tx_public_key) || sc_check(input.mask) != 0 ||
        !add_amount(out.summary.input_total, input.amount))
      return fail(error, "Invalid input amount, scalar, public key or indices");
    cryptonote::tx_source_entry source{};
    source.amount = input.amount; source.real_output = input.real_member;
    source.real_out_tx_key = pod<crypto::public_key>(input.tx_public_key);
    source.real_output_in_tx_index = input.output_index; source.rct = true;
    source.mask = pod<rct::key>(input.mask);
    for (unsigned j = 0; j < input.additional_key_count; ++j) {
      if (!point(input.additional_tx_public_keys[j])) return fail(error, "Invalid additional transaction public key");
      source.real_out_additional_tx_keys.push_back(pod<crypto::public_key>(input.additional_tx_public_keys[j]));
    }
    for (unsigned j = 0; j < MONERO_CORE_RING_SIZE; ++j) {
      const auto &member = input.ring[j];
      if (!point(member.public_key) || !point(member.commitment) ||
          (j && member.global_index <= input.ring[j - 1].global_index))
        return fail(error, "Invalid or unordered ring members");
      rct::ctkey key{pod<rct::key>(member.public_key), pod<rct::key>(member.commitment)};
      auto inserted = indexed_outputs.emplace(member.global_index, std::make_pair(key.dest, key.mask));
      if (!inserted.second && inserted.first->second != std::make_pair(key.dest, key.mask))
        return fail(error, "Conflicting public data for one global output index");
      source.outputs.emplace_back(member.global_index, key);
    }
    const auto &real = input.ring[input.real_member];
    if (!(rct::commit(input.amount, source.mask) == pod<rct::key>(real.commitment)))
      return fail(error, "Real input amount/mask does not match its commitment");
    if (!real_keys.insert(std::string(reinterpret_cast<const char *>(real.public_key), 32)).second)
      return fail(error, "Repeated real input");
    const cryptonote::subaddress_index index{input.subaddress_major, input.subaddress_minor};
    const auto sub = device.get_subaddress(out.keys, index);
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> claimed_subaddress{
        {sub.m_spend_public_key, index}};
    cryptonote::keypair ephemeral;
    crypto::key_image image;
    const bool owned = cryptonote::generate_key_image_helper(out.keys, claimed_subaddress,
        pod<crypto::public_key>(real.public_key), source.real_out_tx_key,
        source.real_out_additional_tx_keys, input.output_index, ephemeral, image, device);
    memwipe(&ephemeral.sec, sizeof(ephemeral.sec));
    if (!owned || std::memcmp(&ephemeral.pub, real.public_key, 32))
      return fail(error, "Real input is not owned by the selected wallet/subaddress");
    out.subaddresses[sub.m_spend_public_key] = index;
    if (!key_images.insert(std::string(reinterpret_cast<const char *>(&image), 32)).second)
      return fail(error, "Repeated key image");
    out.sources.push_back(std::move(source));
  }
  unsigned changes = 0, recipients = 0;
  for (unsigned i = 0; i < plan.output_count; ++i) {
    const auto &entry = plan.destinations[i];
    if (!entry.amount || std::memchr(entry.address, 0, 96) != entry.address + 95 || entry.is_change > 1 ||
        !add_amount(out.summary.output_total, entry.amount))
      return fail(error, "Invalid destination amount/address or total overflow");
    cryptonote::address_parse_info decoded{};
    if (!cryptonote::get_account_address_from_str(decoded,
          static_cast<cryptonote::network_type>(plan.network), entry.address) || decoded.has_payment_id ||
        !point(reinterpret_cast<const uint8_t *>(&decoded.address.m_spend_public_key)) ||
        !point(reinterpret_cast<const uint8_t *>(&decoded.address.m_view_public_key)))
      return fail(error, "Invalid destination address for the requested network");
    if (entry.is_change) {
      if (++changes > 1) return fail(error, "More than one change destination");
      const cryptonote::subaddress_index index{entry.change_major, entry.change_minor};
      const auto expected = device.get_subaddress(out.keys, index);
      if (std::memcmp(&expected, &decoded.address, sizeof(expected)) ||
          decoded.is_subaddress != (entry.change_major != 0 || entry.change_minor != 0))
        return fail(error, "Change destination is not the requested wallet subaddress");
      out.subaddresses[expected.m_spend_public_key] = index;
      out.change = expected;
    } else {
      if (entry.change_major || entry.change_minor)
        return fail(error, "Recipient cannot carry change indices");
      ++recipients;
    }
    out.destinations.emplace_back(entry.address, entry.amount, decoded.address, decoded.is_subaddress);
    out.summary.destinations[i] = entry;
  }
  if (!recipients || out.summary.output_total > out.summary.input_total ||
      out.summary.input_total - out.summary.output_total != plan.fee)
    return fail(error, "Input/output totals do not match the declared fee");
  out.summary.fee = plan.fee; out.summary.output_count = plan.output_count;
  plan_hash(plan, out.summary.plan_hash);
  return true;
}

/* Core shuffles destinations. Recompute the exact stealth key, view tag,
 * encrypted amount and commitment for that final order before releasing any
 * transaction bytes. Public verification alone cannot reveal recipient data.
 */
bool bind_outputs(const monero_core_plan &plan, const Prepared &prepared,
                  const cryptonote::transaction &tx, const crypto::secret_key &txkey,
                  const std::vector<crypto::secret_key> &additional, char *error) {
  if (prepared.destinations.size() != plan.output_count || tx.vout.size() != plan.output_count ||
      tx.rct_signatures.ecdhInfo.size() != plan.output_count ||
      tx.rct_signatures.outPk.size() != plan.output_count)
    return fail(error, "Constructed destination count changed");
  std::vector<bool> matched(plan.output_count, false);
  for (const auto &dest : prepared.destinations) {
    const std::string address = cryptonote::get_account_address_as_str(
        static_cast<cryptonote::network_type>(plan.network), dest.is_subaddress, dest.addr);
    bool found = false;
    for (unsigned n = 0; n < plan.output_count; ++n) {
      if (!matched[n] && dest.amount == plan.destinations[n].amount && address == plan.destinations[n].address) {
        matched[n] = true; found = true; break;
      }
    }
    if (!found) return fail(error, "Constructed destination differs from the approved plan");
  }
  size_t standard_count = 0, sub_count = 0;
  cryptonote::account_public_address single_sub;
  cryptonote::classify_addresses(prepared.destinations, prepared.change,
                                 standard_count, sub_count, single_sub);
  const bool need_additional = sub_count > 0 && (standard_count > 0 || sub_count > 1);
  if ((need_additional && additional.size() != plan.output_count) ||
      (!need_additional && !additional.empty()))
    return fail(error, "Constructed additional key count changed");
  crypto::public_key expected_main;
  if (!standard_count && sub_count == 1) {
    expected_main = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(single_sub.m_spend_public_key), rct::sk2rct(txkey)));
  } else if (!crypto::secret_key_to_public_key(txkey, expected_main)) {
    return fail(error, "Invalid generated transaction key");
  }
  const crypto::public_key actual_main = cryptonote::get_tx_pub_key_from_extra(tx);
  if (actual_main != expected_main) return fail(error, "Transaction public key changed");
  const std::vector<crypto::public_key> extra_public = cryptonote::get_additional_tx_pub_keys_from_extra(tx.extra);
  if (extra_public.size() != additional.size()) return fail(error, "Additional public keys changed");
  struct Scratch {
    crypto::key_derivation derivation;
    crypto::ec_scalar scalar;
    crypto::public_key output;
    crypto::view_tag tag;
    rct::key amount_key;
    rct::ecdhTuple decoded;
    ~Scratch() { memwipe(this, sizeof(*this)); }
  } scratch{};
  for (unsigned i = 0; i < plan.output_count; ++i) {
    const auto &dest = prepared.destinations[i];
    const auto *actual = boost::get<cryptonote::txout_to_tagged_key>(&tx.vout[i].target);
    if (!actual || tx.vout[i].amount != 0) return fail(error, "HF16 requires tagged confidential outputs");
    if (need_additional) {
      crypto::public_key expected;
      if (dest.is_subaddress)
        expected = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(dest.addr.m_spend_public_key), rct::sk2rct(additional[i])));
      else if (!crypto::secret_key_to_public_key(additional[i], expected))
        return fail(error, "Invalid additional transaction key");
      if (expected != extra_public[i]) return fail(error, "Additional transaction public key changed");
    }
    const bool change = prepared.change && dest.addr == *prepared.change;
    bool derived;
    if (change)
      derived = crypto::generate_key_derivation(actual_main, prepared.keys.m_view_secret_key, scratch.derivation);
    else
      derived = crypto::generate_key_derivation(dest.addr.m_view_public_key,
          dest.is_subaddress && need_additional ? additional[i] : txkey, scratch.derivation);
    if (!derived || !crypto::derive_public_key(scratch.derivation, i,
            dest.addr.m_spend_public_key, scratch.output))
      return fail(error, "Could not reconstruct an approved output");
    crypto::derive_view_tag(scratch.derivation, i, scratch.tag);
    if (scratch.output != actual->key || scratch.tag != actual->view_tag)
      return fail(error, "Constructed output does not pay its approved destination");
    crypto::derivation_to_scalar(scratch.derivation, i, scratch.scalar);
    std::memcpy(&scratch.amount_key, &scratch.scalar, 32);
    scratch.decoded = tx.rct_signatures.ecdhInfo[i];
    rct::ecdhDecode(scratch.decoded, scratch.amount_key, true);
    if (sc_check(scratch.decoded.mask.bytes) || sc_check(scratch.decoded.amount.bytes) ||
        rct::h2d(scratch.decoded.amount) != dest.amount ||
        !(rct::commit(dest.amount, scratch.decoded.mask) == tx.rct_signatures.outPk[i].mask))
      return fail(error, "Constructed encrypted output amount differs from the approved amount");
  }
  return true;
}

bool verify(const monero_core_plan *plan, const uint8_t *bytes, size_t size, char *error) {
  if (!plan || !bytes || !size || size > MONERO_CORE_MAX_TX_BYTES ||
      plan->input_count < 1 || plan->input_count > MONERO_CORE_MAX_INPUTS ||
      plan->output_count < 2 || plan->output_count > MONERO_CORE_MAX_OUTPUTS)
    return fail(error, "Invalid verification inputs");
  cryptonote::transaction tx;
  crypto::hash hash, prefix;
  const cryptonote::blobdata raw(reinterpret_cast<const char *>(bytes), size);
  if (!cryptonote::parse_and_validate_tx_from_blob(raw, tx, hash, prefix) ||
      cryptonote::tx_to_blob(tx) != raw || tx.version != 2 || tx.unlock_time != 0 ||
      tx.vin.size() != plan->input_count || tx.vout.size() != plan->output_count ||
      tx.rct_signatures.type != rct::RCTTypeBulletproofPlus ||
      tx.rct_signatures.txnFee != plan->fee || !cryptonote::check_outs_valid(tx))
    return fail(error, "Invalid serialized HF16 Bulletproof+ transaction");
  auto &signature = tx.rct_signatures;
  for (const auto &output : tx.vout)
    if (output.amount || !boost::get<cryptonote::txout_to_tagged_key>(&output.target))
      return fail(error, "HF16 requires tagged confidential outputs");
  if (signature.p.CLSAGs.size() != tx.vin.size()) return fail(error, "Invalid CLSAG count");
  signature.message = rct::hash2rct(prefix);
  signature.mixRing.resize(tx.vin.size());
  std::set<std::string> images;
  std::vector<bool> used(plan->input_count, false);
  for (unsigned i = 0; i < tx.vin.size(); ++i) {
    const auto *input = boost::get<cryptonote::txin_to_key>(&tx.vin[i]);
    if (!input || input->amount != 0 || input->key_offsets.size() != MONERO_CORE_RING_SIZE ||
        !point(reinterpret_cast<const uint8_t *>(&input->k_image)) ||
        !images.insert(std::string(reinterpret_cast<const char *>(&input->k_image), 32)).second)
      return fail(error, "Invalid input ring or key image");
    std::vector<uint64_t> absolute;
    uint64_t value = 0;
    for (const uint64_t relative : input->key_offsets) {
      if (!add_amount(value, relative)) return fail(error, "Ring index overflow");
      absolute.push_back(value);
    }
    unsigned match = plan->input_count;
    for (unsigned n = 0; n < plan->input_count; ++n) {
      if (used[n]) continue;
      bool same = true;
      for (unsigned j = 0; j < MONERO_CORE_RING_SIZE; ++j)
        same &= absolute[j] == plan->sources[n].ring[j].global_index;
      if (same) { match = n; break; }
    }
    if (match == plan->input_count) return fail(error, "Transaction ring is not in the supplied plan");
    used[match] = true;
    for (const auto &member : plan->sources[match].ring) {
      if (!point(member.public_key) || !point(member.commitment)) return fail(error, "Invalid verification ring point");
      signature.mixRing[i].push_back({pod<rct::key>(member.public_key), pod<rct::key>(member.commitment)});
    }
    signature.p.CLSAGs[i].I = rct::ki2rct(input->k_image);
    if (i && std::memcmp(&boost::get<cryptonote::txin_to_key>(tx.vin[i - 1]).k_image,
                         &input->k_image, 32) <= 0)
      return fail(error, "Key images are not canonically sorted");
  }
  if (!rct::verRctSemanticsSimple(signature) || !rct::verRctNonSemanticsSimple(signature))
    return fail(error, "Ring signature or Bulletproof+ verification failed");
  return true;
}
}

extern "C" int monero_core_validate(const monero_core_plan *plan, const uint8_t key[32],
    monero_core_summary *summary, char error[MONERO_CORE_ERROR_CAPACITY]) {
  if (summary) std::memset(summary, 0, sizeof(*summary));
  if (error) error[0] = 0;
  try {
    std::lock_guard<std::mutex> lock(engine_mutex);
    Prepared prepared;
    if (!summary || !prepare(plan, key, prepared, error)) return 0;
    *summary = prepared.summary;
    return 1;
  } catch (...) { return fail(error, "Monero Core validation rejected the plan"); }
}

extern "C" int monero_core_sign(const monero_core_plan *plan, const uint8_t key[32],
    uint8_t *bytes, size_t capacity, size_t *size, uint8_t hash[32],
    char error[MONERO_CORE_ERROR_CAPACITY]) {
  if (size) *size = 0;
  if (hash) std::memset(hash, 0, 32);
  if (error) error[0] = 0;
  if (!bytes || capacity > MONERO_CORE_MAX_TX_BYTES || !size || !hash)
    return fail(error, "Invalid transaction output buffer");
  std::memset(bytes, 0, capacity);
  try {
    std::lock_guard<std::mutex> lock(engine_mutex);
    Prepared prepared;
    if (!prepare(plan, key, prepared, error)) return 0;
    cryptonote::transaction tx;
    crypto::secret_key txkey;
    std::vector<crypto::secret_key> additional;
    const bool constructed = cryptonote::construct_tx_and_get_tx_key(prepared.keys,
        prepared.subaddresses, prepared.sources, prepared.destinations, prepared.change,
        {}, tx, txkey, additional, true, {rct::RangeProofPaddedBulletproof, 4}, true);
    const bool bound = constructed && bind_outputs(*plan, prepared, tx, txkey, additional, error);
    memwipe(&txkey, sizeof(txkey));
    for (auto &secret : additional) memwipe(&secret, sizeof(secret));
    if (!constructed) return fail(error, "Monero Core could not construct the transaction");
    if (!bound) return 0;
    const cryptonote::blobdata raw = cryptonote::tx_to_blob(tx);
    if (raw.empty() || raw.size() > capacity || !verify(plan,
        reinterpret_cast<const uint8_t *>(raw.data()), raw.size(), error))
      return fail(error, "Constructed transaction failed verification or output bounds");
    const crypto::hash txhash = cryptonote::get_transaction_hash(tx);
    std::memcpy(bytes, raw.data(), raw.size()); std::memcpy(hash, &txhash, 32);
    *size = raw.size();
    return 1;
  } catch (...) { return fail(error, "Monero Core signing rejected the plan"); }
}

extern "C" int monero_core_verify(const monero_core_plan *plan, const uint8_t *bytes,
    size_t size, char error[MONERO_CORE_ERROR_CAPACITY]) {
  if (error) error[0] = 0;
  try { std::lock_guard<std::mutex> lock(engine_mutex); return verify(plan, bytes, size, error); }
  catch (...) { return fail(error, "Monero Core rejected the serialized transaction"); }
}

extern "C" size_t monero_core_plan_size(void) { return sizeof(monero_core_plan); }
extern "C" size_t monero_core_summary_size(void) { return sizeof(monero_core_summary); }
