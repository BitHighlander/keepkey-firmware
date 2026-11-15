/* Turns what a stock Monero watch-only wallet exports into the plain JSON
 * the KeepKey stream signer takes (python-keepkey keepkeylib/monero_stream.py).
 * Test tooling for the private-regtest end-to-end run; links Monero Core
 * v0.18.5.4's wallet library.
 *
 * One JSON request on stdin, one JSON reply on stdout:
 *   {"op": "outputs", "address", "view_key", "outputs_data_hex"}
 *       -> the wallet's outputs in transfer order, for key-image sync
 *   {"op": "plan", ..., "unsigned_txset"}
 *       -> the unsigned transfer plan: inputs with their rings, outputs,
 *          change, fee, payment ID
 *
 * It holds the view key only: no spend key is accepted, it opens no wallet
 * file and talks to no daemon. */
#include <cstring>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
#include "wallet/wallet2.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"
#include "string_tools.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace {
using Json = rapidjson::Value;
using Alloc = rapidjson::Document::AllocatorType;
using Exported = tools::wallet2::exported_transfer_details;
using epee::string_tools::pod_to_hex;

void require(bool ok, const char *why) {
  if (!ok) throw std::runtime_error(why);
}
std::string field(const Json &request, const char *name) {
  require(request.HasMember(name) && request[name].IsString(), "missing request field");
  return std::string(request[name].GetString(), request[name].GetStringLength());
}
std::string unhex(const std::string &hex) {
  std::string out;
  require(epee::string_tools::parse_hexstr_to_binbuff(hex, out), "invalid hex");
  return out;
}
void put(Json &object, const char *name, const std::string &value, Alloc &a) {
  object.AddMember(Json(name, a), Json(value.data(), value.size(), a), a);
}
void put(Json &object, const char *name, uint64_t value, Alloc &a) {
  object.AddMember(Json(name, a), Json().SetUint64(value), a);
}
void put(Json &object, const char *name, bool value, Alloc &a) {
  object.AddMember(Json(name, a), Json().SetBool(value), a);
}

/* export_outputs: magic, then (wallet address, outputs) under the view key. */
std::vector<Exported> outputs_of(const tools::wallet2 &wallet, const std::string &hex) {
  static const char magic[] = "Monero output export\004";
  const std::string data = unhex(hex);
  const size_t prefix = sizeof(magic) - 1;
  require(data.size() > prefix && !data.compare(0, prefix, magic), "not an output export");
  const std::string plain = wallet.decrypt_with_view_secret_key(data.substr(prefix));
  const auto &own = wallet.get_account().get_keys().m_account_address;
  require(plain.size() > 64 && !std::memcmp(plain.data(), &own.m_spend_public_key, 32) &&
          !std::memcmp(plain.data() + 32, &own.m_view_public_key, 32),
          "output export of another wallet");
  const std::string body = plain.substr(64);
  std::tuple<uint64_t, uint64_t, std::vector<Exported>> exported;
  binary_archive<false> archive{epee::strspan<std::uint8_t>(body)};
  require(::serialization::serialize(archive, exported), "invalid output export");
  require(std::get<0>(exported) == 0 && std::get<2>(exported).size() == std::get<1>(exported),
          "a complete export is required (export_outputs all=true)");
  return std::get<2>(exported);
}

Json keys_json(const std::vector<crypto::public_key> &keys, Alloc &a) {
  Json list(rapidjson::kArrayType);
  for (const auto &key : keys) list.PushBack(Json(pod_to_hex(key).c_str(), a), a);
  return list;
}

void outputs_reply(const std::vector<Exported> &outputs, rapidjson::Document &reply) {
  auto &a = reply.GetAllocator();
  Json list(rapidjson::kArrayType);
  for (const auto &o : outputs) {
    Json item(rapidjson::kObjectType);
    put(item, "amount", o.m_amount, a);
    put(item, "global_index", o.m_global_output_index, a);
    put(item, "out_key", pod_to_hex(o.m_pubkey), a);
    put(item, "tx_public_key", pod_to_hex(o.m_tx_pubkey), a);
    item.AddMember("additional_tx_public_keys", keys_json(o.m_additional_tx_keys, a), a);
    put(item, "output_index", o.m_internal_output_index, a);
    put(item, "subaddress_major", uint64_t(o.m_subaddr_index_major), a);
    put(item, "subaddress_minor", uint64_t(o.m_subaddr_index_minor), a);
    list.PushBack(item, a);
  }
  reply.AddMember("outputs", list, a);
}

Json destination_json(const cryptonote::tx_destination_entry &d, Alloc &a) {
  Json item(rapidjson::kObjectType);
  put(item, "amount", d.amount, a);
  put(item, "spend_public_key", pod_to_hex(d.addr.m_spend_public_key), a);
  put(item, "view_public_key", pod_to_hex(d.addr.m_view_public_key), a);
  put(item, "is_subaddress", d.is_subaddress, a);
  put(item, "is_integrated", d.is_integrated, a);
  return item;
}

void plan_reply(const tools::wallet2 &wallet, const std::vector<Exported> &owned,
                const std::string &hex, rapidjson::Document &reply) {
  auto &a = reply.GetAllocator();
  tools::wallet2::unsigned_tx_set set;
  require(wallet.parse_unsigned_tx_from_str(unhex(hex), set), "invalid unsigned tx set");
  require(set.txes.size() == 1, "exactly one unsigned transaction is required");
  const auto &tx = set.txes.front();
  require(tx.use_rct && tx.use_view_tags && tx.rct_config.bp_version == 4,
          "not a CLSAG + Bulletproofs+ transaction with view tags");

  /* Core's cold-signing export carries the short payment ID in the clear
   * (wallet2 get_construction_data_with_decrypted_short_payment_id); a
   * transaction without one carries the all-zero dummy. */
  crypto::hash8 payment_id = crypto::null_hash8;
  std::vector<cryptonote::tx_extra_field> extra;
  require(cryptonote::parse_tx_extra(tx.extra, extra), "invalid tx extra");
  for (const auto &entry : extra) {
    if (boost::get<cryptonote::tx_extra_pub_key>(&entry) ||
        boost::get<cryptonote::tx_extra_additional_pub_keys>(&entry))
      continue; /* the watch wallet's placeholders; the device makes its own */
    const auto *nonce = boost::get<cryptonote::tx_extra_nonce>(&entry);
    require(nonce && cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(nonce->nonce, payment_id),
            "tx extra carries something other than a short payment ID");
  }

  put(reply, "account", uint64_t(tx.subaddr_account), a);
  put(reply, "unlock_time", tx.unlock_time, a);
  uint64_t in = 0, out = 0;
  Json inputs(rapidjson::kArrayType), outputs(rapidjson::kArrayType);
  for (const auto &source : tx.sources) {
    require(source.rct && source.real_output < source.outputs.size(), "invalid source");
    const auto &real = source.outputs[source.real_output];
    /* The subaddress that received the real output: from the wallet's own
     * record of it. */
    const Exported *record = nullptr;
    for (const auto &o : owned)
      if (o.m_global_output_index == real.first && rct::pk2rct(o.m_pubkey) == real.second.dest)
        record = &o;
    require(record, "a source is not one of the wallet's exported outputs");
    Json input(rapidjson::kObjectType), ring(rapidjson::kArrayType);
    put(input, "amount", source.amount, a);
    put(input, "mask", pod_to_hex(source.mask), a);
    put(input, "real_index", source.real_output, a);
    put(input, "tx_public_key", pod_to_hex(source.real_out_tx_key), a);
    input.AddMember("additional_tx_public_keys", keys_json(source.real_out_additional_tx_keys, a), a);
    put(input, "output_index", source.real_output_in_tx_index, a);
    put(input, "subaddress_major", uint64_t(record->m_subaddr_index_major), a);
    put(input, "subaddress_minor", uint64_t(record->m_subaddr_index_minor), a);
    for (const auto &member : source.outputs) {
      Json item(rapidjson::kObjectType);
      put(item, "global_index", member.first, a);
      put(item, "public_key", pod_to_hex(member.second.dest), a);
      put(item, "commitment", pod_to_hex(member.second.mask), a);
      ring.PushBack(item, a);
    }
    input.AddMember("ring", ring, a);
    inputs.PushBack(input, a);
    in += source.amount;
  }
  bool integrated = false;
  for (const auto &d : tx.splitted_dsts) {
    outputs.PushBack(destination_json(d, a), a);
    integrated |= d.is_integrated;
    out += d.amount;
  }
  require(in >= out, "outputs exceed inputs");
  put(reply, "fee", in - out, a);
  if (integrated) put(reply, "payment_id", pod_to_hex(payment_id), a);
  reply.AddMember("inputs", inputs, a);
  reply.AddMember("outputs", outputs, a);
  reply.AddMember("change", destination_json(tx.change_dts, a), a);
}
}  // namespace

int main() {
  mlog_configure("", false);
  mlog_set_log("0");
  rapidjson::Document reply;
  reply.SetObject();
  int status = 0;
  try {
    const std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    rapidjson::Document request;
    require(!request.Parse(input.data(), input.size()).HasParseError() && request.IsObject(), "invalid JSON request");
    require(!request.HasMember("spend_key"), "spend keys are never accepted");
    const std::string op = field(request, "op");
    cryptonote::address_parse_info address{};
    require(cryptonote::get_account_address_from_str(address, cryptonote::MAINNET, field(request, "address")) &&
            !address.is_subaddress && !address.has_payment_id, "a primary wallet address is required");
    crypto::secret_key view;
    require(epee::string_tools::hex_to_pod(field(request, "view_key"), view), "invalid view key");
    crypto::public_key view_public;
    require(crypto::secret_key_to_public_key(view, view_public) && view_public == address.address.m_view_public_key,
            "the view key does not match the address");
    tools::wallet2 wallet(cryptonote::MAINNET, 1, true);
    wallet.generate("", epee::wipeable_string(), address.address, view, false);
    require(wallet.watch_only(), "the adapter wallet must be watch-only");
    const auto outputs = outputs_of(wallet, field(request, "outputs_data_hex"));
    if (op == "outputs") outputs_reply(outputs, reply);
    else if (op == "plan") plan_reply(wallet, outputs, field(request, "unsigned_txset"), reply);
    else require(false, "unknown op");
    put(reply, "status", std::string("pass"), reply.GetAllocator());
  } catch (const std::exception &error) {
    reply.SetObject();
    put(reply, "status", std::string("error"), reply.GetAllocator());
    put(reply, "error", std::string(error.what()), reply.GetAllocator());
    status = 1;
  }
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  reply.Accept(writer);
  std::cout << buffer.GetString() << '\n';
  return status;
}
