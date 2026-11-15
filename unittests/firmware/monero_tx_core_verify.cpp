// Host tool: checks the transactions that firmware-unit's MoneroTx tests
// assemble from the device's replies, with unmodified Monero Core v0.18.5.4.
// Built and run by monero_tx_vectors_gen.sh; never part of firmware.
//
// Each record (written by monero_tx.cpp when KK_XMR_TX_RECORDS is set):
//   'T', expect, name, le32 size, transaction, prefix hash and CLSAG message
//   as the device reported them, le64 fee, inputs in transaction order (ring
//   of 16 x {le64 global index, key, commitment}, then the spend secret x of
//   the real member), 2 outputs (le64 amount, recipient view secret, address
//   spend key), payment ID and the view secret of who decrypts it.
//
//   'A', expect, name, network, address string, spend and view keys,
//   is_subaddress, is_integrated, payment ID: an address the device showed.
//   Core must parse it for that network to exactly those fields.
//
// A record expected to pass must: parse; be version 2, RingCT type 6, with
// tagged-key outputs and key-offset inputs matching the ring; have the
// prefix hash and the CLSAG message the device reported; pass Core's
// verRctSemanticsSimple (range proof, balance) and verRctNonSemanticsSimple
// (every CLSAG over the ring); have key images sorted as consensus needs and
// equal to Core's own for each spend secret; carry a sorted, parseable extra
// with one tx key, no additional keys and the encrypted payment ID; and each
// output must scan for its recipient: Core's derivation gives the output
// key and the view tag, and decodeRctSimple opens the commitment to the
// expected amount. A record expected to fail must fail Core's parse or
// verification. The header is written only if Core agrees with every record.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "device/device.hpp"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "version.h"

static std::vector<unsigned char> buf;
static size_t pos = 0;

static unsigned U8() { return buf.at(pos++); }
static uint64_t U(int bytes) {
  uint64_t v = 0;
  for (int b = 0; b < bytes; b++) v |= (uint64_t)U8() << (8 * b);
  return v;
}
static rct::key K() {
  rct::key k;
  memcpy(k.bytes, &buf.at(pos), 32);
  pos += 32;
  return k;
}

struct Input {
  uint64_t index[16];
  rct::ctkeyV ring;
  rct::key secret;
};
struct Output {
  uint64_t amount;
  rct::key view_secret, spend_public;
};

static std::string why;
#define REQUIRE(cond, text) \
  do {                      \
    if (!(cond)) {          \
      why = (text);         \
      return false;         \
    }                       \
  } while (0)

static bool verify(const std::string &blob, const rct::key &prefix_hash,
                   const rct::key &message, uint64_t fee,
                   const std::vector<Input> &inputs,
                   const std::vector<Output> &outputs,
                   const crypto::hash8 &payment_id,
                   const rct::key &pid_view_secret, bool full) {
  hw::device &hwdev = hw::get_device("default");
  cryptonote::transaction tx;
  REQUIRE(cryptonote::parse_and_validate_tx_from_blob(blob, tx), "parse");
  REQUIRE(tx.version == 2, "version");
  REQUIRE(tx.vin.size() == inputs.size(), "input count");
  REQUIRE(tx.vout.size() == outputs.size(), "output count");
  REQUIRE(cryptonote::check_inputs_types_supported(tx), "input types");
  REQUIRE(cryptonote::check_outs_valid(tx), "outs valid");
  REQUIRE(cryptonote::check_output_types(tx, 16), "output types at HF16");
  rct::rctSig &rv = tx.rct_signatures;
  REQUIRE(rv.type == rct::RCTTypeBulletproofPlus, "rct type");
  REQUIRE(rv.p.bulletproofs_plus.size() == 1, "one aggregate proof");
  REQUIRE(rv.p.CLSAGs.size() == inputs.size(), "CLSAG count");
  REQUIRE(rv.p.pseudoOuts.size() == inputs.size(), "pseudo-output count");

  // What consensus fills in before it verifies (Blockchain::
  // expand_transaction_2): the message, the rings and the key images.
  crypto::hash h;
  cryptonote::get_transaction_prefix_hash(tx, h);
  rv.message = rct::hash2rct(h);
  rv.mixRing.resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); i++) {
    const auto &in = boost::get<cryptonote::txin_to_key>(tx.vin[i]);
    rv.mixRing[i] = inputs[i].ring;
    rv.p.CLSAGs[i].I = rct::ki2rct(in.k_image);
  }
  const bool semantics = rct::verRctSemanticsSimple(rv);
  const bool signatures = semantics && rct::verRctNonSemanticsSimple(rv);
  REQUIRE(semantics, "verRctSemanticsSimple");
  REQUIRE(signatures, "verRctNonSemanticsSimple");
  if (!full) return true;

  REQUIRE(rv.message == prefix_hash, "device prefix hash");
  REQUIRE(rct::get_pre_mlsag_hash(rv, hwdev) == message,
          "device CLSAG message");
  REQUIRE(rv.txnFee == fee, "fee");

  for (size_t i = 0; i < inputs.size(); i++) {
    const auto &in = boost::get<cryptonote::txin_to_key>(tx.vin[i]);
    REQUIRE(in.amount == 0, "input amount");
    std::vector<uint64_t> absolute(inputs[i].index, inputs[i].index + 16);
    REQUIRE(in.key_offsets ==
                cryptonote::absolute_output_offsets_to_relative(absolute),
            "ring offsets");
    // Consensus: key images strictly decreasing.
    if (i > 0) {
      const auto &prev = boost::get<cryptonote::txin_to_key>(tx.vin[i - 1]);
      REQUIRE(memcmp(&prev.k_image, &in.k_image, 32) > 0, "input order");
    }
    // The key image is Core's own for the spend secret of a ring member.
    crypto::secret_key sec;
    crypto::public_key pub;
    crypto::key_image ki;
    memcpy((void *)&sec, inputs[i].secret.bytes, 32);
    REQUIRE(crypto::secret_key_to_public_key(sec, pub), "spend secret");
    crypto::generate_key_image(pub, sec, ki);
    REQUIRE(ki == in.k_image, "key image");
    bool member = false;
    for (const auto &m : inputs[i].ring)
      member = member || m.dest == rct::pk2rct(pub);
    REQUIRE(member, "real member in ring");
  }

  // Extra: sorted, one tx key, no additional keys, an encrypted payment ID.
  std::vector<cryptonote::tx_extra_field> fields;
  std::vector<uint8_t> sorted;
  REQUIRE(cryptonote::parse_tx_extra(tx.extra, fields), "parse extra");
  REQUIRE(cryptonote::sort_tx_extra(tx.extra, sorted) && sorted == tx.extra,
          "extra is in Core's order");
  const crypto::public_key R = cryptonote::get_tx_pub_key_from_extra(tx);
  REQUIRE(R != crypto::null_pkey, "tx public key");
  REQUIRE(cryptonote::get_additional_tx_pub_keys_from_extra(tx).empty(),
          "no additional keys");
  cryptonote::tx_extra_nonce nonce;
  crypto::hash8 pid8;
  REQUIRE(cryptonote::find_tx_extra_field_by_type(fields, nonce), "nonce");
  REQUIRE(cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(
              nonce.nonce, pid8),
          "encrypted payment ID");
  crypto::secret_key pid_sec;
  memcpy((void *)&pid_sec, pid_view_secret.bytes, 32);
  REQUIRE(hwdev.decrypt_payment_id(pid8, R, pid_sec), "decrypt payment ID");
  REQUIRE(pid8 == payment_id, "payment ID");

  // Each output, scanned as its recipient would.
  for (size_t j = 0; j < outputs.size(); j++) {
    crypto::secret_key view;
    crypto::public_key spend, expected, actual;
    crypto::key_derivation derivation;
    crypto::view_tag tag;
    crypto::secret_key scalar;
    memcpy((void *)&view, outputs[j].view_secret.bytes, 32);
    memcpy(&spend, outputs[j].spend_public.bytes, 32);
    REQUIRE(tx.vout[j].amount == 0, "output amount");
    REQUIRE(crypto::generate_key_derivation(R, view, derivation),
            "derivation");
    REQUIRE(crypto::derive_public_key(derivation, j, spend, expected),
            "derive output key");
    REQUIRE(cryptonote::get_output_public_key(tx.vout[j], actual),
            "output key");
    REQUIRE(actual == expected, "output key is the recipient's");
    crypto::derive_view_tag(derivation, j, tag);
    const boost::optional<crypto::view_tag> on_chain =
        cryptonote::get_output_view_tag(tx.vout[j]);
    REQUIRE(on_chain && *on_chain == tag, "view tag");
    crypto::derivation_to_scalar(derivation, j, scalar);
    rct::key mask;
    // Throws unless the amount and the mask open the commitment.
    const uint64_t amount =
        rct::decodeRctSimple(rv, rct::sk2rct(scalar), j, mask, hwdev);
    REQUIRE(amount == outputs[j].amount, "amount");
  }
  return true;
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  std::ifstream f(argv[1], std::ios::binary);
  buf.assign(std::istreambuf_iterator<char>(f), {});
  int records = 0, accepted = 0, rejected = 0, disagree = 0;
  int accepted_addresses = 0;
  std::string rows, address_rows;
  while (pos < buf.size()) {
    const unsigned record = U8();
    if (record == 'A') {
      const bool expect = U8() != 0;
      const size_t name_size = U8();
      const std::string name((const char *)&buf.at(pos), name_size);
      pos += name_size;
      const unsigned network = U8();
      const size_t length = U8();
      const std::string address((const char *)&buf.at(pos), length);
      pos += length;
      const rct::key spend = K(), view = K();
      const bool subaddress = U8() != 0, integrated = U8() != 0;
      crypto::hash8 payment_id;
      memcpy(&payment_id, &buf.at(pos), 8);
      pos += 8;
      const cryptonote::network_type nets[] = {
          cryptonote::MAINNET, cryptonote::TESTNET, cryptonote::STAGENET};
      cryptonote::address_parse_info info;
      bool ok = network < 3 && cryptonote::get_account_address_from_str(
                                   info, nets[network], address);
      ok = ok && rct::pk2rct(info.address.m_spend_public_key) == spend &&
           rct::pk2rct(info.address.m_view_public_key) == view &&
           info.is_subaddress == subaddress &&
           info.has_payment_id == integrated &&
           (!integrated || info.payment_id == payment_id);
      // And no other network takes it for its own.
      for (unsigned other = 0; ok && other < 3; other++) {
        cryptonote::address_parse_info wrong;
        if (other != network &&
            cryptonote::get_account_address_from_str(wrong, nets[other],
                                                     address))
          ok = false;
      }
      records++;
      (ok ? accepted_addresses : rejected)++;
      printf("%-28s %5zu ch core=%s\n", name.c_str(), length,
             ok ? "accept" : "reject");
      if (ok != expect) {
        disagree++;
        printf("  ^ expected %s\n", expect ? "accept" : "reject");
      }
      if (ok && expect)
        address_rows += "    {\"" + name + "\",\n     \"" + address +
                        "\"},\n";
      continue;
    }
    if (record != 'T') {
      printf("bad record tag\n");
      return 2;
    }
    const bool expect = U8() != 0;
    const size_t name_size = U8();
    const std::string name((const char *)&buf.at(pos), name_size);
    pos += name_size;
    const size_t size = (size_t)U(4);
    const std::string blob((const char *)&buf.at(pos), size);
    pos += size;
    const rct::key prefix_hash = K(), message = K();
    const uint64_t fee = U(8);
    std::vector<Input> inputs(U8());
    for (auto &in : inputs) {
      in.ring.resize(16);
      for (int i = 0; i < 16; i++) {
        in.index[i] = U(8);
        in.ring[i].dest = K();
        in.ring[i].mask = K();
      }
      in.secret = K();
    }
    std::vector<Output> outputs(2);
    for (auto &out : outputs) {
      out.amount = U(8);
      out.view_secret = K();
      out.spend_public = K();
    }
    crypto::hash8 payment_id;
    memcpy(&payment_id, &buf.at(pos), 8);
    pos += 8;
    const rct::key pid_view_secret = K();

    bool ok = false;
    why.clear();
    try {
      ok = verify(blob, prefix_hash, message, fee, inputs, outputs,
                  payment_id, pid_view_secret, expect);
    } catch (const std::exception &e) {
      why = std::string("exception: ") + e.what();
    }
    records++;
    (ok ? accepted : rejected)++;
    printf("%-28s %5zu B  core=%s%s%s\n", name.c_str(), size,
           ok ? "accept" : "reject", ok ? "" : "  at: ", why.c_str());
    if (ok != expect) {
      disagree++;
      printf("  ^ expected %s\n", expect ? "accept" : "reject");
    }
    if (ok && expect) {
      crypto::hash digest;
      crypto::cn_fast_hash(blob.data(), blob.size(), digest);
      char row[512];
      int n = snprintf(row, sizeof(row), "    {\"%s\", %zuu, {", name.c_str(),
                       size);
      std::string line(row, n);
      for (int i = 0; i < 32; i++) {
        n = snprintf(row, sizeof(row), "%s0x%02x", i ? ", " : "",
                     (unsigned char)digest.data[i]);
        line.append(row, n);
      }
      rows += line + "}},\n";
    }
  }
  const std::string core = std::string("v") + MONERO_VERSION;
  printf("core=%s records=%d accepted=%d addresses=%d rejected=%d "
         "disagreements=%d\n",
         core.c_str(), records, accepted, accepted_addresses, rejected,
         disagree);
  if (disagree || !accepted) return 1;

  FILE *out = fopen(argv[2], "w");
  if (!out) return 2;
  fprintf(out,
          "/* Generated by monero_tx_vectors_gen.sh. Do not edit.\n"
          " *\n"
          " * Each row is a transaction the MoneroTx unit tests assemble "
          "from the\n"
          " * signer's replies, with its size and Keccak-256. Monero Core %s\n"
          " * (monero_tx_core_verify.cpp) accepted every one of them, and "
          "rejected the\n"
          " * %d tampered copies recorded with them. */\n"
          "#ifndef MONERO_TX_VECTORS_H\n#define MONERO_TX_VECTORS_H\n\n"
          "#include <stddef.h>\n#include <stdint.h>\n\n"
          "#define MONERO_TX_VECTORS_CORE \"%s\"\n"
          "#define MONERO_TX_VECTORS_CORE_REJECTED %d\n\n"
          "typedef struct {\n  const char* name;\n  size_t size;\n"
          "  uint8_t keccak[32];\n} MoneroTxVector;\n\n"
          "static const MoneroTxVector monero_tx_vectors[] = {\n%s};\n\n"
          "#define MONERO_TX_VECTOR_COUNT %d\n\n"
          "/* Addresses the review showed; Core parsed each back to the "
          "same keys,\n * kind, payment ID and network. */\n"
          "typedef struct {\n  const char* name;\n  const char* address;\n"
          "} MoneroTxAddressVector;\n\n"
          "static const MoneroTxAddressVector monero_tx_address_vectors[] = "
          "{\n%s};\n\n"
          "#define MONERO_TX_ADDRESS_VECTOR_COUNT %d\n\n#endif\n",
          core.c_str(), rejected, core.c_str(), rejected, rows.c_str(),
          accepted, address_rows.c_str(), accepted_addresses);
  fclose(out);
  return 0;
}
