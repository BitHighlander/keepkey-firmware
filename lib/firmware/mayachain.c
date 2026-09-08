/*
 * This file is part of the Keepkey project.
 *
 * Copyright (C) 2021 Shapeshift
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/mayachain.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tendermint.h"
#include "messages-mayachain.pb.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/segwit_addr.h"

#include <stdbool.h>
#include <string.h>

bool mayachain_isValidDenom(const char* denom) {
  return tendermint_isValidDenom(denom);
}

bool mayachain_isValidAsset(const char* asset) {
  return tendermint_isValidAsset(asset);
}

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool initialized;
static bool has_message;
static uint32_t msgs_remaining;
static MayachainSignTx msg;
static bool testnet;

bool mayachain_isValidSigner(const char* signer) {
  return tendermint_isValidSigner(signer, testnet ? "smaya" : "maya");
}

const MayachainSignTx* mayachain_getMayachainSignTx(void) { return &msg; }

bool mayachain_signTxInit(const HDNode* _node, const MayachainSignTx* _msg) {
  initialized = true;
  msgs_remaining = _msg->msg_count;
  testnet = false;

  if (_msg->has_testnet) {
    testnet = _msg->testnet;
  }

  memzero(&node, sizeof(node));
  memcpy(&node, _node, sizeof(node));
  memcpy(&msg, _msg, sizeof(msg));

  bool success = true;
  char buffer[64 + 1];

  sha256_Init(&ctx);

  // Each segment guaranteed to be less than or equal to 64 bytes
  // 19 + ^20 + 1 = ^40
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "{\"account_number\":\"%" PRIu64 "\"",
                           msg.account_number))
    return false;

  // <escape chain_id>
  const char* const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t*)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, msg.chain_id, strlen(msg.chain_id));

  // 30 + ^10 + 19 = ^59
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32
                          "\",\"denom\":\"cacao\"}]",
                          msg.fee_amount);

  // 8 + ^10 + 2 = ^20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"gas\":\"%" PRIu32 "\"}", msg.gas);

  // <escape memo>
  const char* const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)memo_prefix, strlen(memo_prefix));
  if (msg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, msg.memo, strlen(msg.memo));
  }

  // 10
  sha256_Update(&ctx, (uint8_t*)"\",\"msgs\":[", 10);

  return success;
}

bool mayachain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom) {
  const char mainnetp[] = "maya";
  const char testnetp[] = "smaya";
  const char* pfix;
  char buffer[64 + 1];

  size_t decoded_len;
  char hrp[BECH32_MAX_HRP_LEN + 1];
  uint8_t decoded[BECH32_DECODED_MAX];
  if (!bech32_decode(hrp, decoded, &decoded_len, to_address)) {
    return false;
  }

  char from_address[46];

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  // Default to "cacao" for backward compatibility; validate all non-default
  // denoms. Defended here too (not just by the FSM caller) so this signing
  // path is safe even if called directly or reused elsewhere later.
  const char* coin_denom = (denom && denom[0]) ? denom : "cacao";
  if (!mayachain_isValidDenom(coin_denom)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"mayachain/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // Write amount prefix: 21 + ^20 = ^41
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":[{\"amount\":\"%" PRIu64 "\",\"denom\":\"", amount);
  // Use escaping as defense-in-depth; valid denoms have no escapable chars
  tendermint_sha256UpdateEscaped(&ctx, coin_denom, strlen(coin_denom));
  // Close coins array: 3 bytes
  sha256_Update(&ctx, (uint8_t*)"\"}]", 3);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool mayachain_signTxUpdateMsgDeposit(const MayachainMsgDeposit* depmsg) {
  char buffer[64 + 1];

  // Defended here too (not just by the FSM caller) so this signing path is
  // safe even if called directly or reused elsewhere later.
  if (!mayachain_isValidAsset(depmsg->asset) ||
      !mayachain_isValidSigner(depmsg->signer)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"mayachain/MsgDeposit\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // 20 + ^20 + 1 = ^41
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"coins\":[{\"amount\":\"%" PRIu64 "\"",
                                 depmsg->amount);

  // Use escaping as defense-in-depth; valid assets have no escapable chars
  const char* const asset_prefix = ",\"asset\":\"";
  sha256_Update(&ctx, (uint8_t*)asset_prefix, strlen(asset_prefix));
  tendermint_sha256UpdateEscaped(&ctx, depmsg->asset, strlen(depmsg->asset));
  sha256_Update(&ctx, (uint8_t*)"\"}]", 3);

  // <escape memo>
  const char* const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)memo_prefix, strlen(memo_prefix));
  tendermint_sha256UpdateEscaped(&ctx, depmsg->memo, strlen(depmsg->memo));

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\",\"signer\":\"%s\"}}", depmsg->signer);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool mayachain_signTxFinalize(uint8_t* public_key, uint8_t* signature) {
  char buffer[64 + 1];

  // 16 + ^20 = ^36
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64 "\"}", msg.sequence))
    return false;

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool mayachain_signingIsInited(void) { return initialized; }

bool mayachain_signingIsFinished(void) {
  return msgs_remaining == 0 && has_message;
}

void mayachain_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}
