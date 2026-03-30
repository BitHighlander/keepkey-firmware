/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts/thortx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/address.h"

/* Helper: format msg->to as lowercase hex string (40 chars + NUL) */
static void thor_format_to_addr(const EthereumSignTx *msg, char out[41]) {
  for (uint32_t i = 0; i < 20; i++) {
    snprintf(&out[i * 2], 3, "%02x", msg->to.bytes[i]);
  }
  out[40] = '\0';
}

/*
 * Match either THORChain/Maya router selector.
 * Both start with 4-byte selector followed by 12 zero-bytes (address padding).
 *
 * deposit(address,address,uint256,string)                   = 0x1fece7b4
 * depositWithExpiry(address,address,uint256,string,uint256) = 0x44bc937b
 *
 * The confirm path reads vault, asset, amount AND 64 bytes of memo data,
 * so we enforce the minimum chunk size here to avoid out-of-bounds reads
 * when the host streams calldata across multiple acks.
 *
 *   deposit():            memo at 4+5*32, +64 bytes → min 228
 *   depositWithExpiry():  memo at 4+6*32, +64 bytes → min 260
 *
 * If the initial chunk is too short, we decline to handle the tx and let
 * the normal signing path (signed-metadata or blind-signing) take over.
 */
#define THOR_MIN_CHUNK_DEPOSIT          228  /* 4 + 5*32 + 64 */
#define THOR_MIN_CHUNK_DEPOSIT_EXPIRY   260  /* 4 + 6*32 + 64 */

static bool thor_has_deposit_selector(const EthereumSignTx *msg) {
  if (!msg->has_to || msg->to.size != 20 ||
      msg->data_initial_chunk.size < 16)
    return false;

  const uint8_t *d = msg->data_initial_chunk.bytes;

  /* Check 12 zero-bytes of address padding (bytes 4-15) */
  static const uint8_t addr_pad[12] = {0};
  if (memcmp(d + 4, addr_pad, 12) != 0)
    return false;

  /* Match selector AND enforce minimum chunk for safe field access */
  if (memcmp(d, THOR_SELECTOR_DEPOSIT, 4) == 0)
    return msg->data_initial_chunk.size >= THOR_MIN_CHUNK_DEPOSIT;
  if (memcmp(d, THOR_SELECTOR_DEPOSIT_WITH_EXPIRY, 4) == 0)
    return msg->data_initial_chunk.size >= THOR_MIN_CHUNK_DEPOSIT_EXPIRY;

  return false;
}

/* Returns true when the calldata uses the modern depositWithExpiry selector */
static bool thor_is_expiry_variant(const EthereumSignTx *msg) {
  return memcmp(msg->data_initial_chunk.bytes,
                THOR_SELECTOR_DEPOSIT_WITH_EXPIRY, 4) == 0;
}

bool thor_isMayachainTx(const EthereumSignTx *msg) {
  if (!thor_has_deposit_selector(msg)) return false;
  char toStr[41];
  thor_format_to_addr(msg, toStr);
  return strncmp(toStr, MAYA_ROUTER, 40) == 0;
}

bool thor_isThorchainTx(const EthereumSignTx *msg) {
  /* Matches any deposit() or depositWithExpiry() call — Maya transactions are
   * a subset; call thor_isMayachainTx() first to distinguish them. */
  return thor_has_deposit_selector(msg);
}

/* Internal helper used by both thor_confirmThorTx and thor_confirmMayaTx.
 *
 * ABI layout (both variants share params 0-2 at identical offsets):
 *
 *   deposit(address vault, address asset, uint256 amount, string memo)
 *     vault  @ 4+12    asset @ 4+32+12   amount @ 4+2*32
 *     memo data        @ 4 + 5*32  (string offset = 0x80)
 *
 *   depositWithExpiry(address vault, address asset, uint256 amount,
 *                     string memo, uint256 expiry)
 *     vault  @ 4+12    asset @ 4+32+12   amount @ 4+2*32
 *     memo data        @ 4 + 6*32  (expiry pushes string data one word later)
 */
static bool thor_confirm_deposit_tx(uint32_t data_total, const EthereumSignTx *msg,
                                    const char *protocol_label,
                                    const char *router_label) {
    (void)data_total;

    char confStr[41];
    const char *conf;
    const TokenType *assetToken;
    uint8_t *thorchainData, *vaultAddress, *assetAddress, *contractAssetAddress;
    uint32_t ctr;
    bignum256 Amount;

    vaultAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 12);
    contractAssetAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 + 12);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &Amount);

    /* Memo location depends on which selector was used:
     *   deposit()            → 4 params → memo at 4 + 5*32
     *   depositWithExpiry()  → 5 params → memo at 4 + 6*32   */
    uint32_t memo_offset = thor_is_expiry_variant(msg)
        ? (4 + 6*32)
        : (4 + 5*32);
    thorchainData = (uint8_t *)(msg->data_initial_chunk.bytes + memo_offset);

    /* Show routing router */
    thor_format_to_addr(msg, confStr);
    if (strncmp(confStr, THOR_ROUTER, 40) == 0) {
        conf = "Thorchain router";
    } else if (strncmp(confStr, MAYA_ROUTER, 40) == 0) {
        conf = router_label;
    } else {
        conf = confStr;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             protocol_label, "Routing through %s", conf)) {
        return false;
    }

    /* Show Asgard vault address */
    for (ctr=0; ctr<20; ctr++) {
        snprintf(&confStr[ctr*2], 3, "%02x", vaultAddress[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             protocol_label, "Using Asgard vault %s", confStr)) {
        return false;
    }

    if (memcmp(contractAssetAddress, ETH_ADDRESS, sizeof(ETH_ADDRESS)) == 0) {
        assetAddress = (uint8_t *)ETH_NATIVE;
    } else {
        assetAddress = contractAssetAddress;
    }

    assetToken = tokenByChainAddress(msg->chain_id, assetAddress);

    if (strncmp(assetToken->ticker, " UNKN", 5) == 0) {
        for (ctr=0; ctr<20; ctr++) {
            snprintf(&confStr[ctr*2], 3, "%02x", assetAddress[ctr]);
        }
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 protocol_label, "from asset %s", confStr)) {
            return false;
        }
        bn_format(&Amount, NULL, " unformatted", 0, 0, false, confStr, sizeof(confStr));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 protocol_label, "amount %s", confStr)) {
            return false;
        }
    } else {
        ethereumFormatAmount(&Amount, assetToken, msg->chain_id, confStr,
                           sizeof(confStr));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     protocol_label, "Confirm sending %s", confStr)) {
            return false;
        }
    }

    if (!thorchain_parseConfirmMemo((const char *)thorchainData, 64))
        return false;

    return true;
}

bool thor_confirmThorTx(uint32_t data_total, const EthereumSignTx *msg) {
    return thor_confirm_deposit_tx(data_total, msg, "Thorchain data", "Thorchain router");
}

bool thor_confirmMayaTx(uint32_t data_total, const EthereumSignTx *msg) {
    return thor_confirm_deposit_tx(data_total, msg, "Maya data", "Maya router");
}
