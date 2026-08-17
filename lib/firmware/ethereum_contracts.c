/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
 * Copyright (C) 2019 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts.h"

#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts/saproxy.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/ethereum_contracts/zxswap.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"

bool zx_isExchangeProxyChain(uint32_t chain_id) {
  /* Optimism is deliberately absent: 0x deploys a DIFFERENT Exchange Proxy
     there (0xdef1abe32c034e558cdd535791643c58a13acc10), so allowing chain 10
     for ZXSWAP_ADDRESS would let the 0x decoder narrate an unrelated contract —
     exactly the confusion the chain scoping exists to prevent. Verified against
     0xProject/protocol packages/contract-addresses/addresses.json. */
  /* Base (8453), Arbitrum (42161) and Avalanche (43114) are deliberately absent
     even though 0x deploys the same Exchange Proxy there. The decoder can find
     the contract on those chains but cannot describe the trade, so allowing
     them would produce a screen that asserts understanding it does not have.

     TokenType.chain_id and tokenByChainAddress() are uint8_t
     (include/keepkey/firmware/ethereum_tokens.h:42,54), so those three chain
     ids truncate to 5, 177 and 106 -- values matching no table entry. The
     lookup returns UnknownToken and ethereumFormatAmount() short-circuits to
     the literal "Unknown token value" (lib/firmware/ethereum.c:347) for BOTH
     operands, so zx_confirmZxTransERC20() renders

         Transform ERC20
         Input Unknown token value
         Output Unknown token value

     while the transformations[] body executes. The whole justification for
     clear-signing transformERC20 is that the input amount and minimum output
     amount shown on screen bound the outcome; on these chains no amount is
     shown, so there is no bound and no disclosure -- a blind signature wearing
     a decoder's title.

     Denying them here routes those swaps to the generic raw-calldata path,
     which is AdvancedMode-gated and shows the bytes. That is the honest answer
     until the token table carries a full-width chain id (#455), at which point
     these three can be restored with their amounts actually rendering. */
  switch (chain_id) {
    case 1:   /* Ethereum  */
    case 56:  /* BNB Chain */
    case 137: /* Polygon   */
      return true;
    default:
      /* Including chain_id 0 / absent, which callers treat as unknown. */
      return false;
  }
}

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx* msg,
                              const HDNode* node) {
  (void)node;

  /* Every handler parses and displays fixed offsets inside the initial chunk
   * only. If the calldata does not fit in that chunk, the remainder streams
   * in via EthereumTxAck and is hashed into the signature without ever being
   * shown, so refuse to claim the tx and fall through to the generic raw-data
   * disclosure path. This gate runs BEFORE any decoder, including 0x
   * transformERC20, so a transformERC20 whose transformations[] tail exceeds
   * one 1024-byte chunk is NOT clear-signed blind: it falls through to raw
   * disclosure (AdvancedMode-gated). */
  if (data_total != msg->data_initial_chunk.size) return false;

  /* 0x transformERC20 is pinned to the ExchangeProxy address and its outcome
   * is bounded by the input amount and minimum output amount shown on screen,
   * so it stays clear-signable at any calldata size that fits one chunk. */
  if (zx_isZxTransformERC20(msg)) return true;

  if (sa_isWithdrawFromSalary(msg)) return true;
  if (zx_isZxSwap(msg)) return true;
  if (zx_isZxLiquidTx(msg)) return true;
  if (zx_isZxApproveLiquid(msg)) return true;

  if (thor_isThorchainTx(msg)) return true;

  if (makerdao_isMakerDAO(data_total, msg)) return true;

  return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx* msg,
                                const HDNode* node) {
  (void)node;

  if (sa_isWithdrawFromSalary(msg))
    return sa_confirmWithdrawFromSalary(data_total, msg);

  if (zx_isZxTransformERC20(msg))
    return zx_confirmZxTransERC20(data_total, msg);

  if (zx_isZxSwap(msg)) return zx_confirmZxSwap(data_total, msg);

  if (zx_isZxLiquidTx(msg)) return zx_confirmZxLiquidTx(data_total, msg);

  if (zx_isZxApproveLiquid(msg))
    return zx_confirmApproveLiquidity(data_total, msg);

  if (thor_isThorchainTx(msg)) return thor_confirmThorTx(data_total, msg);

  if (makerdao_isMakerDAO(data_total, msg))
    return makerdao_confirmMakerDAO(data_total, msg);

  return false;
}
