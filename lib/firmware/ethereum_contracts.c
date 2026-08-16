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

#include "keepkey/firmware/ethereum.h"  // completes EthereumSignTx (msg fields)
#include "keepkey/firmware/ethereum_contracts/saproxy.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/ethereum_contracts/zxswap.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx* msg,
                              const HDNode* node) {
  (void)node;

  /* Only a CALL to a contract may be clear-signed, never a CREATE
   * (to.size == 0 must reach the deploy screen). */
  if (msg->to.size != 20) {
    return false;
  }

  /* 0x transformERC20 is pinned to the ExchangeProxy and bounded by its
   * displayed input/min-output amounts, so it is safe to clear-sign at ANY
   * calldata size; its transformations[] tail legitimately exceeds one 1024-
   * byte chunk. (It guards its own fixed-offset reads against
   * data_initial_chunk.size.) */
  if (zx_isZxTransformERC20(msg)) return true;

  /* Every other handler must have the ENTIRE calldata in the first chunk, so
   * the fields it parses and displays are the whole transaction and nothing
   * unshown streams in afterwards. */
  if (data_total != msg->data_initial_chunk.size) {
    return false;
  }

  if (sa_isWithdrawFromSalary(msg)) return true;
  if (zx_isZxSwap(msg)) return true;

  /* The Uniswap liquidity handlers are deliberately NOT claimed here.
   *
   * Claiming a contract suppresses the generic amount/recipient screen, so the
   * handler becomes the only thing the user sees. Both liquidity handlers are
   * unfit for that: zx_confirmZxLiquidTx never reads msg->value, so an
   * addLiquidityETH call displayed a modest "minimum ETH" while transferring
   * whatever the host asked for, and both handlers discard confirm() results
   * and return true regardless, so Reject did not stop signing.
   *
   * Falling through instead routes them down the generic path: the real value
   * and recipient are shown, and arbitrary calldata requires AdvancedMode.
   * Restore these only with the value displayed and every confirm() checked. */

  if (thor_isMayachainTx(msg)) return true;
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

  /* Uniswap liquidity: see ethereum_contractHandled(). Not dispatched. */

  if (thor_isMayachainTx(msg)) return thor_confirmMayaTx(data_total, msg);
  if (thor_isThorchainTx(msg)) return thor_confirmThorTx(data_total, msg);

  if (makerdao_isMakerDAO(data_total, msg))
    return makerdao_confirmMakerDAO(data_total, msg);

  return false;
}
