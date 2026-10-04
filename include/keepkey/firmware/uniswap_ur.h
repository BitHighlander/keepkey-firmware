/*
 * This file is part of the KeepKey project.
 *
 * Uniswap Universal Router execute() decoder. Pure parsing: no UI, no state.
 * A certified ClearSign entry selects it for one router on one chain; the
 * device then reads every value it shows from the calldata it signs.
 */

#ifndef KEEPKEY_FIRMWARE_UNISWAP_UR_H
#define KEEPKEY_FIRMWARE_UNISWAP_UR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The longest shape ur_summarize accepts: permit|wrap, swap, fee, final. */
#define UR_MAX_STEPS 4

typedef enum {
  UR_V3_SWAP_EXACT_IN,
  UR_V3_SWAP_EXACT_OUT,
  UR_V2_SWAP_EXACT_IN,
  UR_V2_SWAP_EXACT_OUT,
  UR_PERMIT2_PERMIT,
  UR_WRAP_ETH,
  UR_UNWRAP_WETH,
  UR_SWEEP,
  UR_PAY_PORTION,
  UR_TRANSFER,
} UrKind;

/* Recipient constants the router substitutes (Constants.sol). */
#define UR_RECIPIENT_MSG_SENDER 1
#define UR_RECIPIENT_ADDRESS_THIS 2

typedef struct {
  UrKind kind;
  /* Swaps: endpoints of the path. PERMIT2_PERMIT / SWEEP / PAY_PORTION /
   * TRANSFER: token_in is the token. */
  uint8_t token_in[20];
  /* Swaps: output token. PERMIT2_PERMIT: the spender (no output token). */
  uint8_t token_out[20];
  /* As encoded; 0x..01 and 0x..02 are the router's constants. */
  uint8_t recipient[20];
  /* Swaps: exact amount (in for EXACT_IN, out for EXACT_OUT).
   * WRAP / UNWRAP / SWEEP: minimum. PAY_PORTION: bips. TRANSFER: value.
   * PERMIT2_PERMIT: allowance (uint160). Big-endian. */
  uint8_t amount[32];
  /* Swaps: the limit (minimum out for EXACT_IN, maximum in for EXACT_OUT). */
  uint8_t limit[32];
  /* PERMIT2_PERMIT only. */
  uint64_t expiration;
  bool payer_is_user;
} UrStep;

typedef struct {
  uint8_t n;
  UrStep steps[UR_MAX_STEPS];
  bool has_deadline;
  uint64_t deadline;
} UrPlan;

/* execute(bytes,bytes[],uint256) and execute(bytes,bytes[]). Returns false on
 * any command or encoding it does not fully understand, so a caller never
 * shows a partial decode. */
bool ur_decode(const uint8_t* calldata, size_t len, UrPlan* out);

/* True for the router's MSG_SENDER / ADDRESS_THIS placeholders. */
bool ur_recipient_is_constant(const uint8_t recipient[20], uint8_t which);


/* What the user is asked to approve: one swap, how it is paid, where the
 * output goes, and any Permit2 allowance or fee riding along. */
typedef struct {
  bool exact_in;
  bool in_is_eth;  /* msg.value wrapped by the router */
  bool out_is_eth; /* output unwrapped to ETH */
  uint8_t token_in[20];
  uint8_t token_out[20];
  /* exact_in: spend exactly amount_in, receive at least amount_out.
   * !exact_in: spend at most amount_in, receive exactly amount_out. */
  uint8_t amount_in[32];
  uint8_t amount_out[32];
  bool recipient_is_sender;
  uint8_t recipient[20];
  bool has_permit;
  uint8_t permit_token[20];
  uint8_t permit_amount[32];
  uint64_t permit_expiration;
  bool has_fee;
  uint16_t fee_bips;
  uint8_t fee_recipient[20];
} UrSummary;

/* Accepts only [PERMIT2_PERMIT | WRAP_ETH] -> one swap (or a split of two
 * exact-in swaps of the same pair) -> [PAY_PORTION] ->
 * [SWEEP | UNWRAP_WETH] -> [clean-up: ETH back to the same recipient].
 * `router` is the contract being called (a permit must
 * name it as spender); `value` is msg.value, big-endian. False for any other
 * shape, so nothing partial is ever shown. */
bool ur_summarize(const UrPlan* plan, const uint8_t router[20],
                  const uint8_t value[32], UrSummary* out);

#endif
