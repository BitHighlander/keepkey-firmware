/*
 * This file is part of the KeepKey project.
 *
 * Uniswap Universal Router execute() decoder, fed the calldata as it arrives.
 * Offsets are followed as Solidity's abi.decode (and the router's
 * CalldataDecoder) follows them, so the device reads the same values the
 * contract executes; they must point forward (uniswap_ur.h). Anything outside
 * the supported command set, a set allow-revert flag, or a value wider than
 * its declared type rejects the whole call.
 */

#include "keepkey/firmware/uniswap_ur.h"

#include <string.h>

/* Commands.sol */
#define CMD_V3_SWAP_EXACT_IN 0x00
#define CMD_V3_SWAP_EXACT_OUT 0x01
#define CMD_SWEEP 0x04
#define CMD_TRANSFER 0x05
#define CMD_PAY_PORTION 0x06
#define CMD_V2_SWAP_EXACT_IN 0x08
#define CMD_V2_SWAP_EXACT_OUT 0x09
#define CMD_PERMIT2_PERMIT 0x0a
#define CMD_WRAP_ETH 0x0b
#define CMD_UNWRAP_WETH 0x0c
/* Bit 7 is FLAG_ALLOW_REVERT; bit 6 is unused. Either set: not decoded. */
#define CMD_FLAGS 0xc0

#define V3_HOP 23 /* fee(3) + token(20) */

enum {
  S_SELECTOR,
  S_HEAD, /* execute()'s head words */
  S_CMDS_LEN,
  S_CMDS, /* the command bytes, one at a time */
  S_INPUTS_LEN,
  S_INPUT_HEAD, /* bytes[] element offsets */
  S_ELEM_LEN,
  S_FIELD,   /* an input's head words */
  S_DYN_LEN, /* an input's dynamic tail: its length word */
  S_V3_PATH, /* path bytes, one at a time */
  S_V2_PATH, /* path addresses */
  S_DONE,
};

/* An input head word: what it holds (high nibble) and where it goes. */
enum {
  F_ADDR = 0x10,
  F_U256 = 0x20,
  F_U160 = 0x30,
  F_U48 = 0x40,
  F_BOOL = 0x50,
  F_OFF = 0x60
};
enum {
  D_NONE,
  D_TOKEN_IN,
  D_TOKEN_OUT,
  D_RECIPIENT,
  D_AMOUNT,
  D_LIMIT,
  D_EXPIRATION,
  D_PAYER
};

/* (recipient, amount, limit, path, payerIsUser): a V3 path is bytes, a V2
 * path address[]. Later routers append a further dynamic argument, which is
 * not read, as abi.decode does not read it for the older shape. */
static const uint8_t SWAP_FIELDS[] = {F_ADDR | D_RECIPIENT, F_U256 | D_AMOUNT,
                                      F_U256 | D_LIMIT, F_OFF,
                                      F_BOOL | D_PAYER};
/* PermitSingle{details{token, amount, expiration, nonce}, spender,
 * sigDeadline} then bytes signature. */
static const uint8_t PERMIT_FIELDS[] = {F_ADDR | D_TOKEN_IN,
                                        F_U160 | D_AMOUNT,
                                        F_U48 | D_EXPIRATION,
                                        F_U48,
                                        F_ADDR | D_TOKEN_OUT,
                                        F_U256,
                                        F_OFF};
static const uint8_t WRAP_FIELDS[] = {F_ADDR | D_RECIPIENT, F_U256 | D_AMOUNT};
static const uint8_t SWEEP_FIELDS[] = {F_ADDR | D_TOKEN_IN,
                                       F_ADDR | D_RECIPIENT, F_U256 | D_AMOUNT};

typedef struct {
  uint8_t cmd;
  uint8_t kind;
  uint8_t nfields;
  const uint8_t* fields;
} Command;

static const Command COMMANDS[] = {
    {CMD_V3_SWAP_EXACT_IN, UR_V3_SWAP_EXACT_IN, 5, SWAP_FIELDS},
    {CMD_V3_SWAP_EXACT_OUT, UR_V3_SWAP_EXACT_OUT, 5, SWAP_FIELDS},
    {CMD_V2_SWAP_EXACT_IN, UR_V2_SWAP_EXACT_IN, 5, SWAP_FIELDS},
    {CMD_V2_SWAP_EXACT_OUT, UR_V2_SWAP_EXACT_OUT, 5, SWAP_FIELDS},
    {CMD_PERMIT2_PERMIT, UR_PERMIT2_PERMIT, 7, PERMIT_FIELDS},
    {CMD_WRAP_ETH, UR_WRAP_ETH, 2, WRAP_FIELDS},
    {CMD_UNWRAP_WETH, UR_UNWRAP_WETH, 2, WRAP_FIELDS},
    {CMD_SWEEP, UR_SWEEP, 3, SWEEP_FIELDS},
    {CMD_PAY_PORTION, UR_PAY_PORTION, 3, SWEEP_FIELDS},
    {CMD_TRANSFER, UR_TRANSFER, 3, SWEEP_FIELDS},
};

static const Command* command(uint8_t cmd) {
  for (size_t i = 0; i < sizeof(COMMANDS) / sizeof(COMMANDS[0]); i++) {
    if (COMMANDS[i].cmd == cmd) return &COMMANDS[i];
  }
  return NULL;
}

static bool fail(UrStream* s) {
  s->failed = true;
  return false;
}

/* The word's top 32 - `bytes` bytes are zero. Offsets and lengths use 4:
 * size_t is 32-bit on the device, so a wider value would wrap there while a
 * 64-bit host (and the router) read it in full. */
static bool narrow(const uint8_t w[32], size_t bytes, uint64_t* out) {
  uint64_t v = 0;
  for (size_t i = 0; i < 32; i++) {
    if (i < 32 - bytes && w[i] != 0) return false;
    v = (v << 8) | w[i];
  }
  if (out) *out = v;
  return true;
}

static bool word_u32(UrStream* s, uint32_t* out) {
  uint64_t v;
  if (!narrow(s->word, 4, &v)) return fail(s);
  *out = (uint32_t)v;
  return true;
}

/* The next field starts at `at`: never behind what was already read, never
 * past the end of the call. */
static bool next_at(UrStream* s, uint64_t at) {
  if (at < s->pos || at > s->total) return fail(s);
  s->at = (uint32_t)at;
  return true;
}

/* The next word of the current input, at `rel` into its payload: it must lie
 * inside the payload. */
static bool next_in_input(UrStream* s, uint64_t rel) {
  if (rel > s->len || s->len - rel < 32) return fail(s);
  return next_at(s, (uint64_t)s->base + rel);
}

static const Command* current(const UrStream* s) {
  return command(s->cmds[s->step]);
}

static UrStep* current_step(const UrStream* s) {
  return &s->plan->steps[s->step];
}

static bool next_input(UrStream* s) {
  if (s->step == s->ncmds) {
    s->state = S_DONE;
    return true;
  }
  s->state = S_ELEM_LEN;
  return next_at(s, (uint64_t)s->heads + s->elem[s->step]);
}

/* The input in hand is complete; the next one starts at or past its end. */
static bool input_done(UrStream* s) {
  const uint32_t end = s->base + s->len; /* <= total, checked at its length */
  s->step++;
  if (s->step < s->ncmds && (uint64_t)s->heads + s->elem[s->step] < end) {
    return fail(s);
  }
  return next_input(s);
}

static bool head_field(UrStream* s) {
  const Command* c = current(s);
  UrStep* st = current_step(s);
  const uint8_t f = c->fields[s->field];
  uint8_t* dst = NULL;
  switch (f & 0x0f) {
    case D_TOKEN_IN:
      dst = st->token_in;
      break;
    case D_TOKEN_OUT:
      dst = st->token_out;
      break;
    case D_RECIPIENT:
      dst = st->recipient;
      break;
    case D_AMOUNT:
      dst = st->amount;
      break;
    case D_LIMIT:
      dst = st->limit;
      break;
    default:
      break;
  }
  uint64_t v = 0;
  switch (f & 0xf0) {
    case F_ADDR:
      if (!narrow(s->word, 20, NULL)) return fail(s);
      if (dst) memcpy(dst, s->word + 12, 20);
      break;
    case F_U160:
      if (!narrow(s->word, 20, NULL)) return fail(s);
      /* fall through */
    case F_U256:
      if (dst) memcpy(dst, s->word, 32);
      break;
    case F_U48:
      if (!narrow(s->word, 6, &v)) return fail(s);
      if ((f & 0x0f) == D_EXPIRATION) st->expiration = v;
      break;
    case F_BOOL:
      if (!narrow(s->word, 1, &v) || v > 1) return fail(s);
      st->payer_is_user = v == 1;
      break;
    default: /* F_OFF: the dynamic tail, relative to the payload */
      if (!narrow(s->word, 4, &v)) return fail(s);
      s->n = (uint32_t)v;
      break;
  }
  s->field++;
  if (s->field < c->nfields) return next_in_input(s, 32u * s->field);
  bool tail = false;
  for (uint8_t i = 0; i < c->nfields; i++) tail = tail || c->fields[i] == F_OFF;
  if (!tail) return input_done(s); /* static input */
  s->state = S_DYN_LEN;
  return next_in_input(s, s->n);
}

/* The dynamic tail's length word: a V3 path, a V2 path, or the permit's
 * signature (whose bytes are not read). */
static bool dyn_len(UrStream* s) {
  const uint8_t kind = current(s)->kind;
  uint32_t n;
  if (!word_u32(s, &n)) return false;
  /* The payload starts right after this word. */
  const uint32_t start = s->pos - s->base;
  if (kind == UR_V2_SWAP_EXACT_IN || kind == UR_V2_SWAP_EXACT_OUT) {
    if (n < 2 || n > 8) return fail(s);
    s->n = n;
    s->k = 0;
    s->state = S_V2_PATH;
    return next_in_input(s, start);
  }
  if (n > s->len - start) return fail(s);
  if (kind == UR_PERMIT2_PERMIT) return input_done(s);
  /* V3 path: token(20) (fee(3) token(20))+ — at least one hop. */
  if (n < 20 + V3_HOP || (n - 20) % V3_HOP != 0) return fail(s);
  s->n = n;
  s->k = 0;
  s->state = S_V3_PATH;
  return next_at(s, s->pos);
}

static bool v3_path_byte(UrStream* s, uint8_t b) {
  UrStep* st = current_step(s);
  /* Exact-output paths are encoded output-first. */
  const bool exact_in = st->kind == UR_V3_SWAP_EXACT_IN;
  if (s->k < 20) (exact_in ? st->token_in : st->token_out)[s->k] = b;
  if (s->k >= s->n - 20) {
    (exact_in ? st->token_out : st->token_in)[s->k - (s->n - 20)] = b;
  }
  if (++s->k == s->n) return input_done(s);
  return next_at(s, s->pos);
}

static bool v2_path_word(UrStream* s) {
  UrStep* st = current_step(s);
  if (!narrow(s->word, 20, NULL)) return fail(s);
  if (s->k == 0) memcpy(st->token_in, s->word + 12, 20);
  if (s->k == s->n - 1) memcpy(st->token_out, s->word + 12, 20);
  if (++s->k == s->n) return input_done(s);
  return next_in_input(s, s->pos - s->base);
}

static bool on_byte(UrStream* s, uint8_t b) {
  if (s->state == S_CMDS) {
    if ((b & CMD_FLAGS) != 0 || !command(b)) return fail(s);
    s->cmds[s->k++] = b;
    if (s->k < s->ncmds) return next_at(s, s->pos);
    s->state = S_INPUTS_LEN;
    return next_at(s, (uint64_t)4 + s->heads);
  }
  return v3_path_byte(s, b);
}

static bool on_word(UrStream* s) {
  static const uint8_t SEL_DEADLINE[4] = {0x35, 0x93, 0x56, 0x4c};
  static const uint8_t SEL_NO_DEADLINE[4] = {0x24, 0x85, 0x6b, 0xc3};
  uint32_t v;
  switch (s->state) {
    case S_SELECTOR:
      if (memcmp(s->word, SEL_DEADLINE, 4) == 0) {
        s->plan->has_deadline = true;
      } else if (memcmp(s->word, SEL_NO_DEADLINE, 4) != 0) {
        return fail(s);
      }
      s->state = S_HEAD;
      return next_at(s, s->pos);
    case S_HEAD:
      /* commands offset, inputs offset[, deadline]: relative to the body. */
      if (s->field == 2) {
        if (!narrow(s->word, 8, &s->plan->deadline)) return fail(s);
      } else if (!word_u32(s, s->field == 0 ? &s->base : &s->heads)) {
        return false;
      }
      if (++s->field < (s->plan->has_deadline ? 3 : 2)) {
        return next_at(s, s->pos);
      }
      s->state = S_CMDS_LEN;
      return next_at(s, (uint64_t)4 + s->base);
    case S_CMDS_LEN:
      if (!word_u32(s, &v)) return false;
      if (v == 0 || v > UR_MAX_STEPS) return fail(s);
      s->ncmds = (uint8_t)v;
      s->k = 0;
      s->state = S_CMDS;
      return next_at(s, s->pos);
    case S_INPUTS_LEN:
      if (!word_u32(s, &v)) return false;
      if (v != s->ncmds) return fail(s);
      s->heads = s->pos; /* element heads are relative to the first one */
      s->k = 0;
      s->state = S_INPUT_HEAD;
      return next_at(s, s->pos);
    case S_INPUT_HEAD:
      if (!word_u32(s, &s->elem[s->k])) return false;
      if (++s->k < s->ncmds) return next_at(s, s->pos);
      s->step = 0;
      return next_input(s);
    case S_ELEM_LEN: {
      if (!word_u32(s, &s->len)) return false;
      if (s->len > s->total - s->pos) return fail(s);
      s->base = s->pos;
      UrStep* st = current_step(s);
      memset(st, 0, sizeof(*st));
      st->kind = (UrKind)current(s)->kind;
      s->field = 0;
      s->state = S_FIELD;
      return next_in_input(s, 0);
    }
    case S_FIELD:
      return head_field(s);
    case S_DYN_LEN:
      return dyn_len(s);
    case S_V2_PATH:
      return v2_path_word(s);
    default:
      return fail(s);
  }
}

void ur_stream_begin(UrStream* s, UrPlan* out, size_t total) {
  memset(s, 0, sizeof(*s));
  memset(out, 0, sizeof(*out));
  s->plan = out;
  if (total > UINT32_MAX) {
    s->failed = true;
    return;
  }
  s->total = (uint32_t)total;
  s->state = S_SELECTOR;
}

bool ur_stream_feed(UrStream* s, const uint8_t* data, size_t len) {
  if (len > s->total - s->pos) {
    s->pos = s->total;
    return fail(s);
  }
  for (size_t i = 0; i < len && !s->failed; i++) {
    const uint32_t off = s->pos++;
    if (off < s->at || s->state == S_DONE) continue; /* not read */
    if (s->state == S_CMDS || s->state == S_V3_PATH) {
      on_byte(s, data[i]);
      continue;
    }
    s->word[s->got++] = data[i];
    if (s->got == (s->state == S_SELECTOR ? 4 : 32)) {
      s->got = 0;
      on_word(s);
    }
  }
  return !s->failed;
}

bool ur_stream_finish(UrStream* s) {
  if (s->failed || s->state != S_DONE || s->pos != s->total) {
    if (s->plan) memset(s->plan, 0, sizeof(*s->plan));
    s->failed = true;
    return false;
  }
  s->plan->n = s->ncmds;
  return true;
}

bool ur_decode(const uint8_t* calldata, size_t len, UrPlan* out) {
  UrStream s;
  ur_stream_begin(&s, out, len);
  if (calldata && len) ur_stream_feed(&s, calldata, len);
  return ur_stream_finish(&s);
}

bool ur_recipient_is_constant(const uint8_t recipient[20], uint8_t which) {
  for (int i = 0; i < 19; i++) {
    if (recipient[i] != 0) return false;
  }
  return recipient[19] == which;
}

/* ActionConstants.CONTRACT_BALANCE: "everything the router holds". */
static bool is_contract_balance(const uint8_t a[32]) {
  if (a[0] != 0x80) return false;
  for (int i = 1; i < 32; i++) {
    if (a[i] != 0) return false;
  }
  return true;
}

static bool is_zero32(const uint8_t a[32]) {
  for (int i = 0; i < 32; i++) {
    if (a[i] != 0) return false;
  }
  return true;
}

/* The router itself, by placeholder or by its own address: either way it
 * holds the funds for a later step. Apps encode both. */
static bool is_router(const uint8_t r[20], const uint8_t router[20]) {
  return ur_recipient_is_constant(r, UR_RECIPIENT_ADDRESS_THIS) ||
         memcmp(r, router, 20) == 0;
}

/* a += b, big-endian; false on overflow. */
static bool add32(uint8_t a[32], const uint8_t b[32]) {
  unsigned carry = 0;
  for (int i = 31; i >= 0; i--) {
    carry += (unsigned)a[i] + b[i];
    a[i] = (uint8_t)carry;
    carry >>= 8;
  }
  return carry == 0;
}

static bool is_swap(UrKind k) {
  return k == UR_V3_SWAP_EXACT_IN || k == UR_V3_SWAP_EXACT_OUT ||
         k == UR_V2_SWAP_EXACT_IN || k == UR_V2_SWAP_EXACT_OUT;
}

bool ur_summarize(const UrPlan* plan, const uint8_t router[20],
                  const uint8_t value[32], UrSummary* out) {
  memset(out, 0, sizeof(*out));
  if (!plan || plan->n == 0) return false;
  size_t i = 0;
  const UrStep* permit = NULL;
  const UrStep* wrap = NULL;
  /* Before the swap: at most one permit or one wrap. */
  if (i < plan->n && plan->steps[i].kind == UR_PERMIT2_PERMIT) {
    permit = &plan->steps[i++];
  } else if (i < plan->n && plan->steps[i].kind == UR_WRAP_ETH) {
    wrap = &plan->steps[i++];
  }
  if (i >= plan->n || !is_swap(plan->steps[i].kind)) return false;
  const UrStep* swap = &plan->steps[i++];
  /* A split route: a second exact-in swap of the same pair, paid and
   * delivered the same way. Its totals are what the user spends and is
   * guaranteed (each swap enforces its own minimum). */
  UrStep split;
  if (i < plan->n && is_swap(plan->steps[i].kind)) {
    const UrStep* b = &plan->steps[i++];
    const bool in_a = swap->kind == UR_V3_SWAP_EXACT_IN ||
                      swap->kind == UR_V2_SWAP_EXACT_IN;
    const bool in_b =
        b->kind == UR_V3_SWAP_EXACT_IN || b->kind == UR_V2_SWAP_EXACT_IN;
    split = *swap;
    if (!in_a || !in_b || memcmp(b->token_in, swap->token_in, 20) != 0 ||
        memcmp(b->token_out, swap->token_out, 20) != 0 ||
        memcmp(b->recipient, swap->recipient, 20) != 0 ||
        b->payer_is_user != swap->payer_is_user ||
        is_contract_balance(swap->amount) || is_contract_balance(b->amount) ||
        !add32(split.amount, b->amount) || !add32(split.limit, b->limit)) {
      return false;
    }
    swap = &split;
  }
  const UrStep* fee = NULL;
  const UrStep* tail[2] = {NULL, NULL}; /* final, then clean-up */
  if (i < plan->n && plan->steps[i].kind == UR_PAY_PORTION) {
    fee = &plan->steps[i++];
  }
  for (int t = 0; t < 2 && i < plan->n &&
                  (plan->steps[i].kind == UR_SWEEP ||
                   plan->steps[i].kind == UR_UNWRAP_WETH);
       t++) {
    tail[t] = &plan->steps[i++];
  }
  if (i != plan->n) return false;
  const UrStep* final = tail[0];
  const UrStep* cleanup = tail[1];

  out->exact_in = swap->kind == UR_V3_SWAP_EXACT_IN ||
                  swap->kind == UR_V2_SWAP_EXACT_IN;
  memcpy(out->token_in, swap->token_in, 20);
  memcpy(out->token_out, swap->token_out, 20);

  /* Input side. */
  if (wrap) {
    /* ETH in: the router wraps msg.value and pays from its own balance.
     * Exact in spends all of it; exact out spends at most its limit, which
     * may not exceed what was sent (the rest is refunded, below). */
    if (swap->payer_is_user || is_zero32(value) ||
        !is_router(wrap->recipient, router) ||
        (memcmp(wrap->amount, value, 32) != 0 &&
         !is_contract_balance(wrap->amount)) ||
        (out->exact_in && memcmp(swap->amount, value, 32) != 0 &&
         !is_contract_balance(swap->amount)) ||
        (!out->exact_in && memcmp(swap->limit, value, 32) > 0)) {
      return false;
    }
    out->in_is_eth = true;
    memcpy(out->amount_in, value, 32);
  } else {
    /* Token in, pulled from the user through Permit2. */
    if (!is_zero32(value) || !swap->payer_is_user ||
        is_contract_balance(swap->amount)) {
      return false;
    }
    memcpy(out->amount_in, out->exact_in ? swap->amount : swap->limit, 32);
  }
  if (permit) {
    if (memcmp(permit->token_out /* spender */, router, 20) != 0 ||
        memcmp(permit->token_in, swap->token_in, 20) != 0) {
      return false;
    }
    out->has_permit = true;
    memcpy(out->permit_token, permit->token_in, 20);
    memcpy(out->permit_amount, permit->amount, 32);
    out->permit_expiration = permit->expiration;
  }

  /* Output side. */
  memcpy(out->amount_out, out->exact_in ? swap->limit : swap->amount, 32);
  const UrStep* deliver = swap;
  if (!is_router(swap->recipient, router)) {
    /* Delivered by the swap itself: what follows is clean-up. */
    if (fee || cleanup) return false;
    cleanup = final;
    goto delivered;
  }
  /* Held by the router: a final step must deliver it, after any fee. */
  if (!final || is_contract_balance(final->amount)) return false;
  if (final->kind == UR_SWEEP &&
      memcmp(final->token_in, swap->token_out, 20) != 0) {
    return false;
  }
  if (fee) {
    uint64_t bips = 0;
    for (int k = 24; k < 32; k++) bips = (bips << 8) | fee->amount[k];
    for (int k = 0; k < 24; k++) {
      if (fee->amount[k] != 0) return false;
    }
    if (bips == 0 || bips > 10000 ||
        memcmp(fee->token_in, swap->token_out, 20) != 0 ||
        is_router(fee->recipient, router)) {
      return false;
    }
    out->has_fee = true;
    out->fee_bips = (uint16_t)bips;
    memcpy(out->fee_recipient, fee->recipient, 20);
    /* The user's floor is what the final step guarantees after the fee. */
    if (out->exact_in) memcpy(out->amount_out, final->amount, 32);
  }
  if (is_router(final->recipient, router)) {
    return false;
  }
  /* Apps put the floor on the final step and leave the swap's limit at 0:
   * the user is guaranteed the larger of the two. */
  if (out->exact_in && !fee &&
      memcmp(final->amount, out->amount_out, 32) > 0) {
    memcpy(out->amount_out, final->amount, 32);
  }
  out->out_is_eth = final->kind == UR_UNWRAP_WETH;
  deliver = final;
delivered:
  /* Apps add one clean-up step returning leftover ETH (unwrapped, or swept
   * as address 0). Allowed only to the recipient the review names. */
  if (cleanup && (memcmp(cleanup->recipient, deliver->recipient, 20) != 0 ||
                  (cleanup->kind == UR_SWEEP &&
                   !ur_recipient_is_constant(cleanup->token_in, 0)))) {
    return false;
  }
  out->recipient_is_sender =
      ur_recipient_is_constant(deliver->recipient, UR_RECIPIENT_MSG_SENDER);
  memcpy(out->recipient, deliver->recipient, 20);
  return true;
}
