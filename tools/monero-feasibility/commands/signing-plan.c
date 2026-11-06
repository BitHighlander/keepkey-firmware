/* Bounded protobuf-to-Core conversion for the native-emulator experiment. */
#include "signing-plan.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "memzero.h"

static bool plan_error(monero_core_plan* plan, char* error, const char* text) {
  if (plan) memzero(plan, sizeof(*plan));
  if (error) snprintf(error, MONERO_CORE_ERROR_CAPACITY, "%s", text);
  return false;
}

static bool address_valid(const char address[96]) {
  static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  for (size_t i = 0; i < 95; ++i)
    if (!address[i] || !strchr(alphabet, address[i])) return false;
  return address[95] == '\0';
}

bool monero_signing_plan_from_message(const MoneroResearchSignTransaction* request,
                                      monero_core_plan* plan,
                                      char error[MONERO_CORE_ERROR_CAPACITY]) {
  if (error) error[0] = '\0';
  if (!request || !plan || !error)
    return plan_error(plan, error, "Missing Monero transaction plan");
  memzero(plan, sizeof(*plan));
  if (!monero_research_path_valid(request->address_n, request->address_n_count))
    return plan_error(plan, error, "Expected Monero path m/44'/128'/account'");
  plan->network = request->has_network_type ? request->network_type : 0;
  if (plan->network > 2)
    return plan_error(plan, error, "Invalid Monero transaction network");
  if (request->has_unlock_time && request->unlock_time != 0)
    return plan_error(plan, error, "Locked Monero transactions are not supported");
  if (!request->inputs_count || request->inputs_count > MONERO_CORE_MAX_INPUTS ||
      !request->outputs_count || request->outputs_count > MONERO_CORE_MAX_OUTPUTS)
    return plan_error(plan, error, "Monero transaction count exceeds research bounds");
  plan->input_count = request->inputs_count;
  plan->output_count = request->outputs_count;
  plan->fee = request->fee;
  for (size_t i = 0; i < plan->input_count; ++i) {
    const MoneroResearchSource* source = &request->inputs[i];
    monero_core_source* dest = &plan->sources[i];
    if (source->ring_count != MONERO_CORE_RING_SIZE ||
        source->real_member >= MONERO_CORE_RING_SIZE ||
        source->tx_public_key.size != 32 || source->mask.size != 32 ||
        source->additional_tx_public_keys_count > MONERO_CORE_MAX_ADDITIONAL_KEYS)
      return plan_error(plan, error, "Invalid Monero source dimensions");
    dest->amount = source->amount;
    dest->real_member = source->real_member;
    dest->output_index = source->output_index;
    dest->subaddress_major = source->subaddress_major;
    dest->subaddress_minor = source->subaddress_minor;
    memcpy(dest->tx_public_key, source->tx_public_key.bytes, 32);
    memcpy(dest->mask, source->mask.bytes, 32);
    dest->additional_key_count = source->additional_tx_public_keys_count;
    for (size_t j = 0; j < dest->additional_key_count; ++j) {
      if (source->additional_tx_public_keys[j].size != 32)
        return plan_error(plan, error, "Invalid additional Monero transaction key");
      memcpy(dest->additional_tx_public_keys[j], source->additional_tx_public_keys[j].bytes, 32);
    }
    for (size_t j = 0; j < MONERO_CORE_RING_SIZE; ++j) {
      const MoneroResearchRingMember* member = &source->ring[j];
      if (member->public_key.size != 32 || member->commitment.size != 32 ||
          (j && member->global_index <= source->ring[j-1].global_index))
        return plan_error(plan, error, "Invalid or unordered Monero ring member");
      dest->ring[j].global_index = member->global_index;
      memcpy(dest->ring[j].public_key, member->public_key.bytes, 32);
      memcpy(dest->ring[j].commitment, member->commitment.bytes, 32);
    }
  }
  for (size_t i = 0; i < plan->output_count; ++i) {
    const MoneroResearchDestination* source = &request->outputs[i];
    monero_core_destination* dest = &plan->destinations[i];
    if (!address_valid(source->address))
      return plan_error(plan, error, "Expected a complete Monero base or subaddress");
    dest->amount = source->amount;
    memcpy(dest->address, source->address, sizeof(dest->address));
    dest->is_change = source->has_is_change && source->is_change;
    if (!dest->is_change && (source->has_change_major || source->has_change_minor))
      return plan_error(plan, error, "Change indices require a change output");
    dest->change_major = source->has_change_major ? source->change_major : 0;
    dest->change_minor = source->has_change_minor ? source->change_minor : 0;
  }
  return true;
}

bool monero_signing_summary_matches(const monero_core_summary* approved,
                                     const monero_core_summary* current) {
  if (!approved || !current || !approved->output_count ||
      approved->output_count > MONERO_CORE_MAX_OUTPUTS ||
      approved->output_count != current->output_count ||
      approved->input_total != current->input_total ||
      approved->output_total != current->output_total ||
      approved->fee != current->fee ||
      memcmp(approved->plan_hash, current->plan_hash, 32)) return false;
  for (size_t i = 0; i < approved->output_count; ++i) {
    const monero_core_destination* a = &approved->destinations[i];
    const monero_core_destination* b = &current->destinations[i];
    if (!address_valid(a->address) || !address_valid(b->address) ||
        a->amount != b->amount || a->is_change != b->is_change ||
        a->change_major != b->change_major || a->change_minor != b->change_minor ||
        memcmp(a->address, b->address, sizeof(a->address))) return false;
  }
  return true;
}

bool monero_signing_summary_matches_plan(const monero_core_plan* plan,
                                          const monero_core_summary* summary) {
  if (!plan || !summary || !plan->input_count || !plan->output_count ||
      plan->input_count > MONERO_CORE_MAX_INPUTS ||
      plan->output_count > MONERO_CORE_MAX_OUTPUTS ||
      summary->output_count != plan->output_count || summary->fee != plan->fee)
    return false;
  uint64_t input_total = 0, output_total = 0;
  for (size_t i = 0; i < plan->input_count; ++i) {
    if (plan->sources[i].amount > UINT64_MAX - input_total) return false;
    input_total += plan->sources[i].amount;
  }
  for (size_t i = 0; i < plan->output_count; ++i) {
    const monero_core_destination* a = &plan->destinations[i];
    const monero_core_destination* b = &summary->destinations[i];
    if (a->amount > UINT64_MAX - output_total ||
        !address_valid(a->address) || !address_valid(b->address) ||
        a->amount != b->amount || a->is_change != b->is_change ||
        a->change_major != b->change_major || a->change_minor != b->change_minor ||
        memcmp(a->address, b->address, sizeof(a->address))) return false;
    output_total += a->amount;
  }
  return summary->input_total == input_total && summary->output_total == output_total &&
         plan->fee <= UINT64_MAX - output_total && output_total + plan->fee == input_total;
}

bool monero_signing_format_amount(uint64_t amount, char* out, size_t size) {
  if (!out || !size) return false;
  int written = snprintf(out, size, "%" PRIu64 ".%012" PRIu64 " XMR",
                         amount / UINT64_C(1000000000000),
                         amount % UINT64_C(1000000000000));
  if (written < 0 || (size_t)written >= size) {
    memzero(out, size);
    return false;
  }
  return true;
}
