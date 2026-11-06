#ifndef KEEPKEY_MONERO_SIGNING_PLAN_RESEARCH_H
#define KEEPKEY_MONERO_SIGNING_PLAN_RESEARCH_H

#include "monero_research.h"
#include "research-schema.h"
#include "core-signing.h"

#if !defined(KK_MONERO_CORE_SIGNING) || !KK_MONERO_CORE_SIGNING
#error "Monero transaction construction requires the explicit native Core experiment"
#endif

bool monero_signing_plan_from_message(const MoneroResearchSignTransaction* request,
                                      monero_core_plan* plan,
                                      char error[MONERO_CORE_ERROR_CAPACITY]);
bool monero_signing_summary_matches(const monero_core_summary* approved,
                                     const monero_core_summary* current);
bool monero_signing_summary_matches_plan(const monero_core_plan* plan,
                                          const monero_core_summary* summary);
bool monero_signing_format_amount(uint64_t amount, char* out, size_t size);

/* Defined with the synchronous FSM handler. Authorization revocation clears
 * the complete plan, summaries, transaction buffer, and grant. */
bool monero_signing_active(void);
void monero_signing_abort(void);
bool monero_signing_state_is_zero(void);

#endif
