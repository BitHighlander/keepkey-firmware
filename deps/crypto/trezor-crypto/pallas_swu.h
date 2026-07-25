/**
 * Copyright (c) 2026 KeepKey
 *
 * Pallas hash-to-curve primitives for Zcash Orchard.
 */

#ifndef __PALLAS_SWU_H__
#define __PALLAS_SWU_H__

#include <stddef.h>
#include <stdint.h>

#include "bignum.h"
#include "ecdsa.h"

typedef struct {
  bignum256 x;
  bignum256 y;
  bignum256 z;
} pallas_jacobian_point;

/*
 * Map a Pallas base-field element to the iso-Pallas curve using the
 * simplified SWU map used by pasta_curves.
 */
int pallas_map_to_curve_simple_swu(const uint8_t u_le[32],
                                   pallas_jacobian_point *out);

/* Apply the degree-3 isogeny from iso-Pallas to Pallas. */
int pallas_iso_map_to_pallas(const pallas_jacobian_point *iso,
                             curve_point *out);

/* Hash to Pallas using domain_prefix as in pasta_curves::Point::hash_to_curve. */
int pallas_hash_to_curve(const char *domain_prefix, const uint8_t *msg,
                         size_t msg_len, curve_point *out);

/* Alias for protocol GroupHash^Pallas call sites. */
int pallas_group_hash(const char *domain_prefix, const uint8_t *msg,
                      size_t msg_len, curve_point *out);

#endif
