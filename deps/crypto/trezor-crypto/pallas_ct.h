/**
 * Constant-time Pallas arithmetic for secret-scalar operations.
 *
 * This module intentionally has a narrow interface matching the legacy Pallas
 * API types.  Internally it uses fixed-width Montgomery arithmetic and
 * branchless Jacobian point operations.  It must be used for every operation
 * whose inputs include Orchard secret scalars.
 */

#ifndef __PALLAS_CT_H__
#define __PALLAS_CT_H__

#include "bignum.h"
#include "ecdsa.h"

/* Progress is reported from the fixed 255-round scalar schedule.  Both values
 * are public loop counters; callbacks must not inspect scalar data. */
typedef void (*pallas_ct_progress_callback)(uint32_t completed, uint32_t total,
                                            void* context);

void pallas_ct_mul_mod_p(bignum256* x, const bignum256* k);
void pallas_ct_add_mod_p(const bignum256* a, const bignum256* b,
                         bignum256* res);
void pallas_ct_sub_mod_p(const bignum256* a, const bignum256* b,
                         bignum256* res);
void pallas_ct_inv_mod_p(bignum256* x);
void pallas_ct_mod_p(bignum256* x);

void pallas_ct_mul_mod_q(bignum256* x, const bignum256* k);
void pallas_ct_add_mod_q(bignum256* a, const bignum256* b);
void pallas_ct_mod_q(bignum256* x);
void pallas_ct_scalar_replace_zero_with_one(bignum256* scalar);

void pallas_ct_point_add(const curve_point* p, const curve_point* q,
                         curve_point* res);
void pallas_ct_point_mult(const bignum256* k, const curve_point* p,
                          curve_point* res);
void pallas_ct_point_mult_progress(const bignum256* k, const curve_point* p,
                                   curve_point* res,
                                   pallas_ct_progress_callback progress,
                                   void* progress_context);

#ifdef PALLAS_CT_TESTING
typedef struct {
  uint32_t field_add;
  uint32_t field_sub;
  uint32_t field_mul;
  uint32_t field_select;
  uint32_t point_add;
  uint32_t point_double;
  uint32_t scalar_round;
} pallas_ct_counts;

void pallas_ct_test_reset_counts(void);
void pallas_ct_test_get_counts(pallas_ct_counts* counts);
#endif

#endif
