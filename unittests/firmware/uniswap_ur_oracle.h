/* Test oracle: the pre-streaming buffered decoder (uniswap_ur_oracle.c). */
#ifndef UNITTESTS_FIRMWARE_UNISWAP_UR_ORACLE_H
#define UNITTESTS_FIRMWARE_UNISWAP_UR_ORACLE_H

#include "keepkey/firmware/uniswap_ur.h"

#ifdef __cplusplus
extern "C" {
#endif

bool ur_oracle_decode(const uint8_t* calldata, size_t len, UrPlan* out);

#ifdef __cplusplus
}
#endif

#endif
