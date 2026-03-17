/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
 *
 * TRC-20 token definitions for on-device display.
 * Source: Trezor common/defs/tron/tokens.json
 */

#ifndef KEEPKEY_FIRMWARE_TRON_TOKENS_H
#define KEEPKEY_FIRMWARE_TRON_TOKENS_H

#include <stdint.h>
#include <string.h>

typedef struct {
    const char *address;   /* Base58Check contract address */
    const char *symbol;    /* Token ticker */
    uint8_t decimals;      /* Token decimals */
} TronToken;

static const TronToken tron_tokens[] = {
    {"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "USDT",  6},
    {"TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn", "USDD",  18},
    {"TSSMHYeV2uE9qYH95DqyoCuNCzEL1NvU3S", "SUN",   18},
    {"TCFLL5dx5ZJdKnWuesXxi1VPwjLVmWZZy9", "JST",   18},
    {"TAFjULxiVgT4qWk6UZwjqwZXTSaGaqnVp4", "BTT",   18},
    {"TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7", "WIN",   6},
    {"TXpw8XeWYeTUd4quDskoUqeQPowRh4jY65", "WBTC",  8},
    {"THb4CqiFdwNHsWsQCs4JhzwjMWys4aqCbF", "ETH",   18},
    {"TL1e26eRb7CgbNHLP53JYEoSqVAFSd4oVF", "USD1",  6},
    {"TUPM7K8REVzD2UdV4R5fe5M8XbnR2DdoJ6", "HTX",   18},
    {"TUpMhErZL2fhh4sVNULAbNKLokS4GjC1F4", "TUSD",  18},
    {"TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", "USDC",  6},
};

#define TRON_TOKEN_COUNT (sizeof(tron_tokens) / sizeof(tron_tokens[0]))

static inline const TronToken *tron_token_by_address(
    const char *contract_address) {
    for (size_t i = 0; i < TRON_TOKEN_COUNT; i++) {
        if (strcmp(tron_tokens[i].address, contract_address) == 0) {
            return &tron_tokens[i];
        }
    }
    return NULL;
}

#endif /* KEEPKEY_FIRMWARE_TRON_TOKENS_H */
