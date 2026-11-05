#ifndef KEEPKEY_MONERO_RESEARCH_H
#define KEEPKEY_MONERO_RESEARCH_H

/* Internal API of the explicitly selected native-emulator experiment. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(EMULATOR) || !defined(KK_MONERO_EMULATOR_RESEARCH) || \
    !KK_MONERO_EMULATOR_RESEARCH || BITCOIN_ONLY
/* The analyzer also explores unsupported build configurations; the compiler
 * must continue to reject those configurations at this exact boundary. */
// cppcheck-suppress preprocessorErrorDirective
#error "Monero research commands are limited to the regular firmware emulator"
#endif

#define MONERO_RESEARCH_ADDRESS_LENGTH 95u
#define MONERO_RESEARCH_ADDRESS_CAPACITY 96u

/* Accept exactly m/44'/128'/account'. Subaddresses are separate request fields. */
bool monero_research_path_valid(const uint32_t* path, size_t count);

const char* monero_research_network_name(uint32_t network);

/* node_key is the Ed25519 SLIP-0010 private node key, not a spend scalar.
 * Returns only public address text; this API never exports private keys. */
bool monero_research_get_address(
    const uint8_t node_key[32], uint32_t network, uint32_t major, uint32_t minor,
    char address[MONERO_RESEARCH_ADDRESS_CAPACITY]);

#endif
