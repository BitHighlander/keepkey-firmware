#include "keepkey/firmware/erc7730_field.h"

#include <stdio.h>
#include <string.h>

#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"

bool erc7730_format_address(const uint8_t address[20], bool this_wallet,
                            char* output, size_t output_size) {
  const char* suffix = this_wallet ? "\n(this wallet)" : "";
  if (!address || !output || output_size < 43u + strlen(suffix)) {
    if (output && output_size) output[0] = '\0';
    return false;
  }
  output[0] = '0';
  output[1] = 'x';
  ethereum_address_checksum(address, output + 2, false, 0);
  strlcpy(output + 42, suffix, output_size - 42u);
  return true;
}

/* The exact unsigned decimal of a 256-bit big-endian value. */
static bool format_integer(const uint8_t amount[32], char* output,
                           size_t output_size) {
  bignum256 value;
  bn_read_be(amount, &value);
  const size_t written =
      bn_format(&value, NULL, NULL, 0, 0, false, output, output_size);
  memzero(&value, sizeof(value));
  return written != 0;
}

bool erc7730_format_token_amount(const uint8_t amount[32],
                                 const uint8_t token[20], bool native,
                                 uint64_t chain_id, const char* message,
                                 char* output, size_t output_size) {
  if (!amount || !token || !output || output_size == 0) return false;
  output[0] = '\0';
  static const uint8_t zero[20] = {0};
  const TokenType* known = NULL;
  if (chain_id <= UINT32_MAX && !native && memcmp(token, zero, 20) != 0) {
    known = tokenByChainAddress((uint32_t)chain_id, token);
    if (known == UnknownToken) known = NULL;
  }

  char value[160]; /* 78 digits + "\nunknown token\n0x" + 40 */
  bool ok;
  if (native || known) {
    bignum256 amnt;
    bn_read_be(amount, &amnt);
    /* The ordinary Ethereum review's own rendering: exact, with the ticker
     * from the token table or the chain's native symbol. */
    ok = chain_id <= UINT32_MAX &&
         ethereumFormatAmount(&amnt, native ? NULL : known, (uint32_t)chain_id,
                              value, sizeof(value));
    memzero(&amnt, sizeof(amnt));
  } else {
    char digits[80], checksummed[41];
    ethereum_address_checksum(token, checksummed, false, 0);
    ok = format_integer(amount, digits, sizeof(digits)) &&
         (size_t)snprintf(value, sizeof(value), "%s\nunknown token\n0x%s",
                          digits, checksummed) < sizeof(value);
    memzero(digits, sizeof(digits));
  }
  if (ok) {
    const int length =
        message ? snprintf(output, output_size, "%s\n%s", message, value)
                : snprintf(output, output_size, "%s", value);
    ok = length > 0 && (size_t)length < output_size;
  }
  if (!ok) output[0] = '\0';
  memzero(value, sizeof(value));
  return ok;
}
