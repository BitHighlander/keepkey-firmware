/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined(EMULATOR)
// FIXME: cortex.h should really have these includes inside it.
#include <inttypes.h>
#include <stdbool.h>
#include <libopencm3/cm3/cortex.h>
#endif

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/util.h"

#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/coins.h"

#include "trezor/crypto/memzero.h"
#include "trezor/crypto/bignum.h"

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * confirm_cipher() - Show cipher confirmation
 *
 * INPUT
 *     - encrypt: true/false whether we are encrypting
 *     - key: string of key value
 * OUTPUT
 *     true/false of confirmation
 */
bool confirm_cipher(bool encrypt, const char* key) {
  bool ret_stat;

  if (encrypt) {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                       "Encrypt Key Value", "%s", key);
  } else {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                       "Decrypt Key Value", "%s", key);
  }

  return (ret_stat);
}

/*
 * confirm_transfer_output() - Show transfer output confirmation
 *
 * INPUT -
 *      - button_request: button request type
 *      - amount: amount to send
 *      - to: who to send to
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transfer_output(ButtonRequestType button_request,
                             const char* amount, const char* to) {
  return confirm_with_custom_layout(&layout_notification_no_title_bold,
                                    button_request, "", "Transfer %s\nto %s",
                                    amount, to);
}

/*
 * confirm_transaction_output() - Show transaction output confirmation
 *
 * INPUT -
 *      - button_request: button request type
 *      - amount: amount to send
 *      - to: who to send to
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transaction_output(ButtonRequestType button_request,
                                const char* amount, const char* to) {
  return confirm_with_custom_layout(&layout_notification_no_title_bold,
                                    button_request, "", "Send %s to\n%s",
                                    amount, to);
}

/*
 * confirm_transaction() - Show transaction summary confirmation
 *
 * INPUT -
 *      - total_amount: total transaction amount
 *      - fee: fee amount
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transaction(const char* total_amount, const char* fee) {
  if (!fee || strcmp(fee, "0.0 BTC") == 0) {
    return confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
                   "Do you want to send %s from your wallet?", total_amount);
  } else {
    return confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
                   "Do you want to send %s from your wallet? This includes a "
                   "transaction fee of %s.",
                   total_amount, fee);
  }
}

/*
 * confirm_load_device() - Show load device confirmation
 *
 * INPUT
 *     - is_node: true/false whether this is an hdnode
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_load_device(bool is_node) {
  bool ret_stat;

  if (is_node) {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_ImportPrivateKey,
                       "Import Private Key",
                       "Importing is not recommended unless you understand the "
                       "risks. Do you want to import private key?");
  } else {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_ImportRecoverySentence,
                       "Import Recovery Sentence",
                       "Importing is not recommended unless you understand the "
                       "risks. Do you want to import recovery sentence?");
  }

  return (ret_stat);
}

/* Use the custom address screen only when all text fits its real geometry.
 * A long address gets the standard pager; QR codes must never encode fragments
 * produced by paging a custom QR layout. */
static bool confirm_address_layout(layout_notification_t layout,
                                   const char* desc, const char* address) {
  if (!desc || !address || strlen(address) >= BODY_CHAR_MAX) return false;
  if (!app_layout_address_text_fits(layout, address)) {
    return confirm(ButtonRequestType_ButtonRequest_Address, desc, "%s",
                   address);
  }
  return confirm_with_custom_layout(
      layout, ButtonRequestType_ButtonRequest_Address, desc, "%s", address);
}

/*
 * confirm_xpub() - Show extended public key confirmation
 *
 * INPUT
 *      - xpub: xpub to display as string
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_xpub(const char* node_str, const char* xpub) {
  return confirm_address_layout(&layout_xpub_notification, node_str, xpub);
}

/*
 * confirm_cosmos_address() - Show cosmos address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_cosmos_address(const char* desc, const char* address) {
  return confirm_address_layout(&layout_cosmos_address_notification, desc,
                                address);
}

/*
 * confirm_osmosis_address() - Show osmosis address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_osmosis_address(const char* desc, const char* address) {
  return confirm_address_layout(&layout_osmosis_address_notification, desc,
                                address);
}

/*
 * confirm_ethereum_address() - Show ethereum address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_ethereum_address(const char* desc, const char* address) {
  return confirm_address_layout(&layout_ethereum_address_notification, desc,
                                address);
}

/*
 * confirm_nano_address() - Show nano address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_nano_address(const char* desc, const char* address) {
  return confirm_address_layout(&layout_nano_address_notification, desc,
                                address);
}

/*
 * confirm_zcash_address() - Show zcash address confirmation
 *
 * INPUT
 *      - desc: description (title) shown on both screens
 *      - address: zcash unified address — full text on the first screen,
 *        QR on the second
 * OUTPUT
 *     true/false of confirmation
 *
 */
#if ZCASH_PRIVACY
bool confirm_zcash_address_text(const char* desc, const char* address) {
  return confirm_address_layout(&layout_zcash_address_text_notification, desc,
                                address);
}

bool confirm_zcash_address(const char* desc, const char* address) {
  if (!confirm_zcash_address_text(desc, address)) {
    return false;
  }

  return confirm_with_custom_layout(&layout_zcash_address_notification,
                                    ButtonRequestType_ButtonRequest_Address,
                                    desc, "%s", address);
}
#endif

/*
 * confirm_address() - Show address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_address(const char* desc, const char* address) {
  return confirm_with_custom_layout(&layout_address_notification,
                                    ButtonRequestType_ButtonRequest_Address,
                                    desc, "%s", address);
}

/*
 * confirm_sign_identity() - Show identity confirmation
 *
 * INPUT
 *      - identity: identity information from protocol buffer
 *      - challenge: challenge string
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_sign_identity(const IdentityType* identity,
                           const char* challenge) {
  char title[CONFIRM_SIGN_IDENTITY_TITLE], body[CONFIRM_SIGN_IDENTITY_BODY];

  /* Format protocol */
  if (identity->has_proto && identity->proto[0]) {
    strlcpy(title, identity->proto, sizeof(title));
    kk_strupr(title);
    strlcat(title, " login to: ", sizeof(title));
  } else {
    strlcpy(title, "Login to: ", sizeof(title));
  }

  /* Format host and port */
  if (identity->has_host && identity->host[0]) {
    strlcpy(body, "host: ", sizeof(body));
    strlcat(body, identity->host, sizeof(body));

    if (identity->has_port && identity->port[0]) {
      strlcat(body, ":", sizeof(body));
      strlcat(body, identity->port, sizeof(body));
    }

    strlcat(body, "\n", sizeof(body));
  } else {
    body[0] = 0;
  }

  /* Format user */
  if (identity->has_user && identity->user[0]) {
    strlcat(body, "user: ", sizeof(body));
    strlcat(body, identity->user, sizeof(body));
    strlcat(body, "\n", sizeof(body));
  }

  /* Format challenge */
  if (challenge && strlen(challenge) != 0) {
    strlcat(body, challenge, sizeof(body));
  }

  return confirm(ButtonRequestType_ButtonRequest_SignIdentity, title, "%s",
                 body);
}

static size_t confirm_byte_token(uint8_t byte, char token[5]) {
  if (byte >= 0x21 && byte <= 0x7e && byte != '\\') {
    token[0] = (char)byte;
    token[1] = '\0';
    return 1;
  }

  snprintf(token, 5, "\\x%02X", byte);
  return 4;
}

size_t confirm_bytes_format_page(const uint8_t* data, size_t size, char* out,
                                 size_t out_len) {
  if ((!data && size != 0) || !out || out_len == 0) return 0;

  out[0] = '\0';
  size_t used = 0;
  size_t consumed = 0;
  while (consumed < size) {
    char token[5];
    const size_t token_len = confirm_byte_token(data[consumed], token);
    if (used >= out_len - 1 || token_len > (out_len - 1) - used) break;

    memcpy(out + used, token, token_len + 1);
    if (calc_str_line(get_body_font(), out, BODY_WIDTH) > BODY_ROWS) {
      out[used] = '\0';
      break;
    }

    used += token_len;
    consumed++;
  }

  return consumed;
}

bool confirm_bytes(ButtonRequestType button_request, const char* title,
                   const uint8_t* data, size_t size) {
  if (!title || (!data && size != 0)) return false;
  if (size == 0) return confirm(button_request, title, "(empty)");

  static char page_body[BODY_CHAR_MAX];
  static char page_title[TITLE_CHAR_MAX];
  bool approved = false;

  size_t pages = 0;
  size_t offset = 0;
  while (offset < size) {
    const size_t take = confirm_bytes_format_page(data + offset, size - offset,
                                                  page_body, sizeof(page_body));
    if (take == 0) goto cleanup;
    offset += take;
    pages++;
  }

  offset = 0;
  for (size_t page = 0; page < pages; page++) {
    const size_t take = confirm_bytes_format_page(data + offset, size - offset,
                                                  page_body, sizeof(page_body));
    if (take == 0) goto cleanup;

    int title_len;
    if (pages == 1) {
      title_len = snprintf(page_title, sizeof(page_title), "%s", title);
    } else {
      title_len = snprintf(page_title, sizeof(page_title), "%s %u/%u", title,
                           (unsigned)(page + 1), (unsigned)pages);
    }
    if (title_len < 0 || (size_t)title_len >= sizeof(page_title)) goto cleanup;

    if (!confirm(button_request, page_title, "%s", page_body)) goto cleanup;
    offset += take;
  }

  approved = true;

cleanup:
  memzero(page_body, sizeof(page_body));
  memzero(page_title, sizeof(page_title));
  return approved;
}

bool confirm_omni(ButtonRequestType button_request, const char* title,
                  const uint8_t* data, uint32_t size) {
  if (data && size == 20 && memcmp(data, "omni\0\0\0\0", 8) == 0) {
    uint32_t property_be, property;
    uint64_t amount_be, amount;
    memcpy(&property_be, data + 8, sizeof(property_be));
    memcpy(&amount_be, data + 12, sizeof(amount_be));
    REVERSE32(property_be, property);
    REVERSE64(amount_be, amount);
    /* OMNI and Test OMNI are protocol-defined divisible currencies. Other
     * properties need chain state to establish divisibility: disclose their
     * ID and raw amount without claiming a ticker or decimal precision. */
    if (property == 1 || property == 2) {
      char formatted[32];
      if (!bn_format_uint64(amount, NULL, property == 1 ? " OMNI" : " tOMNI", 8,
                            0, false, formatted, sizeof(formatted))) {
        return false;
      }
      return confirm(button_request, title, "Property #%" PRIu32 "\nSend %s?",
                     property, formatted);
    }
    return confirm(button_request, title,
                   "Property #%" PRIu32 "\nRaw amount: %" PRIu64
                   "\nDivisibility unknown",
                   property, amount);
  }
  /* Unsupported Omni messages still disclose every signed payload byte. */
  return confirm_bytes(button_request, title, data, size);
}

bool confirm_data(ButtonRequestType button_request, const char* title,
                  const uint8_t* data, uint32_t size) {
  /* OP_RETURN is signed byte-for-byte, so disclose it byte-for-byte. The old
   * non-ASCII path silently clamped at 50 bytes and then tested the already
   * clamped length, making its ".." marker unreachable. The ASCII path also
   * handed a size-delimited protobuf field to "%s", which assumes a trailing
   * NUL that the wire format does not promise. */
  return confirm_bytes(button_request, title, data, size);
}
