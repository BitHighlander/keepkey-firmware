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

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/supervise.h"
#include "trezor/crypto/memzero.h"

#ifndef EMULATOR
#include <libopencm3/cm3/cortex.h>
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Button request ack */
static bool button_request_acked = false;

extern bool reset_msg_stack;

static CONFIDENTIAL char strbuf[BODY_CHAR_MAX];

/* Scratch for confirm_helper()'s pagination. Static rather than stack: confirm
 * is reached from deep inside the signing call chains, and a 480-byte frame
 * there is what boot-faulted rc8. */
static CONFIDENTIAL char page_body[BODY_CHAR_MAX];
static char page_title[TITLE_CHAR_MAX];

/// Handler for push button being pressed.
/// \param context current state context.
static void handle_screen_press(void* context) {
  assert(context != NULL);

  StateInfo* si = (StateInfo*)context;

  if (button_request_acked) {
    switch (si->display_state) {
      case HOME:
        si->active_layout = LAYOUT_CONFIRM_ANIMATION;
        si->display_state = CONFIRM_WAIT;
        break;

      default:
        break;
    }
  }
}

/// Handler for push button being pressed.
/// \param context current state context.
static void handle_screen_release(void* context) {
  assert(context != NULL);

  StateInfo* si = (StateInfo*)context;

  switch (si->display_state) {
    case CONFIRM_WAIT:
      si->active_layout = LAYOUT_REQUEST_NO_ANIMATION;
      si->display_state = HOME;
      break;

    case CONFIRMED:
      si->active_layout = LAYOUT_FINISHED;
      si->display_state = FINISHED;
      break;

    default:
      break;
  }
}

/// User has held down the push button for duration as requested.
/// \param context current state context.
static void handle_confirm_timeout(void* context) {
  assert(context != NULL);

  StateInfo* si = (StateInfo*)context;
  si->display_state = CONFIRMED;
  si->active_layout = LAYOUT_CONFIRMED;
}

/// Changes the active layout of the confirmation screen.
/// \param active_layout The layout to swtich to.
/// \param si current state information.
/// \param layout_notification_func layout callback for displaying confirm
/// message.
static void swap_layout(ActiveLayout active_layout, volatile StateInfo* si,
                        layout_notification_t layout_notification_func) {
  switch (active_layout) {
    case LAYOUT_REQUEST:
      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_REQUEST);
      remove_runnable(&handle_confirm_timeout);
      break;

    case LAYOUT_REQUEST_NO_ANIMATION:
      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_REQUEST_NO_ANIMATION);
      remove_runnable(&handle_confirm_timeout);
      break;

    case LAYOUT_CONFIRM_ANIMATION:
      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_CONFIRM_ANIMATION);
      if (si->immediate) {
        post_delayed(&handle_confirm_timeout, (void*)si, 1);
      } else {
        post_delayed(&handle_confirm_timeout, (void*)si, CONFIRM_TIMEOUT_MS);
      }
      break;

    case LAYOUT_CONFIRMED:

      /* Finish confirming animation */
      while (is_animating()) {
        animate();
        display_refresh();
      }

      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_CONFIRMED);
      remove_runnable(&handle_confirm_timeout);
      break;

    default:
      assert(0);
  };
}

/// Common confirmation function.
/// \param request_title  The confirmation's title.
/// \param requesta_body  The body of the confirmation message.
/// \param layout_notification_func  layout callback for displaying confirm
/// message. \returns true iff the device confirmed.
static bool confirm_screen(const char* request_title_param,
                           const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate) {
  bool ret_stat = false;
  volatile StateInfo state_info;
  ActiveLayout new_layout, cur_layout;
  DisplayState new_ds;
  uint16_t tiny_msg;
  static CONFIDENTIAL uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];
  const char* request_title;
  request_title = request_title_param;

#if DEBUG_LINK
  const DebugLinkDecision* dld;
  bool debug_decided = false;
#endif

  layout_has_icon(iconNum == NO_ICON ? false : true);

  reset_msg_stack = false;

  memset((void*)&state_info, 0, sizeof(state_info));
  state_info.immediate = immediate;
  state_info.display_state = HOME;
  state_info.active_layout = LAYOUT_REQUEST;

  /* Request */
  state_info.lines[LAYOUT_REQUEST].request_title = request_title;
  state_info.lines[LAYOUT_REQUEST].request_body = request_body;
  state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_title = request_title;
  state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_body = request_body;

  /* Confirming */
  state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_title = request_title;
  state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_body = request_body;

  /* Confirmed */
  state_info.lines[LAYOUT_CONFIRMED].request_title = request_title;
  state_info.lines[LAYOUT_CONFIRMED].request_body = request_body;

  keepkey_button_set_on_press_handler(&handle_screen_press, (void*)&state_info);
  keepkey_button_set_on_release_handler(&handle_screen_release,
                                        (void*)&state_info);

  cur_layout = LAYOUT_INVALID;

  while (1) {
#ifndef EMULATOR
    svc_disable_interrupts();
#endif
    new_layout = state_info.active_layout;
    new_ds = state_info.display_state;
#ifndef EMULATOR
    svc_enable_interrupts();
#endif

    /* Don't process usb tiny message unless usb has been initialized */
#ifndef EMULATOR
    if (usbInitialized())
#else
    if (1)
#endif
    {
      /* Listen for tiny messages */
      tiny_msg = check_for_tiny_msg(msg_tiny_buf);

      switch (tiny_msg) {
        case MessageType_MessageType_ButtonAck:
          button_request_acked = true;
          break;

        case MessageType_MessageType_Cancel:
        case MessageType_MessageType_Initialize:
          if (tiny_msg == MessageType_MessageType_Initialize) {
            reset_msg_stack = true;
          }

          ret_stat = false;
          goto confirm_screen_exit;
#if DEBUG_LINK

        case MessageType_MessageType_DebugLinkDecision:
          dld = (DebugLinkDecision*)msg_tiny_buf;
          ret_stat = dld->yes_no;
          debug_decided = true;
          break;

        case MessageType_MessageType_DebugLinkGetState:
          call_msg_debug_link_get_state_handler(
              (DebugLinkGetState*)msg_tiny_buf);
          break;
#endif

        default:
          break; /* break from switch statement and stay in the while loop*/
      }
    }

    if (new_ds == FINISHED) {
      ret_stat = true;
      break; /* confirmation done.  Exiting function */
    }

    if (cur_layout != new_layout) {
      swap_layout(new_layout, &state_info, layout_notification_func);
      cur_layout = new_layout;
    }

#if DEBUG_LINK

    if (debug_decided && button_request_acked) {
      break; /* confirmation done via debug link.  Exiting function */
    }

#endif

    if (iconNum != NO_ICON) {
      layout_add_icon(iconNum);
    }

    display_constant_power(constant_power);

    display_refresh();
    animate();
  }

confirm_screen_exit:

  keepkey_button_set_on_press_handler(NULL, NULL);
  keepkey_button_set_on_release_handler(NULL, NULL);

  return (ret_stat);
}

size_t confirm_body_split(const char* body, uint16_t body_width, size_t index,
                          char* out) {
  if (!body) return 0;

  const Font* font = get_body_font();
  const size_t len = strlen(body);
  size_t pages = 0;

  for (size_t offset = 0; offset < len;) {
    const size_t take =
        calc_str_page(font, body + offset, len - offset, body_width, BODY_ROWS);
    /* A glyph wider than the whole body would never advance the offset. Report
     * failure rather than spin, or draw a screen that discloses nothing. */
    if (take == 0) return 0;

    if (out && pages == index) {
      memcpy(out, body + offset, take);
      out[take] = '\0';
    }

    offset += take;
    pages++;
  }

  /* An empty body is one (empty) page, as it has always been. */
  return pages ? pages : 1;
}

/// Show a confirmation, across as many screens as its body needs.
///
/// draw_string() renders until a character no longer fits the canvas and then
/// simply stops: a body longer than BODY_ROWS was drawn in part, with no
/// ellipsis and nothing to tell the user that the tail of an address, an
/// amount or a warning had been dropped. Every such body is now split into
/// screen-sized pages, each its own ButtonRequest and its own press, so a
/// screen either discloses its content or does not exist.
///
/// Bodies that already fit take exactly the path they did before: one page, no
/// page counter in the title.
///
/// \param button_request  Sent to the host before each page. NULL to send none.
/// \param request_title   Title of confirm message.
/// \param request_body    Body of confirm message.
/// \param layout_notification_func  layout callback for displaying confirm
/// message. \returns true iff the device confirmed every page.
static bool confirm_helper(const ButtonRequest* button_request,
                           const char* request_title, const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate) {
  /* Custom layouts place and size their own body — layout_zcash_address_text_
   * notification deliberately renders 106 characters as 38+38+30. Only the two
   * standard layouts are known to wrap at BODY_WIDTH over BODY_ROWS rows. */
  const bool standard =
      layout_notification_func == &layout_standard_notification;
  const bool pageable = standard || layout_notification_func ==
                                        &layout_constant_power_notification;

  uint16_t body_width = BODY_WIDTH;
  if (standard && iconNum != NO_ICON) {
    body_width = BODY_WIDTH_WITH_ICON;
  }

  const size_t pages =
      pageable ? confirm_body_split(request_body, body_width, 0, NULL) : 1;
  if (pages == 0) return false;

  if (pages == 1) {
    if (button_request) {
      msg_write(MessageType_MessageType_ButtonRequest, button_request);
    }
    return confirm_screen(request_title, request_body, layout_notification_func,
                          constant_power, iconNum, immediate);
  }

  for (size_t page = 0; page < pages; page++) {
    if (confirm_body_split(request_body, body_width, page, page_body) == 0) {
      return false;
    }
    snprintf(page_title, sizeof(page_title), "%s %u/%u", request_title,
             (unsigned)(page + 1), (unsigned)pages);

    if (button_request) {
      /* Each page is a fresh press the host has to be told about, and must not
       * be dismissable before it acks. */
      button_request_acked = false;
      msg_write(MessageType_MessageType_ButtonRequest, button_request);
    }

    const bool ok =
        confirm_screen(page_title, page_body, layout_notification_func,
                       constant_power, iconNum, immediate);
    memzero(page_body, sizeof(page_body));
    if (!ok) return false;
  }

  return true;
}

bool confirm(ButtonRequestType type, const char* request_title,
             const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret =
      confirm_helper(&resp, request_title, strbuf,
                     &layout_standard_notification, false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_icon(ButtonRequestType type, IconType iconNum,
                       const char* request_title, const char* request_body,
                       ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret =
      confirm_helper(&resp, request_title, strbuf,
                     &layout_standard_notification, false, iconNum, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_constant_power(ButtonRequestType type, const char* request_title,
                            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret =
      confirm_helper(&resp, request_title, strbuf,
                     &layout_constant_power_notification, true, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_button_request(const ButtonRequest* button_request,
                                        const char* request_title,
                                        const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  bool ret =
      confirm_helper(button_request, request_title, strbuf,
                     &layout_standard_notification, false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_layout(layout_notification_t layout_notification_func,
                                ButtonRequestType type,
                                const char* request_title,
                                const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret = confirm_helper(&resp, request_title, strbuf,
                            layout_notification_func, false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_without_button_request(const char* request_title,
                                    const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  bool ret =
      confirm_helper(NULL, request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review(ButtonRequestType type, const char* request_title,
            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret =
      confirm_helper(&resp, request_title, strbuf,
                     &layout_standard_notification, false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review_without_button_request(const char* request_title,
                                   const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  bool ret =
      confirm_helper(NULL, request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review_with_icon(ButtonRequestType type, IconType iconNum,
                      const char* request_title, const char* request_body,
                      ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret =
      confirm_helper(&resp, request_title, strbuf,
                     &layout_standard_notification, false, iconNum, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review_immediate(ButtonRequestType type, const char* request_title,
                      const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  va_end(vl);

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;

  bool ret =
      confirm_helper(&resp, request_title, strbuf,
                     &layout_standard_notification, false, NO_ICON, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}
