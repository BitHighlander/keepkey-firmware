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
static CONFIDENTIAL char scroll_body[BODY_CHAR_MAX];
static CONFIDENTIAL char scroll_title[TITLE_CHAR_MAX];

typedef struct {
  bool enabled;
  volatile bool advance;
  const uint8_t* data;
  size_t size;
  size_t offset;
  size_t page;
  size_t pages;
  uint16_t body_width;
  confirm_page_formatter_t formatter;
  const char* title;
} ScrollInfo;

typedef struct {
  volatile StateInfo* state;
  volatile ScrollInfo* scroll;
} ScreenContext;

/* Set by format_body() when the formatted body did not fit strbuf, i.e. when
 * characters were lost before any screen existed to show them. Read and
 * cleared by confirm_helper(). Truncation here is invisible to every later
 * check: what reaches the renderer is a complete, well-formed, shorter string,
 * so the screen looks correct and is not. */
static bool body_truncated = false;

/* The single place a host-supplied body is formatted. vsnprintf() returns the
 * length it WOULD have written, which is the only chance to notice that
 * strbuf was too small -- after this, the evidence is gone. */
static void format_body(const char* request_body, va_list vl) {
  const int needed = vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  body_truncated = (needed < 0) || ((size_t)needed >= sizeof(strbuf));
}

/// Handler for push button being pressed.
/// \param context current state context.
static void handle_screen_press(void* context) {
  assert(context != NULL);

  ScreenContext* screen = (ScreenContext*)context;

  if (button_request_acked) {
    volatile StateInfo* si = screen->state;
    const volatile ScrollInfo* scroll = screen->scroll;
    switch (si->display_state) {
      case HOME:
        if (scroll->enabled && scroll->offset < scroll->size) {
          si->active_layout = LAYOUT_REQUEST_NO_ANIMATION;
          si->display_state = SCROLLING;
        } else {
          si->active_layout = LAYOUT_CONFIRM_ANIMATION;
          si->display_state = CONFIRM_WAIT;
        }
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

  ScreenContext* screen = (ScreenContext*)context;
  volatile StateInfo* si = screen->state;

  switch (si->display_state) {
    case SCROLLING:
      /* Pause on exactly the page that is currently visible. Reaching the end
       * still comes back through HOME, so approval requires a fresh press. */
      si->active_layout = LAYOUT_REQUEST_NO_ANIMATION;
      si->display_state = HOME;
      break;

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

/// Ask the main loop to advance one page. Formatting and drawing stay out of
/// the timer interrupt so the OLED never reads a page buffer while it changes.
static void handle_scroll_timeout(void* context) {
  assert(context != NULL);

  ScreenContext* screen = (ScreenContext*)context;
  if (screen->state->display_state == SCROLLING) {
    screen->scroll->advance = true;
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

static size_t count_scroll_pages(const uint8_t* data, size_t size,
                                 confirm_page_formatter_t formatter,
                                 uint16_t body_width) {
  size_t pages = 0;
  size_t offset = 0;

  while (offset < size) {
    const size_t take = formatter(data + offset, size - offset, scroll_body,
                                  sizeof(scroll_body), body_width);
    if (take == 0 || take > size - offset) return 0;
    offset += take;
    pages++;
  }

  return pages;
}

static bool prepare_scroll_page(volatile ScrollInfo* scroll,
                                volatile StateInfo* state) {
  if (scroll->offset >= scroll->size) return false;

  const size_t take = scroll->formatter(
      scroll->data + scroll->offset, scroll->size - scroll->offset, scroll_body,
      sizeof(scroll_body), scroll->body_width);
  if (take == 0 || take > scroll->size - scroll->offset) return false;

  scroll->offset += take;
  scroll->page++;

  const int title_len =
      (scroll->pages > 1)
          ? snprintf(scroll_title, sizeof(scroll_title), "%s %u/%u",
                     scroll->title, (unsigned)scroll->page,
                     (unsigned)scroll->pages)
          : snprintf(scroll_title, sizeof(scroll_title), "%s", scroll->title);
  const char* page_title = scroll->title;
  if (title_len >= 0 && (size_t)title_len < sizeof(scroll_title)) {
    page_title = scroll_title;
  }

  for (size_t layout = LAYOUT_REQUEST; layout <= LAYOUT_CONFIRMED; layout++) {
    state->lines[layout].request_title = page_title;
    state->lines[layout].request_body = scroll_body;
  }

  return true;
}

/// Run one confirmation screen: draw it, then wait for either the user's hold
/// or the host's Cancel. Callers go through confirm_helper() below, which is
/// what the public confirm()/review() wrappers use.
/// \param request_title  The confirmation's title.
/// \param requesta_body  The body of the confirmation message.
/// \param layout_notification_func  layout callback for displaying confirm
/// message. \returns true iff the device confirmed.
static bool confirm_screen(const char* request_title_param,
                           const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate, const uint8_t* page_data,
                           size_t page_size,
                           confirm_page_formatter_t page_formatter,
                           uint16_t page_body_width) {
  bool ret_stat = false;
  volatile StateInfo state_info;
  volatile ScrollInfo scroll_info;
  ScreenContext screen_context = {&state_info, &scroll_info};
  ActiveLayout new_layout, cur_layout;
  DisplayState new_ds;
  bool scroll_timer_pending = false;
  bool scroll_advance;
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
  memset((void*)&scroll_info, 0, sizeof(scroll_info));
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

  if (page_formatter != NULL) {
    scroll_info.data = page_data;
    scroll_info.size = page_size;
    scroll_info.formatter = page_formatter;
    scroll_info.body_width = page_body_width;
    scroll_info.title = request_title;
    scroll_info.pages = count_scroll_pages(page_data, page_size, page_formatter,
                                           page_body_width);
    if (scroll_info.pages == 0 ||
        !prepare_scroll_page(&scroll_info, &state_info)) {
      goto confirm_screen_exit;
    }
    scroll_info.enabled = scroll_info.pages > 1;
  }

  keepkey_button_set_on_press_handler(&handle_screen_press,
                                      (void*)&screen_context);
  keepkey_button_set_on_release_handler(&handle_screen_release,
                                        (void*)&screen_context);

  cur_layout = LAYOUT_INVALID;

  while (1) {
#ifndef EMULATOR
    svc_disable_interrupts();
#endif
    new_layout = state_info.active_layout;
    new_ds = state_info.display_state;
    scroll_advance = scroll_info.advance;
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

    if (new_ds != SCROLLING) {
      if (scroll_timer_pending) {
        remove_runnable(&handle_scroll_timeout);
        scroll_timer_pending = false;
      }
      scroll_info.advance = false;
    } else {
      bool page_advanced = false;

      if (scroll_advance) {
        scroll_info.advance = false;
        scroll_timer_pending = false;
        if (!prepare_scroll_page(&scroll_info, &state_info)) {
          ret_stat = false;
          goto confirm_screen_exit;
        }

        (*layout_notification_func)(
            state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_title,
            state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_body,
            NOTIFICATION_REQUEST_NO_ANIMATION);
        cur_layout = LAYOUT_REQUEST_NO_ANIMATION;
        page_advanced = true;
      }

      if (scroll_info.offset < scroll_info.size && !scroll_timer_pending) {
        post_delayed(&handle_scroll_timeout, (void*)&screen_context,
                     page_advanced ? CONFIRM_SCROLL_PERIOD_MS
                                   : CONFIRM_SCROLL_INITIAL_MS);
        scroll_timer_pending = true;
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

  remove_runnable(&handle_scroll_timeout);
  keepkey_button_set_on_press_handler(NULL, NULL);
  keepkey_button_set_on_release_handler(NULL, NULL);
  memzero(scroll_body, sizeof(scroll_body));
  memzero(scroll_title, sizeof(scroll_title));

  return (ret_stat);
}

bool confirm_body_fits(const char* body, uint16_t body_width) {
  /* This used to count rows with calc_str_line() and compare against
   * BODY_ROWS. That was a second model of the screen, and the attacker picks
   * the input on which the two models disagree: the guard has now been broken
   * three separate ways -- by plain overflow, by a uint8_t line counter
   * wrapping at 255 newlines, and by space padding that one walk collapses and
   * the other does not. Each fix taught the model one more rule that
   * draw_string() already knew.
   *
   * So there is no model any more. draw_string_fits() runs draw_string()'s own
   * loop and its own per-glyph fit test with the pixel writes switched off,
   * and reports whether the last character was placed. Measuring and drawing
   * cannot disagree because they are the same code.
   *
   * calc_str_line() survives here for one thing only, and it is not a security
   * decision: layout_standard_notification() uses it to pick the vertical
   * alignment, so the probe must start at the same sp.y the real draw will
   * start at. Both call it with the same arguments, so both get the same
   * answer -- and if that answer were ever wrong, the probe would be wrong in
   * exactly the way the real draw is, which is the property we want. */
  Canvas* canvas = layout_get_canvas();
  const Font* body_font = get_body_font();
  const char* str2 = body ? body : "";

  DrawableParams sp;
  const uint32_t body_line_count = calc_str_line(body_font, str2, body_width);
  sp.y = TOP_MARGIN;
  if (body_line_count == ONE_LINE) {
    sp.y = TOP_MARGIN_FOR_ONE_LINE;
  } else if (body_line_count == TWO_LINES) {
    sp.y = TOP_MARGIN_FOR_TWO_LINES;
  }

  /* Mirrors layout_standard_notification(): the title is drawn from sp.y, then
   * the body starts one title-height plus BODY_TOP_MARGIN below it. */
  sp.y += font_height(body_font) + BODY_TOP_MARGIN;
  sp.x = (body_width == BODY_WIDTH_WITH_ICON) ? LEFT_MARGIN_WITH_ICON
                                              : LEFT_MARGIN;
  sp.color = BODY_COLOR;

  return draw_string_fits(canvas, body_font, str2, &sp, body_width,
                          font_height(body_font) + BODY_FONT_LINE_PADDING);
}

size_t confirm_body_format_page(const uint8_t* data, size_t size, char* out,
                                size_t out_len, uint16_t body_width) {
  if ((!data && size != 0) || !out || out_len < 2 || body_width == 0) return 0;

  const size_t limit = size < out_len - 1 ? size : out_len - 1;
  size_t best = 0;

  /* Prefix fit is normally monotonic, but the standard layout vertically
   * re-centres one- and two-line bodies. Scan the complete bounded buffer so a
   * future font/layout adjustment cannot make an early non-fit hide a later,
   * valid three-line prefix. */
  for (size_t take = 1; take <= limit; take++) {
    memcpy(out, data, take);
    out[take] = '\0';
    if (confirm_body_fits(out, body_width)) best = take;
  }

  if (best == 0) {
    out[0] = '\0';
    return 0;
  }

  memcpy(out, data, best);
  out[best] = '\0';
  return best;
}

/// Show a confirmation, scrolling ordinary text when its complete formatted
/// body does not fit. Source truncation cannot be repaired after vsnprintf()
/// has discarded bytes, so that case fails closed without showing an
/// approve-able prefix.
static bool confirm_helper(const char* request_title, const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate) {
  const uint16_t body_width =
      (uint16_t)((iconNum == NO_ICON) ? BODY_WIDTH : BODY_WIDTH_WITH_ICON);

  /* Consume the source-completeness latch exactly once, whatever happens
   * below: leaving it set would make the NEXT confirmation warn for this
   * one's reason. */
  const bool truncated = body_truncated;
  body_truncated = false;

  /* Custom layouts own their geometry. Only the standard notification can use
   * this renderer-backed pager; source truncation is layout-independent. */
  const bool render_incomplete =
      (layout_notification_func == &layout_standard_notification) &&
      !confirm_body_fits(request_body, body_width);

  if (truncated) return false;

  if (render_incomplete) {
    return confirm_screen(request_title, request_body, layout_notification_func,
                          constant_power, iconNum, immediate,
                          (const uint8_t*)request_body, strlen(request_body),
                          &confirm_body_format_page, body_width);
  }

  return confirm_screen(request_title, request_body, layout_notification_func,
                        constant_power, iconNum, immediate, NULL, 0, NULL, 0);
}

bool confirm_paged(ButtonRequestType type, const char* request_title,
                   const uint8_t* data, size_t size,
                   confirm_page_formatter_t formatter) {
  if (!request_title || !data || size == 0 || !formatter) return false;

  button_request_acked = false;

  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  return confirm_screen(request_title, "", &layout_standard_notification, false,
                        NO_ICON, false, data, size, formatter, BODY_WIDTH);
}

bool confirm(ButtonRequestType type, const char* request_title,
             const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_constant_power(ButtonRequestType type, const char* request_title,
                            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_constant_power_notification,
                     true, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_button_request(const ButtonRequest* button_request,
                                        const char* request_title,
                                        const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  msg_write(MessageType_MessageType_ButtonRequest, button_request);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
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
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret = confirm_helper(request_title, strbuf, layout_notification_func,
                            false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_without_button_request(const char* request_title,
                                    const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_icon(ButtonRequestType type, IconType iconNum,
                       const char* request_title, const char* request_body,
                       ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, iconNum, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review(ButtonRequestType type, const char* request_title,
            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_without_button_request(const char* request_title,
                                   const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_with_icon(ButtonRequestType type, IconType iconNum,
                      const char* request_title, const char* request_body,
                      ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, iconNum, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_immediate(ButtonRequestType type, const char* request_title,
                      const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, true);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}
