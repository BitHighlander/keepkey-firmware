"""Execute the production USB callback bodies with fault-injected USB reads.

This is a host callback test, not a physical USB/controller qualification.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def callback(source, name):
    start = source.index('static void ' + name + '(')
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class ReceiveCallbacks(unittest.TestCase):
    def test_main_and_debug_clear_complete_short_empty_and_error_reads(self):
        source = (ROOT / 'lib/board/usb.c').read_text()
        bodies = '\n'.join(callback(source, n) for n in
                           ('main_rx_callback', 'debug_rx_callback'))
        harness = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
typedef int usbd_device;
#define CONFIDENTIAL
#define ENDPOINT_ADDRESS_MAIN_OUT 1
#define ENDPOINT_ADDRESS_DEBUG_OUT 2
#define debugLog(a,b,c)
static int read_result, calls, expected_endpoint;
static uint8_t *storage;
static void memzero(void *p, size_t n) { memset(p, 0, n); }
static int usbd_ep_read_packet(usbd_device *d, int ep, void *p, int n) {
  (void)d;
  assert(ep == expected_endpoint && n == 64);
  storage = p;
  /* A driver may touch the buffer even on short/error returns. */
  memset(p, 0xa5, n);
  return read_result;
}
static void observe(const void *p, size_t n) {
  assert(n == 64);
  for (size_t i = 0; i < n; i++) assert(((const uint8_t *)p)[i] == 0xa5);
  calls++;
}
static void (*user_rx_callback)(const void *, size_t) = observe;
static void (*user_debug_rx_callback)(const void *, size_t) = observe;
'''
        harness += bodies + r'''
int main(void) {
  const int results[] = {64, 17, 0, -1, 64};
  for (int endpoint = 1; endpoint <= 2; endpoint++) {
    expected_endpoint = endpoint;
    for (size_t i = 0; i < sizeof(results)/sizeof(results[0]); i++) {
      read_result = results[i]; calls = 0; storage = NULL;
      if (endpoint == 1) main_rx_callback(NULL, endpoint);
      else debug_rx_callback(NULL, endpoint);
      assert(calls == (read_result == 64));
      assert(storage);
      for (int j = 0; j < 64; j++) assert(storage[j] == 0);
    }
  }
  return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='s06-usbrx-') as tmp:
            path = Path(tmp)
            (path / 'probe.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'probe.c'), '-o', str(path / 'probe')],
                           check=True)
            subprocess.run([str(path / 'probe')], check=True)


if __name__ == '__main__':
    unittest.main()
