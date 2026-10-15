#ifndef KEEPKEY_BOARD_BSD_COMPAT_H
#define KEEPKEY_BOARD_BSD_COMPAT_H

/* strlcpy/strlcat prototypes for glibc/MinGW emulator builds; force-included
 * (see CMakeLists.txt). Not used by the ARM build. */

#include <stddef.h>

#ifdef __cplusplus
#define KEEPKEY_BSD_NOTHROW noexcept
extern "C" {
#else
#define KEEPKEY_BSD_NOTHROW
#endif

/* Match the native glibc declarations when present (glibc 2.38+). */
size_t strlcpy(char *dst, const char *src, size_t siz) KEEPKEY_BSD_NOTHROW;
size_t strlcat(char *dst, const char *src, size_t siz) KEEPKEY_BSD_NOTHROW;

#ifdef __cplusplus
}
#endif

#undef KEEPKEY_BSD_NOTHROW

#endif /* KEEPKEY_BOARD_BSD_COMPAT_H */
