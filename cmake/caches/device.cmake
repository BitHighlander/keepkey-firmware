load_cache(docker.cmake)

# Tell cmake that we're cross compiling for baremetal
set(CMAKE_SYSTEM_NAME Generic CACHE STRING "")
set(CMAKE_CROSSCOMPILING 1)

include(CMakeForceCompiler)

# The sysroot. Just assume the one installed in the docker image for now
set(CMAKE_SYSROOT /usr/local/arm-none-eabi CACHE PATH "")

set(CMAKE_C_COMPILER arm-none-eabi-gcc CACHE FILEPATH "")
set(CMAKE_CXX_COMPILER arm-none-eabi-g++ CACHE FILEPATH "")

# FIXME: teach cmake how to do compiler tests on baremetal
set(CMAKE_C_COMPILER_WORKS True CACHE BOOL "")
set(CMAKE_CXX_COMPILER_WORKS True CACHE BOOL "")

set(ARCH_FLAGS
    "-mthumb \
    -mcpu=cortex-m3 \
    -msoft-float \
    -ffunction-sections \
    -fdata-sections \
    -fno-common \
    -fstack-usage \
    -fstack-protector-strong" CACHE STRING "")
# -strong, not -all: a canary on every function with a local array or an
# address-taken local, which are the functions a stack overflow can start in
# (812 of the 1,920 that -all instruments). It frees about 50 KB of flash;
# with -all this image is 25 KB over the bootloader's upload limit.

set(WARN_FLAGS
    "-Wall \
    -Wextra \
    -Wformat \
    -Wformat-nonliteral \
    -Wformat-security \
    -Wimplicit-function-declaration \
    -Winit-self \
    -Wmultichar \
    -Wpointer-arith \
    -Wredundant-decls \
    -Wreturn-type \
    -Wshadow \
    -Wsign-compare \
    -Wstrict-prototypes \
    -Wundef \
    -Wuninitialized \
    -Werror")


# Newlib's snprintf unconditionally links the float engine (_svfprintf_r,
# _dtoa_r, soft-double libgcc, malloc) — ~22 KB of ROM with zero %f users in
# the firmware. Route all callers to the integer-only siprintf family instead.
# %lld/%llu still work (this toolchain's libc.a compiles the integer engine
# with long-long support). Device builds only; host/emulator keep libc printf.
set(PRINTF_FLAGS "-Dsnprintf=sniprintf -Dvsnprintf=vsniprintf")

set(KK_C_FLAGS "${ARCH_FLAGS} -std=gnu99 ${WARN_FLAGS} ${PRINTF_FLAGS}" CACHE STRING "")
set(KK_CXX_FLAGS "${ARCH_FLAGS} -std=gnu++11 ${WARN_FLAGS} \
    -fno-exceptions \
    -fno-rtti \
    -fno-threadsafe-statics \
    -fuse-cxa-atexit \
    -Woverloaded-virtual \
    -Weffc++" CACHE STRING "")

set(CMAKE_C_FLAGS_DEBUG "${KK_C_FLAGS} -Os -g" CACHE STRING "")
set(CMAKE_C_FLAGS_MINSIZEREL "${KK_C_FLAGS} -Os" CACHE STRING "")
set(CMAKE_C_FLAGS_RELEASE "${KK_C_FLAGS} -Os" CACHE STRING "")
set(CMAKE_CXX_FLAGS_DEBUG "${KK_CXX_FLAGS} -Os -g" CACHE STRING "")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${KK_CXX_FLAGS} -Os" CACHE STRING "")
set(CMAKE_CXX_FLAGS_RELEASE "${KK_CXX_FLAGS} -Os" CACHE STRING "")

set(CMAKE_ASM_FLAGS "-mcpu=cortex-m3 \
    -mthumb \
    -x assembler-with-cpp \
    -gdwarf-2" CACHE STRING "")

set(CMAKE_EXE_LINKER_FLAGS
    "-mthumb \
    -mcpu=cortex-m3 \
    -nostartfiles \
    -msoft-float \
    -specs=nosys.specs \
    -Wl,--gc-sections" CACHE STRING "")
