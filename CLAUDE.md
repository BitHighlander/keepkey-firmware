# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

### Prerequisites

#### For Docker Builds
- Docker Community Edition installed from https://www.docker.com/get-docker
- Pull the build image: `docker pull kktech/firmware:v15`

#### For Non-Docker Builds
- **nanopb-0.3.9.4**: Download from https://github.com/nanopb/nanopb/releases/tag/nanopb-0.3.9.4
- **protobuf compiler**: Install protoc and python bindings
  ```bash
  pip install protobuf
  ```
- **ARM toolchain** (for device builds): arm-none-eabi-gcc toolchain
- **libopencm3**: Pre-built library for STM32 support (device builds)
- **Build tools**: CMake 3.7.2+, Make, GCC/Clang

### Device Firmware Build

#### Using Docker (Recommended)
```bash
# Clone and initialize repository
git clone https://github.com/keepkey/keepkey-firmware.git
cd keepkey-firmware
git submodule update --init --recursive

# Build release firmware
./scripts/build/docker/device/release.sh
# Output: ./bin/firmware.keepkey.bin, ./bin/firmware.keepkey.elf

# Build debug firmware
./scripts/build/docker/device/debug.sh
# Output: ./bin/firmware.keepkey.bin with debug symbols
```

#### Without Docker (Advanced)
```bash
# Setup build directory
mkdir build && cd build

# Configure for device (cross-compilation)
cmake -C ../cmake/caches/device.cmake .. \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DLIBOPENCM3_PATH=/path/to/libopencm3 \
  -DPROTOC_BINARY=/path/to/protoc \
  -DNANOPB_DIR=/path/to/nanopb

# Build firmware
make -j

# Binaries will be in build/bin/
```

### Emulator Build

#### Using Docker
```bash
# Build emulator with debug symbols and tests
./scripts/build/docker/emulator/debug.sh

# The build directory will be created at ./build/
# Run the emulator
./build/bin/kkemu

# Run unit tests
cd build && make xunit
```

#### Without Docker (Native Build)
```bash
# Prerequisites for emulator
# - SDL2 development libraries
# - nanopb-0.3.9.4 with generator on PATH
# - protoc (protocol buffer compiler)

# Clone and setup
git clone https://github.com/keepkey/keepkey-firmware.git
cd keepkey-firmware
git submodule update --init --recursive

# Configure and build
mkdir build && cd build
cmake -C ../cmake/caches/emulator.cmake .. \
  -DNANOPB_DIR=/path/to/nanopb \
  -DPROTOC_BINARY=/path/to/protoc \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug

make -j

# Run emulator
./bin/kkemu

# Run tests
make all test
# or for XML test output
make xunit
```

### Build Configurations

#### CMake Cache Files
- `cmake/caches/device.cmake` - Cross-compilation for STM32F2 hardware
- `cmake/caches/emulator.cmake` - Native build with emulator and debug link
- `cmake/caches/docker.cmake` - Docker-specific paths and settings

#### Build Types
- **MinSizeRel**: Optimized for size (production firmware)
- **Debug**: Debug symbols, no optimization (development)
- **Release**: Optimized for speed

#### Build Flags
- `KK_EMULATOR`: Build emulator instead of device firmware
- `KK_DEBUG_LINK`: Enable debug link for development
- `KK_BUILD_FUZZERS`: Build fuzzing tests

### Docker Build Details

The Docker builds use the `kktech/firmware:v15` image which includes:
- ARM cross-compilation toolchain
- Pre-built libopencm3
- nanopb with protobuf compiler
- All required build dependencies

Docker build scripts mount the repository as `/root/keepkey-firmware` and:
1. Create a clean build directory
2. Run CMake with appropriate cache file
3. Build all targets
4. Copy outputs back to host with correct permissions

### Verification of Builds

To verify reproducible builds:
```bash
# Build a specific version
git checkout v7.9.3
git submodule update --init --recursive
./scripts/build/docker/device/release.sh

# Compare hash (ignoring signatures)
tail -c +257 ./bin/firmware.keepkey.bin | shasum -a 256
```

## Architecture Overview

### Project Structure
The KeepKey firmware is a hardware wallet implementation with the following key components:

1. **Bootloader** (`bootloader/`) - Handles firmware updates and device initialization
2. **Firmware** (`lib/firmware/`) - Main application logic for cryptocurrency operations
3. **Board Support** (`lib/board/`) - Hardware abstraction layer for STM32F2 microcontroller
4. **Emulator** (`lib/emulator/`) - Software emulation layer for development/testing
5. **Crypto Libraries** (`deps/crypto/`) - Cryptographic primitives and operations
6. **Protocol Definitions** (`deps/device-protocol/`) - Protobuf message definitions for host communication

### Key Components

**State Machines**: The firmware uses state machines for user interactions:
- `home_sm` - Main menu navigation
- `pin_sm` - PIN entry and validation  
- `passphrase_sm` - Passphrase entry
- `confirm_sm` - User confirmation dialogs

**Cryptocurrency Support**: Each blockchain has dedicated modules:
- `ethereum.c` - Ethereum and ERC20 tokens
- `bitcoin/signing.c` - Bitcoin transaction signing
- `binance.c`, `cosmos.c`, `eos.c`, `nano.c`, `ripple.c` - Additional chain support
- `thorchain.c`, `mayachain.c`, `osmosis.c` - Cross-chain DEX protocols

**USB Communication**: 
- WebUSB and WinUSB support for browser-based interfaces
- Protocol buffer encoding/decoding via nanopb
- Message handling in `fsm.c` (Finite State Machine)

### Build System
- CMake-based build system with caches for different targets
- Conditional compilation for device vs emulator (`KK_EMULATOR` flag)
- Debug link support for development (`KK_DEBUG_LINK` flag)

## Testing

### Unit Tests
```bash
# Run unit tests in emulator build
cd build && make xunit

# Test categories:
# - board/ - Hardware abstraction tests
# - crypto/ - Cryptographic function tests  
# - firmware/ - Application logic tests
```

### Test Files Location
- Unit tests: `unittests/` directory
- Test framework: Google Test (via submodule)

## Development Notes

### Firmware Versioning
- Version defined in `CMakeLists.txt` (PROJECT_VERSION)
- Bootloader version separate from firmware version
- Version verification important for signed releases

### Memory Layout
- Firmware has specific memory regions (see `lib/board/memory.h`)
- "confidential" section for sensitive data
- Flash storage for persistent settings

### Security Considerations
- Firmware signing and verification
- MPU (Memory Protection Unit) configuration for security boundaries
- PIN and passphrase protection mechanisms
- Secure random number generation (`lib/rand/rng.c`)

### Protocol Communication
- Uses Protocol Buffers (nanopb) for host communication
- Message definitions in `deps/device-protocol/*.proto`
- Transport layer abstraction in `lib/transport/`

### Platform-Specific Code
- Device-specific code uses libopencm3 for STM32
- Emulator uses SDL for display and user input simulation
- Conditional compilation based on `EMULATOR` define

## Common Development Tasks

### Adding New Cryptocurrency Support
1. Add protocol buffer messages in `deps/device-protocol/`
2. Implement signing logic in `lib/firmware/[coin].c`
3. Add to FSM message handlers in `lib/firmware/fsm.c`
4. Update coin table in `lib/firmware/coins.c`
5. Add unit tests in `unittests/firmware/`

### Modifying UI/UX
- Layout functions in `lib/board/layout.c`
- Display primitives in `lib/board/draw.c`
- Font definitions in `lib/board/font.c`
- Canvas abstraction for rendering

### Debugging
- Enable debug link with `KK_DEBUG_LINK` for development
- Emulator provides easier debugging environment
- Use `supervise.h` for system-level debugging functions

## Host Communication Setup

### USB Device Setup

#### Linux
Add UDEV rules to `/etc/udev/rules.d/51-usb-keepkey.rules`:
```bash
# KeepKey HID Firmware/Bootloader
SUBSYSTEM=="usb", ATTR{idVendor}=="2b24", ATTR{idProduct}=="0001", MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl", SYMLINK+="keepkey%n"
KERNEL=="hidraw*", ATTRS{idVendor}=="2b24", ATTRS{idProduct}=="0001",  MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl"

# KeepKey WebUSB Firmware/Bootloader  
SUBSYSTEM=="usb", ATTR{idVendor}=="2b24", ATTR{idProduct}=="0002", MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl", SYMLINK+="keepkey%n"
KERNEL=="hidraw*", ATTRS{idVendor}=="2b24", ATTRS{idProduct}=="0002",  MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl"
```
Then reload: `sudo udevadm control --reload-rules`

#### Windows
- Windows 7+ uses Microsoft OS Descriptors for USB enumeration
- WebUSB devices: `vid=0x2b24, pid=0x0002`
- HID devices: `vid=0x2b24, pid=0x0001`
- If not recognized, use Zadig to set driver to `libusb0 (v1.2.6.0)`

#### macOS
- Works out-of-the-box, no additional setup required

### Emulator Communication

The emulator communicates via UDP sockets:
- Main channel: Port 11044
- Debug channel: Port 11045

#### Python Bridge for HTTP Access
```bash
# Run the bridge server (provides HTTP interface to emulator)
python scripts/emulator/bridge.py

# Exchange messages via HTTP
# POST to /exchange/main or /exchange/debug
# GET from /exchange/main or /exchange/debug
```

### Running Tests with Emulator

```bash
# Build and start emulator
./scripts/build/docker/emulator/debug.sh
./build/bin/kkemu &

# Run python-keepkey tests (requires python-keepkey submodule)
cd deps/python-keepkey
python -m pytest tests/

# Or use the Docker test runner
docker build -f scripts/emulator/python-keepkey.Dockerfile -t kkemu-pytest .
docker run kkemu-pytest
```