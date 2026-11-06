"""Memory-only transport for a private emulator wallet.

This module performs no file, screenshot, transcript or diagnostic-state I/O.
The caller owns encrypted persistence and must wipe mutable flash snapshots and
watch-key responses when finished with them. No emulator starts on import.
"""
import ctypes
import os
import time


FLASH_SIZE = 1024 * 1024
MAX_BODY = 65536
MAX_INTERACTIONS = 128
RETAINED_PRIVATE_SESSIONS = []


class PrivateTransportError(RuntimeError):
    """A public transport diagnostic that never includes protocol data."""


def wipe(buffer):
    """Overwrite a writable contiguous buffer without making a bytes copy."""
    view = memoryview(buffer).cast("B")
    if view.readonly:
        raise PrivateTransportError("A writable buffer is required")
    if view.nbytes:
        pointer = (ctypes.c_uint8 * view.nbytes).from_buffer(view)
        ctypes.memset(pointer, 0, view.nbytes)


def _varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def _number(field, value):
    return _varint(field << 3) + _varint(value)


def _text(field, value):
    data = value.encode("ascii")
    return _varint((field << 3) | 2) + _varint(len(data)) + data


def _feature_flags(body):
    """Read only public booleans from Features; retain no other fields."""
    offset, flags = 0, {}
    def number():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(body):
                raise PrivateTransportError("Malformed firmware response")
            byte = body[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                if value > 2**64-1:
                    raise PrivateTransportError("Malformed firmware response")
                return value
        raise PrivateTransportError("Malformed firmware response")
    while offset < len(body):
        key = number()
        field, encoding = key >> 3, key & 7
        if not field:
            raise PrivateTransportError("Malformed firmware response")
        if encoding == 0:
            value = number()
            if field in [7, 8, 12, 15, 24]:
                if value not in [0, 1] or field in flags:
                    raise PrivateTransportError("Malformed firmware response")
                flags[field] = bool(value)
        elif encoding == 2:
            length = number()
            offset += length
        elif encoding in [1, 5]:
            offset += 8 if encoding == 1 else 4
        else:
            raise PrivateTransportError("Malformed firmware response")
        if offset > len(body):
            raise PrivateTransportError("Malformed firmware response")
    return {"initialized": flags.get(12, False), "imported": flags.get(15, False),
            "no_backup": flags.get(24, False), "pin_protection": flags.get(7, False),
            "passphrase_protection": flags.get(8, False)}


class PrivateSession:
    """Own a locked flash buffer and the firmware thread until safe shutdown.

    Terminal messages are ``(type, mutable_body, report_count)``. Only public
    management/address messages and the explicitly authorized watch-key export
    are exposed. DebugLinkState and transaction signing are unavailable here.
    A shutdown timeout retains this entire object; it never frees live flash.
    """

    _COMMANDS = frozenset([0, 1, 14, 20, 24, 27, 36, 55, 540, 542])
    _RESPONSES = frozenset([2, 3, 17, 18, 26, 35, 41, 541, 543])

    def __init__(self, library, initial_flash=None):
        self.closed = False
        self.initialized = None
        self.imported = None
        self.no_backup = None
        self.pin_protection = None
        self.passphrase_protection = None
        self.flash = (ctypes.c_uint8 * FLASH_SIZE)()
        self._packet = (ctypes.c_uint8 * 64)()
        self._frame = (ctypes.c_uint8 * 2048)()
        self._partial = None
        self._ready = []
        self._firmware_initialized = False
        self._locked = False
        self._busy = False
        try:
            self._system = ctypes.CDLL(None, use_errno=True)
            self._system.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._system.mlock.restype = ctypes.c_int
            self._system.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._system.munlock.restype = ctypes.c_int
            if self._system.mlock(self.flash, FLASH_SIZE) != 0:
                raise PrivateTransportError("Cannot lock private emulator memory")
            self._locked = True
            if initial_flash is None:
                ctypes.memset(self.flash, 255, FLASH_SIZE)
            else:
                source = memoryview(initial_flash).cast("B")
                if source.nbytes != FLASH_SIZE:
                    raise PrivateTransportError("Invalid private flash size")
                memoryview(self.flash).cast("B")[:] = source
            self.lib = ctypes.CDLL(str(library))
            self._configure_library()
            if self.lib.kkemu_init(self.flash, FLASH_SIZE) != 0:
                raise PrivateTransportError("Cannot initialize the private emulator")
            self._firmware_initialized = True
            RETAINED_PRIVATE_SESSIONS.append(self)
            if self.lib.kkemu_start() != 0:
                raise PrivateTransportError("Cannot start the private emulator")
            self.drain_frames()
        except Exception as error:
            if self._firmware_initialized:
                self.close()
            else:
                self._release_memory()
            if isinstance(error, PrivateTransportError):
                raise
            raise PrivateTransportError("Private emulator initialization failed") from None

    def _configure_library(self):
        lib = self.lib
        lib.kkemu_init.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.kkemu_init.restype = ctypes.c_int
        lib.kkemu_start.argtypes = []
        lib.kkemu_start.restype = ctypes.c_int
        lib.kkemu_is_running.argtypes = []
        lib.kkemu_is_running.restype = ctypes.c_int
        lib.kkemu_write.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.kkemu_write.restype = ctypes.c_int
        lib.kkemu_read.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.kkemu_read.restype = ctypes.c_int
        lib.kkemu_pop_frame.argtypes = [ctypes.c_void_p]
        lib.kkemu_pop_frame.restype = ctypes.c_int
        lib.kkemu_trylock.argtypes = []
        lib.kkemu_trylock.restype = ctypes.c_int
        lib.kkemu_unlock.argtypes = []
        lib.kkemu_unlock.restype = None
        lib.kkemu_shutdown_timeout.argtypes = [ctypes.c_uint32]
        lib.kkemu_shutdown_timeout.restype = ctypes.c_int

    def _require_open(self):
        if self.closed or not self._firmware_initialized:
            raise PrivateTransportError("Private emulator is closed")

    def _release_memory(self):
        ctypes.memset(self.flash, 0, FLASH_SIZE)
        ctypes.memset(self._packet, 0, 64)
        ctypes.memset(self._frame, 0, 2048)
        if self._partial is not None:
            wipe(self._partial[2])
            self._partial = None
        for _, body, _ in self._ready:
            wipe(body)
        self._ready.clear()
        if self._locked:
            self._system.munlock(self.flash, FLASH_SIZE)
            self._locked = False
        self.closed = True

    def send(self, kind, payload=b"", iface=0):
        self._require_open()
        if (iface == 0 and kind not in self._COMMANDS) or (iface == 1 and kind != 100) or iface not in [0, 1]:
            raise PrivateTransportError("Command is unavailable in the private transport")
        try:
            view = memoryview(payload).cast("B")
        except (TypeError, ValueError):
            raise PrivateTransportError("Invalid protocol buffer") from None
        if view.nbytes > MAX_BODY:
            raise PrivateTransportError("Protocol buffer exceeds the private transport bound")
        if iface == 1 and (view.nbytes != 2 or view[0] != 8 or view[1] not in [0, 1]):
            raise PrivateTransportError("Invalid private button decision")
        header = b"##" + kind.to_bytes(2, "big") + view.nbytes.to_bytes(4, "big")
        position, total = 0, len(header) + view.nbytes
        until = time.monotonic() + 5
        try:
            while position < total:
                ctypes.memset(self._packet, 0, 64)
                self._packet[0] = 63
                take = min(63, total-position)
                for index in range(take):
                    source = position+index
                    self._packet[index+1] = header[source] if source < len(header) else view[source-len(header)]
                while self.lib.kkemu_write(self._packet, 64, iface) != 0:
                    if time.monotonic() >= until:
                        raise PrivateTransportError("Private emulator input timed out")
                    self.drain_frames()
                    time.sleep(.001)
                position += take
        finally:
            ctypes.memset(self._packet, 0, 64)

    def drain_frames(self):
        self._require_open()
        try:
            for _ in range(256):
                if self.lib.kkemu_pop_frame(self._frame) != 1:
                    break
                ctypes.memset(self._frame, 0, 2048)
        finally:
            ctypes.memset(self._frame, 0, 2048)

    def _drain_main(self):
        try:
            while True:
                count = self.lib.kkemu_read(self._packet, 64, 0)
                if count == 0:
                    break
                if count != 64:
                    raise PrivateTransportError("Invalid private emulator report")
                if self._partial is None:
                    if self._packet[0] != 63 or self._packet[1] != 35 or self._packet[2] != 35:
                        raise PrivateTransportError("Invalid private emulator framing")
                    kind = (self._packet[3] << 8) | self._packet[4]
                    length = sum(self._packet[5+i] << (24-i*8) for i in range(4))
                    if kind not in self._RESPONSES or length > MAX_BODY:
                        raise PrivateTransportError("Unexpected private emulator response")
                    self._partial = [kind, length, bytearray(), 1]
                    start = 9
                else:
                    if self._packet[0] != 63:
                        raise PrivateTransportError("Invalid private emulator continuation")
                    self._partial[3] += 1
                    start = 1
                kind, length, body, reports = self._partial
                take = min(64-start, length-len(body))
                body.extend(self._packet[index] for index in range(start, start+take))
                ctypes.memset(self._packet, 0, 64)
                if len(body) == length:
                    if kind == 17:
                        for name, value in _feature_flags(body).items():
                            setattr(self, name, value)
                    self._ready.append((kind, body, reports))
                    self._partial = None
        finally:
            ctypes.memset(self._packet, 0, 64)

    def receive(self, timeout=5):
        self._require_open()
        if not 0 <= timeout <= 180:
            raise PrivateTransportError("Invalid private transport timeout")
        until = time.monotonic() + timeout
        while True:
            self.drain_frames()
            self._drain_main()
            if self._ready:
                return self._ready.pop(0)
            if time.monotonic() >= until:
                return None
            time.sleep(.001)

    def rpc(self, kind, payload=b"", host_entropy_callback=None):
        if self._busy:
            raise PrivateTransportError("Private emulator interaction is already active")
        self._busy = True
        try:
            self.send(kind, payload)
            for _ in range(MAX_INTERACTIONS):
                message = self.receive(60)
                if message is None:
                    raise PrivateTransportError("Private emulator response timed out")
                response, body, _ = message
                if response == 26:
                    wipe(body)
                    self.send(27)
                    self.send(100, b"\x08\x01", iface=1)
                elif response == 35:
                    wipe(body)
                    entropy, acknowledgement = None, None
                    try:
                        entropy = bytearray(os.urandom(32) if host_entropy_callback is None else host_entropy_callback())
                        if len(entropy) != 32:
                            raise PrivateTransportError("Invalid host entropy size")
                        acknowledgement = bytearray([10, 32]) + entropy
                        self.send(36, acknowledgement)
                    finally:
                        if acknowledgement is not None:
                            wipe(acknowledgement)
                        if entropy is not None:
                            wipe(entropy)
                elif response in [18, 41]:
                    wipe(body)
                    raise PrivateTransportError("Private emulator requires interactive authentication")
                else:
                    return message
            raise PrivateTransportError("Private emulator interaction exceeded its bound")
        finally:
            self._busy = False

    def features(self):
        message = self.rpc(55)
        try:
            if message[0] != 17:
                raise PrivateTransportError("Cannot read private emulator status")
            return {"initialized": self.initialized, "imported": self.imported,
                    "no_backup": self.no_backup, "pin_protection": self.pin_protection,
                    "passphrase_protection": self.passphrase_protection}
        finally:
            wipe(message[1])

    def reset(self):
        if self.features()["initialized"]:
            raise PrivateTransportError("Private emulator is already initialized")
        request = (_number(2, 256) + _number(3, 0) + _number(4, 0) + _text(5, "english") +
                   _text(6, "MoneroMainnetTest") + _number(7, 0))
        message = self.rpc(14, request)
        try:
            if message[0] != 2:
                raise PrivateTransportError("Private wallet creation failed")
        finally:
            wipe(message[1])
            wipe(request)
        flags = self.features()
        if not flags["initialized"] or flags["imported"] or flags["no_backup"] or flags["pin_protection"] or flags["passphrase_protection"]:
            raise PrivateTransportError("Private wallet creation status is invalid")
        return flags

    def snapshot_locked(self):
        self._require_open()
        snapshot = bytearray(FLASH_SIZE)
        until = time.monotonic() + 5
        while self.lib.kkemu_trylock() != 1:
            if time.monotonic() >= until:
                wipe(snapshot)
                raise PrivateTransportError("Private flash snapshot timed out")
            self.drain_frames()
            time.sleep(.001)
        try:
            target = (ctypes.c_uint8 * FLASH_SIZE).from_buffer(snapshot)
            ctypes.memmove(target, self.flash, FLASH_SIZE)
        except Exception:
            wipe(snapshot)
            raise PrivateTransportError("Private flash snapshot failed") from None
        finally:
            self.lib.kkemu_unlock()
        return snapshot

    def close(self):
        if self.closed:
            return
        if self._firmware_initialized and self.lib.kkemu_shutdown_timeout(5000) != 0:
            if self not in RETAINED_PRIVATE_SESSIONS:
                RETAINED_PRIVATE_SESSIONS.append(self)
            raise PrivateTransportError("Private emulator shutdown timed out; memory retained")
        self._firmware_initialized = False
        self._release_memory()
        if self in RETAINED_PRIVATE_SESSIONS:
            RETAINED_PRIVATE_SESSIONS.remove(self)

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.close()
