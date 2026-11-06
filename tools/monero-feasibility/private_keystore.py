#!/usr/bin/env python3
"""Seal emulator flash with a dedicated native macOS Keychain key.

No subprocesses, credentials in arguments, wallet files, or mnemonic sidecars.
The default login backend uses an ACL for the creating interpreter. Explicit
data-protection mode requires the host's Keychain entitlements and uses
WhenUnlockedThisDeviceOnly. Neither backend claims hardware-backed keys.

The envelope authenticates its version/backend and the exact wallet identifier.
Python and cryptography may make temporary memory copies; this module does not
claim complete process-memory erasure. Callers own durable atomic file storage.
"""
import argparse
import ctypes
from functools import lru_cache
import hmac
import json
import os
import sys
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVICE = "keepkey-monero-mainnet-emulator"
MAGIC = b"KKXMR-SEAL\x00\x01"
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
MAX_PLAINTEXT = 16 * 1024 * 1024
_BACKENDS = {"login": 0, "data-protection": 1}
_selected_backend = "login"
_NOT_FOUND = -25300
_DUPLICATE = -25299


class KeyStoreError(RuntimeError):
    """A bounded public diagnostic without underlying secret-bearing errors."""


def set_backend(name: str) -> None:
    """Choose explicitly before seal/open; there is no automatic downgrade."""
    global _selected_backend
    if type(name) is not str or name not in _BACKENDS:
        raise KeyStoreError("Unsupported Keychain backend")
    _selected_backend = name


def backend_metadata() -> dict:
    """Public storage properties suitable for the recovery manifest."""
    return {
        "service": SERVICE, "backend": _selected_backend,
        "hardware_backed": False, "synchronizable": False,
        "accessibility": ("WhenUnlockedThisDeviceOnly" if _selected_backend == "data-protection"
                          else "login-keychain-unlock-and-creating-interpreter-ACL"),
    }


def _wallet_bytes(wallet_id):
    if type(wallet_id) is not str or not wallet_id or "\0" in wallet_id or any(ord(c) < 32 for c in wallet_id):
        raise KeyStoreError("Invalid wallet identifier")
    try:
        value = wallet_id.encode("utf-8")
    except UnicodeError:
        raise KeyStoreError("Invalid wallet identifier") from None
    if len(value) > 256:
        raise KeyStoreError("Wallet identifier exceeds 256 bytes")
    return value


def _status_error(status):
    labels = {
        -25293: "Keychain authorization denied",
        -25308: "Keychain is locked or interaction is unavailable",
        -128: "Keychain authorization cancelled",
        -34018: "Host lacks required Keychain entitlement",
        _DUPLICATE: "Keychain entry already exists; it was not overwritten",
    }
    return KeyStoreError(labels.get(status, "Native Keychain operation failed") + f" (status {int(status)})")


class _CFRange(ctypes.Structure):
    _fields_ = [("location", ctypes.c_long), ("length", ctypes.c_long)]


class _Scope:
    def __init__(self, native):
        self.native, self.owned = native, []

    def own(self, value):
        if not value:
            raise KeyStoreError("Native Keychain allocation failed")
        self.owned.append(value)
        return value

    def __enter__(self):
        return self

    def __exit__(self, *_):
        for value in reversed(self.owned):
            self.native.cf.CFRelease(value)


class _NativeKeychain:
    def __init__(self, backend):
        if sys.platform != "darwin":
            raise KeyStoreError("Native macOS Keychain is required")
        self.backend = backend
        try:
            self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
            self.sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
            p, n = ctypes.c_void_p, ctypes.c_long
            signatures = {
                "CFRelease": ([p], None), "CFGetTypeID": ([p], ctypes.c_ulong),
                "CFEqual": ([p, p], ctypes.c_ubyte),
                "CFStringCreateWithCString": ([p, ctypes.c_char_p, ctypes.c_uint32], p),
                "CFDictionaryCreateMutable": ([p, n, p, p], p),
                "CFDictionarySetValue": ([p, p, p], None),
                "CFDictionaryGetValue": ([p, p], p),
                "CFDictionaryGetTypeID": ([], ctypes.c_ulong),
                "CFDataCreate": ([p, p, n], p), "CFDataGetLength": ([p], n),
                "CFDataGetBytes": ([p, _CFRange, p], None),
                "CFDataGetTypeID": ([], ctypes.c_ulong),
                "CFArrayCreate": ([p, ctypes.POINTER(p), n, p], p),
            }
            for name, (args, result) in signatures.items():
                function = getattr(self.cf, name)
                function.argtypes, function.restype = args, result
            for name in ("SecItemCopyMatching", "SecItemAdd"):
                function = getattr(self.sec, name)
                function.argtypes, function.restype = [p, ctypes.POINTER(p)], ctypes.c_int32
            self.sec.SecItemDelete.argtypes, self.sec.SecItemDelete.restype = [p], ctypes.c_int32
            self.sec.SecTrustedApplicationCreateFromPath.argtypes = [ctypes.c_char_p, ctypes.POINTER(p)]
            self.sec.SecTrustedApplicationCreateFromPath.restype = ctypes.c_int32
            self.sec.SecAccessCreate.argtypes, self.sec.SecAccessCreate.restype = [p, p, ctypes.POINTER(p)], ctypes.c_int32
            names = ["kSecClass", "kSecClassGenericPassword", "kSecAttrService", "kSecAttrAccount",
                     "kSecUseDataProtectionKeychain", "kSecReturnData", "kSecReturnAttributes",
                     "kSecMatchLimit", "kSecMatchLimitOne", "kSecValueData", "kSecAttrAccessible",
                     "kSecAttrAccessibleWhenUnlockedThisDeviceOnly", "kSecAttrSynchronizable", "kSecAttrAccess"]
            self.constants = {name: p.in_dll(self.sec, name).value for name in names}
            self.true = p.in_dll(self.cf, "kCFBooleanTrue").value
            self.false = p.in_dll(self.cf, "kCFBooleanFalse").value
            # These callback symbols are structs; pass their addresses, not
            # the first word of their contents as though they were CF objects.
            self.key_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks"))
            self.value_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks"))
            self.array_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self.cf, "kCFTypeArrayCallBacks"))
        except (OSError, AttributeError, ValueError):
            raise KeyStoreError("Required native Keychain APIs are unavailable") from None

    def _string(self, value, scope):
        return scope.own(self.cf.CFStringCreateWithCString(None, value.encode("utf-8"), 0x08000100))

    def _set(self, dictionary, name, value):
        self.cf.CFDictionarySetValue(dictionary, self.constants[name], value)

    def _query(self, wallet_id, scope):
        dictionary = scope.own(self.cf.CFDictionaryCreateMutable(None, 0, self.key_callbacks, self.value_callbacks))
        self._set(dictionary, "kSecClass", self.constants["kSecClassGenericPassword"])
        self._set(dictionary, "kSecAttrService", self._string(SERVICE, scope))
        self._set(dictionary, "kSecAttrAccount", self._string(wallet_id, scope))
        self._set(dictionary, "kSecUseDataProtectionKeychain", self.true if self.backend == "data-protection" else self.false)
        return dictionary

    def read(self, wallet_id):
        with _Scope(self) as scope:
            query = self._query(wallet_id, scope)
            self._set(query, "kSecReturnData", self.true)
            self._set(query, "kSecReturnAttributes", self.true)
            self._set(query, "kSecMatchLimit", self.constants["kSecMatchLimitOne"])
            result = ctypes.c_void_p()
            status = self.sec.SecItemCopyMatching(query, ctypes.byref(result))
            if status == _NOT_FOUND:
                return None
            if status:
                raise _status_error(status)
            scope.own(result.value)
            if self.cf.CFGetTypeID(result) != self.cf.CFDictionaryGetTypeID():
                raise KeyStoreError("Unexpected native Keychain result type")
            data = self.cf.CFDictionaryGetValue(result, self.constants["kSecValueData"])
            if not data or self.cf.CFGetTypeID(data) != self.cf.CFDataGetTypeID() or self.cf.CFDataGetLength(data) != KEY_SIZE:
                raise KeyStoreError("Keychain entry has invalid encryption key data")
            if self.backend == "data-protection":
                accessibility = self.cf.CFDictionaryGetValue(result, self.constants["kSecAttrAccessible"])
                if not accessibility or not self.cf.CFEqual(accessibility, self.constants["kSecAttrAccessibleWhenUnlockedThisDeviceOnly"]):
                    raise KeyStoreError("Keychain entry has an unexpected accessibility class")
            synchronizable = self.cf.CFDictionaryGetValue(result, self.constants["kSecAttrSynchronizable"])
            if synchronizable and not self.cf.CFEqual(synchronizable, self.false):
                raise KeyStoreError("Synchronizable encryption keys are refused")
            key = bytearray(KEY_SIZE)
            self.cf.CFDataGetBytes(data, _CFRange(0, KEY_SIZE), (ctypes.c_ubyte * KEY_SIZE).from_buffer(key))
            return key

    def add(self, wallet_id, key):
        with _Scope(self) as scope:
            query = self._query(wallet_id, scope)
            data = scope.own(self.cf.CFDataCreate(None, (ctypes.c_ubyte * KEY_SIZE).from_buffer(key), KEY_SIZE))
            self._set(query, "kSecValueData", data)
            self._set(query, "kSecAttrSynchronizable", self.false)
            if self.backend == "data-protection":
                self._set(query, "kSecAttrAccessible", self.constants["kSecAttrAccessibleWhenUnlockedThisDeviceOnly"])
            else:
                # A one-element trusted application list limits the new login
                # item ACL to this interpreter, instead of trusting all apps.
                application, access = ctypes.c_void_p(), ctypes.c_void_p()
                status = self.sec.SecTrustedApplicationCreateFromPath(None, ctypes.byref(application))
                if status:
                    raise _status_error(status)
                scope.own(application.value)
                values = (ctypes.c_void_p * 1)(application.value)
                trusted = scope.own(self.cf.CFArrayCreate(None, values, 1, self.array_callbacks))
                status = self.sec.SecAccessCreate(self._string(SERVICE, scope), trusted, ctypes.byref(access))
                if status:
                    raise _status_error(status)
                self._set(query, "kSecAttrAccess", scope.own(access.value))
            status = self.sec.SecItemAdd(query, None)
            if status:
                raise _status_error(status)

    def delete_self_test(self, wallet_id):
        if not wallet_id.startswith("self-test-") or len(wallet_id) != len("self-test-") + 32:
            raise KeyStoreError("Refused deletion outside the self-test account namespace")
        with _Scope(self) as scope:
            status = self.sec.SecItemDelete(self._query(wallet_id, scope))
            if status not in (0, _NOT_FOUND):
                raise _status_error(status)


@lru_cache(maxsize=2)
def _native(backend):
    return _NativeKeychain(backend)


def _key(wallet_id, create):
    try:
        native = _native(_selected_backend)
        key = native.read(wallet_id)
    except KeyStoreError:
        raise
    except Exception:
        raise KeyStoreError("Native Keychain access failed") from None
    if key is not None:
        return key
    if not create:
        raise KeyStoreError("No encryption key exists for this wallet")
    try:
        key = bytearray(os.urandom(KEY_SIZE))
    except Exception:
        raise KeyStoreError("Operating-system encryption key generation failed") from None
    try:
        native.add(wallet_id, key)
        stored = native.read(wallet_id)
        if stored is None or not hmac.compare_digest(stored, key):
            if stored is not None:
                stored[:] = b"\0" * len(stored)
            raise KeyStoreError("New Keychain entry could not be verified")
        return stored
    except KeyStoreError:
        raise
    except Exception:
        raise KeyStoreError("Native Keychain key creation failed") from None
    finally:
        key[:] = b"\0" * len(key)


def _header_and_aad(wallet_id):
    account = _wallet_bytes(wallet_id)
    header = MAGIC + bytes([_BACKENDS[_selected_backend]])
    return header, header + len(account).to_bytes(2, "big") + account


def seal(wallet_id: str, plaintext: bytes | bytearray) -> bytes:
    """Encrypt bounded bytes, creating a key only on genuine item-not-found."""
    header, aad = _header_and_aad(wallet_id)
    if type(plaintext) not in (bytes, bytearray) or len(plaintext) > MAX_PLAINTEXT:
        raise KeyStoreError("Invalid flash plaintext type or size")
    key = _key(wallet_id, True)
    try:
        nonce = os.urandom(NONCE_SIZE)
        return header + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    except Exception:
        raise KeyStoreError("Flash encryption failed") from None
    finally:
        key[:] = b"\0" * len(key)


def open_sealed(wallet_id: str, blob: bytes) -> bytes:
    """Authenticate/decrypt with an existing key; never create or replace one."""
    header, aad = _header_and_aad(wallet_id)
    if type(blob) is not bytes or not len(header) + NONCE_SIZE + TAG_SIZE <= len(blob) <= len(header) + NONCE_SIZE + TAG_SIZE + MAX_PLAINTEXT:
        raise KeyStoreError("Invalid encrypted flash type or size")
    if not hmac.compare_digest(blob[:len(header)], header):
        raise KeyStoreError("Encrypted flash version or selected backend does not match")
    key = _key(wallet_id, False)
    try:
        nonce = blob[len(header):len(header) + NONCE_SIZE]
        return AESGCM(key).decrypt(nonce, blob[len(header) + NONCE_SIZE:], aad)
    except InvalidTag:
        raise KeyStoreError("Encrypted flash authentication failed") from None
    except Exception:
        raise KeyStoreError("Flash decryption failed") from None
    finally:
        key[:] = b"\0" * len(key)


def _self_test():
    wallet_id = "self-test-" + uuid.uuid4().hex
    native = _native(_selected_backend)
    if native.read(wallet_id) is not None:
        raise KeyStoreError("Self-test account unexpectedly exists")
    attempted = False
    checks = []
    try:
        dummy = b"KeepKey Monero Keychain self-test: non-sensitive dummy bytes"
        attempted = True
        blob = seal(wallet_id, dummy)
        if open_sealed(wallet_id, blob) != dummy:
            raise KeyStoreError("Self-test round trip failed")
        checks.append("native-keychain-seal-open")
        if seal(wallet_id, dummy) == blob:
            raise KeyStoreError("Self-test nonce freshness failed")
        checks.append("fresh-gcm-nonce")
        corrupt = bytearray(blob)
        corrupt[-1] ^= 1
        try:
            open_sealed(wallet_id, bytes(corrupt))
        except KeyStoreError:
            checks.append("ciphertext-tamper-rejected")
        else:
            raise KeyStoreError("Self-test tampering was accepted")
    finally:
        if attempted:
            native.delete_self_test(wallet_id)
    if native.read(wallet_id) is not None:
        raise KeyStoreError("Self-test cleanup failed")
    checks.append("self-test-item-deleted")
    return {"status": "pass", **backend_metadata(), "checks": checks,
            "seed_generated": False, "secret_files_written": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.add_argument("--backend", choices=tuple(_BACKENDS), default="login")
    args = parser.parse_args()
    set_backend(args.backend)
    try:
        report = _self_test()
    except KeyStoreError as error:
        print(json.dumps({"status": "error", **backend_metadata(), "error": str(error)}))
        return 1
    except Exception:
        print(json.dumps({"status": "error", **backend_metadata(), "error": "Native keystore self-test failed"}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
