# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a ledger's private keys are encrypted with.

A random 32-byte master key encrypts each source's private keys, and the
passphrase encrypts the master key, as in Bitcoin Core's
`CWallet::EncryptWallet` (src/wallet/wallet.cpp:850-923 at
bitcoin/bitcoin@f0de87f040, the v32.1 tag). A new passphrase encrypts
the same master key again, and nothing else is rewritten.

The key that encrypts the master key is scrypt's, through
`hashlib.scrypt`, of the passphrase and a random salt. scrypt's
parameters are written beside the encrypted master key, so a file keeps
the cost it was written with. A file asking for more than this release
writes is refused, as `_assert_cost` says. Where the interpreter's
OpenSSL lacks scrypt, a function that runs it raises
`BTClibRuntimeError`.

scrypt reads its password as an HMAC key, which is padded with zeros,
so a passphrase and the same one with NUL characters appended would
derive one key. What scrypt is given is the passphrase's UTF-8 bytes
after their length, in eight bytes, which tells the two apart.

Every encryption is AES-256-GCM, through the `cryptography` package,
under a random 12-byte nonce written before the ciphertext. Its tag
tells a wrong key from the right one: a wrong passphrase fails at the
master key, and a damaged ciphertext under the right master key fails
at the source it belongs to. The associated data names what a ciphertext
is, so one moved to another place in the file fails too.

Each plaintext key is held in a `bytearray` that `_wipe` zeroes. That
narrows the time a key is in memory and does not close it, since
immutable copies remain, which nothing can zero until they are
collected:

- `hashlib.scrypt` answers `bytes`, copied into the buffer;
- `secrets.token_bytes` answers the new master key as `bytes`, copied
  into the buffer;
- the passphrase is a `str`, and its UTF-8 encoding `bytes`;
- the `cryptography` package holds its own copy of a key for the life
  of each cipher object;
- what `Ledger.encrypt` and `Ledger.add_source` encrypt is a source's
  descriptors and extended private keys as JSON, a `str` and then
  `bytes`;
- parsing a decrypted source copies its keys into `str` objects.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from btclib.exceptions import BTClibRuntimeError, BTClibValueError

if TYPE_CHECKING:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__: list[str] = []

# scrypt's cost for a new passphrase: N = 2**17, r = 8 and p = 1 take
# 128 MiB
_SCRYPT_N = 2**17
_SCRYPT_R = 8
_SCRYPT_P = 1
# what scrypt may allocate, 256 MiB: hashlib's default, 32 MiB, is less
# than the cost above takes
_SCRYPT_MAXMEM = 2**28

_KEY_SIZE = 32
_SALT_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16

# the associated data of the encrypted master key
_MASTER_KEY_AAD = b"btclib-wallet ledger master key"

# `hashlib.scrypt` exists only where the interpreter's OpenSSL has scrypt.
# Probed once, as `bip38` probes it.
_HASHLIB_HAS_SCRYPT = hasattr(hashlib, "scrypt")

_NO_CRYPTOGRAPHY = (
    "the cryptography package is missing, as an install on Windows arm64"
    " leaves it, and a ledger's encryption needs it: install"
    " btclib-wallet[encryption]"
)


class _WrongKeyError(Exception):
    """A ciphertext's tag does not match the key it was opened with."""


@dataclass(frozen=True)
class _MasterKey:
    """The master key as the file holds it: encrypted, with scrypt's inputs.

    The repr leaves out the salt and the ciphertext, which together are
    what a guess of the passphrase is checked against.
    """

    n: int
    r: int
    p: int
    salt: bytes = field(repr=False)
    encrypted: bytes = field(repr=False)


def _assert_cost(n: int, r: int, p: int) -> None:
    """Refuse a scrypt cost above what this release writes.

    N is a power of 2 from 2 to `_SCRYPT_N`, and r and p are from 1 to
    `_SCRYPT_R` and `_SCRYPT_P`, so that a crafted file cannot make an
    unlock cost more than a new passphrase does.
    """
    if not (
        2 <= n <= _SCRYPT_N
        and n & (n - 1) == 0
        and 1 <= r <= _SCRYPT_R
        and 1 <= p <= _SCRYPT_P
    ):
        err_msg = f"not a ledger file: scrypt's cost N={n}, r={r}, p={p}"
        raise BTClibValueError(f"{err_msg} is outside what this release writes")


def _cipher() -> tuple[type[AESGCM], type[InvalidTag]]:
    """Return `cryptography`'s AES-GCM and its tag's failure.

    Imported here, at the first call that needs them: an install on
    Windows arm64 leaves `cryptography` out, and a ledger never encrypted
    runs without it. Where it is missing, the call is refused.
    """
    try:
        from cryptography.exceptions import InvalidTag  # noqa: PLC0415
        from cryptography.hazmat.primitives.ciphers.aead import (  # noqa: PLC0415
            AESGCM,
        )
    except ImportError:
        raise BTClibRuntimeError(_NO_CRYPTOGRAPHY) from None
    return AESGCM, InvalidTag


def _wipe(buffer: bytearray) -> None:
    """Overwrite a buffer with zeros."""
    buffer[:] = bytes(len(buffer))


def _new_key() -> bytearray:
    """Return a new random master key."""
    return bytearray(secrets.token_bytes(_KEY_SIZE))


def _encoded(passphrase: str) -> bytearray:
    """Return a passphrase's UTF-8 bytes after their length.

    A lone surrogate, which UTF-8 cannot encode, is refused.
    """
    try:
        encoded = passphrase.encode("utf-8")
    except UnicodeEncodeError:
        pass
    else:
        return bytearray(len(encoded).to_bytes(8, "big")) + encoded
    # outside the `except`: the UnicodeEncodeError holds the passphrase,
    # and would be the refusal's context
    raise BTClibValueError("invalid passphrase: not encodable in UTF-8")


def _passphrase_key(passphrase: str, n: int, r: int, p: int, salt: bytes) -> bytearray:
    """Return the key scrypt derives from a passphrase.

    `_assert_cost` has bounded the parameters of a file's master key.
    Where `cryptography` is missing, the call is refused before scrypt
    runs, since what the key is for needs it.
    """
    _cipher()
    if not _HASHLIB_HAS_SCRYPT:
        err_msg = (
            "hashlib.scrypt is missing (the interpreter's OpenSSL lacks"
            " scrypt), and a ledger's encryption needs it"
        )
        raise BTClibRuntimeError(err_msg)
    password = _encoded(passphrase)
    try:
        return bytearray(
            hashlib.scrypt(
                password,
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=_SCRYPT_MAXMEM,
                dklen=_KEY_SIZE,
            )
        )
    finally:
        _wipe(password)


def _sealed(key: bytearray, plaintext: bytes | bytearray, aad: bytes) -> bytes:
    """Return the nonce and the ciphertext of `plaintext` under `key`."""
    aesgcm, _ = _cipher()
    nonce = secrets.token_bytes(_NONCE_SIZE)
    return nonce + aesgcm(key).encrypt(nonce, plaintext, aad)


def _opened(key: bytearray, sealed: bytes, aad: bytes) -> bytearray:
    """Return the plaintext `_sealed` encrypted, in a buffer `_wipe` can zero.

    A wrong key, a damaged ciphertext and a wrong `aad` raise
    `_WrongKeyError`, the tag telling none of them apart. The buffer is
    zeroed first: `decrypt_into` writes the plaintext before it checks
    the tag.
    """
    aesgcm, invalid_tag = _cipher()
    size = len(sealed) - _NONCE_SIZE - _TAG_SIZE
    if size < 0:
        raise _WrongKeyError
    plaintext = bytearray(size)
    try:
        aesgcm(key).decrypt_into(
            sealed[:_NONCE_SIZE], sealed[_NONCE_SIZE:], aad, plaintext
        )
    except invalid_tag:
        _wipe(plaintext)
        raise _WrongKeyError from None
    return plaintext


def _master_key(passphrase: str, key: bytearray) -> _MasterKey:
    """Return `key` encrypted under a passphrase, with a new salt."""
    salt = secrets.token_bytes(_SALT_SIZE)
    passphrase_key = _passphrase_key(passphrase, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, salt)
    try:
        encrypted = _sealed(passphrase_key, key, _MASTER_KEY_AAD)
    finally:
        _wipe(passphrase_key)
    return _MasterKey(_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, salt, encrypted)


def _unlocked(passphrase: str, master_key: _MasterKey) -> bytearray | None:
    """Return the master key a passphrase decrypts, None where it is wrong."""
    passphrase_key = _passphrase_key(
        passphrase, master_key.n, master_key.r, master_key.p, master_key.salt
    )
    try:
        key = _opened(passphrase_key, master_key.encrypted, _MASTER_KEY_AAD)
    except _WrongKeyError:
        return None
    finally:
        _wipe(passphrase_key)
    if len(key) != _KEY_SIZE:
        _wipe(key)
        raise BTClibValueError("not a ledger file: the master key is no 32 bytes")
    return key
