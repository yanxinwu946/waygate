"""Pure python BLAKE2s (RFC 7693).

WireGuard's Noise handshake is built on BLAKE2s (hashing, HMAC based KDFs and
the 128 bit MACs).  ``hashlib.blake2s`` is unusable on some CPython builds - the
3.14.7 Windows build hangs forever inside the constructor - so this module ships
a small, dependency free implementation.  It is only used for the handshake
(a handful of short hashes every couple of minutes), never for bulk data, so
being pure python costs nothing measurable.

The API mirrors :mod:`hashlib`: ``Blake2s(data, key=..., digest_size=...)`` with
``update()`` / ``digest()`` / ``hexdigest()`` / ``copy()``.
"""

from __future__ import annotations

import struct

__all__ = ["Blake2s", "blake2s", "new"]

_MASK = 0xFFFFFFFF
_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)
_UNPACK = struct.Struct("<16I").unpack
_PACK = struct.Struct("<8I").pack


def _compress(h: list[int], block: bytes, counter: int, last: bool) -> None:
    m = _UNPACK(block)
    v = h + list(_IV)
    v[12] ^= counter & _MASK
    v[13] ^= (counter >> 32) & _MASK
    if last:
        v[14] ^= _MASK

    for sigma in _SIGMA:
        # column round
        _mix(v, 0, 4, 8, 12, m[sigma[0]], m[sigma[1]])
        _mix(v, 1, 5, 9, 13, m[sigma[2]], m[sigma[3]])
        _mix(v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]])
        _mix(v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]])
        # diagonal round
        _mix(v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]])
        _mix(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]])
        _mix(v, 2, 7, 8, 13, m[sigma[12]], m[sigma[13]])
        _mix(v, 3, 4, 9, 14, m[sigma[14]], m[sigma[15]])

    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]


def _mix(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    va, vb, vc, vd = v[a], v[b], v[c], v[d]

    va = (va + vb + x) & _MASK
    vd = ((vd ^ va) >> 16) | ((vd ^ va) << 16) & _MASK
    vc = (vc + vd) & _MASK
    vb ^= vc
    vb = ((vb >> 12) | (vb << 20)) & _MASK

    va = (va + vb + y) & _MASK
    vd ^= va
    vd = ((vd >> 8) | (vd << 24)) & _MASK
    vc = (vc + vd) & _MASK
    vb ^= vc
    vb = ((vb >> 7) | (vb << 25)) & _MASK

    v[a], v[b], v[c], v[d] = va, vb, vc, vd


class Blake2s:
    """Incremental BLAKE2s hash object."""

    block_size = 64
    digest_size = 32
    name = "blake2s"

    def __init__(self, data: bytes = b"", *, key: bytes = b"", digest_size: int = 32) -> None:
        if not 1 <= digest_size <= 32:
            raise ValueError("digest_size must be between 1 and 32 bytes")
        if len(key) > 32:
            raise ValueError("key must be at most 32 bytes")
        self.digest_size = digest_size
        self._h = list(_IV)
        self._h[0] ^= 0x01010000 ^ (len(key) << 8) ^ digest_size
        self._buffer = bytearray()
        self._counter = 0
        if key:
            # the key is padded to a full block and prepended to the message
            self._buffer += key + b"\x00" * (64 - len(key))
        if data:
            self.update(data)

    # ------------------------------------------------------------- hashing
    def update(self, data: bytes) -> "Blake2s":
        if not data:
            return self
        buffer = self._buffer
        buffer += data
        # keep the final block buffered: only compress complete blocks that are
        # followed by more data.  Note the counter is incremented *before* the
        # compression (RFC 7693 counts the bytes of the block being processed).
        while len(buffer) > 64:
            self._counter += 64
            _compress(self._h, bytes(buffer[:64]), self._counter, False)
            del buffer[:64]
        return self

    def digest(self) -> bytes:
        buffer = bytes(self._buffer)
        if len(buffer) < 64:
            buffer += b"\x00" * (64 - len(buffer))
        h = list(self._h)
        _compress(h, buffer, self._counter + len(self._buffer), True)
        return _PACK(*h)[: self.digest_size]

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "Blake2s":
        clone = object.__new__(Blake2s)
        clone.digest_size = self.digest_size
        clone._h = list(self._h)
        clone._buffer = bytearray(self._buffer)
        clone._counter = self._counter
        return clone


def blake2s(data: bytes = b"", *, key: bytes = b"", digest_size: int = 32) -> Blake2s:
    return Blake2s(data, key=key, digest_size=digest_size)


def new(data: bytes = b"", *, key: bytes = b"", digest_size: int = 32) -> Blake2s:
    return Blake2s(data, key=key, digest_size=digest_size)


def digest(data: bytes, *, key: bytes = b"", digest_size: int = 32) -> bytes:
    return Blake2s(data, key=key, digest_size=digest_size).digest()
