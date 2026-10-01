"""A small, self contained WireGuard client (Noise_IKpsk2) used for WARP.

This implements the parts of the protocol a *client* needs:

* handshake initiation / response consumption (Noise IK with a zero psk)
* transport data messages (ChaCha20-Poly1305, 64 bit counters, replay window)
* the Cloudflare specific ``reserved`` header bytes (the WARP ``client_id``)
* handshake retries, rekeying, persistent keepalives and session expiry

The tunnel is driven entirely from an asyncio event loop; ``send_ip()`` hands a
raw IPv4 packet to the tunnel and ``on_ip`` is called for every packet that
comes back.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
import os
import struct
import time
from typing import Callable, Iterable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .blake2s import Blake2s

log = logging.getLogger("waygate.wg")

# ---------------------------------------------------------------- constants
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

MSG_INITIATION = 1
MSG_RESPONSE = 2
MSG_COOKIE_REPLY = 3
MSG_TRANSPORT = 4

MSG_INITIATION_SIZE = 148
MSG_RESPONSE_SIZE = 92
MSG_TRANSPORT_HEADER = 16

REKEY_AFTER_TIME = 120.0       # initiator rekeys after this many seconds
REJECT_AFTER_TIME = 180.0      # a session is dead after this many seconds
REKEY_TIMEOUT = 5.0            # resend a handshake initiation after this
KEEPALIVE_TIMEOUT = 10.0
PERSISTENT_KEEPALIVE = 25.0
MAX_HANDSHAKE_ATTEMPTS = 12    # 12 * 5s = 60s before we give up
REPLAY_WINDOW = 128

_INITIAL_CHAIN_KEY = Blake2s(CONSTRUCTION).digest()
_INITIAL_HASH = Blake2s(_INITIAL_CHAIN_KEY + IDENTIFIER).digest()

_RAW = serialization.Encoding.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_NO_ENC = serialization.NoEncryption()


# ------------------------------------------------------------- primitives
def _hash(*parts: bytes) -> bytes:
    digest = Blake2s()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _mac(key: bytes, data: bytes, size: int = 16) -> bytes:
    return Blake2s(data, key=key, digest_size=size).digest()


def _kdf(key: bytes, data: bytes, count: int) -> list[bytes]:
    """WireGuard's HKDF over BLAKE2s (KDF1/KDF2/KDF3)."""
    prk = hmac.new(key, data, Blake2s).digest()
    out: list[bytes] = []
    prev = b""
    for index in range(1, count + 1):
        prev = hmac.new(prk, prev + bytes([index]), Blake2s).digest()
        out.append(prev)
    return out


def _kdf1(key: bytes, data: bytes) -> bytes:
    return _kdf(key, data, 1)[0]


def _kdf2(key: bytes, data: bytes) -> tuple[bytes, bytes]:
    out = _kdf(key, data, 2)
    return out[0], out[1]


def _kdf3(key: bytes, data: bytes) -> tuple[bytes, bytes, bytes]:
    out = _kdf(key, data, 3)
    return out[0], out[1], out[2]


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(_RAW, _RAW_PRIV, _NO_ENC)


def public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(_RAW, _RAW_PUB)


def load_private_key(value: str | bytes) -> X25519PrivateKey:
    raw = base64.b64decode(value) if isinstance(value, str) else value
    return X25519PrivateKey.from_private_bytes(raw)


def dh(private: X25519PrivateKey, peer_public: bytes) -> bytes:
    return private.exchange(X25519PublicKey.from_public_bytes(peer_public))


def tai64n_now() -> bytes:
    """12 byte TAI64N timestamp, exactly like wireguard-go's tai64n.Now()."""
    now = time.time()
    seconds = int(now)
    nanos = int((now - seconds) * 1_000_000_000)
    return struct.pack("!QI", 0x400000000000000A + seconds, nanos)


class ReplayFilter:
    """Sliding window replay protection for the 64 bit transport counter."""

    __slots__ = ("highest", "bitmap")

    def __init__(self) -> None:
        self.highest = -1
        self.bitmap = 0

    def check(self, counter: int) -> bool:
        if counter > self.highest:
            shift = counter - self.highest
            self.bitmap = 1 if shift >= REPLAY_WINDOW else ((self.bitmap << shift) | 1)
            self.highest = counter
            return True
        delta = self.highest - counter
        if delta >= REPLAY_WINDOW:
            return False
        bit = 1 << delta
        if self.bitmap & bit:
            return False
        self.bitmap |= bit
        return True


class Keypair:
    """An established transport session."""

    __slots__ = (
        "local_index",
        "remote_index",
        "send",
        "recv",
        "send_counter",
        "replay",
        "created",
        "last_send",
        "last_recv",
        "is_initiator",
        "reserved",
    )

    def __init__(
        self,
        local_index: int,
        remote_index: int,
        send_key: bytes,
        recv_key: bytes,
        reserved: bytes,
    ) -> None:
        self.local_index = local_index
        self.remote_index = remote_index
        self.send = ChaCha20Poly1305(send_key)
        self.recv = ChaCha20Poly1305(recv_key)
        self.send_counter = 0
        self.replay = ReplayFilter()
        self.created = time.monotonic()
        self.last_send = 0.0
        self.last_recv = 0.0
        self.is_initiator = True
        self.reserved = reserved

    # -------------------------------------------------------------- helpers
    @property
    def age(self) -> float:
        return time.monotonic() - self.created

    def needs_rekey(self) -> bool:
        return self.age > REKEY_AFTER_TIME

    def is_dead(self) -> bool:
        return self.age > REJECT_AFTER_TIME

    def encrypt(self, payload: bytes) -> bytes:
        counter = self.send_counter
        self.send_counter += 1
        nonce = struct.pack("<Q", counter) + b"\x00\x00\x00\x00"
        header = (
            bytes((MSG_TRANSPORT,))
            + self.reserved
            + struct.pack("<IQ", self.remote_index, counter)
        )
        self.last_send = time.monotonic()
        return header + self.send.encrypt(nonce, payload, b"")

    def decrypt(self, packet: bytes) -> Optional[bytes]:
        if len(packet) < MSG_TRANSPORT_HEADER + 16:
            return None
        receiver, counter = struct.unpack_from("<IQ", packet, 4)
        if receiver != self.local_index:
            return None
        if not self.replay.check(counter):
            return None
        nonce = struct.pack("<Q", counter) + b"\x00\x00\x00\x00"
        try:
            payload = self.recv.decrypt(nonce, packet[MSG_TRANSPORT_HEADER:], b"")
        except Exception:
            return None
        self.last_recv = time.monotonic()
        return payload


def build_handshake_initiation(
    static_private: X25519PrivateKey,
    peer_public: bytes,
    ephemeral: X25519PrivateKey,
    *,
    reserved: bytes = b"\x00\x00\x00",
    local_index: int = 0,
    timestamp: Optional[bytes] = None,
) -> tuple[bytes, bytes, bytes]:
    """Build a handshake initiation message.

    Returns ``(message, chain_key, hash)``; the last two are the Noise state the
    response has to be mixed into.  ``ephemeral`` and ``timestamp`` are
    injectable so the implementation can be checked against test vectors.
    """
    chain_key = _INITIAL_CHAIN_KEY
    handshake_hash = _INITIAL_HASH
    ephemeral_public = public_bytes(ephemeral.public_key())
    static_public = public_bytes(static_private.public_key())

    handshake_hash = _hash(handshake_hash, peer_public)          # HASH(Hi || Spub_r)
    chain_key = _kdf1(chain_key, ephemeral_public)               # KDF1(Ci, Epub_i)
    handshake_hash = _hash(handshake_hash, ephemeral_public)     # HASH(Hi || Epub_i)

    chain_key, key = _kdf2(chain_key, dh(ephemeral, peer_public))       # es
    encrypted_static = ChaCha20Poly1305(key).encrypt(
        b"\x00" * 12, static_public, handshake_hash
    )
    handshake_hash = _hash(handshake_hash, encrypted_static)

    chain_key, key = _kdf2(chain_key, dh(static_private, peer_public))  # ss
    encrypted_timestamp = ChaCha20Poly1305(key).encrypt(
        b"\x00" * 12, timestamp if timestamp is not None else tai64n_now(), handshake_hash
    )
    handshake_hash = _hash(handshake_hash, encrypted_timestamp)

    message = (
        bytes((MSG_INITIATION,))
        + (reserved + b"\x00\x00\x00")[:3]
        + struct.pack("<I", local_index)
        + ephemeral_public
        + encrypted_static
        + encrypted_timestamp
    )
    message += _mac(_hash(LABEL_MAC1, peer_public), message)
    message += b"\x00" * 16
    assert len(message) == MSG_INITIATION_SIZE
    return message, chain_key, handshake_hash


class _PendingHandshake:
    """State kept between sending an initiation and consuming the response."""

    __slots__ = ("chain_key", "hash", "ephemeral", "local_index", "sent_at")

    def __init__(self, local_index: int) -> None:
        self.chain_key = _INITIAL_CHAIN_KEY
        self.hash = _INITIAL_HASH
        self.ephemeral: Optional[X25519PrivateKey] = None
        self.local_index = local_index
        self.sent_at = 0.0


class _Path:
    """One UDP socket (IPv4 or IPv6) plus the endpoints to talk to."""

    def __init__(self, family: str, endpoints: list[tuple[str, int]]) -> None:
        self.family = family
        self.endpoints = endpoints
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.active: Optional[tuple[str, int]] = None
        self.send_count = 0
        self.recv_count = 0


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnel: "WireGuardTunnel", path: _Path) -> None:
        self.tunnel = tunnel
        self.path = path

    def datagram_received(self, data: bytes, addr) -> None:
        self.path.recv_count += 1
        self.tunnel._on_datagram(data, addr, self.path)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        log.debug("udp error on %s path: %s", self.path.family, exc)

    def connection_lost(self, exc) -> None:  # pragma: no cover
        if exc:
            log.debug("udp socket closed (%s): %s", self.path.family, exc)


class WireGuardTunnel:
    """WireGuard client tunnel towards a WARP endpoint."""

    def __init__(
        self,
        private_key: str | bytes,
        peer_public_key: str | bytes,
        reserved: bytes = b"\x00\x00\x00",
        *,
        on_ip: Optional[Callable[[bytes], None]] = None,
        keepalive: float = PERSISTENT_KEEPALIVE,
        queue_size: int = 256,
        mtu: int = 1280,
    ) -> None:
        self.static_private = load_private_key(private_key)
        self.static_public = public_bytes(self.static_private.public_key())
        self.peer_public = (
            base64.b64decode(peer_public_key)
            if isinstance(peer_public_key, str)
            else peer_public_key
        )
        self.reserved = (reserved + b"\x00\x00\x00")[:3]
        self.on_ip = on_ip
        self.keepalive = keepalive
        self.mtu = mtu
        self.queue_size = queue_size

        self._paths: list[_Path] = []
        self._pending: Optional[_PendingHandshake] = None
        self._attempts = 0
        self._keypairs: dict[int, Keypair] = {}
        self._current: Optional[Keypair] = None
        self._next_index = int.from_bytes(os.urandom(4), "little") | 1
        self._queue: list[bytes] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._timer_task: Optional[asyncio.Task] = None
        self._ready = asyncio.Event()
        self._closed = False
        self._error: Optional[BaseException] = None
        self._last_handshake_error = ""
        self.stats = {
            "tx_packets": 0,
            "rx_packets": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "handshakes": 0,
            "handshake_failures": 0,
        }

    # ------------------------------------------------------------- lifecycle
    async def start(
        self,
        endpoints_v4: Iterable[tuple[str, int]] = (),
        endpoints_v6: Iterable[tuple[str, int]] = (),
    ) -> None:
        self._loop = asyncio.get_running_loop()
        for family, endpoints in (("v4", list(endpoints_v4)), ("v6", list(endpoints_v6))):
            if not endpoints:
                continue
            try:
                await self._open_path(family, endpoints)
            except OSError as exc:
                log.debug("cannot open a %s UDP socket: %s", family, exc)
        if not self._paths:
            raise RuntimeError("no usable UDP socket for the WARP endpoint")
        log.debug(
            "tunnel up with paths: %s",
            ", ".join(f"{p.family}({len(p.endpoints)} endpoints)" for p in self._paths),
        )
        self._timer_task = asyncio.create_task(self._timer_loop(), name="wg-timer")
        self._initiate_handshake()

    async def _open_path(self, family: str, endpoints: list[tuple[str, int]]) -> None:
        loop = asyncio.get_running_loop()
        path = _Path(family, endpoints)
        local = ("0.0.0.0", 0) if family == "v4" else ("::", 0)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self, path), local_addr=local
        )
        path.transport = transport  # type: ignore[assignment]
        self._paths.append(path)

    async def stop(self) -> None:
        self._closed = True
        if self._timer_task:
            self._timer_task.cancel()
            try:
                await self._timer_task
            except (asyncio.CancelledError, Exception):
                pass
        for path in self._paths:
            if path.transport:
                path.transport.close()
        self._paths.clear()

    async def wait_ready(self, timeout: float = 30.0) -> None:
        try:
            await asyncio.wait_for(self._ready.wait(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                "WARP handshake did not complete within %.0fs%s"
                % (timeout, f" ({self._last_handshake_error})" if self._last_handshake_error else "")
            ) from None

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and self._current is not None and not self._current.is_dead()

    @property
    def peer_endpoint(self) -> Optional[tuple[str, int]]:
        for path in self._paths:
            if path.active:
                return path.active
        return None

    @property
    def local_endpoint(self) -> Optional[str]:
        for path in self._paths:
            if path.active and path.transport:
                sock = path.transport.get_extra_info("socket")
                if sock is not None:
                    return f"{sock.getsockname()[0]}:{sock.getsockname()[1]}"
        return None

    # ------------------------------------------------------------- handshake
    def _new_index(self) -> int:
        self._next_index = (self._next_index + 1) & 0xFFFFFFFF
        return self._next_index

    def _initiate_handshake(self) -> None:
        if self._closed:
            return
        pending = _PendingHandshake(self._new_index())
        pending.ephemeral = X25519PrivateKey.generate()
        message, chain_key, handshake_hash = build_handshake_initiation(
            self.static_private,
            self.peer_public,
            pending.ephemeral,
            reserved=self.reserved,
            local_index=pending.local_index,
        )
        pending.chain_key = chain_key
        pending.hash = handshake_hash

        pending.sent_at = time.monotonic()
        self._pending = pending
        self._attempts += 1
        self._broadcast(message)
        log.debug("sent handshake initiation #%d (index %d)", self._attempts, pending.local_index)

    def _consume_response(self, packet: bytes, addr, path: _Path) -> None:
        pending = self._pending
        if pending is None:
            return
        if len(packet) != MSG_RESPONSE_SIZE:
            return
        sender, receiver = struct.unpack_from("<II", packet, 4)
        if receiver != pending.local_index:
            return
        # mac1 must authenticate the responder's static key
        expected_mac1 = _mac(_hash(LABEL_MAC1, self.static_public), packet[:-32])
        if not hmac.compare_digest(expected_mac1, packet[-32:-16]):
            log.debug("handshake response with bad mac1, ignoring")
            return

        ephemeral = packet[12:44]
        empty = packet[44:60]
        chain = pending.chain_key
        handshake_hash = _hash(pending.hash, ephemeral)
        chain = _kdf1(chain, ephemeral)
        try:
            chain = _kdf1(chain, dh(pending.ephemeral, ephemeral))  # ee
            chain = _kdf1(chain, dh(self.static_private, ephemeral))  # se
        except ValueError:
            log.debug("handshake response contained an invalid ephemeral key")
            return
        chain, tau, key = _kdf3(chain, bytes(32))  # zero psk
        handshake_hash = _hash(handshake_hash, tau)
        try:
            if ChaCha20Poly1305(key).decrypt(b"\x00" * 12, empty, handshake_hash) != b"":
                return
        except Exception:
            log.debug("handshake response failed to authenticate")
            return
        handshake_hash = _hash(handshake_hash, empty)
        del handshake_hash

        send_key, recv_key = _kdf2(chain, b"")
        keypair = Keypair(pending.local_index, sender, send_key, recv_key, self.reserved)
        self._install_keypair(keypair)
        path.active = tuple(addr)[:2]  # type: ignore[assignment]
        self._pending = None
        self._attempts = 0
        self.stats["handshakes"] += 1
        log.info(
            "WARP handshake complete via %s (%s) - session index %d",
            path.family,
            addr,
            keypair.local_index,
        )
        # confirm the session and flush anything that piled up while connecting
        self._send_transport(b"")
        self._flush_queue()
        self._ready.set()

    def _install_keypair(self, keypair: Keypair) -> None:
        previous = self._current
        self._keypairs[keypair.local_index] = keypair
        self._current = keypair
        # keep at most two sessions around so late packets of the old one still work
        for index, other in list(self._keypairs.items()):
            if other is not previous and other is not keypair:
                del self._keypairs[index]

    # ---------------------------------------------------------------- data
    def send_ip(self, packet: bytes) -> None:
        """Queue / send one IPv4 packet through the tunnel."""
        keypair = self._current
        if keypair is None or keypair.is_dead():
            if len(self._queue) < self.queue_size:
                self._queue.append(packet)
            if self._pending is None:
                self._initiate_handshake()
            return
        self._send_transport(packet, keypair)

    def _send_transport(self, payload: bytes, keypair: Optional[Keypair] = None) -> None:
        keypair = keypair or self._current
        if keypair is None:
            return
        message = keypair.encrypt(payload)
        self._broadcast(message, prefix_only=keypair.remote_index)
        self.stats["tx_packets"] += 1
        self.stats["tx_bytes"] += len(payload)

    def _flush_queue(self) -> None:
        queue, self._queue = self._queue, []
        for packet in queue:
            self.send_ip(packet)

    def _broadcast(
        self, message: bytes, prefix_only: Optional[int] = None
    ) -> None:
        """Send a message.  Handshakes race all endpoints, data uses the live one."""
        for path in self._paths:
            if path.transport is None:
                continue
            if prefix_only is not None:
                if path.active is None:
                    continue
                path.transport.sendto(message, path.active)
                path.send_count += 1
            else:
                for endpoint in path.endpoints:
                    path.transport.sendto(message, endpoint)
                    path.send_count += 1

    def _on_datagram(self, data: bytes, addr, path: _Path) -> None:
        if not data:
            return
        message_type = data[0]
        if message_type == MSG_RESPONSE:
            self._consume_response(data, addr, path)
            return
        if message_type == MSG_TRANSPORT:
            self._handle_transport(data, addr, path)
            return
        if message_type == MSG_COOKIE_REPLY:
            log.warning(
                "WARP endpoint sent a cookie reply (rate limiting / DoS mitigation); "
                "the handshake will be retried"
            )
            self._last_handshake_error = "cookie reply received (rate limited)"
            return
        log.debug("ignoring unknown wireguard message type %d", message_type)

    def _handle_transport(self, packet: bytes, addr, path: _Path) -> bool:
        receiver = struct.unpack_from("<I", packet, 4)[0]
        keypair = self._keypairs.get(receiver)
        if keypair is None:
            return False
        payload = keypair.decrypt(packet)
        if payload is None:
            return False
        keypair.last_recv = time.monotonic()
        if path.active is None:
            # remember who answered, so data messages go to the live endpoint
            path.active = tuple(addr)[:2]  # type: ignore[assignment]
        if payload:
            self.stats["rx_packets"] += 1
            self.stats["rx_bytes"] += len(payload)
            if self.on_ip is not None:
                try:
                    self.on_ip(payload)
                except Exception:  # pragma: no cover - never kill the tunnel
                    log.exception("error while handling a tunnel packet")
        return True

    # --------------------------------------------------------------- timers
    async def _timer_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(0.25)
                now = time.monotonic()
                keypair = self._current
                if keypair is not None and keypair.is_dead():
                    log.debug("transport session expired, re-handshaking")
                    self._current = None
                    self._ready.clear()
                    keypair = None
                pending = self._pending
                if pending is not None:
                    if now - pending.sent_at > REKEY_TIMEOUT:
                        if self._attempts >= MAX_HANDSHAKE_ATTEMPTS:
                            self._pending = None
                            self._last_handshake_error = (
                                f"no response after {self._attempts} attempts"
                            )
                            self.stats["handshake_failures"] += 1
                            log.warning("handshake gave up: %s", self._last_handshake_error)
                            self._attempts = 0
                        else:
                            self._initiate_handshake()
                elif keypair is None or keypair.needs_rekey():
                    self._initiate_handshake()
                if self._current is not None and self.keepalive > 0:
                    if now - max(self._current.last_send, self._current.created) >= self.keepalive:
                        self._send_transport(b"")
        except asyncio.CancelledError:
            pass
        except Exception:  # pragma: no cover
            log.exception("wireguard timer loop crashed")

    # ---------------------------------------------------------------- status
    def describe(self) -> str:
        endpoint = self.peer_endpoint
        return (
            f"endpoint={endpoint} sessions={len(self._keypairs)} "
            f"tx={self.stats['tx_packets']} rx={self.stats['rx_packets']} "
            f"handshakes={self.stats['handshakes']}"
        )
