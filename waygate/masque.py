"""MASQUE transport: Cloudflare's ``cf-connect-ip`` over HTTP/3.

The official WARP clients switched from WireGuard to MASQUE, and on many
censored networks (China in particular) that is the *only* transport that gets
through: WireGuard's UDP/2408 handshake is dropped, while QUIC to
``162.159.198.1:443`` with SNI ``consumer-masque.cloudflareclient.com`` works.

This module speaks that protocol:

* QUIC + TLS 1.3 with the client certificate that was enrolled through the WARP
  API (``key_type=secp256r1``, ``tunnel_type=masque``)
* an extended CONNECT request (``:protocol: cf-connect-ip``) on an HTTP/3 stream
* raw IPv4 packets as HTTP/3 datagrams on that stream - exactly the same
  ``send_ip`` / ``on_ip`` interface the WireGuard tunnel exposes, so
  :mod:`waygate.ipstack` does not care which one is underneath.

Cloudflare's implementation is not strictly RFC 9484: it does not advertise
routes and accepts datagrams as soon as the request succeeds, so we simply start
sending.  ADDRESS_ASSIGN capsules are parsed (and logged) when they do arrive.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from typing import Callable, Optional

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (ConnectionTerminated, DatagramFrameReceived,
                                 HandshakeCompleted, PingAcknowledged)
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

from .pq import enable_post_quantum

log = logging.getLogger("waygate.masque")

#: Cloudflare's non-standard CONNECT-IP protocol identifier (RFC 9484 says "connect-ip")
CONNECT_PROTOCOL = "cf-connect-ip"
#: SNI the official clients use for consumer WARP over MASQUE
DEFAULT_SNI = "consumer-masque.cloudflareclient.com"
#: the URI template host from the official client
CONNECT_AUTHORITY = "cloudflareaccess.com"
CONNECT_PATH = "/"
#: client version string the official client reports in the CONNECT-IP request
CLIENT_VERSION_MASQUE = "l-2026.6.880.0"
#: the official client's max_udp_payload_size (its qlog advertises 1353)
OFFICIAL_MAX_UDP_PAYLOAD = 1353

CAPSULE_ADDRESS_ASSIGN = 0x01
CAPSULE_ADDRESS_REQUEST = 0x02
CAPSULE_ROUTE_ADVERTISEMENT = 0x03

TUNNEL_MTU = 1280


def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes((value,))
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return ``(value, new_offset)``; raises ``ValueError`` when truncated."""
    if offset >= len(data):
        raise ValueError("truncated varint")
    first = data[offset]
    length = 1 << (first >> 6)
    if offset + length > len(data):
        raise ValueError("truncated varint")
    value = int.from_bytes(data[offset : offset + length], "big")
    value &= (1 << (length * 8 - 2)) - 1
    return value, offset + length


def parse_capsules(payload: bytes) -> list[tuple[int, bytes]]:
    """Split a capsule stream into ``(type, value)`` pairs."""
    capsules: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(payload):
        capsule_type, offset = decode_varint(payload, offset)
        length, offset = decode_varint(payload, offset)
        if offset + length > len(payload):
            break
        capsules.append((capsule_type, payload[offset : offset + length]))
        offset += length
    return capsules


def parse_addresses(payload: bytes) -> list[tuple[int, str, int]]:
    """Decode ADDRESS_ASSIGN / ADDRESS_REQUEST entries."""
    entries: list[tuple[int, str, int]] = []
    offset = 0
    while offset < len(payload):
        request_id, offset = decode_varint(payload, offset)
        if offset >= len(payload):
            break
        version = payload[offset]
        offset += 1
        size = 4 if version == 4 else 16
        if offset + size + 1 > len(payload):
            break
        raw = payload[offset : offset + size]
        offset += size
        prefix = payload[offset]
        offset += 1
        if version == 4:
            address = ".".join(str(byte) for byte in raw)
        else:
            address = ":".join(f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2))
        entries.append((request_id, address, prefix))
    return entries


class _MasqueH3Connection(H3Connection):
    """H3 connection that advertises H3_DATAGRAM without the WebTransport flag.

    aioquic only sends SETTINGS_H3_DATAGRAM when enable_webtransport=True, but
    that mode also sends SETTINGS_ENABLE_WEBTRANSPORT, which the official WARP
    client does not send - and the edge treats the CONNECT-IP request as a
    broken WebTransport session then.  This subclass sends exactly the aioquic
    defaults plus H3_DATAGRAM.
    """

    def _get_local_settings(self) -> dict[int, int]:
        # aioquic's defaults + H3_DATAGRAM, but NOT SETTINGS_ENABLE_WEBTRANSPORT:
        # the official client does not send the webtransport flag, and the edge
        # closes the connection when it sees it
        settings = super()._get_local_settings()
        settings[0x33] = 1  # SETTINGS_H3_DATAGRAM
        return settings


class _MasqueProtocol(QuicConnectionProtocol):
    def __init__(self, *args, tunnel: "MasqueTunnel", **kwargs) -> None:
        # the official client speaks post-quantum MASQUE (X25519MLKEM768);
        # its first flight is two 1200-byte Initials because of the 1216-byte
        # ML-KEM key share, and censored paths treat that very differently
        enable_post_quantum()
        super().__init__(*args, **kwargs)
        self.tunnel = tunnel
        self.http = _MasqueH3Connection(self._quic)

    def quic_event_received(self, event) -> None:
        # count QUIC-level datagram frames to distinguish "the server sent
        # nothing" from "our H3 layer dropped it"
        if isinstance(event, DatagramFrameReceived):
            self.tunnel.stats["quic_rx_dgram"] += 1
        for h3_event in self.http.handle_event(event):
            try:
                self.tunnel._on_h3_event(h3_event)
            except Exception:  # pragma: no cover - never kill the connection
                log.exception("error while handling an HTTP/3 event")
        if isinstance(event, HandshakeCompleted):
            self.tunnel._on_handshake()
        elif isinstance(event, ConnectionTerminated):
            self.tunnel._on_connection_terminated(event)


class MasqueTunnel:
    """A CONNECT-IP tunnel over HTTP/3 with the same surface as ``WireGuardTunnel``."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        *,
        certificate_pem: str = "",
        private_key_pem: str = "",
        sni: str = DEFAULT_SNI,
        on_ip: Optional[Callable[[bytes], None]] = None,
        keepalive: float = 20.0,
        idle_timeout: float = 60.0,
        queue_size: int = 256,
        mtu: int = TUNNEL_MTU,
        reconnect: bool = True,
        stale_timeout: float = 8.0,
        on_reconnect: Optional[Callable[[], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.sni = sni
        self.certificate_pem = certificate_pem
        self.private_key_pem = private_key_pem
        self._on_ip = on_ip
        self.keepalive = keepalive
        self.idle_timeout = idle_timeout
        self.queue_size = queue_size
        self.mtu = mtu
        self.reconnect = reconnect

        self._context = None
        self._client: Optional[_MasqueProtocol] = None
        self._stream_id: Optional[int] = None
        self._ready = asyncio.Event()
        self._connected = asyncio.Event()
        self._response: Optional[int] = None
        self._closed = False
        self._queue: list[bytes] = []
        self._error: Optional[BaseException] = None
        #: seconds without any inbound packet before the flow is considered stale
        self.stale_timeout = stale_timeout
        self.on_reconnect = on_reconnect
        self._last_rx = time.monotonic()
        #: inner packets sent since the last inbound one (staleness detector)
        self._tx_since_rx = 0
        self._tasks: list[asyncio.Task] = []
        self.assigned: list[str] = []
        self._tx_armed = False
        self.stats = {
            "tx_packets": 0,
            "rx_packets": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "reconnects": 0,
            "capsules": 0,
            "quic_rx_dgram": 0,
        }

    # ------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        self._closed = False
        await self._connect()
        self._tasks.append(asyncio.create_task(self._keepalive_loop(), name="masque-keepalive"))
        self._tasks.append(asyncio.create_task(self._supervisor(), name="masque-supervisor"))

    def _configuration(self) -> QuicConfiguration:
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            max_datagram_frame_size=self.mtu + 64,
            # aioquic defaults to a 1200 byte QUIC payload, which silently drops
            # any DATAGRAM frame carrying a full-size inner packet (a 1280 byte
            # IP packet needs ~1310 bytes of QUIC packet).  That is why small
            # requests worked while every TLS ClientHello vanished.
            max_datagram_size=self.mtu + 120,
            idle_timeout=self.idle_timeout,
        )
        # the SNI is not the endpoint's own name, so certificate pinning is not
        # possible; the client certificate is what authenticates us
        configuration.verify_mode = ssl.CERT_NONE
        configuration.server_name = self.sni
        if self.certificate_pem and self.private_key_pem:
            configuration.certificate = load_pem_x509_certificate(
                self.certificate_pem.encode()
            )
            configuration.private_key = serialization.load_pem_private_key(
                self.private_key_pem.encode(), password=None
            )
        return configuration

    async def _connect(self) -> None:
        self._ready.clear()
        self._connected.clear()
        self._response = None
        self._stream_id = None
        log.debug("connecting MASQUE tunnel to %s:%d (sni=%s)", self.host, self.port, self.sni)
        self._context = connect(
            self.host,
            self.port,
            configuration=self._configuration(),
            create_protocol=lambda *args, **kwargs: _MasqueProtocol(
                *args, tunnel=self, **kwargs
            ),
            wait_connected=True,
        )
        self._client = await self._context.__aenter__()
        await asyncio.wait_for(self._connected.wait(), 15)
        self._open_connect_ip()
        await asyncio.wait_for(self._ready.wait(), 20)

    def _open_connect_ip(self) -> None:
        assert self._client is not None
        stream_id = self._client._quic.get_next_available_stream_id()
        self._stream_id = stream_id
        # exactly what the official client sends (verified against its qlog):
        # note the scheme is "http" even though the transport is TLS, there is
        # no capsule-protocol header, and cf-client-version is required.
        headers = [
            (b":method", b"CONNECT"),
            (b":protocol", CONNECT_PROTOCOL.encode()),
            (b":scheme", b"http"),
            (b":authority", CONNECT_AUTHORITY.encode()),
            (b":path", CONNECT_PATH.encode()),
            (b"pq-enabled", b"true"),
            (b"cf-client-version", CLIENT_VERSION_MASQUE.encode()),
        ]
        self._client.http.send_headers(stream_id, headers, end_stream=False)
        self._client.transmit()
        log.debug("sent CONNECT-IP request on stream %d", stream_id)

    async def stop(self) -> None:
        self._closed = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks.clear()
        await self._close_quic()

    async def _close_quic(self) -> None:
        if self._context is not None:
            try:
                await self._context.__aexit__(None, None, None)
            except Exception:  # pragma: no cover
                pass
            self._context = None
            self._client = None
        self._ready.clear()

    @property
    def on_ip(self) -> Optional[Callable[[bytes], None]]:
        return self._on_ip

    @on_ip.setter
    def on_ip(self, callback: Optional[Callable[[bytes], None]]) -> None:
        """Keep the inner protocol in sync.

        The datagrams are delivered by ``_MasqueProtocol``, which holds its own
        ``on_ip``; assigning to the tunnel alone would silently drop every
        reply, so forward the callback as well.
        """
        self._on_ip = callback
        client = getattr(self, "_client", None)
        if client is not None:
            client.on_ip = callback

    async def wait_ready(self, timeout: float = 30.0) -> None:
        if timeout <= 0:
            # a zero timeout would make this race the CONNECT-IP response and
            # tear down a perfectly healthy tunnel - never do that
            timeout = 30.0
        try:            await asyncio.wait_for(self._ready.wait(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"MASQUE CONNECT-IP to {self.host}:{self.port} did not come up"
            ) from None
        if self._error is not None:
            raise self._error

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and self._client is not None

    @property
    def peer_endpoint(self):
        return (self.host, self.port)

    @property
    def local_endpoint(self):
        if self._client is None:
            return None
        transport = getattr(self._client, "_transport", None)  # type: ignore[attr-defined]
        if transport is None:
            return None
        sock = transport.get_extra_info("sockname")
        return f"{sock[0]}:{sock[1]}" if sock else None

    # ------------------------------------------------------------------ data
    def send_ip(self, packet: bytes) -> None:
        if not self.ready or self._stream_id is None:
            if len(self._queue) < self.queue_size:
                self._queue.append(packet)
            return
        try:
            # RFC 9484 section 5/6: every HTTP Datagram for IP proxying starts
            # with a Context ID (0 = the IP payload).  aioquic's send_datagram
            # only prepends the quarter-stream-id, so add the context id here.
            # Context ID 0 is the one-byte varint 0x00.
            self._client.http.send_datagram(self._stream_id, b"\x00" + packet)  # type: ignore[union-attr]
            self.stats["tx_packets"] += 1
            self.stats["tx_bytes"] += len(packet)
            self._tx_since_rx += 1
            # A TCP send is many segments. Flushing each one is a separate UDP
            # write; one flush per loop turn is the same latency and far less overhead.
            self._arm_transmit()
        except Exception as exc:  # noqa: BLE001 - datagram support may be missing
            log.debug("cannot send a MASQUE datagram: %s", exc)

    def _arm_transmit(self) -> None:
        if self._tx_armed:
            return
        self._tx_armed = True
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._flush_transmit()
            return
        loop.call_soon(self._flush_transmit)

    def _flush_transmit(self) -> None:
        self._tx_armed = False
        client = self._client
        if client is None:
            return
        try:
            client.transmit()
        except Exception as exc:  # noqa: BLE001
            log.debug("MASQUE transmit failed: %s", exc)

    def _flush_queue(self) -> None:
        queue, self._queue = self._queue, []
        for packet in queue:
            self.send_ip(packet)

    # ---------------------------------------------------------------- events
    def _on_handshake(self) -> None:
        log.debug("MASQUE QUIC handshake completed")
        self._connected.set()

    def _on_h3_event(self, event) -> None:
        if isinstance(event, HeadersReceived):
            headers = {key: value for key, value in event.headers}
            if event.stream_id != self._stream_id:
                return
            status = headers.get(b":status", b"")
            self._response = int(status) if status.isdigit() else None
            if self._response == 200:
                log.info(
                    "MASQUE tunnel up: CONNECT-IP accepted by %s:%d", self.host, self.port
                )
                self._ready.set()
                self._flush_queue()
            else:
                self._error = ConnectionError(
                    f"CONNECT-IP rejected with status {self._response!r}"
                )
                self._ready.set()
        elif isinstance(event, DatagramReceived):
            self._last_rx = time.monotonic()
            self._tx_since_rx = 0
            if event.stream_id not in (None, self._stream_id):
                return
            # aioquic stripped the quarter-stream-id; what remains starts with
            # the RFC 9484 context id (a varint, 0 = IP payload)
            buf = Buffer(data=event.data)
            try:
                context_id = buf.pull_uint_var()
            except Exception:  # noqa: BLE001
                return
            if context_id != 0:
                log.debug("ignoring datagram with context id %d", context_id)
                return
            payload = event.data[buf.tell():]
            if not payload:
                return
            self.stats["rx_packets"] += 1
            self.stats["rx_bytes"] += len(payload)
            if self.on_ip is not None:
                try:
                    self.on_ip(payload)
                except Exception:  # pragma: no cover
                    log.exception("error while handling a tunnel packet")
        elif isinstance(event, DataReceived):
            # capsules (ADDRESS_ASSIGN and friends) arrive on the same stream
            self._last_rx = time.monotonic()
            for capsule_type, value in parse_capsules(event.data):
                self.stats["capsules"] += 1
                if capsule_type == CAPSULE_ADDRESS_ASSIGN:
                    for _, address, prefix in parse_addresses(value):
                        if address not in self.assigned:
                            self.assigned.append(address)
                        log.info("MASQUE address assigned: %s/%d", address, prefix)
                else:
                    log.debug("ignoring capsule type %d (%d bytes)", capsule_type, len(value))

    def _on_connection_terminated(self, event: ConnectionTerminated) -> None:
        log.warning(
            "MASQUE connection closed (code=%s reason=%r)",
            getattr(event, "error_code", "?"),
            getattr(event, "reason_phrase", b""),
        )
        self._ready.clear()
        self._connected.clear()

    # --------------------------------------------------------------- timers
    async def _keepalive_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(self.keepalive)
                if self._client is not None and self.ready:
                    try:
                        self._client._quic.send_ping(0)  # type: ignore[attr-defined]
                        self._client.transmit()
                    except Exception as exc:  # noqa: BLE001
                        log.debug("keepalive ping failed: %s", exc)
        except asyncio.CancelledError:
            pass

    async def _supervisor(self) -> None:
        """Reconnect when the QUIC connection dies or its flow goes stale.

        A long-lived MASQUE flow on a filtered network degrades: the path
        starts dropping the connection's packets while the QUIC connection
        itself stays "alive" (no close frame), so every inner packet is lost
        and TCP just stalls.  A brand new QUIC connection gets a fresh,
        unthrottled flow - so reconnect when we are sending but nothing comes
        back.
        """
        try:
            while not self._closed:
                await asyncio.sleep(2.0)
                if self._closed:
                    return
                if not self.reconnect:
                    return
                if not self.ready or self._client is None:
                    stale = True
                else:
                    idle_rx = time.monotonic() - self._last_rx
                    stale = self._tx_since_rx >= 2 and idle_rx > self.stale_timeout
                if not stale:
                    continue
                self.stats["reconnects"] += 1
                if self.ready:
                    log.info(
                        "MASQUE flow looks stale (%d packets sent, %.0fs without a reply) "
                        "- reconnecting (attempt %d) ...",
                        self.stats["tx_packets"], time.monotonic() - self._last_rx,
                        self.stats["reconnects"],
                    )
                else:
                    log.info("reconnecting the MASQUE tunnel (attempt %d) ...",
                             self.stats["reconnects"])
                await self._close_quic()
                try:
                    await self._connect()
                    self.stats["tx_packets"] = 0
                    self.stats["rx_packets"] = 0
                    self._last_rx = time.monotonic()
                    self._tx_since_rx = 0
                    # a brand new flow: let the IP stack retransmit right away
                    if self.on_reconnect is not None:
                        try:
                            self.on_reconnect()
                        except Exception:  # noqa: BLE001
                            log.exception("on_reconnect hook failed")
                except Exception as exc:  # noqa: BLE001
                    log.warning("MASQUE reconnect failed: %s", exc)
                    await asyncio.sleep(min(30.0, 2.0 * self.stats["reconnects"]))
        except asyncio.CancelledError:
            pass

    # ---------------------------------------------------------------- status
    def describe(self) -> str:
        return (
            f"transport=masque endpoint={self.host}:{self.port} "
            f"tx={self.stats['tx_packets']} rx={self.stats['rx_packets']} "
            f"reconnects={self.stats['reconnects']} ready={self.ready}"
        )
