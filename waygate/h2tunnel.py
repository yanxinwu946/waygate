"""CONNECT-IP over HTTP/2 (TCP) - the official client's fallback transport.

The official WARP client races two protocols per endpoint: MASQUE (QUIC, the
primary) and H2 over TCP/443 (the secondary, started 1s later).  On filtered
networks the TCP path is frequently the one that wins - its log is full of

    warp_edge::fallback::racing: Secondary protocol won race, upgrading
        protocol="H2" endpoint=162.159.198.2:443 secondary_delay=Some(1s)

and while it runs on H2 the client has *zero* QUIC sockets.  TCP also brings
kernel retransmission, which matters a lot more than QUIC datagrams on a lossy
path.

On HTTP/2 there are no datagrams, so IP packets travel as HTTP Datagram
capsules (RFC 9297 section 3.4) inside the CONNECT-IP request stream:

    Capsule { Type=0x00, Length, ContextID(0) + IP packet }

This class exposes exactly the same surface as ``MasqueTunnel``
(``start/stop/wait_ready/send_ip/on_ip/stats``) so the IP stack, SOCKS5 server
and web UI work unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

import h2.config
import h2.connection
import h2.events

from aioquic.buffer import Buffer, encode_uint_var

from .masque import CLIENT_VERSION_MASQUE, CONNECT_AUTHORITY, CONNECT_PATH, CONNECT_PROTOCOL

log = logging.getLogger("waygate.h2")

DEFAULT_SNI = "consumer-masque.cloudflareclient.com"
KEEPALIVE = 3.0          # the official client keeps 3s idle on the H2 path
STALE_TIMEOUT = 8.0


class H2Tunnel:
    """A CONNECT-IP tunnel over HTTP/2 on TCP/443."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        *,
        certificate_pem: str = "",
        private_key_pem: str = "",
        sni: str = DEFAULT_SNI,
        on_ip: Optional[Callable[[bytes], None]] = None,
        keepalive: float = KEEPALIVE,
        stale_timeout: float = STALE_TIMEOUT,
        queue_size: int = 256,
        mtu: int = 1280,
        reconnect: bool = True,
        connect_timeout: float = 6.0,
        on_reconnect: Optional[Callable[[], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.sni = sni
        self.certificate_pem = certificate_pem
        self.private_key_pem = private_key_pem
        self.on_ip = on_ip
        self.keepalive = keepalive
        self.stale_timeout = stale_timeout
        self.queue_size = queue_size
        self.mtu = mtu
        self.reconnect = reconnect
        # keep this short: when the TCP path is blackholed we want the race to
        # move on quickly instead of stalling every candidate
        self.connect_timeout = connect_timeout
        self.on_reconnect = on_reconnect

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._h2: Optional[h2.connection.H2Connection] = None
        self._stream_id: Optional[int] = None
        self._tasks: list[asyncio.Task] = []
        self._ready = asyncio.Event()
        self._closed = False
        self._queue: list[bytes] = []
        self._error: Optional[BaseException] = None
        self._last_rx = time.monotonic()
        self._tx_since_rx = 0
        self.assigned: list[str] = []
        self.stats = {"tx_packets": 0, "rx_packets": 0, "reconnects": 0, "capsules": 0}
        self._pending_capsule = bytearray()

    # ---------------------------------------------------------------- helpers
    @property
    def peer_endpoint(self) -> tuple[str, int]:
        return (self.host, self.port)

    @property
    def local_endpoint(self) -> Optional[str]:
        if self._writer is None:
            return None
        sock = self._writer.get_extra_info("sockname")
        return f"{sock[0]}:{sock[1]}" if sock else None

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and self._writer is not None

    def describe(self) -> str:
        return (f"transport=h2-tcp endpoint={self.host}:{self.port} "
                f"tx={self.stats['tx_packets']} rx={self.stats['rx_packets']} "
                f"reconnects={self.stats['reconnects']} ready={self.ready}")

    # ------------------------------------------------------------------- life
    async def start(self) -> None:
        self._closed = False
        await self._connect()
        self._tasks.append(asyncio.create_task(self._reader_loop(), name="h2-reader"))
        self._tasks.append(asyncio.create_task(self._keepalive_loop(), name="h2-keepalive"))
        if self.reconnect:
            self._tasks.append(asyncio.create_task(self._supervisor(), name="h2-supervisor"))

    async def _connect(self) -> None:
        self._ready.clear()
        self._stream_id = None
        self._pending_capsule.clear()
        context = self._ssl_context()
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=context, server_hostname=self.sni),
            self.connect_timeout,
        )
        negotiation = self._writer.get_extra_info("ssl_object")
        if negotiation is not None and negotiation.selected_alpn_protocol() != "h2":
            raise ConnectionError(
                f"server did not negotiate h2 (got {negotiation.selected_alpn_protocol()!r})"
            )
        self._h2 = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        self._h2.initiate_connection()
        self._send_headers()

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        if self.certificate_pem and self.private_key_pem:
            cert = Path(tempfile.mkstemp(suffix=".pem")[1])
            key = Path(tempfile.mkstemp(suffix=".pem")[1])
            cert.write_text(self.certificate_pem)
            key.write_text(self.private_key_pem)
            try:
                context.load_cert_chain(str(cert), str(key))
            finally:
                cert.unlink(missing_ok=True)
                key.unlink(missing_ok=True)
        return context

    def _send_headers(self) -> None:
        assert self._h2 is not None
        stream_id = self._h2.get_next_available_stream_id()
        self._stream_id = stream_id
        headers = [
            (b":method", b"CONNECT"),
            (b":protocol", CONNECT_PROTOCOL.encode()),
            (b":scheme", b"http"),
            (b":authority", CONNECT_AUTHORITY.encode()),
            (b":path", CONNECT_PATH.encode()),
            (b"pq-enabled", b"true"),
            (b"cf-client-version", CLIENT_VERSION_MASQUE.encode()),
        ]
        self._h2.send_headers(stream_id, headers, end_stream=False)
        self._flush()

    def _flush(self) -> None:
        if self._h2 is None or self._writer is None:
            return
        data = self._h2.data_to_send()
        if data:
            self._writer.write(data)

    async def wait_ready(self, timeout: float = 30.0) -> None:
        if timeout <= 0:
            # never treat this as "do not wait": the CONNECT-IP response may
            # still be in flight and giving up here kills a healthy tunnel
            timeout = 30.0
        try:
            await asyncio.wait_for(self._ready.wait(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"H2 CONNECT-IP to {self.host}:{self.port} did not come up"
            ) from None
        if self._error is not None:
            raise self._error

    async def stop(self) -> None:
        self._closed = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks.clear()
        await self._close()

    async def _close(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._writer = None
        self._reader = None
        self._h2 = None
        self._stream_id = None
        self._ready.clear()

    # ------------------------------------------------------------------- data
    def send_ip(self, packet: bytes) -> None:
        """Wrap the IP packet in a DATAGRAM capsule and write it to the stream."""
        if not self.ready or self._h2 is None or self._stream_id is None:
            if len(self._queue) < self.queue_size:
                self._queue.append(packet)
            return
        payload = encode_uint_var(0) + packet           # Context ID 0 = IP payload
        capsule = encode_uint_var(0x00) + encode_uint_var(len(payload)) + payload
        try:
            window = self._h2.local_flow_control_window(self._stream_id)
            if window < len(capsule):
                self._queue.append(packet)
                return
            self._h2.send_data(self._stream_id, capsule, end_stream=False)
            self._flush()
            self.stats["tx_packets"] += 1
            self._tx_since_rx += 1
        except Exception as exc:  # noqa: BLE001
            log.debug("H2 send failed: %s", exc)

    def _flush_queue(self) -> None:
        queue, self._queue = self._queue, []
        for packet in queue:
            self.send_ip(packet)

    # ---------------------------------------------------------------- reading
    async def _reader_loop(self) -> None:
        assert self._reader is not None
        try:
            while not self._closed:
                data = await self._reader.read(65536)
                if not data:
                    break
                self._handle(data)
                if self._closed:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.debug("H2 reader stopped: %s", exc)
        finally:
            if not self._closed:
                self._ready.clear()

    def _handle(self, data: bytes) -> None:
        assert self._h2 is not None
        events = self._h2.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                status = dict(event.headers).get(b":status", b"")
                if status == b"200":
                    log.info("H2 tunnel up: CONNECT-IP accepted by %s:%d", self.host, self.port)
                    self._ready.set()
                    self._flush_queue()
                else:
                    self._error = ConnectionError(f"CONNECT-IP rejected with status {status!r}")
                    self._ready.set()
            elif isinstance(event, h2.events.DataReceived):
                self._last_rx = time.monotonic()
                self._tx_since_rx = 0
                self._h2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                self._on_stream_data(event.data)
            elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset,
                                    h2.events.ConnectionTerminated)):
                self._ready.clear()
        self._flush()

    def _on_stream_data(self, data: bytes) -> None:
        """Split the byte stream into capsules; type 0x00 is an IP packet."""
        self._pending_capsule += data
        while True:
            buf = Buffer(data=bytes(self._pending_capsule))
            try:
                capsule_type = buf.pull_uint_var()
                length = buf.pull_uint_var()
            except Exception:  # noqa: BLE001
                return
            if len(self._pending_capsule) - buf.tell() < length:
                return
            value = bytes(self._pending_capsule[buf.tell():buf.tell() + length])
            del self._pending_capsule[:buf.tell() + length]
            self.stats["capsules"] += 1
            if capsule_type != 0x00:
                continue
            inner = Buffer(data=value)
            try:
                context_id = inner.pull_uint_var()
            except Exception:  # noqa: BLE001
                continue
            if context_id != 0:
                continue
            payload = value[inner.tell():]
            if not payload:
                continue
            self.stats["rx_packets"] += 1
            if self.on_ip is not None:
                try:
                    self.on_ip(payload)
                except Exception:  # pragma: no cover
                    log.exception("error while handling a tunnel packet")

    # --------------------------------------------------------------- timers
    async def _keepalive_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(self.keepalive)
                if self._h2 is not None and self.ready:
                    self._h2.ping(b"waygate")
                    self._flush()
        except asyncio.CancelledError:
            pass

    async def _supervisor(self) -> None:
        """Replace a stale H2 connection (the TCP path does get throttled too)."""
        try:
            while not self._closed:
                await asyncio.sleep(2.0)
                if self._closed or not self.reconnect:
                    return
                stale = (not self.ready) or (
                    self._tx_since_rx >= 2
                    and time.monotonic() - self._last_rx > self.stale_timeout
                )
                if not stale:
                    continue
                self.stats["reconnects"] += 1
                log.info("H2 flow stale - reconnecting (attempt %d) ...",
                         self.stats["reconnects"])
                for task in self._tasks[2:]:
                    task.cancel()
                await self._close()
                try:
                    await self._connect()
                    self.stats["tx_packets"] = 0
                    self.stats["rx_packets"] = 0
                    self._tx_since_rx = 0
                    self._last_rx = time.monotonic()
                    if self.on_reconnect is not None:
                        self.on_reconnect()
                except Exception as exc:  # noqa: BLE001
                    log.warning("H2 reconnect failed: %s", exc)
                    await asyncio.sleep(3.0)
        except asyncio.CancelledError:
            pass
