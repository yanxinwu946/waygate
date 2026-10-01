"""A small user space IPv4 stack that runs on top of the WARP tunnel.

It provides exactly what a proxy needs:

* :class:`TcpConnection` - an RFC 793 style **client** TCP implementation
  (handshake, sliding send window, congestion window, retransmission, out of
  order reassembly, zero window probing, half close).
* :class:`UdpSocket` / :meth:`IPStack.udp_exchange` - enough UDP to run DNS
  inside the tunnel.
* ICMP handling good enough to fail fast on unreachable destinations.

Everything is driven from the asyncio event loop: incoming packets arrive via
``tunnel.on_ip``, timers run in one task shared by all connections.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct
import time
from typing import Callable, Optional

from . import packets as P

log = logging.getLogger("waygate.stack")

#: env-gated verbose trace of a single TCP connection's segments
TCP_TRACE = bool(os.environ.get("WAYGATE_TCP_TRACE") or os.environ.get("WARP2S5_TCP_TRACE"))

def _tlog(fmt: str, *args) -> None:
    if TCP_TRACE:
        log.info(fmt, *args)

SEQ_MASK = 0xFFFFFFFF
FIN = P.TCP_FIN
SYN = P.TCP_SYN
RST = P.TCP_RST
PSH = P.TCP_PSH
ACK = P.TCP_ACK

#: states
CLOSED = "CLOSED"
SYN_SENT = "SYN_SENT"
ESTABLISHED = "ESTABLISHED"
FIN_WAIT_1 = "FIN_WAIT_1"
FIN_WAIT_2 = "FIN_WAIT_2"
CLOSING = "CLOSING"
TIME_WAIT = "TIME_WAIT"
LAST_ACK = "LAST_ACK"
CLOSE_WAIT = "CLOSE_WAIT"

TIMER_INTERVAL = 0.02
MAX_OOO_SEGMENTS = 64


def seq_lt(a: int, b: int) -> bool:
    return ((a - b) & SEQ_MASK) >= 0x80000000


def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


def seq_gt(a: int, b: int) -> bool:
    return seq_lt(b, a)


def seq_ge(a: int, b: int) -> bool:
    return not seq_lt(a, b)


class _SentSegment:
    __slots__ = ("seq", "flags", "payload", "first_sent", "last_sent", "retries", "end")

    def __init__(self, seq: int, flags: int, payload: bytes, now: float) -> None:
        self.seq = seq
        self.flags = flags
        self.payload = payload
        self.first_sent = now
        self.last_sent = now
        self.retries = 0
        self.end = (seq + len(payload) + (1 if flags & (SYN | FIN) else 0)) & SEQ_MASK


class TcpConnection:
    """A client side TCP connection living inside the tunnel."""

    RX_BUFFER = 1 << 20          #: receive buffer we advertise (window scaled)
    MY_WSCALE = 7                #: window scale we announce
    TX_BACKPRESSURE = 512 * 1024  #: unacked bytes before send() blocks
    IDLE_TIMEOUT = 600.0
    CLOSE_TIMEOUT = 5.0
    MAX_RETRIES = 12

    def __init__(self, stack: "IPStack", dst_ip: str, dst_port: int, src_port: int) -> None:
        self.stack = stack
        self.family = 6 if ":" in dst_ip else 4
        # the connection table is keyed by this text, so normalise it: DNS
        # and a parsed packet must produce identical strings, or replies
        # are dropped as "no such connection"
        if self.family == 6:
            dst_ip = str(ipaddress.IPv6Address(dst_ip))
        self.dst_ip = dst_ip
        self.dst_ip_b = (
            P.ipv6_to_bytes(dst_ip) if self.family == 6 else P.ipv4_to_bytes(dst_ip)
        )
        self.dst_port = dst_port
        self.src_port = src_port

        self.state = CLOSED
        self.iss = struct.unpack("<I", os.urandom(4))[0]
        self.snd_una = self.iss
        self.snd_nxt = self.iss
        self.snd_wnd = 65535
        self.rcv_nxt = 0
        self.peer_mss = 1220
        self.peer_wscale = 0
        self.cwnd = 10 * 1220
        self.ssthresh = 1 << 30
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto = 1.0
        self.backoff = 1.0

        self.unacked: list[_SentSegment] = []
        self.ooo: dict[int, tuple[bytes, bool]] = {}
        self.rx = bytearray()
        self._rx_event = asyncio.Event()
        self._tx_event = asyncio.Event()
        self._connected = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._error: Optional[BaseException] = None
        self._eof = False
        self._peer_fin = False
        self._fin_sent = False
        self._fin_acked = False
        self._dup_acks = 0
        self._last_ack = 0
        self._send_lock = asyncio.Lock()
        self.started = time.monotonic()
        self.last_activity = self.started
        self.bytes_sent = 0
        self.bytes_received = 0
        self.retransmits = 0

    # ------------------------------------------------------------- helpers
    @property
    def key(self) -> tuple[str, int, int]:
        return (self.dst_ip, self.dst_port, self.src_port)

    @property
    def closed(self) -> bool:
        return self.state == CLOSED

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return (
            f"<TcpConnection {self.src_port}->{self.dst_ip}:{self.dst_port} "
            f"{self.state} sent={self.bytes_sent} recv={self.bytes_received}>"
        )

    def diagnostics(self) -> str:
        """One line summary of the connection state (used by --check and tests)."""
        return (
            f"state={self.state} rcv_nxt={self.rcv_nxt} rxbuf={len(self.rx)} "
            f"ooo={len(self.ooo)} unacked={len(self.unacked)} flight={self._flight()} "
            f"snd_wnd={self.snd_wnd} cwnd={self.cwnd} adv_win={self._advertised_window()} "
            f"rto={self.rto:.2f} retx={self.retransmits} eof={self._eof} "
            f"fin_sent={self._fin_sent} fin_acked={self._fin_acked} "
            f"error={type(self._error).__name__ if self._error else None}"
        )

    def _fail(self, exc: BaseException) -> None:
        if self._error is None:
            self._error = exc
        self._rx_event.set()
        self._tx_event.set()
        self._connected.set()

    def _advertised_window(self) -> int:
        free = max(0, self.RX_BUFFER - len(self.rx))
        return min(0xFFFF, free >> self.MY_WSCALE)

    def _flight(self) -> int:
        return (self.snd_nxt - self.snd_una) & SEQ_MASK

    def _emit(
        self,
        seq: int,
        flags: int,
        payload: bytes = b"",
        options: bytes = b"",
        window: Optional[int] = None,
    ) -> None:
        window = self._advertised_window() if window is None else window
        segment = P.tcp_pack(
            self.src_port,
            self.dst_port,
            seq,
            self.rcv_nxt,
            flags,
            window,
            self.stack._local_bytes(self.dst_ip_b),
            self.dst_ip_b,
            payload,
            options,
        )
        self.stack._send(self.dst_ip_b, P.IPPROTO_TCP, segment)
        self.last_activity = time.monotonic()
        if TCP_TRACE:
            _tlog("TX %s:%d seq=%s ack=%s len=%d unacked=%d wnd=%d cwnd=%d",
                  self.dst_ip, self.dst_port, seq, self.rcv_nxt, len(payload),
                  len(self.unacked) + (1 if payload or flags & (SYN | FIN) else 0),
                  self.snd_wnd, self.cwnd)
        if payload or flags & (SYN | FIN):
            now = self.last_activity
            record = _SentSegment(seq, flags, payload, now)
            self.unacked.append(record)
            self.snd_nxt = record.end
            if payload:
                self.bytes_sent += len(payload)

    def _retransmit(self, record: _SentSegment, now: float) -> None:
        segment = P.tcp_pack(
            self.src_port,
            self.dst_port,
            record.seq,
            self.rcv_nxt,
            record.flags,
            self._advertised_window(),
            self.stack._local_bytes(self.dst_ip_b),
            self.dst_ip_b,
            record.payload,
        )
        self.stack._send(self.dst_ip_b, P.IPPROTO_TCP, segment)
        record.last_sent = now
        record.retries += 1
        self.retransmits += 1
        self.backoff = min(self.backoff * 2, 32.0)

    # -------------------------------------------------------------- connect
    async def connect(self, timeout: float = 10.0) -> "TcpConnection":
        self.state = SYN_SENT
        options = P.build_tcp_options(
            mss=self.stack.mss_for(len(self.dst_ip_b)), wscale=self.MY_WSCALE
        )
        self._emit(self.iss, SYN, options=options)
        try:
            await asyncio.wait_for(self._connected.wait(), timeout)
        except asyncio.TimeoutError:
            self._fail(TimeoutError(f"connect to {self.dst_ip}:{self.dst_port} timed out"))
            raise
        if self._error is not None:
            raise self._error
        return self

    # ----------------------------------------------------------------- data
    async def send(self, data: bytes) -> None:
        if not data:
            return
        view = memoryview(data)
        offset = 0
        last_probe = 0.0
        async with self._send_lock:
            while offset < len(view):
                if self._error is not None:
                    raise self._error
                if self.state in (CLOSED, FIN_WAIT_2, LAST_ACK):
                    raise ConnectionError("connection is closing")
                allowed = min(self.cwnd, max(self.snd_wnd, 0)) - self._flight()
                if allowed <= 0:
                    now = time.monotonic()
                    if self.snd_wnd <= 0 and now - last_probe > 1.0:
                        # zero window probe: send a single byte past the window
                        self._emit(self.snd_nxt, ACK | PSH, bytes(view[offset : offset + 1]))
                        offset += 1
                        last_probe = now
                        continue
                    await self._wait_tx_space()
                    continue
                chunk = view[offset : offset + min(allowed, self.peer_mss)]
                self._emit(self.snd_nxt, ACK | PSH, bytes(chunk))
                offset += len(chunk)

    async def _wait_tx_space(self) -> None:
        self._tx_event.clear()
        try:
            await asyncio.wait_for(self._tx_event.wait(), 0.5)
        except asyncio.TimeoutError:
            pass

    async def recv(self, max_bytes: int = 65536) -> bytes:
        while True:
            if self.rx:
                data = bytes(self.rx[:max_bytes])
                del self.rx[: len(data)]
                return data
            if self._error is not None:
                raise self._error
            if self._eof:
                return b""
            self._rx_event.clear()
            await self._rx_event.wait()

    async def close(self) -> None:
        """Graceful close: send FIN and wait (briefly) for the peer's FIN."""
        if self.state == CLOSED:
            return
        if self._error is not None:
            self.abort()
            return
        if not self._fin_sent:
            self._fin_sent = True
            if self.state in (ESTABLISHED, FIN_WAIT_1):
                self._emit(self.snd_nxt, ACK | FIN)
                self.state = FIN_WAIT_1
            elif self.state == CLOSE_WAIT:
                self._emit(self.snd_nxt, ACK | FIN)
                self.state = LAST_ACK
        deadline = time.monotonic() + self.CLOSE_TIMEOUT
        while time.monotonic() < deadline:
            self._maybe_closed()
            if self._fin_acked and self._peer_fin:
                break
            if self._error is not None:
                break
            self._closed_event.clear()
            try:
                await asyncio.wait_for(self._closed_event.wait(), 0.2)
            except asyncio.TimeoutError:
                pass
        self._teardown()

    def _maybe_closed(self) -> None:
        if self._fin_sent and self._fin_acked and self._peer_fin:
            self._closed_event.set()

    def abort(self, exc: Optional[BaseException] = None) -> None:
        """Hard close - send RST when the connection was established."""
        if exc is not None and self._error is None:
            self._error = exc
        if self.state not in (CLOSED, SYN_SENT):
            try:
                self._emit(self.snd_nxt, ACK | RST)
            except Exception:  # pragma: no cover - best effort
                pass
        self._teardown()

    def _teardown(self) -> None:
        self.state = CLOSED
        self.unacked.clear()
        self.ooo.clear()
        self.stack._forget(self)
        self._rx_event.set()
        self._tx_event.set()
        self._connected.set()
        self._closed_event.set()

    # ------------------------------------------------------- inbound packets
    def _on_segment(self, seg: P.TcpSegment) -> None:
        now = time.monotonic()
        self.last_activity = now
        if self.state == CLOSED:
            return

        if seg.flags & RST:
            self._fail(ConnectionResetError(f"{self.dst_ip}:{self.dst_port} reset the connection"))
            self._teardown()
            return

        if seg.flags & ACK:
            self._handle_ack(seg, now)

        if seg.flags & SYN and self.state == SYN_SENT:
            self._handle_syn_ack(seg)
            return

        if self.state in (SYN_SENT,):
            return

        # ---- payload / FIN
        payload = seg.payload
        fin = bool(seg.flags & FIN)
        if payload:
            self._handle_data(seg.seq, payload, fin)
        elif fin:
            self._handle_fin(seg.seq)

        if payload or fin or (seg.flags & (SYN | FIN)):
            self._send_ack()

    def _handle_syn_ack(self, seg: P.TcpSegment) -> None:
        if not (seg.flags & ACK) or seq_gt(seg.ack, self.snd_nxt):
            return
        options = P.parse_tcp_options(seg.options)
        cap = self.stack.mss_for(len(self.dst_ip_b))
        self.peer_mss = max(256, min(options.get("mss", 536), cap))
        self.peer_wscale = min(options.get("wscale", 0), 14)
        self.snd_wnd = seg.window << self.peer_wscale
        self.rcv_nxt = (seg.seq + 1) & SEQ_MASK
        self.snd_una = seg.ack
        self.state = ESTABLISHED
        # our SYN is acknowledged now
        self.unacked = [record for record in self.unacked if seq_gt(record.end, self.snd_una)]
        self.cwnd = min(self.cwnd, 10 * self.peer_mss)
        self._emit(self.snd_nxt, ACK)
        self._connected.set()
        self._tx_event.set()

    def _handle_ack(self, seg: P.TcpSegment, now: float) -> None:
        ack = seg.ack
        if seq_gt(ack, self.snd_nxt):
            return  # invalid ack, ignore
        if seq_gt(ack, self.snd_una):
            newly_acked = (ack - self.snd_una) & SEQ_MASK
            # RTT sampling (Karn's algorithm: only for segments never retransmitted)
            while self.unacked and seq_le(self.unacked[0].end, ack):
                record = self.unacked.pop(0)
                if record.retries == 0:
                    sample = now - record.first_sent
                    if self.srtt is None:
                        self.srtt, self.rttvar = sample, sample / 2
                    else:
                        self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                        self.srtt = 0.875 * self.srtt + 0.125 * sample
                    self.rto = min(6.0, max(0.2, self.srtt + 4 * self.rttvar))
            if self.unacked and seq_gt(ack, self.unacked[0].seq):
                # partial ack: trim the head segment
                head = self.unacked[0]
                delta = (ack - head.seq) & SEQ_MASK
                if delta < len(head.payload):
                    head.payload = head.payload[delta:]
                    head.seq = ack
                    head.end = (head.seq + len(head.payload)) & SEQ_MASK
            self.snd_una = ack
            self.backoff = 1.0
            self._dup_acks = 0
            # congestion control
            if self.cwnd < self.ssthresh:
                self.cwnd += newly_acked
            else:
                self.cwnd += max(1, (self.peer_mss * newly_acked) // max(self.cwnd, 1))
            self.cwnd = min(self.cwnd, 1 << 20)
            self._tx_event.set()
            if self._fin_sent and seq_ge(self.snd_una, self.snd_nxt):
                self._fin_acked = True
                if self.state == FIN_WAIT_1:
                    self.state = FIN_WAIT_2
                self._maybe_closed()
        elif ack == self.snd_una and not seg.payload and not (seg.flags & (SYN | FIN)):
            self._dup_acks += 1
            if self._dup_acks == 3 and self.unacked:
                # fast retransmit
                self.ssthresh = max(self.cwnd // 2, 2 * self.peer_mss)
                self.cwnd = self.ssthresh + 3 * self.peer_mss
                self._retransmit(self.unacked[0], now)
        self.snd_wnd = seg.window << self.peer_wscale
        if self.snd_wnd > 0:
            self._tx_event.set()

    def _handle_data(self, seq: int, payload: bytes, fin: bool) -> None:
        if TCP_TRACE:
            _tlog("RX %s:%d seq=%s len=%d rx_nxt=%s ooo=%d",
                  self.dst_ip, self.dst_port, seq, len(payload), self.rcv_nxt, len(self.ooo))
        if seq == self.rcv_nxt:
            self._deliver(payload, fin)
            self._drain_ooo()
        elif seq_lt(seq, self.rcv_nxt):
            # overlapping retransmission: keep only the new tail
            offset = (self.rcv_nxt - seq) & SEQ_MASK
            if offset < len(payload):
                self._deliver(payload[offset:], fin)
                self._drain_ooo()
        else:
            if len(self.ooo) < MAX_OOO_SEGMENTS:
                self.ooo[seq] = (payload, fin)

    def _deliver(self, payload: bytes, fin: bool) -> None:
        if payload:
            if TCP_TRACE:
                _tlog("RX-DELIVER %s:%d len=%d rx_nxt->%d rxbuf=%d",
                      self.dst_ip, self.dst_port, len(payload),
                      (self.rcv_nxt + len(payload)) & SEQ_MASK, len(self.rx) + len(payload))
            self.rx += payload
            self.bytes_received += len(payload)
            self.rcv_nxt = (self.rcv_nxt + len(payload)) & SEQ_MASK
            self._rx_event.set()
        if fin:
            self.rcv_nxt = (self.rcv_nxt + 1) & SEQ_MASK
            self._peer_fin = True
            self._eof = True
            self._rx_event.set()
            if not self._fin_sent and self.state == ESTABLISHED:
                self.state = CLOSE_WAIT
            self._maybe_closed()

    def _handle_fin(self, seq: int) -> None:
        if seq == self.rcv_nxt:
            self._deliver(b"", True)
            self._drain_ooo()
        elif seq_gt(seq, self.rcv_nxt):
            if len(self.ooo) < MAX_OOO_SEGMENTS:
                self.ooo[seq] = (b"", True)

    def _drain_ooo(self) -> None:
        progressed = True
        while progressed:
            progressed = False
            entry = self.ooo.pop(self.rcv_nxt, None)
            if entry is not None:
                self._deliver(entry[0], entry[1])
                progressed = True

    def _send_ack(self) -> None:
        self._emit(self.snd_nxt, ACK)

    # --------------------------------------------------------------- timers
    def poke(self, now: float) -> None:
        """A fresh tunnel appeared: retransmit immediately instead of backing off."""
        self.backoff = 1.0
        self.rto = min(self.rto, 1.0)
        if self.cwnd < 4 * self.peer_mss:
            self.cwnd = 4 * self.peer_mss
        if self.unacked:
            self._retransmit(self.unacked[0], now)
            self.last_activity = now

    def _on_timer(self, now: float) -> None:
        if self.state == CLOSED:
            return
        if self.state == SYN_SENT:
            if now - self.started > 30:
                self._fail(TimeoutError("connect timed out"))
            elif self.unacked and now - self.unacked[0].last_sent > min(2.0, self.rto):
                self._retransmit(self.unacked[0], now)
                if self.unacked[0].retries > self.MAX_RETRIES:
                    self._fail(TimeoutError(f"no response from {self.dst_ip}:{self.dst_port}"))
            return

        if self.unacked:
            head = self.unacked[0]
            if now - head.last_sent > min(self.rto * self.backoff, 8.0):
                self.ssthresh = max(self.cwnd // 2, 2 * self.peer_mss)
                self.cwnd = self.peer_mss
                self._retransmit(head, now)
                if head.retries > self.MAX_RETRIES:
                    self._fail(TimeoutError("too many retransmissions"))

        if self._fin_sent and not self._fin_acked and self.unacked:
            if now - self.unacked[0].last_sent > 8.0:
                self._closed_event.set()

        if now - self.last_activity > self.IDLE_TIMEOUT:
            self._fail(TimeoutError("connection idle for too long"))
            self.abort()

        if self._error is not None:
            self._teardown()

    def _on_icmp_unreachable(self) -> None:
        self._fail(ConnectionError(f"{self.dst_ip} is unreachable"))
        self.abort()


class UdpSocket:
    """A tiny datagram socket inside the tunnel."""

    def __init__(self, stack: "IPStack", dst_ip: str, dst_port: int, src_port: int) -> None:
        self.stack = stack
        self.family = 6 if ":" in dst_ip else 4
        # the connection table is keyed by this text, so normalise it: DNS
        # and a parsed packet must produce identical strings, or replies
        # are dropped as "no such connection"
        if self.family == 6:
            dst_ip = str(ipaddress.IPv6Address(dst_ip))
        self.dst_ip = dst_ip
        self.dst_ip_b = (
            P.ipv6_to_bytes(dst_ip) if self.family == 6 else P.ipv4_to_bytes(dst_ip)
        )
        self.dst_port = dst_port
        self.src_port = src_port
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=64)
        self.closed = False
        self.unreachable = asyncio.Event()

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.dst_ip, self.dst_port, self.src_port)

    def sendto(self, payload: bytes) -> None:
        if self.closed:
            raise ValueError("socket is closed")
        packet = P.udp_pack(
            self.src_port, self.dst_port, payload,
            self.stack._local_bytes(self.dst_ip_b), self.dst_ip_b
        )
        self.stack._send(self.dst_ip_b, P.IPPROTO_UDP, packet)

    async def recvfrom(self, timeout: Optional[float] = None) -> tuple[bytes, tuple[str, int]]:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"no UDP response from {self.dst_ip}:{self.dst_port}") from None

    def close(self) -> None:
        self.closed = True
        self.stack._forget_udp(self)

    def _deliver(self, payload: bytes, src: tuple[str, int]) -> None:
        if self.closed:
            return
        try:
            self.queue.put_nowait((payload, src))
        except asyncio.QueueFull:  # pragma: no cover
            pass

    def _on_icmp_unreachable(self) -> None:
        self.unreachable.set()


class IPStack:
    """IPv4 (and just enough ICMP) on top of a tunnel object."""

    def __init__(
        self,
        tunnel,
        local_ip: str,
        *,
        local_ip_v6: str = "",
        mtu: int = 1280,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.tunnel = tunnel
        self.local_ip = local_ip
        self.local_ip_bytes = P.ipv4_to_bytes(local_ip)
        #: the address WARP assigned for the inner IPv6 family (may be empty)
        self.local_ip_v6 = local_ip_v6
        self.local_ip_v6_bytes = P.ipv6_to_bytes(local_ip_v6) if local_ip_v6 else b""
        self.mtu = mtu
        self.mss = mtu - 40
        self.tcp: dict[tuple[str, int, int], TcpConnection] = {}
        self.udp: dict[tuple[str, int, int], UdpSocket] = {}
        self._port_counter = 20000 + (os.getpid() % 20000)
        self._ports: set[int] = set()
        self._timer_task: Optional[asyncio.Task] = None
        self._closed = False
        self.stats = {"tcp_opened": 0, "udp_opened": 0, "unknown_proto": 0}

    # ------------------------------------------------------------- plumbing
    def start(self) -> None:
        self.tunnel.on_ip = self._on_ip
        self._timer_task = asyncio.create_task(self._timer_loop(), name="ipstack-timer")

    async def stop(self) -> None:
        self._closed = True
        if self._timer_task is not None:
            self._timer_task.cancel()
            try:
                await self._timer_task
            except (asyncio.CancelledError, Exception):
                pass
        for conn in list(self.tcp.values()):
            conn.abort()
        for sock in list(self.udp.values()):
            sock.close()

    def poke_all(self) -> None:
        """Called when the tunnel reconnected: kick every stalled TCP connection."""
        now = time.monotonic()
        for conn in list(self.tcp.values()):
            try:
                conn.poke(now)
            except Exception:  # noqa: BLE001
                pass

    def _next_port(self) -> int:
        for _ in range(60000):
            self._port_counter += 1
            if self._port_counter > 65000:
                self._port_counter = 20000
            port = self._port_counter
            if port not in self._ports:
                self._ports.add(port)
                return port
        raise RuntimeError("no free source port")

    def _forget(self, conn: TcpConnection) -> None:
        self.tcp.pop(conn.key, None)
        self._ports.discard(conn.src_port)

    def _forget_udp(self, sock: UdpSocket) -> None:
        self.udp.pop(sock.key, None)
        self._ports.discard(sock.src_port)

    def mss_for(self, addr_len: int) -> int:
        """TCP MSS that still fits in the tunnel MTU for this address family."""
        return self.mtu - (60 if addr_len == 16 else 40)

    @staticmethod
    def _addr_str(raw: bytes) -> str:
        """Bytes -> text, for either family.

        Normalised through ``ipaddress`` so it matches whatever DNS handed us:
        the connection table is keyed by this string, and a difference in
        compression (``::1`` vs ``0:0:...:1``) would drop every reply.
        """
        if len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
        return P.bytes_to_ipv4(raw)

    def _local_bytes(self, dst_ip: bytes) -> bytes:
        """Source address matching the destination's family (16 bytes => IPv6)."""
        if len(dst_ip) == 16:
            if not self.local_ip_v6_bytes:
                raise ConnectionError(
                    "this device has no IPv6 address; cannot reach an IPv6 target"
                )
            return self.local_ip_v6_bytes
        return self.local_ip_bytes

    def _send(self, dst_ip: bytes, proto: int, payload: bytes) -> None:
        """Build and inject a packet, IPv4 or IPv6 depending on the address."""
        if len(dst_ip) == 16:
            packet = P.ipv6_pack(self._local_bytes(dst_ip), dst_ip, proto, payload)
        else:
            packet = P.ipv4_pack(self.local_ip_bytes, dst_ip, proto, payload)
        if len(packet) > self.mtu + 40:
            log.debug("refusing to send oversized packet: %d bytes", len(packet))
        self.tunnel.send_ip(packet)

    def _send_ipv4(self, dst_ip: bytes, proto: int, payload: bytes) -> None:
        self._send(dst_ip, proto, payload)

    # ------------------------------------------------------------ inbound
    def _on_ip(self, packet: bytes) -> None:
        if packet and (packet[0] >> 4) == 6:
            parsed: P.IPv4Packet | P.IPv6Packet | None = P.ipv6_parse(packet)
        else:
            parsed = P.ipv4_parse(packet)
        if parsed is None:
            return
        if parsed.proto == P.IPPROTO_TCP:
            self._on_tcp(parsed)
        elif parsed.proto == P.IPPROTO_UDP:
            self._on_udp(parsed)
        elif parsed.proto == P.IPPROTO_ICMP:
            self._on_icmp(parsed)
        else:
            self.stats["unknown_proto"] += 1

    def _on_tcp(self, packet: P.IPv4Packet) -> None:
        seg = P.tcp_parse(packet.payload)
        if seg is None:
            return
        src_ip = self._addr_str(packet.src)
        conn = self.tcp.get((src_ip, seg.sport, seg.dport))
        if conn is None:
            # nothing listening: tell the peer to go away
            if not seg.flags & RST:
                reset = P.tcp_pack(
                    seg.dport,
                    seg.sport,
                    seg.ack if seg.flags & ACK else 0,
                    (seg.seq + len(seg.payload) + (1 if seg.flags & SYN else 0)) & SEQ_MASK,
                    RST | (ACK if seg.flags & ACK else 0),
                    0,
                    self._local_bytes(packet.src),
                    packet.src,
                )
                self._send(packet.src, P.IPPROTO_TCP, reset)
            return
        try:
            conn._on_segment(seg)
        except Exception:  # pragma: no cover - never kill the stack
            log.exception("error while handling a TCP segment")

    def _on_udp(self, packet: P.IPv4Packet) -> None:
        datagram = P.udp_parse(packet.payload)
        if datagram is None:
            return
        src_ip = self._addr_str(packet.src)
        sock = self.udp.get((src_ip, datagram.sport, datagram.dport)) or self.udp.get(
            (src_ip, datagram.sport, 0)
        )
        if sock is None:
            for candidate in self.udp.values():
                if candidate.src_port == datagram.dport and candidate.dst_port == datagram.sport:
                    sock = candidate
                    break
        if sock is not None:
            sock._deliver(datagram.payload, (src_ip, datagram.sport))

    def _on_icmp(self, packet: P.IPv4Packet) -> None:
        data = packet.payload
        if len(data) < 8:
            return
        icmp_type = data[0]
        if icmp_type == 3 and len(data) >= 8 + 20 + 8:
            # destination unreachable - figure out which flow it belongs to
            inner = P.ipv4_parse(data[8:])
            if inner is None:
                return
            if inner.proto == P.IPPROTO_TCP:
                seg = P.tcp_parse(inner.payload)
                if seg is not None:
                    conn = self.tcp.get((self._addr_str(inner.dst), seg.dport, seg.sport))
                    if conn is not None:
                        conn._on_icmp_unreachable()
            elif inner.proto == P.IPPROTO_UDP:
                datagram = P.udp_parse(inner.payload)
                if datagram is not None:
                    for sock in self.udp.values():
                        if sock.src_port == datagram.dport and sock.dst_port == datagram.sport:
                            sock._on_icmp_unreachable()
                            break

    # ------------------------------------------------------------ outbound
    async def tcp_connect(self, ip: str, port: int, timeout: float = 10.0) -> TcpConnection:
        if self._closed:
            raise RuntimeError("stack is closed")
        conn = TcpConnection(self, ip, port, self._next_port())
        self.tcp[conn.key] = conn
        self.stats["tcp_opened"] += 1
        try:
            await conn.connect(timeout)
        except BaseException:
            conn._teardown()
            raise
        return conn

    def open_udp(self, ip: str, port: int) -> UdpSocket:
        sock = UdpSocket(self, ip, port, self._next_port())
        self.udp[sock.key] = sock
        self.stats["udp_opened"] += 1
        return sock

    async def udp_exchange(
        self, ip: str, port: int, payload: bytes, timeout: float = 3.0
    ) -> Optional[bytes]:
        sock = self.open_udp(ip, port)
        try:
            sock.sendto(payload)
            try:
                data, _ = await sock.recvfrom(timeout)
                return data
            except TimeoutError:
                return None
        finally:
            sock.close()

    # -------------------------------------------------------------- timers
    async def _timer_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(TIMER_INTERVAL)
                now = time.monotonic()
                for conn in list(self.tcp.values()):
                    if conn.state == CLOSED:
                        continue
                    try:
                        conn._on_timer(now)
                    except Exception:  # pragma: no cover
                        log.exception("connection timer failed")
        except asyncio.CancelledError:
            pass

    def describe(self) -> str:
        return (
            f"tcp={len(self.tcp)} udp={len(self.udp)} "
            f"opened={self.stats['tcp_opened']}"
        )
