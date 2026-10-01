"""Protocol racing + loss measurement - official-client racing meets yxip-style scoring.

Two ideas combined:

* **racing** (from the official client's log):
  ``connect_with_protocol_racing{primary="masque" secondary="H2"}`` with
  ``secondary_delay=Some(1s)`` - MASQUE(QUIC) starts immediately, H2(TCP) starts
  a second later, and whichever proves it can carry traffic first wins.
* **loss scoring** (from warp-endpoint-optimizer / warp-yxip): a single probe
  says almost nothing on a lossy path, so the winner is measured with several
  probes and scored by *(loss rate, latency)* - the same ordering as its
  ``result.csv`` (``sort -k2 -k3``, loss first then latency).

A transport only qualifies once a real DNS query sent *through* it comes back;
a finished handshake plus ``:status 200`` proves nothing on a filtered network.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import packets as P
from .dns import build_query
from .h2tunnel import H2Tunnel
from .masque import MasqueTunnel
from .warp import MASQUE_SNI

log = logging.getLogger("waygate.race")

SECONDARY_DELAY = 1.0     # the official client's secondary_delay=Some(1s)
QUIC_TIMEOUT = 10.0
H2_TIMEOUT = 12.0
PROBES = 5                # probes per candidate when scoring loss
PROBE_WAIT = 1.2          # seconds to wait for one probe's answer


def dns_probe_packet(src: str, txid: int = 0x1234) -> bytes:
    """A real IPv4/UDP/DNS query, used to prove a transport carries traffic."""
    query, _ = build_query("www.cloudflare.com", qid=txid)
    udp = P.udp_pack(55000, 53, query, P.ipv4_to_bytes(src), P.ipv4_to_bytes("1.1.1.1"))
    return P.ipv4_pack(P.ipv4_to_bytes(src), P.ipv4_to_bytes("1.1.1.1"), P.IPPROTO_UDP, udp)


@dataclass
class RaceOutcome:
    """The winning transport plus how good it actually looks."""

    transport: str
    tunnel: object
    loss: float = 0.0          # 0.0 = perfect, 1.0 = nothing came back
    latency: float = 0.0       # mean round trip of the answered probes, seconds
    replies: int = 0
    probes: int = 0
    setup: float = 0.0         # seconds until the transport was usable
    rtts: list[float] = field(default_factory=list)

    @property
    def score(self) -> tuple[float, float]:
        """Sort key: least loss first, then lowest latency (warp-yxip order)."""
        return (round(self.loss, 3), round(self.latency, 4))

    def info(self) -> dict:
        return {
            "transport": self.transport,
            "loss": round(self.loss * 100, 1),
            "latency": round(self.latency * 1000),
            "replies": self.replies,
            "probes": self.probes,
            "setup": round(self.setup, 2),
        }


async def _measure(tunnel, address: str, probes: int, wait: float,
                   received: list) -> tuple[list[float], int]:
    """Send ``probes`` DNS packets through the tunnel and time the answers.

    ``received`` is the list the tunnel was created with, so replies land in it.
    """
    rtts: list[float] = []
    for index in range(probes):
        before = len(received)
        started = time.monotonic()
        tunnel.send_ip(dns_probe_packet(address, txid=0x1000 + index))  # type: ignore[attr-defined]
        deadline = started + wait
        while time.monotonic() < deadline:
            if len(received) > before:
                rtts.append(time.monotonic() - started)
                break
            await asyncio.sleep(0.05)
        if index + 1 < probes:
            await asyncio.sleep(0.15)
    return rtts, len(received)


async def _attempt(
    name: str,
    factory: Callable[[], object],
    identity,
    *,
    timeout: float,
    probes: int,
    probe_wait: float,
) -> Optional[RaceOutcome]:
    """Bring one transport up and score it."""
    received: list[bytes] = []
    tunnel = factory(received.append)
    started = time.monotonic()
    try:
        await tunnel.start()  # type: ignore[attr-defined]
        await tunnel.wait_ready(timeout)  # the tunnel enforces its own timeout
        setup = time.monotonic() - started
        rtts, replies = await _measure(tunnel, identity.address_v4, probes, probe_wait,
                                       received)
        if replies == 0:
            log.debug("%s came up but nothing came back", name)
            await tunnel.stop()  # type: ignore[attr-defined]
            return None
        outcome = RaceOutcome(
            transport=name,
            tunnel=tunnel,
            loss=max(0.0, 1.0 - replies / probes),
            latency=statistics.fmean(rtts) if rtts else probe_wait,
            replies=replies,
            probes=probes,
            setup=setup,
            rtts=rtts,
        )
        log.info("%s won: loss=%.0f%% latency=%dms replies=%d/%d setup=%.1fs",
                 name, outcome.loss * 100, outcome.latency * 1000,
                 replies, probes, setup)
        return outcome
    except asyncio.CancelledError:
        try:
            await tunnel.stop()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
        raise
    except Exception as exc:  # noqa: BLE001
        log.debug("%s failed: %s: %s", name, type(exc).__name__, exc)
        try:
            await tunnel.stop()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
        return None


async def race(
    host: str,
    port: int,
    identity,
    *,
    mtu: int = 1280,
    secondary_delay: float = SECONDARY_DELAY,
    probes: int = PROBES,
    probe_wait: float = PROBE_WAIT,
    quic_timeout: float = QUIC_TIMEOUT,
    h2_timeout: float = H2_TIMEOUT,
    transports: tuple[str, ...] = ("masque", "h2-tcp"),
) -> Optional[RaceOutcome]:
    """Race the transports for one endpoint, then score the winner by loss."""
    tasks: list[asyncio.Task] = []
    if "masque" in transports:
        tasks.append(asyncio.create_task(_attempt(
            "masque",
            lambda on_ip: MasqueTunnel(
                host, port,
                certificate_pem=identity.ec_certificate,
                private_key_pem=identity.ec_private_key,
                sni=identity.sni or MASQUE_SNI,
                mtu=mtu,
                on_ip=on_ip,
            ),
            identity, timeout=quic_timeout, probes=probes, probe_wait=probe_wait,
        )))
    if "h2-tcp" in transports:
        async def h2_attempt() -> Optional[RaceOutcome]:
            await asyncio.sleep(secondary_delay)
            return await _attempt(
                "h2-tcp",
                lambda on_ip: H2Tunnel(
                    host, port,
                    certificate_pem=identity.ec_certificate,
                    private_key_pem=identity.ec_private_key,
                    sni=identity.sni or MASQUE_SNI,
                    mtu=mtu,
                    on_ip=on_ip,
                ),
                identity, timeout=h2_timeout, probes=probes, probe_wait=probe_wait,
            )
        tasks.append(asyncio.create_task(h2_attempt()))

    winner: Optional[RaceOutcome] = None
    try:
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is not None:
                winner = result
                break
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return winner
