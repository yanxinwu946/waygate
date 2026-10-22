"""Endpoint scanning: find which MASQUE (ip, port) pairs actually carry traffic.

A handshake on its own proves nothing on a filtered network - the path happily
completes QUIC+TLS, returns ``:status 200`` for CONNECT-IP and then drops every
packet.  So every candidate is probed end to end:

1. QUIC + TLS handshake with the device certificate,
2. CONNECT-IP request (expect 200),
3. a real DNS query sent *through* the tunnel, waiting for the answer.

Only candidates that return the answer count as live.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import statistics
import time
from pathlib import Path
from typing import Optional

from . import packets as P
from .dns import build_query
from .masque import MasqueTunnel
from .racing import dns_probe_packet
from .warp import (
    MASQUE_ENDPOINTS_V4,
    MASQUE_ENDPOINTS_V6,
    MASQUE_PORTS,
    MASQUE_SNI,
    load_or_register_masque,
)

log = logging.getLogger("waygate.scan")

#: extra anycast addresses seen in the wild, beyond the official MASQUE pair.
#: 198.9–.16 includes the H2 backend .10 reported by Xray; 199.3–.8 is WARP+.
EXTRA_V4 = (
    "162.159.198.3", "162.159.198.4", "162.159.198.5", "162.159.198.6",
    "162.159.198.7", "162.159.198.8",
    "162.159.198.9", "162.159.198.10", "162.159.198.11", "162.159.198.12",
    "162.159.198.13", "162.159.198.14", "162.159.198.15", "162.159.198.16",
    "162.159.199.3", "162.159.199.4", "162.159.199.5", "162.159.199.6",
    "162.159.199.7", "162.159.199.8",
    "162.159.197.3", "162.159.197.4", "162.159.197.5", "162.159.197.6",
    "162.159.197.7", "162.159.197.8",
    "162.159.192.1", "162.159.192.8",
    "162.159.193.1", "162.159.195.1",
    "162.159.204.1",
    "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1",
)
EXTRA_V6 = (
    "2606:4700:103::3", "2606:4700:103::4",
    "2606:4700:103::5", "2606:4700:103::6",
    "2606:4700:103::7", "2606:4700:103::8",
    "2606:4700:104::3", "2606:4700:104::4",
    "2606:4700:104::5", "2606:4700:104::6",
    "2606:4700:104::7", "2606:4700:104::8",
)

#: Cloudflare WARP anycast prefixes (WireGuard + MASQUE share the same blocks)
SCAN_RANGES_V4 = (
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.194.0/24",
    "162.159.195.0/24",
    "162.159.196.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "162.159.199.0/24",
    "162.159.204.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
)

#: MASQUE H2 answers on the whole of these /24s (warpscout); QUIC on .1/.2.
MASQUE_EXIT_RANGES_V4 = (
    "162.159.198.0/24",
    "162.159.199.0/24",
)

#: ports used by the expanded profile (443 first; 4443 is an official MASQUE fallback)
EXPANDED_PORTS = (443, 500, 1701, 4500, 4443, 8095, 8443, 2408)
RANGE_PORTS = (443,)
RANGE_WIDE_PORTS = (443, 500, 2408)

SCAN_PROFILES = {
    "curated": {
        "label": "精选任播",
        "hint": "官方 MASQUE 地址与备用端口，扫描最快。",
    },
    "expanded": {
        "label": "扩展任播",
        "hint": "精选地址加上更多已知任播与常用端口。",
    },
    "range": {
        "label": "WARP 网段",
        "hint": "全部 WARP IPv4 /24 与 443 端口交叉，耗时约数分钟。",
    },
    "range_wide": {
        "label": "全量交叉",
        "hint": "全部网段乘以 443/500/2408，候选最多，耗时最长。",
    },
}


def _family_of(host: str) -> str:
    try:
        return "v6" if ipaddress.ip_address(host).version == 6 else "v4"
    except ValueError:
        return "v4"


def _filter_family(
    targets: list[tuple[str, int]], family: str
) -> list[tuple[str, int]]:
    if family not in ("v4", "v6"):
        return targets
    return [(host, port) for host, port in targets if _family_of(host) == family]


def expand_ranges(ranges: tuple[str, ...] = SCAN_RANGES_V4,
                  ports: tuple[int, ...] = (443,)) -> list[tuple[str, int]]:
    """Every address of every range, crossed with the given ports."""
    out: list[tuple[str, int]] = []
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        for host in network.hosts():
            for port in ports:
                out.append((str(host), port))
    return out


def _port_major(hosts: list[str], ports: list[int]) -> list[tuple[str, int]]:
    ordered: dict[tuple[str, int], None] = {}
    for port in ports:
        for host in hosts:
            if host:
                ordered.setdefault((host, port), None)
    return list(ordered)


def candidate_endpoints(preferred: Optional[str] = None) -> list[tuple[str, int]]:
    """Ordered *port-major*: port 443 across every host first, then 500, and so on.

    With a small candidate budget (an instance only tries a handful) this is
    what matters: trying 443 on six different hosts beats trying six ports on a
    single host, and it is how the official client behaves (443 is the primary,
    hosts and address families are what it races).
    """
    hosts = [
        h
        for h in (preferred, *MASQUE_ENDPOINTS_V6, *MASQUE_ENDPOINTS_V4, *EXTRA_V6, *EXTRA_V4)
        if h
    ]
    ports = [443, *[p for p in MASQUE_PORTS if p != 443]]
    return _port_major(hosts, ports)


def expanded_endpoints(preferred: Optional[str] = None) -> list[tuple[str, int]]:
    """Curated MASQUE hosts plus extra anycast, crossed with the expanded ports."""
    hosts = [
        h
        for h in (
            preferred,
            *MASQUE_ENDPOINTS_V6,
            *MASQUE_ENDPOINTS_V4,
            *EXTRA_V6,
            *EXTRA_V4,
        )
        if h
    ]
    return _port_major(hosts, list(EXPANDED_PORTS))


def parse_ports(value) -> list[int]:
    """Accept a list, a comma-separated string, or a single int."""
    if value is None or value == "":
        return []
    if isinstance(value, int):
        return [value] if 1 <= value <= 65535 else []
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        raw = str(value).replace(" ", "").split(",")
    out: list[int] = []
    seen: set[int] = set()
    for item in raw:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in seen:
            seen.add(port)
            out.append(port)
    return out


def parse_ranges(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.replace(";", ",").split(",")]
    elif isinstance(value, (list, tuple)):
        items = [str(part).strip() for part in value]
    else:
        return []
    out: list[str] = []
    for item in items:
        if not item:
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        out.append(item)
    return out


def build_targets(
    profile: str = "curated",
    *,
    family: str = "both",
    ports: Optional[list[int]] = None,
    ranges: Optional[list[str]] = None,
    preferred: Optional[str] = None,
) -> list[tuple[str, int]]:
    """Materialize the candidate list for a named scan profile."""
    profile = profile if profile in SCAN_PROFILES else "curated"
    port_list = ports or []
    if profile == "curated":
        targets = candidate_endpoints(preferred)
        if port_list:
            hosts = list(dict.fromkeys(host for host, _ in targets))
            targets = _port_major(hosts, port_list)
    elif profile == "expanded":
        targets = expanded_endpoints(preferred)
        if port_list:
            hosts = list(dict.fromkeys(host for host, _ in targets))
            targets = _port_major(hosts, port_list)
    elif profile == "range_wide":
        cidrs = tuple(ranges) if ranges else SCAN_RANGES_V4
        targets = expand_ranges(cidrs, tuple(port_list or RANGE_WIDE_PORTS))
    else:  # range
        cidrs = tuple(ranges) if ranges else SCAN_RANGES_V4
        targets = expand_ranges(cidrs, tuple(port_list or RANGE_PORTS))
    return _filter_family(targets, family)


def format_endpoint(host: str, port: int = 443) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def official_masque_endpoints() -> list[tuple[str, int]]:
    """Account-type anycast only: WARP / WARP+ / Zero Trust .1 and .2."""
    ordered: dict[str, int] = {}
    for host in (*MASQUE_ENDPOINTS_V4, *MASQUE_ENDPOINTS_V6):
        ordered.setdefault(host, 443)
    return [(host, port) for host, port in ordered.items()]


def unique_endpoint_pool(min_hosts: int = 0) -> list[tuple[str, int]]:
    """Curated MASQUE hosts for placement fallback. Not a padded /24.

    Live scan results override this list. QUIC is proven on ``.1`` / ``.2`` of
    each account block; extra 198/199/197 addresses are field reports, not a
    generated sequence.
    """
    ordered: dict[str, int] = {}
    for host, port in official_masque_endpoints():
        ordered.setdefault(host, port)
    for host in EXTRA_V4:
        if host.startswith(("162.159.198.", "162.159.199.", "162.159.197.")):
            ordered.setdefault(host, 443)
    for host in EXTRA_V6:
        ordered.setdefault(host, 443)
    if min_hosts > 0:
        return list(ordered.items())[:max(min_hosts, len(ordered))]
    return [(host, port) for host, port in ordered.items()]


def dns_probe_packet_legacy(src: str) -> bytes:  # kept for compatibility
    query, _ = build_query("www.cloudflare.com")
    udp = P.udp_pack(55000, 53, query, P.ipv4_to_bytes(src), P.ipv4_to_bytes("1.1.1.1"))
    return P.ipv4_pack(P.ipv4_to_bytes(src), P.ipv4_to_bytes("1.1.1.1"), P.IPPROTO_UDP, udp)


async def probe_endpoint(
    host: str,
    port: int,
    identity,
    *,
    timeout: float = 8.0,
    answer_timeout: float = 6.0,
    probes: int = 3,
    probe_wait: float = 0.8,
    transports: tuple[str, ...] = ("masque",),
) -> dict:
    """Bring the endpoint up on the verified direct path and score it.

    Deliberately *not* using the racing helper: it comes up but never sees a
    reply, which is exactly why every scan reported zero live endpoints.
    This is the same code path the pool uses to serve traffic.
    """
    result = {"target": f"{host}:{port}", "host": host, "port": port,
              "live": False, "handshake": None, "rtt": None, "error": "",
              "transport": "", "loss": None, "latency": None, "replies": 0,
              "probes": probes}
    received: list[bytes] = []
    tunnel = MasqueTunnel(
        host,
        port,
        certificate_pem=identity.ec_certificate,
        private_key_pem=identity.ec_private_key,
        sni=identity.sni or MASQUE_SNI,
        reconnect=False,
    )
    tunnel.on_ip = received.append
    started = time.monotonic()
    try:
        await tunnel.start()
        await tunnel.wait_ready(timeout)
        result["handshake"] = round(time.monotonic() - started, 2)

        rtts: list[float] = []
        for index in range(probes):
            before = len(received)
            probe_started = time.monotonic()
            tunnel.send_ip(dns_probe_packet(identity.address_v4, txid=0x6000 + index))
            deadline = probe_started + probe_wait
            while time.monotonic() < deadline:
                if len(received) > before:
                    rtts.append(time.monotonic() - probe_started)
                    break
                await asyncio.sleep(0.05)
            if index + 1 < probes:
                await asyncio.sleep(0.15)

        result["replies"] = len(rtts)
        if rtts:
            result["live"] = True
            result["transport"] = "masque"
            result["loss"] = max(0.0, 1.0 - len(rtts) / probes)
            result["latency"] = statistics.fmean(rtts)
            result["rtt"] = round(result["latency"], 3)
        else:
            result["error"] = "TimeoutError"
    except Exception as exc:  # noqa: BLE001
        result["error"] = type(exc).__name__
    finally:
        try:
            await tunnel.stop()
        except Exception:  # noqa: BLE001
            pass
    return result


class EndpointScanner:
    """Runs the probe over every candidate and remembers the outcome."""

    def __init__(
        self,
        identity_path: Path | str,
        *,
        timeout: float = 8.0,
        concurrency: int = 60,
        stagger: float = 0.0,
        whole_range: bool = False,
        profile: str = "curated",
        family: str = "both",
        ports: Optional[list[int]] = None,
        ranges: Optional[list[str]] = None,
    ) -> None:
        self.identity_path = Path(identity_path)
        self.timeout = timeout
        # 60 in flight: the curated list of 60 candidates finishes in about a
        # minute without leaning on the per-device limits
        self.concurrency = concurrency
        self.stagger = stagger
        #: sweep every address of the Cloudflare WARP ranges instead of the
        #: curated MASQUE list.  Measured: 2540 candidates, 3 minutes, and only
        #: the same two anycast addresses come back - the wide ranges serve
        #: WireGuard, not MASQUE.  Off by default.
        self.whole_range = whole_range
        self.profile = "range" if whole_range else (profile if profile in SCAN_PROFILES else "curated")
        self.family = family if family in ("v4", "v6", "both") else "both"
        self.ports = list(ports or [])
        self.ranges = list(ranges or [])
        self.last_submitted: dict = {}
        #: set by the "stop" button in the web UI
        self.stop_requested = False
        #: how the survivors of the cheap first pass are scored
        self.probes = 3
        self.probe_wait = 0.8
        self._task: Optional[asyncio.Task] = None
        self.results: list[dict] = []
        self.scanning = False
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.started_at_unix: Optional[float] = None
        self.finished_at_unix: Optional[float] = None
        self.error = ""
        self.total = 0

    def configure(
        self,
        *,
        profile: Optional[str] = None,
        family: Optional[str] = None,
        ports=None,
        ranges=None,
        concurrency: Optional[int] = None,
        whole_range: Optional[bool] = None,
    ) -> None:
        """Update scan options. Ignored while a scan is already running."""
        if self.scanning:
            return
        if profile is not None:
            self.profile = profile if profile in SCAN_PROFILES else "curated"
        if family is not None:
            self.family = family if family in ("v4", "v6", "both") else "both"
        if ports is not None:
            self.ports = parse_ports(ports)
        if ranges is not None:
            self.ranges = parse_ranges(ranges)
        if concurrency is not None:
            try:
                self.concurrency = max(1, min(int(concurrency), 200))
            except (TypeError, ValueError):
                pass
        if whole_range is not None:
            self.whole_range = bool(whole_range)
            if self.whole_range and self.profile == "curated":
                self.profile = "range"

    def request_stop(self) -> None:
        """Emergency stop.

        Setting a flag alone is not enough: 300 probes can be in flight and each
        one would keep running to its own timeout.  Cancelling the scan task
        aborts them immediately (every probe closes its tunnel in ``finally``).
        """
        if not self.scanning:
            return
        self.stop_requested = True
        task = self._task
        if task is not None and not task.done():
            log.info("scan stop requested - cancelling %d probes in flight", self.concurrency)
            task.cancel()

    # ------------------------------------------------------------------ state
    def live(self) -> list[dict]:
        """Ranked like warp-yxip's result.csv: least loss first, then latency."""
        return sorted(
            (r for r in self.results if r["live"]),
            key=lambda r: (r.get("loss") if r.get("loss") is not None else 1.0,
                           r.get("latency") if r.get("latency") is not None else 9.9),
        )

    def state(self) -> dict:
        live = self.live()
        failures: dict[str, int] = {}
        for result in self.results:
            if not result["live"] and result["error"]:
                failures[result["error"]] = failures.get(result["error"], 0) + 1
        return {
            "scanning": self.scanning,
            "scanned": len(self.results),
            "total": self.total,
            "stop_requested": self.stop_requested,
            "live": live,
            "live_count": len(live),
            "failures": failures,
            "duration": (
                round((self.finished_at or time.monotonic()) - self.started_at, 1)
                if self.started_at
                else None
            ),
            "error": self.error,
            "profile": self.profile,
            "family": self.family,
            "ports": list(self.ports),
            "ranges": list(self.ranges),
            "concurrency": self.concurrency,
            "started_at": self.started_at_unix,
            "finished_at": self.finished_at_unix,
            "submitted": dict(self.last_submitted),
            "profiles": {
                key: {"id": key, **meta} for key, meta in SCAN_PROFILES.items()
            },
        }

    # ------------------------------------------------------------------- work
    async def scan(self, candidates: Optional[list[tuple[str, int]]] = None) -> list[dict]:
        if self.scanning:
            return self.results
        self.scanning = True
        self.stop_requested = False
        self._task = asyncio.current_task()
        self.error = ""
        self.started_at = time.monotonic()
        self.finished_at = None
        self.started_at_unix = time.time()
        self.finished_at_unix = None
        try:
            identity = await load_or_register_masque(self.identity_path)
            if candidates:
                targets = candidates
            elif self.whole_range and self.profile == "curated":
                targets = expand_ranges()
            else:
                targets = build_targets(
                    self.profile,
                    family=self.family,
                    ports=self.ports or None,
                    ranges=self.ranges or None,
                )
            if self.family in ("v4", "v6"):
                targets = _filter_family(targets, self.family)
            self.total = len(targets)
            self.last_submitted = {
                "profile": self.profile,
                "family": self.family,
                "ports": list(self.ports),
                "ranges": list(self.ranges),
                "concurrency": self.concurrency,
                "total": self.total,
                "at": self.started_at_unix,
            }
            log.info("scanning %d candidates at concurrency %d ...",
                     len(targets), self.concurrency)
            self.results = []
            semaphore = asyncio.Semaphore(self.concurrency)
            # a full sweep is mostly misses (only a few addresses serve MASQUE),
            # so the first pass is cheap: one probe, short timeout.  Survivors
            # are re-measured properly afterwards.
            cheap = self.whole_range or len(targets) > 200

            async def one(host: str, port: int) -> Optional[dict]:
                async with semaphore:
                    if self.stop_requested:
                        return None
                    try:
                        if cheap:
                            result = await probe_endpoint(
                                host, port, identity, timeout=4.0,
                                probes=1, probe_wait=0.6)
                        else:
                            result = await probe_endpoint(host, port, identity,
                                                          timeout=self.timeout)
                    finally:
                        await asyncio.sleep(self.stagger)
                # publish immediately so the UI shows progress instead of
                # looking stuck at "0 / 0" for the whole scan
                self.results.append(result)
                return result

            await asyncio.gather(*(one(h, p) for h, p in targets))

            # second pass: score the few that answered with a real measurement
            survivors = [r for r in self.results if r["live"]]
            if survivors and cheap and not self.stop_requested:
                log.info("re-measuring %d live endpoint(s) with %d probes",
                         len(survivors), self.probes)
                for entry in survivors:
                    if self.stop_requested:
                        break
                    better = await probe_endpoint(
                        entry["host"], entry["port"], identity,
                        timeout=self.timeout, probes=self.probes, probe_wait=self.probe_wait)
                    if better["live"]:
                        entry.update(loss=better["loss"], latency=better["latency"],
                                     replies=better["replies"], probes=better["probes"],
                                     rtt=better["rtt"])
        except asyncio.CancelledError:
            log.info("scan cancelled with %d/%d probed", len(self.results), self.total)
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            log.warning("endpoint scan failed: %s", self.error)
        finally:
            self.scanning = False
            self._task = None
            self.finished_at = time.monotonic()
            self.finished_at_unix = time.time()
            log.info("scan finished: %d/%d live in %.1fs",
                     sum(1 for r in self.results if r["live"]), len(self.results),
                     (self.finished_at - self.started_at) if self.started_at else 0.0)
        return self.results
