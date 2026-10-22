"""Run several independent WARP tunnels at once, each with its own SOCKS5 port.

Cloudflare rate-limits per *device* and the local network throttles individual
QUIC flows, so the practical way to get a fast, always-available proxy is to run
several independent instances:

* every instance has its own device identity (its own EC key + certificate),
* its own MASQUE tunnel (its own QUIC connection / flow),
* its own user-space IP stack and SOCKS5 listener on its own port.

``WarpPool`` starts each instance on demand and reports health, which is what
the web UI drives.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

from .dns import DnsClient
from .ipstack import IPStack
from .masque import MasqueTunnel
from .racing import dns_probe_packet
from .scan import (
    SCAN_PROFILES,
    candidate_endpoints,
    format_endpoint,
    official_masque_endpoints,
)
from .socks5 import Socks5Server
from .warp import (
    MASQUE_SNI,
    load_or_register_masque,
)

log = logging.getLogger("waygate.pool")

DEFAULT_DNS = ("1.1.1.1", "1.0.0.1")

ROUTING_MODES = {
    "least_load": {
        "label": "最少连接",
        "hint": "新连接交给当前 TCP 流最少的线路。",
    },
    "unique_ip": {
        "label": "差异 IP",
        "hint": "优先把流量摊到不同出口地址，同一地址内再选最空闲线路。",
    },
    "round_robin": {
        "label": "轮询",
        "hint": "按线路顺序轮流分发新连接。",
    },
    "failover": {
        "label": "主备",
        "hint": "始终使用列表中第一条健康线路，故障才切到下一条。",
    },
}

PLACEMENT_MODES = {
    "unique_ip": {
        "label": "差异 IP",
        "hint": "新线路优先占用尚未使用的扫描地址。",
    },
    "fastest": {
        "label": "最快端点",
        "hint": "新线路落在当前排名最高的地址，允许共用。",
    },
    "least_owned": {
        "label": "最少占用",
        "hint": "优先落在被占用次数最少的可用地址。",
    },
}

MAX_BATCH = 64
MAX_ADD = 64
EXIT_TARGET = 30


def endpoint_host(endpoint: str) -> str:
    """Strip the port from ``host:port`` / ``[v6]:port``."""
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return ""
    if endpoint.startswith("["):
        end = endpoint.find("]")
        return endpoint[1:end] if end > 0 else endpoint
    if endpoint.count(":") == 1:
        return endpoint.split(":")[0]
    host, _, port = endpoint.rpartition(":")
    if host and port.isdigit():
        return host
    return endpoint


def _load_of(instance: WarpInstance) -> int:
    stack = instance._stack
    if stack is None:
        return 10**9
    return len(stack.tcp)


async def _tcp_http(stack, ip: str, request: bytes, *, timeout: float = 8.0) -> str:
    connection = await stack.tcp_connect(ip, 80, timeout=timeout)
    try:
        await connection.send(request)
        chunks = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remain = deadline - time.monotonic()
            try:
                data = await asyncio.wait_for(connection.recv(65536), max(0.1, remain))
            except asyncio.TimeoutError:
                break
            if not data:
                break
            chunks += data
            if b"\r\n\r\n" in chunks and (
                b"ip=" in chunks or len(chunks) > 80
            ):
                break
        return chunks.decode("latin-1", "replace")
    finally:
        await connection.close()


def _looks_like_ip(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _trace_public(stack, resolver) -> dict:
    """Public egress IP of this tunnel, plus colo/loc when Cloudflare answers."""
    out = {"ip": "", "colo": "", "loc": ""}
    try:
        raw = await _tcp_http(
            stack,
            "1.1.1.1",
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n",
        )
        body = raw.split("\r\n\r\n", 1)[-1]
        for line in body.splitlines():
            if line.startswith("ip=") and _looks_like_ip(line[3:]):
                out["ip"] = line[3:].strip()
            elif line.startswith("colo="):
                out["colo"] = line[5:].strip()
            elif line.startswith("loc="):
                out["loc"] = line[4:].strip()
    except Exception:  # noqa: BLE001
        pass
    if not out["ip"]:
        try:
            addresses = await asyncio.wait_for(resolver.resolve("api.ipify.org"), 6.0)
            if addresses:
                raw = await _tcp_http(
                    stack,
                    addresses[0],
                    b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n",
                )
                text = raw.split("\r\n\r\n", 1)[-1].strip().split()[0]
                if _looks_like_ip(text):
                    out["ip"] = text
        except Exception:  # noqa: BLE001
            pass
    return out


async def _trace_ip(stack, resolver) -> str:
    """Public address as the internet sees this tunnel. Empty on failure."""
    info = await _trace_public(stack, resolver)
    return info.get("ip") or ""


class WarpInstance:
    """One device: MASQUE tunnel + IP stack + SOCKS5 listener."""

    def __init__(
        self,
        name: str,
        port: int,
        identity_path: Path | str,
        *,
        endpoint: Optional[str] = None,
        mtu: int = 1280,
        dns: tuple[str, ...] = DEFAULT_DNS,
        connect_timeout: float = 12.0,
        max_candidates: int = 6,
    ) -> None:
        self.name = name
        self.port = port
        self.identity_path = Path(identity_path)
        self.endpoint = endpoint
        self.mtu = mtu
        self.dns = dns
        self.connect_timeout = connect_timeout
        self.max_candidates = max_candidates

        self.status = "stopped"
        self.error = ""
        self.device_id = ""
        self.transport = ""
        self.loss = 0.0
        self.latency = 0.0
        self.exit_ip = ""
        self.exit_colo = ""
        self.exit_loc = ""
        self.endpoint_used = ""
        self.started_at: Optional[float] = None
        self.last_probe: Optional[float] = None
        self.tunnel: Optional[MasqueTunnel] = None
        self.probe_failures = 0
        self._stack: Optional[IPStack] = None
        self._server: Optional[Socks5Server] = None
        self._lock = asyncio.Lock()
        self._samples: dict[str, tuple[float, int]] = {}
        self._last_bps: dict[str, int] = {}

    # ------------------------------------------------------------------ state
    def _bps(self, key: str, value: int, now: float) -> int:
        prev = self._samples.get(key)
        if prev is None:
            self._samples[key] = (now, value)
            return 0
        dt = now - prev[0]
        if dt < 0.4:
            return self._last_bps.get(key, 0)
        bps = int(max(0, (value - prev[1]) / dt))
        self._samples[key] = (now, value)
        self._last_bps[key] = bps
        return bps

    def info(self) -> dict:
        tunnel = self.tunnel
        now = time.monotonic()
        uptime = round(now - self.started_at) if self.started_at else 0
        tx_bytes = int(tunnel.stats.get("tx_bytes", 0)) if tunnel else 0
        rx_bytes = int(tunnel.stats.get("rx_bytes", 0)) if tunnel else 0
        return {
            "name": self.name,
            "port": self.port,
            "status": self.status,
            "error": self.error,
            "device": self.device_id[:8],
            "endpoint": self.endpoint_used or self.endpoint or "",
            "transport": self.transport or "-",
            "loss": round(self.loss * 100, 1),
            "latency": round(self.latency * 1000),
            "exit_ip": self.exit_ip,
            "exit_colo": self.exit_colo,
            "exit_loc": self.exit_loc,
            "uptime": uptime,
            "uptime_text": _duration(uptime),
            "tx": tunnel.stats["tx_packets"] if tunnel else 0,
            "rx": tunnel.stats["rx_packets"] if tunnel else 0,
            "tx_bytes": tx_bytes,
            "rx_bytes": rx_bytes,
            "tx_bps": self._bps("tx", tx_bytes, now),
            "rx_bps": self._bps("rx", rx_bytes, now),
            "reconnects": tunnel.stats["reconnects"] if tunnel else 0,
            "socks_url": f"socks5h://127.0.0.1:{self.port}",
            "connections": getattr(self._server, "total", 0) if self._server else 0,
            "active": getattr(self._server, "active", 0) if self._server else 0,
            "flows": len(self._stack.tcp) if self._stack is not None else 0,
            "pinned": bool(self.endpoint),
            "endpoint_host": endpoint_host(self.endpoint_used or self.endpoint or ""),
        }

    # ------------------------------------------------------------------ life
    async def start(self) -> bool:
        async with self._lock:
            if self.status == "running":
                return True
            self.status = "starting"
            self.error = ""
            try:
                await self._start_locked()
            except Exception as exc:  # noqa: BLE001
                self.status = "error"
                self.error = f"{type(exc).__name__}: {exc}"
                log.warning("[%s] start failed: %s", self.name, self.error)
                await self._teardown()
                return False
            self.status = "running"
            self.started_at = time.monotonic()
            log.info("[%s] up on port %d via %s", self.name, self.port, self.endpoint_used)
            return True

    async def _start_locked(self) -> None:
        identity = await load_or_register_masque(self.identity_path)
        self.device_id = identity.device_id
        api_host = (identity.endpoint_v4 or "").split(":")[0] or None
        last_error: Optional[BaseException] = None

        # an endpoint may be pinned as "host" or "host:port" (from the web UI)
        pinned: Optional[tuple[str, int]] = None
        if self.endpoint:
            host_part, _, port_part = self.endpoint.rpartition(":")
            if host_part and port_part.isdigit():
                pinned = (host_part, int(port_part))
            else:
                pinned = (self.endpoint, 443)
        if pinned:
            # fixed endpoint: this instance stays on it and does not wander
            candidates = [pinned]
        else:
            candidates = candidate_endpoints(api_host)

        # racing costs a few seconds per candidate, so an instance only tries
        # the best few (pinned first, then IPv6, then IPv4) instead of all 60
        for host, port in candidates[:self.max_candidates]:
            # NOTE: this mirrors the hand-verified working path.  The racing
            # helper is not used here yet - it comes up but never sees a reply,
            # and a working proxy matters more than the fancy path right now.
            tunnel = MasqueTunnel(
                host, port,
                certificate_pem=identity.ec_certificate,
                private_key_pem=identity.ec_private_key,
                sni=identity.sni or MASQUE_SNI,
                mtu=self.mtu,
            )
            received: list[bytes] = []
            tunnel.on_ip = received.append
            try:
                await tunnel.start()
                await tunnel.wait_ready(self.connect_timeout)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                await tunnel.stop()
                continue

            # prove the data plane with real DNS probes before serving
            carried = False
            for index in range(3):
                before = len(received)
                tunnel.send_ip(dns_probe_packet(identity.address_v4, txid=0x5000 + index))
                for _ in range(20):
                    if len(received) > before:
                        carried = True
                        break
                    await asyncio.sleep(0.1)
                if carried:
                    break
                await asyncio.sleep(0.2)
            if not carried:
                last_error = TimeoutError(f"{host}:{port} carried no traffic")
                await tunnel.stop()
                continue
            transport = "masque"
            stack = IPStack(tunnel, identity.address_v4,
                            local_ip_v6=identity.address_v6, mtu=self.mtu)
            stack.start()
            resolver = DnsClient(stack, list(self.dns), timeout=7.0)
            try:
                addresses = await asyncio.wait_for(
                    resolver.resolve("www.cloudflare.com"), 8.0
                )
            except Exception as exc:  # noqa: BLE001
                addresses = []
                last_error = exc
            if not addresses:
                await stack.stop()
                await tunnel.stop()  # type: ignore[attr-defined]
                continue
            # keep this verified stack - rebuilding it lets the fresh flow go
            # cold and the line throttles it
            tunnel.on_reconnect = stack.poke_all  # type: ignore[attr-defined]
            server = Socks5Server(stack, resolver, host="0.0.0.0", port=self.port)
            await server.start()
            self.tunnel = tunnel
            self._stack = stack
            self._server = server
            self.transport = transport
            self.endpoint_used = format_endpoint(host, port)
            traced = await _trace_public(stack, resolver)
            self.exit_ip = traced.get("ip") or ""
            self.exit_colo = traced.get("colo") or ""
            self.exit_loc = traced.get("loc") or ""
            return
        raise TimeoutError(
            f"no MASQUE endpoint carried traffic ({last_error!r})" if last_error
            else "no MASQUE endpoint carried traffic"
        )

    async def stop(self) -> None:
        async with self._lock:
            await self._teardown()
            self.status = "stopped"
            self.started_at = None
            log.info("[%s] stopped", self.name)

    async def restart(self) -> bool:
        await self.stop()
        return await self.start()

    async def probe_exit(self) -> str:
        """Query the tunnel's own DNS to confirm it still answers."""
        if self._stack is None:
            return ""
        try:
            resolver = DnsClient(self._stack, list(self.dns), timeout=4.0)
            addresses = await asyncio.wait_for(resolver.resolve("one.one.one.one"), 8.0)
        except Exception:  # noqa: BLE001
            return ""
        self.last_probe = time.monotonic()
        return addresses[0] if addresses else ""

    async def refresh_exit_ip(self) -> str:
        """Re-query the public IP through a running tunnel."""
        if self._stack is None or self._server is None:
            return self.exit_ip
        traced = await _trace_public(self._stack, self._server.resolver)
        if traced.get("ip"):
            self.exit_ip = traced["ip"]
        if traced.get("colo"):
            self.exit_colo = traced["colo"]
        if traced.get("loc"):
            self.exit_loc = traced["loc"]
        return self.exit_ip

    async def _teardown(self) -> None:
        if self._server is not None:
            try:
                await self._server.stop()
            except Exception:  # noqa: BLE001
                pass
            self._server = None
        if self._stack is not None:
            try:
                await self._stack.stop()
            except Exception:  # noqa: BLE001
                pass
            self._stack = None
        if self.tunnel is not None:
            try:
                await self.tunnel.stop()
            except Exception:  # noqa: BLE001
                pass
            self.tunnel = None


class WarpPool:
    """A set of instances plus the supervisor that keeps them healthy."""

    def __init__(
        self,
        base_dir: Path | str,
        *,
        count: int = 3,
        base_port: int = 1080,
        mtu: int = 1280,
        dns: tuple[str, ...] = DEFAULT_DNS,
        supervise: bool = True,
        supervise_interval: float = 30.0,
        scanner: object = None,
        saved: Optional[list] = None,
        on_change: Optional[Callable[[], None]] = None,
        front_port: Optional[int] = None,
        front_host: str = "0.0.0.0",
        routing_mode: str = "least_load",
        placement_mode: str = "unique_ip",
    ) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = scanner
        self.on_change = on_change
        self.base_port = base_port
        self.mtu = mtu
        self.dns = dns
        self.supervise = supervise
        self.supervise_interval = supervise_interval
        self.instances: list[WarpInstance] = []
        self._retiring: set[str] = set()
        if saved:
            # restore exactly what was there before, pinned endpoints included
            for entry in saved:
                slot = len(self.instances)
                self.instances.append(self._make_instance(
                    str(entry.get("name") or f"warp{slot + 1}"),
                    int(entry.get("port") or (self.base_port + slot)),
                    entry.get("endpoint") or None,
                ))
        else:
            for _ in range(count):
                self.add()
        self._supervisor: Optional[asyncio.Task] = None
        self._closed = False
        self.front_host = front_host
        self.front_error = ""
        self._front: Optional[Socks5Server] = None
        self.routing_mode = (
            routing_mode if routing_mode in ROUTING_MODES else "least_load"
        )
        self.placement_mode = (
            placement_mode if placement_mode in PLACEMENT_MODES else "unique_ip"
        )
        self._rr = 0
        used = {item.port for item in self.instances}
        if front_port is None:
            front_port = self.base_port - 1
            while front_port < 1 or front_port in used:
                front_port += 1
        self.front_port = front_port

    # ------------------------------------------------------------- membership
    def _make_instance(self, name: str, port: int, endpoint: Optional[str]) -> WarpInstance:
        return WarpInstance(
            name,
            port,
            self.base_dir / f"identity-masque-{name}.json",
            endpoint=endpoint,
            mtu=self.mtu,
            dns=self.dns,
        )

    def _notify(self) -> None:
        """Tell the owner the instance list changed so it can be persisted."""
        if self.on_change is not None:
            try:
                self.on_change()
            except Exception:  # noqa: BLE001
                log.exception("persisting the pool failed")

    def add(self, endpoint: Optional[str] = None) -> WarpInstance:
        # take the first *free* slot: numbering by len(instances) would reuse a
        # live name and port after something earlier in the list was removed
        taken_names = {i.name for i in self.instances} | self._retiring
        taken_ports = {i.port for i in self.instances}
        index = 1
        while (f"warp{index}" in taken_names
               or (self.base_port + index - 1) in taken_ports):
            index += 1
        name = f"warp{index}"
        endpoint = endpoint or self.place_endpoint()
        instance = self._make_instance(name, self.base_port + index - 1, endpoint)
        self.instances.append(instance)
        self._notify()
        return instance

    def add_many(
        self, count: int = 1, endpoint: Optional[str] = None
    ) -> list[WarpInstance]:
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 1
        count = max(1, min(count, MAX_ADD))
        added = [self.add(endpoint) for _ in range(count)]
        return added

    def snapshot(self) -> list[dict]:
        """Everything needed to rebuild the pool exactly as it is now."""
        return [
            {"name": i.name, "port": i.port, "endpoint": i.endpoint or ""}
            for i in self.instances
        ]

    def export_state(self) -> dict:
        return {
            "count": len(self.instances),
            "instances": self.snapshot(),
            "settings": {
                "routing_mode": self.routing_mode,
                "placement_mode": self.placement_mode,
                "scan_profile": getattr(self.scanner, "profile", "curated"),
                "scan_family": getattr(self.scanner, "family", "both"),
                "scan_ports": getattr(self.scanner, "ports", []),
                "scan_concurrency": getattr(self.scanner, "concurrency", 60),
            },
        }

    def remove(self, name: str) -> bool:
        for index, instance in enumerate(self.instances):
            if instance.name == name:
                self.instances.pop(index)
                # keep the slot reserved until the listener is really gone,
                # otherwise a quick re-add can collide with the dying socket
                self._retiring.add(name)

                async def _stop_and_release(inst: WarpInstance = instance,
                                            slot: str = name) -> None:
                    try:
                        await inst.stop()
                    finally:
                        self._retiring.discard(slot)

                asyncio.create_task(_stop_and_release())
                self._notify()
                return True
        return False

    def get(self, name: str) -> Optional[WarpInstance]:
        return next((i for i in self.instances if i.name == name), None)

    def best_endpoint(self) -> Optional[str]:
        """The top ranked live endpoint.

        Several instances may share one endpoint: there is nothing wrong with
        putting three tunnels on the best address, and the per-device limits are
        about the device, not the address.
        """
        ranked = self.scanner.live() if self.scanner is not None else []
        return ranked[0]["target"] if ranked else None

    def _owner_counts(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for instance in self.instances:
            target = instance.endpoint or instance.endpoint_used
            if target:
                counts[target] += 1
        return counts

    def _candidate_targets(self) -> list[str]:
        """Live scan hits first, then official MASQUE anycast."""
        seen: dict[str, None] = {}
        ranked = self.scanner.live() if self.scanner is not None else []
        for entry in ranked:
            target = entry.get("target") or format_endpoint(entry.get("host", ""), int(entry.get("port") or 443))
            if target:
                seen.setdefault(target, None)
        for host, port in official_masque_endpoints():
            seen.setdefault(format_endpoint(host, port), None)
        return list(seen)

    def unique_host_targets(self) -> list[str]:
        """One endpoint per distinct host: live scan, else official MASQUE."""
        seen: dict[str, str] = {}
        ranked = self.scanner.live() if self.scanner is not None else []
        for entry in ranked:
            target = entry.get("target") or format_endpoint(
                entry.get("host", ""), int(entry.get("port") or 443)
            )
            host = endpoint_host(target)
            if host and host not in seen:
                seen[host] = target
        if seen:
            return list(seen.values())
        for host, port in official_masque_endpoints():
            seen.setdefault(host, format_endpoint(host, port))
        return list(seen.values())

    def place_endpoint(self) -> Optional[str]:
        """Pick an endpoint for a new instance according to ``placement_mode``."""
        targets = self._candidate_targets()
        if not targets:
            return None
        used_hosts = {
            endpoint_host(instance.endpoint or instance.endpoint_used)
            for instance in self.instances
            if instance.endpoint or instance.endpoint_used
        }
        used_hosts.discard("")
        if self.placement_mode == "fastest":
            return targets[0]
        if self.placement_mode == "unique_ip":
            for target in targets:
                host = endpoint_host(target)
                if host and host not in used_hosts:
                    return target
            return targets[0]
        owners = self._owner_counts()
        return min(targets, key=lambda t: (owners.get(t, 0), t))

    def ensure_unique_exits(self, count: Optional[int] = None, *, start: bool = True) -> dict:
        """One line per distinct live (or official) host. Count is not a padded quota."""
        targets = self.unique_host_targets()
        auto = count is None
        if auto:
            want = len(targets) or 1
        else:
            try:
                want = int(count)
            except (TypeError, ValueError):
                want = len(targets) or 1
            want = max(1, min(want, MAX_ADD))
        capped = False
        if targets and want > len(targets):
            want = len(targets)
            capped = not auto
        self.placement_mode = "unique_ip"
        self.routing_mode = "unique_ip"
        added: list[str] = []
        used = {
            endpoint_host(instance.endpoint or instance.endpoint_used)
            for instance in self.instances
            if instance.endpoint or instance.endpoint_used
        }
        used.discard("")
        for instance in self.instances:
            if instance.endpoint or instance.endpoint_used:
                continue
            for target in targets:
                host = endpoint_host(target)
                if host and host not in used:
                    instance.endpoint = target
                    used.add(host)
                    break
        while len(self.instances) < want:
            added.append(self.add().name)
        hosts = {
            endpoint_host(instance.endpoint or instance.endpoint_used)
            for instance in self.instances
            if instance.endpoint or instance.endpoint_used
        }
        hosts.discard("")
        pending = [
            instance.name
            for instance in self.instances
            if instance.status not in ("running", "starting")
        ]
        if start:
            asyncio.create_task(self._start_pending())
        self._notify()
        return {
            "ok": True,
            "auto": auto,
            "capped": capped,
            "available": len(targets),
            "target": want,
            "added": added,
            "total": len(self.instances),
            "unique_hosts": len(hosts),
            "starting": pending,
            "routing_mode": self.routing_mode,
            "placement_mode": self.placement_mode,
        }

    async def refresh_exit_ips(self) -> dict:
        """Re-trace the public IP of every running line."""
        items = []
        for instance in list(self.instances):
            if instance.status != "running":
                items.append({
                    "name": instance.name,
                    "exit_ip": instance.exit_ip,
                    "exit_colo": instance.exit_colo,
                    "ok": False,
                })
                continue
            try:
                ip = await instance.refresh_exit_ip()
                items.append({
                    "name": instance.name,
                    "exit_ip": ip,
                    "exit_colo": instance.exit_colo,
                    "exit_loc": instance.exit_loc,
                    "ok": bool(ip),
                })
            except Exception:  # noqa: BLE001
                items.append({
                    "name": instance.name,
                    "exit_ip": instance.exit_ip,
                    "ok": False,
                })
        public = sorted({item["exit_ip"] for item in items if item.get("exit_ip")})
        self._notify()
        return {
            "ok": True,
            "exits": items,
            "exit_ips": public,
            "exit_ip_count": len(public),
        }

    async def _start_pending(self, stagger: float = 0.35) -> None:
        for instance in list(self.instances):
            if instance.status in ("running", "starting"):
                continue
            try:
                await instance.start()
            except Exception:  # noqa: BLE001
                log.warning("[%s] ensure-start failed", instance.name)
            if stagger:
                await asyncio.sleep(stagger)

    def pin(self, name: str, endpoint: Optional[str]) -> Optional[WarpInstance]:
        instance = self.get(name)
        if instance is None:
            return None
        instance.endpoint = (endpoint or "").strip() or None
        self._notify()
        return instance

    def ranked_endpoints(self) -> list[dict]:
        """The ranked list the web UI shows, annotated with who uses what."""
        owners: dict[str, list[str]] = {}
        for instance in self.instances:
            target = instance.endpoint or instance.endpoint_used
            if target:
                owners.setdefault(target, []).append(instance.name)
        ranked = []
        for rank, entry in enumerate(self.scanner.live() if self.scanner else [], 1):
            names = owners.get(entry["target"], [])
            ranked.append({**entry, "rank": rank, "owners": names,
                           "owner": ", ".join(names)})
        return ranked

    def identities(self) -> list[dict]:
        """Public identity summary for the account panel. Keys stay on disk."""
        items: list[dict] = []
        for instance in self.instances:
            record = {
                "name": instance.name,
                "port": instance.port,
                "device_id": instance.device_id,
                "account_type": "",
                "address_v4": "",
                "address_v6": "",
                "transport": instance.transport or "masque",
                "path": str(instance.identity_path.name),
            }
            path = instance.identity_path
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001
                    data = {}
                record["device_id"] = data.get("device_id") or instance.device_id
                record["account_type"] = data.get("account_type") or "free"
                record["address_v4"] = data.get("address_v4") or ""
                record["address_v6"] = data.get("address_v6") or ""
                record["transport"] = data.get("transport") or record["transport"]
            items.append(record)
        return items

    def settings(self) -> dict:
        scanner = self.scanner
        return {
            "routing_mode": self.routing_mode,
            "placement_mode": self.placement_mode,
            "routing_modes": {
                key: {"id": key, **meta} for key, meta in ROUTING_MODES.items()
            },
            "placement_modes": {
                key: {"id": key, **meta} for key, meta in PLACEMENT_MODES.items()
            },
            "scan_profiles": {
                key: {"id": key, **meta} for key, meta in SCAN_PROFILES.items()
            },
            "scan_profile": getattr(scanner, "profile", "curated"),
            "scan_family": getattr(scanner, "family", "both"),
            "scan_ports": getattr(scanner, "ports", []),
            "scan_concurrency": getattr(scanner, "concurrency", 60),
            "front_port": self.front_port,
            "base_port": self.base_port,
        }

    def apply_settings(self, data: dict) -> dict:
        changed = False
        routing = data.get("routing_mode")
        if routing is not None:
            if routing not in ROUTING_MODES:
                raise ValueError(f"unknown routing_mode: {routing}")
            self.routing_mode = routing
            changed = True
        placement = data.get("placement_mode")
        if placement is not None:
            if placement not in PLACEMENT_MODES:
                raise ValueError(f"unknown placement_mode: {placement}")
            self.placement_mode = placement
            changed = True
        if self.scanner is not None:
            scan_kwargs = {}
            if "scan_profile" in data:
                scan_kwargs["profile"] = data.get("scan_profile")
            if "scan_family" in data:
                scan_kwargs["family"] = data.get("scan_family")
            if "scan_ports" in data:
                scan_kwargs["ports"] = data.get("scan_ports")
            if "scan_ranges" in data:
                scan_kwargs["ranges"] = data.get("scan_ranges")
            if "scan_concurrency" in data:
                scan_kwargs["concurrency"] = data.get("scan_concurrency")
            if scan_kwargs:
                self.scanner.configure(**scan_kwargs)
                changed = True
        if changed:
            self._notify()
        return self.settings()

    def _running(self) -> list[WarpInstance]:
        return [
            instance
            for instance in self.instances
            if instance.status == "running"
            and instance._stack is not None
            and instance._server is not None
        ]

    async def batch(self, action: str, names: list[str]) -> dict:
        action = (action or "").strip()
        if action not in ("start", "stop", "restart", "remove"):
            raise ValueError(f"unknown batch action: {action}")
        unique: list[str] = []
        seen: set[str] = set()
        for name in names or []:
            name = str(name).strip()
            if name and name not in seen:
                seen.add(name)
                unique.append(name)
        unique = unique[:MAX_BATCH]
        ok: list[str] = []
        missing: list[str] = []
        for name in unique:
            instance = self.get(name)
            if instance is None:
                missing.append(name)
                continue
            if action == "remove":
                self.remove(name)
                ok.append(name)
                continue
            if action == "start":
                asyncio.create_task(instance.start())
            elif action == "stop":
                asyncio.create_task(instance.stop())
            else:
                asyncio.create_task(instance.restart())
            ok.append(name)
        return {"ok": True, "action": action, "names": ok, "missing": missing}

    # ------------------------------------------------------------------ front
    def _pick_least_load(self, running: list[WarpInstance]) -> Optional[WarpInstance]:
        return min(running, key=_load_of) if running else None

    def _pick_round_robin(self, running: list[WarpInstance]) -> Optional[WarpInstance]:
        if not running:
            return None
        self._rr %= len(running)
        chosen = running[self._rr]
        self._rr = (self._rr + 1) % len(running)
        return chosen

    def _pick_failover(self, running: list[WarpInstance]) -> Optional[WarpInstance]:
        return running[0] if running else None

    def _pick_unique_ip(self, running: list[WarpInstance]) -> Optional[WarpInstance]:
        """Spread new connections across distinct endpoint IPs first."""
        if not running:
            return None
        groups: dict[str, list[WarpInstance]] = defaultdict(list)
        for instance in running:
            host = endpoint_host(instance.endpoint_used or instance.endpoint or "") or instance.name
            groups[host].append(instance)
        best_group: Optional[list[WarpInstance]] = None
        best_score = 10**18
        for members in groups.values():
            score = sum(_load_of(item) for item in members)
            if score < best_score:
                best_score = score
                best_group = members
        if not best_group:
            return self._pick_least_load(running)
        return self._pick_least_load(best_group)

    def _pick(self) -> Optional[tuple]:
        """Choose a live instance according to the configured routing mode."""
        running = self._running()
        mode = self.routing_mode
        if mode == "round_robin":
            chosen = self._pick_round_robin(running)
        elif mode == "failover":
            chosen = self._pick_failover(running)
        elif mode == "unique_ip":
            chosen = self._pick_unique_ip(running)
        else:
            chosen = self._pick_least_load(running)
        if chosen is None or chosen._server is None:
            return None
        return chosen._stack, chosen._server.resolver

    async def start_front(self) -> bool:
        """One SOCKS5 listener that spreads connections across live instances."""
        server = Socks5Server(
            None, None, host=self.front_host, port=self.front_port, acquire=self._pick,
        )
        try:
            await server.start()
        except OSError as exc:
            self.front_error = str(exc)
            log.warning("front door %s:%d failed: %s", self.front_host, self.front_port, exc)
            return False
        self._front = server
        self.front_error = ""
        log.info("front door on socks5h://127.0.0.1:%d", server.bound_port)
        return True

    # ------------------------------------------------------------------ life
    async def start_all(self) -> None:
        await asyncio.gather(*(i.start() for i in self.instances))

    async def stop_all(self) -> None:
        await asyncio.gather(*(i.stop() for i in self.instances))

    def status(self) -> dict:
        states = [i.info() for i in self.instances]
        front = self._front
        unique_ips = sorted({
            item["endpoint_host"]
            for item in states
            if item.get("endpoint_host")
        })
        exit_ips = sorted({
            item["exit_ip"]
            for item in states
            if item.get("exit_ip")
        })
        available = self.unique_host_targets()
        return {
            "instances": states,
            "running": sum(1 for s in states if s["status"] == "running"),
            "starting": sum(1 for s in states if s["status"] == "starting"),
            "stopped": sum(1 for s in states if s["status"] == "stopped"),
            "error": sum(1 for s in states if s["status"] == "error"),
            "total": len(states),
            "base_port": self.base_port,
            "tx_bps": sum(item["tx_bps"] for item in states),
            "rx_bps": sum(item["rx_bps"] for item in states),
            "active": sum(item["active"] for item in states),
            "flows": sum(item["flows"] for item in states),
            "unique_ips": unique_ips,
            "unique_ip_count": len(unique_ips),
            "exit_ips": exit_ips,
            "exit_ip_count": len(exit_ips),
            "exit_pool": exit_ips,
            "exit_pool_count": len(exit_ips),
            "exit_target": len(available),
            "routing_mode": self.routing_mode,
            "placement_mode": self.placement_mode,
            "front": {
                "enabled": front is not None,
                "host": self.front_host,
                "port": front.bound_port if front is not None else self.front_port,
                "url": f"socks5h://127.0.0.1:{front.bound_port if front is not None else self.front_port}",
                "active": front.active if front is not None else 0,
                "total": front.total if front is not None else 0,
                "error": self.front_error,
            },
        }

    def start_supervisor(self) -> None:
        if self.supervise and self._supervisor is None:
            self._supervisor = asyncio.create_task(self._supervise(), name="pool-supervisor")

    async def _supervise(self) -> None:
        """Restart dead instances and re-check the running ones.

        Retries back off: hammering fresh connections every 30s while the path
        is filtering new sessions only makes things worse, so the delay grows to
        five minutes before it settles.
        """
        delay = self.supervise_interval
        while not self._closed:
            await asyncio.sleep(delay)
            restarted = False
            for instance in list(self.instances):
                if instance.status in ("error", "stopped"):
                    log.info("[%s] supervisor restarting (%s)", instance.name, instance.error)
                    asyncio.create_task(instance.start())
                    restarted = True
                elif instance.status == "running":
                    if await instance.probe_exit():
                        instance.probe_failures = 0
                        if not instance.exit_ip:
                            await instance.refresh_exit_ip()
                    else:
                        # one missed probe is normal on this path; only a run of
                        # them means the tunnel is really gone.  Restarting on a
                        # single blip tears down a working listener and the
                        # browser then reports a broken proxy.
                        instance.probe_failures += 1
                        if instance.probe_failures >= 3:
                            log.warning("[%s] data plane silent %d times - restarting",
                                        instance.name, instance.probe_failures)
                            asyncio.create_task(instance.restart())
                            instance.probe_failures = 0
                            restarted = True
                        else:
                            log.info("[%s] probe missed (%d/3), keeping it up",
                                     instance.name, instance.probe_failures)
            healthy = self.status()["running"]
            if healthy:
                delay = self.supervise_interval
            elif restarted:
                delay = min(delay * 2, 300.0)
            else:
                delay = min(delay * 2, 300.0)

    async def close(self) -> None:
        self._closed = True
        if self._supervisor is not None:
            self._supervisor.cancel()
            try:
                await self._supervisor
            except (asyncio.CancelledError, Exception):
                pass
            self._supervisor = None
        if self._front is not None:
            try:
                await self._front.stop()
            except Exception:  # noqa: BLE001
                pass
            self._front = None
        await self.stop_all()


def _duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
