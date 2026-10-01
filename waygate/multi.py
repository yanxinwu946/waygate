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
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .dns import DnsClient
from .ipstack import IPStack
from .masque import MasqueTunnel
from .racing import dns_probe_packet
from .scan import candidate_endpoints
from .socks5 import Socks5Server
from .warp import (
    MASQUE_SNI,
    load_or_register_masque,
)

log = logging.getLogger("waygate.pool")

DEFAULT_DNS = ("1.1.1.1", "1.0.0.1")


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
            "endpoint": self.endpoint_used,
            "transport": self.transport or "-",
            "loss": round(self.loss * 100, 1),
            "latency": round(self.latency * 1000),
            "exit_ip": self.exit_ip,
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
            self.endpoint_used = f"{host}:{port}"
            self.exit_ip = ""
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
        # no endpoint given: take the best ranking one, so a new instance lands
        # on the fastest address (several instances may share it)
        endpoint = endpoint or self.best_endpoint()
        instance = self._make_instance(name, self.base_port + index - 1, endpoint)
        self.instances.append(instance)
        self._notify()
        return instance

    def snapshot(self) -> list[dict]:
        """Everything needed to rebuild the pool exactly as it is now."""
        return [
            {"name": i.name, "port": i.port, "endpoint": i.endpoint or ""}
            for i in self.instances
        ]

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
        if self.scanner is None:
            return None
        ranked = self.scanner.live()
        return ranked[0]["target"] if ranked else None

    def ranked_endpoints(self) -> list[dict]:
        """The ranked list the web UI shows, annotated with who uses what."""
        owners: dict[str, list[str]] = {}
        for instance in self.instances:
            if instance.endpoint:
                owners.setdefault(instance.endpoint, []).append(instance.name)
        ranked = []
        for rank, entry in enumerate(self.scanner.live() if self.scanner else [], 1):
            names = owners.get(entry["target"], [])
            ranked.append({**entry, "rank": rank, "owners": names,
                           "owner": ", ".join(names)})
        return ranked

    # ------------------------------------------------------------------ front
    def _pick(self) -> Optional[tuple]:
        """Least-loaded running instance, measured by live TCP flows."""
        best: Optional[WarpInstance] = None
        best_load = 10**9
        for instance in self.instances:
            stack = instance._stack
            if instance.status != "running" or stack is None or instance._server is None:
                continue
            load = len(stack.tcp)
            if load < best_load:
                best = instance
                best_load = load
        if best is None or best._server is None:
            return None
        return best._stack, best._server.resolver

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
        return {
            "instances": states,
            "running": sum(1 for s in states if s["status"] == "running"),
            "total": len(states),
            "base_port": self.base_port,
            "tx_bps": sum(item["tx_bps"] for item in states),
            "rx_bps": sum(item["rx_bps"] for item in states),
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
