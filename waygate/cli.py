"""Command line interface: ``python -m waygate`` (or the ``waygate`` script)."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from . import __version__
from .dns import DnsClient
from .ipstack import IPStack
from .masque import MasqueTunnel
from .socks5 import Socks5Server
from .warp import (
    ENDPOINT_PREFIXES_V4,
    ENDPOINT_PREFIXES_V6,
    MASQUE_ENDPOINTS_V4,
    MASQUE_ENDPOINTS_V6,
    MASQUE_PORT,
    MASQUE_PORTS,
    MASQUE_SNI,
    WarpIdentity,
    load_or_register,
    load_or_register_masque,
    masque_identity_path,
    register,
    update_license,
)
from .wireguard import PERSISTENT_KEEPALIVE, WireGuardTunnel

log = logging.getLogger("waygate")

def _default_data_dir() -> Path:
    env = os.environ.get("WAYGATE_HOME") or os.environ.get("WARP2S5_HOME")
    if env:
        return Path(env)
    current = Path.home() / ".waygate"
    previous = Path.home() / ".warp2s5"
    if current.exists() or not previous.exists():
        return current
    return previous


DEFAULT_DATA_DIR = _default_data_dir()


# --------------------------------------------------------------------- helpers
def host_of(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        return endpoint[1 : endpoint.index("]")]
    if endpoint.count(":") == 1:
        return endpoint.split(":")[0]
    return endpoint


def parse_host_port(value: str, default_port: int = 2408) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port = int(rest.lstrip(":") or default_port)
        return host, port
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, int(port or default_port)
    return value, default_port


def candidate_endpoints(
    identity: WarpIdentity,
    families: tuple[str, ...] = ("v4", "v6"),
    explicit: Optional[list[str]] = None,
    ports: Optional[list[int]] = None,
    max_ips: int = 4,
    max_ports: int = 3,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Build the (v4, v6) endpoint candidate lists used for the handshake race."""
    port_list = list(ports or identity.ports or [2408, 500, 1701, 4500])
    port_list = port_list[:max_ports] if not ports else port_list

    if explicit:
        v4: list[tuple[str, int]] = []
        v6: list[tuple[str, int]] = []
        for item in explicit:
            host, port = parse_host_port(item, port_list[0])
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                log.warning("ignoring non-literal endpoint %s", item)
                continue
            (v4 if address.version == 4 else v6).append((host, port))
        return (v4 if "v4" in families else []), (v6 if "v6" in families else [])

    hosts_v4: list[str] = []
    hosts_v6: list[str] = []
    if identity.endpoint_v4:
        hosts_v4.append(host_of(identity.endpoint_v4))
    hosts_v4.extend(prefix + "1" for prefix in ENDPOINT_PREFIXES_V4)
    hosts_v4.append("162.159.192.8")
    if identity.endpoint_v6:
        hosts_v6.append(host_of(identity.endpoint_v6))
    hosts_v6.extend(prefix + "1" for prefix in ENDPOINT_PREFIXES_V6)

    def dedupe(items: list[str]) -> list[str]:
        seen: dict[str, None] = {}
        for item in items:
            seen.setdefault(item, None)
        return list(seen)

    v4 = [(ip, port) for ip in dedupe(hosts_v4)[:max_ips] for port in port_list]
    v6 = [(ip, port) for ip in dedupe(hosts_v6)[:2] for port in port_list]
    return (v4 if "v4" in families else []), (v6 if "v6" in families else [])


def setup_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity < 0 else logging.INFO if verbosity == 0 else logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


async def _masque_carries_traffic(
    tunnel, identity: WarpIdentity, args: argparse.Namespace, timeout: float = 6.0
) -> bool:
    """Verify the MASQUE *data* plane, not just the CONNECT-IP handshake.

    On censored paths the handshake (and even the ``:status 200`` of the
    CONNECT-IP request) succeeds while every single packet is then dropped, so
    the only trustworthy check is: send a DNS query and see whether an answer
    comes back.
    """
    stack = IPStack(tunnel, identity.address_v4,
                        local_ip_v6=identity.address_v6, mtu=args.mtu)
    stack.start()
    try:
        resolver = DnsClient(stack, [args.dns.split(",")[0]], timeout=max(2.0, timeout / 2))
        addresses = await asyncio.wait_for(resolver.resolve("www.cloudflare.com"), timeout + 3)
        if addresses:
            log.info("MASQUE data plane verified: www.cloudflare.com -> %s", addresses[0])
            # hand the *verified* stack to the caller: rebuilding a second stack
            # leaves the fresh QUIC flow idle, and on a filtered network that
            # flow is throttled by the time real traffic arrives
            tunnel.verify_stack = stack  # type: ignore[attr-defined]
            return True
        await stack.stop()
        return False
    except Exception as exc:  # noqa: BLE001
        log.debug("MASQUE data plane check failed: %s", exc)
        await stack.stop()
        return False


async def open_tunnel(args: argparse.Namespace):
    """Bring a tunnel up, honouring ``--transport`` (auto tries MASQUE first).

    Returns ``(tunnel, identity, transport_name)`` or raises the last error.
    """
    transports = ["masque", "wireguard"] if args.transport == "auto" else [args.transport]
    per_transport_timeout = min(args.timeout, 12.0) if len(transports) > 1 else args.timeout
    last_error: Optional[BaseException] = None

    for transport in transports:
        if transport == "masque":
            identity = await load_or_register_masque(
                masque_identity_path(args.identity), force=args.register
            )
            api_endpoint = (identity.endpoint_v4 or "").split(":")[0]
            hosts = [h for h in (args.masque_endpoint, api_endpoint,
                                 *MASQUE_ENDPOINTS_V6, *MASQUE_ENDPOINTS_V4) if h]
            ports = [args.masque_port]
            if args.masque_port == MASQUE_PORT:
                ports += [p for p in MASQUE_PORTS if p != MASQUE_PORT]
            candidates: list[tuple[str, int]] = []
            for host in hosts:
                for port in ports:
                    if (host, port) not in candidates:
                        candidates.append((host, port))
            for host, port in candidates:
                log.info("connecting to WARP over MASQUE (%s:%d) ...", host, port)
                tunnel = MasqueTunnel(
                    host,
                    port,
                    certificate_pem=identity.ec_certificate,
                    private_key_pem=identity.ec_private_key,
                    sni=identity.sni or MASQUE_SNI,
                    keepalive=args.keepalive,
                    mtu=args.mtu,
                )
                try:
                    await tunnel.start()
                    await tunnel.wait_ready(per_transport_timeout)
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    log.debug("MASQUE endpoint %s:%d failed: %s", host, port, exc)
                    await tunnel.stop()
                    continue
                # a CONNECT-IP "200" is not enough: censored paths happily
                # complete the handshake and then drop every packet, so make sure
                # the data plane actually carries traffic before declaring success
                if await _masque_carries_traffic(tunnel, identity, args):
                    return tunnel, identity, "masque"
                last_error = TimeoutError(
                    f"{host}:{port} accepted the tunnel but no packet came back"
                )
                await tunnel.stop()
        else:
            identity = await load_or_register(args.identity, force=args.register)
            v4, v6 = candidate_endpoints(
                identity, args.family, args.endpoint, args.port, max_ips=args.max_ips
            )
            log.info("connecting to WARP over WireGuard (%d endpoints) ...", len(v4) + len(v6))
            tunnel = WireGuardTunnel(
                identity.private_key,
                identity.peer_public_key,
                identity.reserved,
                keepalive=args.keepalive,
                mtu=args.mtu,
            )
            await tunnel.start(v4, v6)
            try:
                await tunnel.wait_ready(per_transport_timeout)
                return tunnel, identity, "wireguard"
            except TimeoutError as exc:
                last_error = exc
                await tunnel.stop()
    raise last_error if last_error is not None else RuntimeError("no transport available")


def _hint(transport: str) -> str:
    return (
        "WireGuard (UDP/2408) is blocked on many censored networks; "
        "MASQUE (QUIC/UDP/443) usually gets through - try --transport masque."
        if transport == "wireguard"
        else "the QUIC path to Cloudflare seems to be filtered; try --transport wireguard "
        "or another network."
    )


async def fetch_through_tunnel(
    stack: IPStack, host: str, port: int, request: str, timeout: float = 15.0
) -> bytes:
    """Tiny HTTP/1.1 helper used by --check (plain HTTP on port 80)."""
    import re

    connection = await stack.tcp_connect(host, port, timeout=timeout)
    try:
        await connection.send(request.encode())
        chunks = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = await asyncio.wait_for(
                    connection.recv(65536), max(0.1, deadline - time.monotonic())
                )
            except asyncio.TimeoutError:
                break
            if not data:
                break
            chunks += data
            header_end = chunks.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            header = chunks[:header_end].decode("latin-1").lower()
            length = re.search(r"content-length:\s*(\d+)", header)
            if length and len(chunks) - header_end - 4 >= int(length.group(1)):
                break
            if "transfer-encoding: chunked" in header and chunks.endswith(b"0\r\n\r\n"):
                break
        log.debug(
            "http fetch %s:%d -> %d bytes (%s)",
            host,
            port,
            len(chunks),
            connection.diagnostics(),
        )
        return bytes(chunks)
    finally:
        await connection.close()


# ------------------------------------------------------------------- commands
async def command_check(args: argparse.Namespace) -> int:
    print("=" * 72)
    print("Waygate self test")
    print("=" * 72)
    started = time.monotonic()
    print("tunnel        : ", end="", flush=True)
    try:
        tunnel, identity, transport = await open_tunnel(args)
    except Exception as exc:  # noqa: BLE001
        print("FAILED")
        print(f"  {type(exc).__name__}: {exc}")
        print(f"  hint: {_hint('masque' if args.transport == 'masque' else 'wireguard')}")
        return 1
    print(
        f"{transport} up in {time.monotonic()-started:.2f}s via {tunnel.peer_endpoint}"
    )
    print(f"identity      : device {identity.device_id} ({identity.account_type or 'free'})")
    print(f"tunnel address: {identity.address_v4} (v6 {identity.address_v6})")
    stack = IPStack(tunnel, identity.address_v4,
                        local_ip_v6=identity.address_v6, mtu=args.mtu)
    stack.start()

    resolver = DnsClient(stack, args.dns.split(","), timeout=args.dns_timeout)
    print("dns           : ", end="", flush=True)
    addresses = await resolver.resolve("www.cloudflare.com")
    if not addresses:
        print("FAILED")
        await stack.stop()
        await tunnel.stop()
        return 1
    print(f"ok  www.cloudflare.com -> {addresses[0]}")

    print("http via warp : ", end="", flush=True)
    try:
        response = await fetch_through_tunnel(
            stack, addresses[0], 80, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED ({type(exc).__name__}: {exc})")
        await stack.stop()
        await tunnel.stop()
        return 1
    text = response.decode("utf-8", "replace")
    warp_line = next((line for line in text.splitlines() if line.startswith("warp=")), None)
    ip_line = next((line for line in text.splitlines() if line.startswith("ip=")), None)
    if not text.startswith("HTTP/"):
        print("FAILED (no HTTP response)")
        print(text[:400])
        await stack.stop()
        await tunnel.stop()
        return 1
    print("ok")
    print(f"  {ip_line or 'ip=?'}   {warp_line or 'warp=?'}")
    if warp_line and warp_line.strip() in ("warp=on", "warp=plus"):
        print("  => traffic is indeed leaving through Cloudflare WARP")
    print(f"tunnel stats  : {tunnel.describe()}")
    print(f"stack stats   : {stack.describe()} dns={resolver.stats}")
    await stack.stop()
    await tunnel.stop()
    return 0


async def command_serve(args: argparse.Namespace) -> int:
    if args.print_config:
        identity = await load_or_register(args.identity, force=args.register)
        print(identity.wg_quick_config())
        return 0

    try:
        tunnel, identity, transport = await open_tunnel(args)
    except Exception as exc:  # noqa: BLE001
        log.error("could not bring the WARP tunnel up: %s: %s", type(exc).__name__, exc)
        log.error("%s", _hint("masque" if args.transport == "masque" else "wireguard"))
        return 1

    if args.license and identity.account_type != "plus":
        try:
            await update_license(identity, args.license)
            identity.save(
                args.identity if transport == "wireguard" else masque_identity_path(args.identity)
            )
            log.info("WARP+ license applied")
        except Exception as exc:  # noqa: BLE001
            log.warning("could not apply the license key: %s", exc)

    stack = getattr(tunnel, "verify_stack", None)
    if stack is None:
        stack = IPStack(tunnel, identity.address_v4,
                        local_ip_v6=identity.address_v6, mtu=args.mtu)
        stack.start()
    else:
        log.debug("reusing the verified stack (keeps the QUIC flow warm)")
    # when the MASQUE flow goes stale and is replaced, stalled TCP connections
    # must retransmit on the new flow immediately
    if hasattr(tunnel, "on_reconnect"):
        tunnel.on_reconnect = stack.poke_all  # type: ignore[attr-defined]
    resolver = DnsClient(stack, args.dns.split(","), timeout=args.dns_timeout)
    server = Socks5Server(
        stack,
        resolver,
        host=args.bind_host,
        port=args.bind_port,
        username=args.username,
        password=args.password,
    )
    await server.start()

    print()
    print(f"  Waygate {__version__} - Cloudflare WARP -> SOCKS5")
    print(f"  identity : {identity.device_id} ({identity.account_type or 'free'})  {identity.address_v4}")
    print(f"  transport: {transport}   endpoint {tunnel.peer_endpoint} from {tunnel.local_endpoint}")
    print(f"  socks5   : socks5://{args.bind_host}:{server.bound_port}"
          + (f"  user={args.username}" if args.username else ""))
    print(f"  dns      : {args.dns} (queried inside the tunnel)")
    print()
    print(f"  curl -x socks5h://{args.bind_host}:{server.bound_port} https://www.cloudflare.com/cdn-cgi/trace")
    print()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):  # Windows
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop_event.set))

    async def reporter() -> None:
        while True:
            await asyncio.sleep(args.stats_interval)
            log.info(
                "stats: %s | %s | socks5 active=%d total=%d",
                tunnel.describe(),
                stack.describe(),
                server.active,
                server.total,
            )

    reporter_task = asyncio.create_task(reporter()) if args.stats_interval else None
    try:
        await stop_event.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        log.info("shutting down ...")
        if reporter_task is not None:
            reporter_task.cancel()
        await server.stop()
        await stack.stop()
        await tunnel.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="waygate",
        description="Cloudflare WARP client (pure python) that exposes a SOCKS5 proxy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"waygate {__version__}")
    parser.add_argument("-b", "--bind", default="127.0.0.1:1080",
                        help="SOCKS5 listen address host:port")
    parser.add_argument("--identity", default=str(DEFAULT_DATA_DIR / "identity.json"),
                        help="where the WARP device identity is stored")
    parser.add_argument("--register", action="store_true",
                        help="register a new WARP device even if an identity exists")
    parser.add_argument("--license", help="WARP+ / Zero Trust license key to apply")
    parser.add_argument("--print-config", action="store_true",
                        help="print a wg-quick style config and exit")
    parser.add_argument("--endpoint", action="append", metavar="IP[:PORT]",
                        help="use this WARP endpoint (repeatable, skips the built-in list)")
    parser.add_argument("--port", action="append", type=int, metavar="PORT",
                        help="endpoint port to try (repeatable)")
    parser.add_argument("--family", choices=("v4", "v6", "both"), default="both",
                        help="which endpoint address families to race")
    parser.add_argument("--transport", choices=("auto", "wireguard", "masque"), default="auto",
                        help="tunnel transport: auto tries MASQUE (QUIC/443) first, then WireGuard")
    parser.add_argument("--masque-endpoint", metavar="IP",
                        help="override the MASQUE anycast address (default: from the API)")
    parser.add_argument("--masque-port", type=int, default=MASQUE_PORT,
                        help="MASQUE UDP port")
    parser.add_argument("--max-ips", type=int, default=4,
                        help="how many anycast addresses to probe per family")
    parser.add_argument("--dns", default="1.1.1.1,1.0.0.1",
                        help="resolvers used *inside* the tunnel")
    parser.add_argument("--dns-timeout", type=float, default=7.0, help="DNS timeout in seconds")
    parser.add_argument("--mtu", type=int, default=1280, help="tunnel MTU")
    parser.add_argument("--keepalive", type=float, default=PERSISTENT_KEEPALIVE,
                        help="persistent keepalive interval in seconds")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="how long to wait for the WARP handshake")
    parser.add_argument("--username", help="require SOCKS5 username/password auth")
    parser.add_argument("--password", help="SOCKS5 password")
    parser.add_argument("--stats-interval", type=float, default=0.0,
                        help="log statistics every N seconds (0 disables)")
    parser.add_argument("--check", action="store_true",
                        help="run a self test (handshake, DNS, HTTP through WARP) and exit")

    multi = parser.add_argument_group("multi-instance / web UI")
    multi.add_argument("--webui", action="store_true",
                       help="run a pool of WARP instances with a web dashboard")
    multi.add_argument("--webui-bind", default="127.0.0.1:8080", metavar="HOST:PORT",
                       help="web dashboard listen address")
    multi.add_argument("--instances", type=int, default=None,
                       help="how many WARP instances to run (default: remembered, else 3)")
    multi.add_argument("--base-port", type=int, default=1080,
                       help="first SOCKS5 port; instance N uses base+N-1")
    multi.add_argument("--front-port", type=int, default=0,
                       help="balancing SOCKS5 port (0 picks the port just below --base-port)")

    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-q", "--quiet", action="count", default=0)
    return parser


async def command_multi(args: argparse.Namespace) -> int:
    """Run a pool of independent WARP instances behind a web UI."""
    from .multi import WarpPool
    from .scan import EndpointScanner
    from .webui import WebUI

    if args.webui_bind.count(":") != 1:
        print(f"invalid --webui-bind value: {args.webui_bind!r} (expected host:port)",
              file=sys.stderr)
        return 2
    webui_host, webui_port = args.webui_bind.split(":")
    webui_port = int(webui_port)

    state_path = DEFAULT_DATA_DIR / "pool.json"
    saved, saved_settings = _load_state(state_path)
    holder: dict = {}

    def _persist() -> None:
        current = holder.get("pool")
        if current is not None:
            _save_pool(state_path, current)

    if args.instances is not None:
        count = args.instances
    elif saved:
        count = len(saved)
    else:
        try:
            count = int(json.loads(state_path.read_text())["count"])
        except Exception:  # noqa: BLE001
            count = 3

    # a dedicated device for scanning keeps the probe traffic away from the
    # instances that are actually serving
    scanner = EndpointScanner(DEFAULT_DATA_DIR / "identity-masque-scan.json")
    if saved_settings:
        scanner.configure(
            profile=saved_settings.get("scan_profile"),
            family=saved_settings.get("scan_family"),
            ports=saved_settings.get("scan_ports"),
            concurrency=saved_settings.get("scan_concurrency"),
        )
    pool = WarpPool(
        DEFAULT_DATA_DIR,
        count=count,
        base_port=args.base_port,
        mtu=args.mtu,
        dns=tuple(args.dns.split(",")),
        scanner=scanner,
        saved=saved,
        on_change=_persist,
        front_port=args.front_port or None,
        routing_mode=saved_settings.get("routing_mode") or "least_load",
        placement_mode=saved_settings.get("placement_mode") or "unique_ip",
    )
    holder["pool"] = pool
    # --instances only changes *how many* instances there are; the saved names,
    # ports and pinned endpoints are always kept, otherwise restarting with the
    # same flag would silently undo every edit made in the web UI
    while len(pool.instances) > count:
        pool.remove(pool.instances[-1].name)
    while len(pool.instances) < count:
        pool.add()
    ui = WebUI(pool, webui_host, webui_port, scanner=scanner)
    _save_pool(state_path, pool)

    await pool.start_front()
    await ui.start()
    front_url = f"socks5h://127.0.0.1:{pool.front_port}"
    print()
    print(f"  Waygate {__version__} - multi-instance WARP pool")
    print(f"  web ui   : http://{webui_host}:{ui.bound_port if ui.bound_port != webui_port else webui_port}")
    if pool.front_error:
        print(f"  front    : {front_url} FAILED ({pool.front_error})")
    else:
        print(f"  front    : {front_url}  ({pool.routing_mode})")
    print(f"  instances: {len(pool.instances)} (SOCKS5 ports {args.base_port}.."
          f"{args.base_port + len(pool.instances) - 1})")
    for instance in pool.instances:
        print(f"    {instance.name}: socks5h://127.0.0.1:{instance.port}")
    print()
    pool.start_supervisor()
    asyncio.create_task(pool.start_all())

    try:
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await ui.stop()
        await pool.close()
    return 0


def _load_pool(path: Path) -> Optional[list]:
    """Read the saved instance list (name, port, pinned endpoint)."""
    instances, _settings = _load_state(path)
    return instances


def _load_state(path: Path) -> tuple[Optional[list], dict]:
    """Read instances and console settings from pool.json."""
    try:
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return None, {}
    instances = data.get("instances")
    if not (isinstance(instances, list) and instances):
        instances = None
    settings = data.get("settings") if isinstance(data.get("settings"), dict) else {}
    return instances, settings


def _save_pool(path: Path, pool) -> None:  # type: ignore[no-untyped-def]
    """Persist the whole instance list, not just how many there are.

    Saving only a count meant deletions came back after a restart and every
    pinned endpoint was lost.
    """
    try:
        if hasattr(pool, "export_state"):
            payload = pool.export_state()
        else:
            snapshot = pool.snapshot() if hasattr(pool, "snapshot") else []
            payload = {"count": len(pool.instances), "instances": snapshot}
        path.write_text(json.dumps(payload, indent=2))
    except Exception:  # noqa: BLE001
        pass


async def async_main(args: argparse.Namespace) -> int:
    if args.bind.count(":") != 1:
        print(f"invalid --bind value: {args.bind!r} (expected host:port)", file=sys.stderr)
        return 2
    args.bind_host, args.bind_port = args.bind.split(":")
    args.bind_port = int(args.bind_port)
    args.family = ("v4", "v6") if args.family == "both" else (args.family,)

    if args.webui:
        return await command_multi(args)
    if args.check:
        return await command_check(args)
    return await command_serve(args)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose - args.quiet)
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        log.error("%s: %s", type(exc).__name__, exc)
        if args.verbose:
            log.exception("traceback")
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
