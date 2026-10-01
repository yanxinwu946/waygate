"""A tiny DNS client that resolves names *inside* the WARP tunnel.

Leaking DNS to the local resolver would defeat the point of the proxy (and on
censored networks it often returns poisoned answers), so queries are sent to
Cloudflare's resolver through the tunnel itself, with a TCP fallback when a
response comes back truncated.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from typing import Optional, Sequence

log = logging.getLogger("waygate.dns")

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
CLASS_IN = 1

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsError(Exception):
    pass


def build_query(name: str, qtype: int = QTYPE_A, qid: Optional[int] = None) -> tuple[bytes, int]:
    qid = qid if qid is not None else struct.unpack("<H", os.urandom(2))[0]
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD set
    labels = b"".join(bytes((len(part),)) + part.encode("idna") for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", qtype, CLASS_IN)
    return header + question, qid


def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name."""
    labels: list[str] = []
    jumps = 0
    position = offset
    while True:
        if position >= len(data):
            raise DnsError("truncated name")
        length = data[position]
        if length == 0:
            position += 1
            break
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(data):
                raise DnsError("truncated compression pointer")
            pointer = struct.unpack_from("!H", data, position)[0] & 0x3FFF
            if jumps == 0:
                offset = position + 2
            jumps += 1
            if jumps > 8:
                raise DnsError("compression loop")
            position = pointer
            continue
        labels.append(data[position + 1 : position + 1 + length].decode("latin-1"))
        position += 1 + length
    return ".".join(labels), (offset if jumps else position)


def parse_response(data: bytes) -> dict:
    if len(data) < 12:
        raise DnsError("short response")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    result = {
        "id": qid,
        "rcode": flags & 0x0F,
        "truncated": bool(flags & 0x0200),
        "answers": [],
        "authorities": [],
    }
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4
    for section, count in (("answers", ancount), ("authorities", nscount)):
        for _ in range(count):
            name, offset = parse_name(data, offset)
            if offset + 10 > len(data):
                raise DnsError("truncated record")
            rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            entry = {"name": name, "type": rtype, "class": rclass, "ttl": ttl}
            if rtype == QTYPE_A and len(rdata) == 4:
                entry["address"] = ".".join(str(byte) for byte in rdata)
            elif rtype == QTYPE_CNAME:
                entry["target"], _ = parse_name(data, offset - rdlength)
            elif rtype == QTYPE_AAAA and len(rdata) == 16:
                entry["address"] = ":".join(f"{rdata[i] << 8 | rdata[i+1]:x}" for i in range(0, 16, 2))
            result[section].append(entry)
    return result


class DnsClient:
    """Resolves A records through the tunnel (UDP first, TCP on truncation)."""

    def __init__(
        self,
        stack,
        servers: Sequence[str] = ("1.1.1.1", "1.0.0.1"),
        timeout: float = 3.0,
        cache_ttl: float = 120.0,
    ) -> None:
        self.stack = stack
        self.servers = list(servers)
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, list[str]]] = {}
        self.stats = {"queries": 0, "cache_hits": 0, "failures": 0, "tcp_fallbacks": 0}

    # ------------------------------------------------------------------ api
    def _recall(self, key: str) -> Optional[list[str]]:
        entry = self._cache.get(key)
        if entry is not None and entry[0] > time.monotonic():
            self.stats["cache_hits"] += 1
            return entry[1]
        return None

    def _remember(self, key: str, addresses: list[str]) -> list[str]:
        if addresses:
            now = time.monotonic()
            if len(self._cache) > 1024:
                self._cache = {
                    item: value for item, value in self._cache.items() if value[0] > now
                }
            self._cache[key] = (now + self.cache_ttl, addresses)
        return addresses

    async def resolve(self, name: str) -> list[str]:
        """Return the IPv4 addresses of ``name`` (cached)."""
        name = name.rstrip(".")
        try:
            return [str(__import__("ipaddress").ip_address(name))]
        except ValueError:
            pass
        hit = self._recall("A:" + name)
        if hit is not None:
            return hit
        return self._remember("A:" + name, await self._resolve_uncached(name))

    async def resolve_aaaa(self, name: str) -> list[str]:
        """AAAA records (inner IPv6), cached the same way as A records."""
        name = name.rstrip(".")
        hit = self._recall("AAAA:" + name)
        if hit is not None:
            return hit
        try:
            addresses = await self._resolve_uncached(name, QTYPE_AAAA)
        except Exception as exc:  # noqa: BLE001
            log.debug("AAAA lookup for %s failed: %s", name, exc)
            return []
        return self._remember("AAAA:" + name, addresses)

    async def _resolve_uncached(self, name: str, qtype: int = QTYPE_A) -> list[str]:
        query, qid = build_query(name, qtype=qtype)
        last_error: Optional[Exception] = None
        for server in self.servers:
            for attempt in range(2):
                self.stats["queries"] += 1
                try:
                    response = await self.stack.udp_exchange(
                        server, 53, query, self.timeout
                    )
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    response = None
                if response is None:
                    continue
                try:
                    parsed = parse_response(response)
                except DnsError as exc:
                    last_error = exc
                    continue
                if parsed["id"] != qid:
                    last_error = DnsError("response id mismatch")
                    continue
                if parsed["truncated"]:
                    self.stats["tcp_fallbacks"] += 1
                    response = await self._query_tcp(server, query)
                    if response is None:
                        continue
                    parsed = parse_response(response)
                if parsed["rcode"] != 0:
                    raise DnsError(
                        f"{name}: {RCODE_NAMES.get(parsed['rcode'], parsed['rcode'])}"
                    )
                addresses = [
                    entry["address"]
                    for entry in parsed["answers"]
                    if entry["type"] == qtype and "address" in entry
                ]
                if addresses:
                    log.debug("resolved %s -> %s (via %s)", name, addresses, server)
                    return addresses
                # CNAME chains: query the target once
                for entry in parsed["answers"]:
                    if entry["type"] == QTYPE_CNAME and entry.get("target"):
                        return await self._resolve_uncached(entry["target"])
                last_error = DnsError(f"{name}: no A records")
        self.stats["failures"] += 1
        if last_error is not None:
            log.debug("DNS lookup for %s failed: %s", name, last_error)
        return []

    async def _query_tcp(self, server: str, query: bytes) -> Optional[bytes]:
        connection = None
        try:
            connection = await self.stack.tcp_connect(server, 53, timeout=self.timeout + 2)
            await connection.send(struct.pack("!H", len(query)) + query)
            header = await connection.recv(2)
            if len(header) < 2:
                return None
            length = struct.unpack("!H", header)[0]
            body = b""
            while len(body) < length:
                chunk = await connection.recv(length - len(body))
                if not chunk:
                    break
                body += chunk
            return body
        except Exception as exc:  # noqa: BLE001
            log.debug("DNS over TCP to %s failed: %s", server, exc)
            return None
        finally:
            if connection is not None:
                await connection.close()
