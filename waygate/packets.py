"""Raw IPv4 / UDP / TCP packet helpers.

Everything here works on ``bytes`` and plain tuples; there is no socket involved.
The user-space stack in :mod:`waygate.ipstack` builds on top of these helpers.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

TCP_OPT_END = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2
TCP_OPT_WINDOW_SCALE = 3
TCP_OPT_SACK_PERMITTED = 4
TCP_OPT_SACK = 5
TCP_OPT_TIMESTAMPS = 8

IPV4_HEADER_LEN = 20
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8

#: total per-packet overhead of an IP+TCP header (used for MSS math)
_MAX_U16 = 0xFFFF


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) over ``data``."""
    if len(data) & 1:
        data += b"\x00"
    total = 0
    # unpack as native big-endian 16 bit words - much faster than a python loop
    for value in struct.unpack("!%dH" % (len(data) // 2), data):
        total += value
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for value in struct.unpack("!%dH" % (len(data) // 2), data):
        total += value
    return total


def ipv4_pack(
    src: bytes,
    dst: bytes,
    proto: int,
    payload: bytes,
    ttl: int = 64,
    ident: int = 0,
    flags_frag: int = 0x4000,
) -> bytes:
    """Build an IPv4 packet.  ``flags_frag`` defaults to DF."""
    total_len = IPV4_HEADER_LEN + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident & 0xFFFF,
        flags_frag,
        ttl,
        proto,
        0,
        src,
        dst,
    )
    csum = checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


class IPv4Packet(NamedTuple):
    src: bytes
    dst: bytes
    proto: int
    payload: bytes
    header_len: int
    total_len: int
    ident: int
    flags_frag: int
    ttl: int
    header: bytes


def ipv4_parse(pkt: bytes) -> IPv4Packet | None:
    """Parse an IPv4 packet; returns ``None`` when malformed."""
    if len(pkt) < IPV4_HEADER_LEN:
        return None
    vihl = pkt[0]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < IPV4_HEADER_LEN or len(pkt) < ihl:
        return None
    total_len = struct.unpack_from("!H", pkt, 2)[0]
    if total_len > len(pkt):
        total_len = len(pkt)
    ident, flags_frag, ttl, proto = struct.unpack_from("!HHBB", pkt, 4)
    src = pkt[12:16]
    dst = pkt[16:20]
    return IPv4Packet(
        src=src,
        dst=dst,
        proto=proto,
        payload=pkt[ihl:total_len],
        header_len=ihl,
        total_len=total_len,
        ident=ident,
        flags_frag=flags_frag,
        ttl=ttl,
        header=pkt[:ihl],
    )


def _pseudo_header(src_ip: bytes, dst_ip: bytes, proto: int, length: int) -> bytes:
    """TCP/UDP checksum pseudo-header, for either address family.

    IPv4 uses a 4+4 byte pseudo-header with a zero pad byte; IPv6 uses 16+16
    plus a 32 bit length.  Picking the shape from the address length keeps the
    existing IPv4 callers working unchanged.
    """
    if len(src_ip) == 16 or len(dst_ip) == 16:
        return src_ip + dst_ip + struct.pack("!IBBBB", length, 0, 0, 0, proto)
    return src_ip + dst_ip + struct.pack("!BBH", 0, proto, length)


def ipv6_to_bytes(addr: str) -> bytes:
    import ipaddress as _ipaddress

    return _ipaddress.IPv6Address(addr).packed


def bytes_to_ipv6(addr: bytes) -> str:
    import ipaddress as _ipaddress

    return str(_ipaddress.IPv6Address(addr))


class IPv6Packet(NamedTuple):
    src: bytes
    dst: bytes
    next_header: int
    hop_limit: int
    payload: bytes

    @property
    def proto(self) -> int:
        """Same name as IPv4Packet.proto so callers can stay family agnostic."""
        return self.next_header


def ipv6_pack(
    src_ip: bytes,
    dst_ip: bytes,
    next_header: int,
    payload: bytes,
    hop_limit: int = 64,
    traffic_class: int = 0,
    flow_label: int = 0,
) -> bytes:
    """Build an IPv6 packet.  ``src_ip``/``dst_ip`` are 16 byte addresses."""
    version_tc_fl = (6 << 28) | ((traffic_class & 0xFF) << 20) | (flow_label & 0xFFFFF)
    header = struct.pack(
        "!IHBB", version_tc_fl, len(payload), next_header, hop_limit
    ) + src_ip + dst_ip
    return header + payload


def ipv6_parse(pkt: bytes) -> IPv6Packet | None:
    """Parse an IPv6 packet; returns None for anything that is not IPv6."""
    if len(pkt) < 40 or (pkt[0] >> 4) != 6:
        return None
    version_tc_fl, payload_len, next_header, hop_limit = struct.unpack("!IHBB", pkt[:8])
    del version_tc_fl
    end = 40 + payload_len
    if payload_len == 0 or end > len(pkt):
        end = len(pkt)
    return IPv6Packet(
        src=pkt[8:24],
        dst=pkt[24:40],
        next_header=next_header,
        hop_limit=hop_limit,
        payload=pkt[40:end],
    )


def udp_pack(sport: int, dport: int, payload: bytes, src_ip: bytes, dst_ip: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, UDP_HEADER_LEN + len(payload), 0)
    pseudo = _pseudo_header(src_ip, dst_ip, IPPROTO_UDP, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    if csum == 0:
        csum = 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


class UdpPacket(NamedTuple):
    sport: int
    dport: int
    payload: bytes
    checksum: int


def udp_parse(payload: bytes) -> UdpPacket | None:
    if len(payload) < UDP_HEADER_LEN:
        return None
    sport, dport, length, csum = struct.unpack_from("!HHHH", payload, 0)
    body = payload[UDP_HEADER_LEN:length] if 0 < length <= len(payload) else payload[UDP_HEADER_LEN:]
    return UdpPacket(sport, dport, body, csum)


class TcpSegment(NamedTuple):
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    options: bytes
    urg: int
    header_len: int


def tcp_parse(payload: bytes) -> TcpSegment | None:
    if len(payload) < TCP_HEADER_LEN:
        return None
    sport, dport, seq, ack, offset_flags, window, csum, urg = struct.unpack_from(
        "!HHIIHHHH", payload, 0
    )
    header_len = (offset_flags >> 12) * 4
    if header_len < TCP_HEADER_LEN or len(payload) < header_len:
        return None
    return TcpSegment(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=offset_flags & 0x01FF,
        window=window,
        payload=payload[header_len:],
        options=payload[TCP_HEADER_LEN:header_len],
        urg=urg,
        header_len=header_len,
    )


def tcp_pack(
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    window: int,
    src_ip: bytes,
    dst_ip: bytes,
    payload: bytes = b"",
    options: bytes = b"",
) -> bytes:
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    offset = (TCP_HEADER_LEN + len(options)) // 4
    header = struct.pack(
        "!HHIIHHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        (offset << 12) | (flags & 0x01FF),
        window & 0xFFFF,
        0,
        0,
    )
    segment = header + options + payload
    pseudo = _pseudo_header(src_ip, dst_ip, IPPROTO_TCP, len(segment))
    csum = checksum(pseudo + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def parse_tcp_options(options: bytes) -> dict:
    """Decode the options we care about (MSS / window scale / SACK permitted)."""
    out: dict = {}
    i = 0
    end = len(options)
    while i < end:
        kind = options[i]
        if kind == TCP_OPT_END:
            break
        if kind == TCP_OPT_NOP:
            i += 1
            continue
        if i + 1 >= end:
            break
        length = options[i + 1]
        if length < 2 or i + length > end:
            break
        body = options[i + 2 : i + length]
        if kind == TCP_OPT_MSS and len(body) == 2:
            out["mss"] = struct.unpack("!H", body)[0]
        elif kind == TCP_OPT_WINDOW_SCALE and len(body) == 1:
            out["wscale"] = body[0]
        elif kind == TCP_OPT_SACK_PERMITTED:
            out["sack_permitted"] = True
        i += length
    return out


def build_tcp_options(mss: int | None = None, wscale: int | None = None) -> bytes:
    opts = b""
    if mss is not None:
        opts += struct.pack("!BBH", TCP_OPT_MSS, 4, mss)
    if wscale is not None:
        opts += struct.pack("!BBB", TCP_OPT_WINDOW_SCALE, 3, wscale)
    return opts


def ipv4_to_bytes(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def bytes_to_ipv4(addr: bytes) -> str:
    return ".".join(str(byte) for byte in addr)
