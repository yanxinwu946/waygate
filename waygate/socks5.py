"""An asyncio SOCKS5 server (RFC 1928 / RFC 1929) bridged onto the IP stack.

Only ``CONNECT`` is implemented; ``UDP ASSOCIATE`` is answered with "command not
supported" which makes clients such as browsers fall back to TCP.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
from typing import Callable, Optional

from .dns import DnsClient, DnsError

log = logging.getLogger("waygate.socks5")

SOCKS_VERSION = 5

METHOD_NO_AUTH = 0x00
METHOD_USER_PASS = 0x02
METHOD_NONE = 0xFF

CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_NOT_SUPPORTED = 0x08


class Socks5Server:
    def __init__(
        self,
        stack,
        resolver: DnsClient,
        host: str = "127.0.0.1",
        port: int = 1080,
        username: Optional[str] = None,
        password: Optional[str] = None,
        connect_timeout: float = 15.0,
        acquire: Optional[Callable[[], Optional[tuple]]] = None,
    ) -> None:
        self.stack = stack
        self.resolver = resolver
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        # When set, each CONNECT borrows a (stack, resolver) pair. Used by the
        # front door so one listener can spread load across live instances.
        self.acquire = acquire
        self._server: Optional[asyncio.AbstractServer] = None
        self.active = 0
        self.total = 0

    @property
    def bound_port(self) -> int:
        if self._server and self._server.sockets:
            return self._server.sockets[0].getsockname()[1]
        return self.port

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info(
            "SOCKS5 listening on %s:%d%s",
            self.host,
            self.bound_port,
            " (username/password auth)" if self.username else "",
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # pragma: no cover
                pass

    # ------------------------------------------------------------- handling
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        connection = None
        target = "?"
        try:
            if not await self._negotiate(reader, writer):
                return
            request = await self._read_request(reader, writer)
            if request is None:
                return
            command, host, port = request
            target = f"{host}:{port}"
            if command != CMD_CONNECT:
                await self._reply(writer, REP_COMMAND_NOT_SUPPORTED)
                return

            stack = self.stack
            resolver = self.resolver
            if self.acquire is not None:
                picked = self.acquire()
                if not picked:
                    await self._reply(writer, REP_HOST_UNREACHABLE)
                    return
                stack, resolver = picked
            address = await self._resolve(host, resolver)
            if address is None:
                await self._reply(
                    writer,
                    REP_ADDRESS_NOT_SUPPORTED if ":" in host else REP_HOST_UNREACHABLE,
                )
                return
            try:
                connection = await stack.tcp_connect(
                    address, port, timeout=self.connect_timeout
                )
            except TimeoutError:
                await self._reply(writer, REP_TTL_EXPIRED)
                return
            except (ConnectionRefusedError, ConnectionResetError):
                await self._reply(writer, REP_CONNECTION_REFUSED)
                return
            except (OSError, ConnectionError) as exc:
                log.debug("CONNECT %s failed: %s", target, exc)
                await self._reply(writer, REP_NETWORK_UNREACHABLE)
                return

            await self._reply(writer, REP_SUCCESS)
            self.active += 1
            self.total += 1
            log.info("CONNECT %s (from %s)", target, peer)
            await self._relay(reader, writer, connection)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception:  # pragma: no cover - defensive
            log.exception("unexpected SOCKS5 error for %s", target)
        finally:
            if connection is not None:
                connection.abort()
                self.active = max(0, self.active - 1)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _negotiate(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        header = await reader.readexactly(2)
        if header[0] != SOCKS_VERSION:
            log.debug("unsupported SOCKS version %d", header[0])
            return False
        methods = await reader.readexactly(header[1])
        if self.username:
            if METHOD_USER_PASS not in methods:
                writer.write(bytes((SOCKS_VERSION, METHOD_NONE)))
                await writer.drain()
                return False
            writer.write(bytes((SOCKS_VERSION, METHOD_USER_PASS)))
            await writer.drain()
            version = (await reader.readexactly(1))[0]
            if version != 0x01:
                return False
            user = await reader.readexactly((await reader.readexactly(1))[0])
            password = await reader.readexactly((await reader.readexactly(1))[0])
            if user.decode("utf-8", "replace") != self.username or (
                password.decode("utf-8", "replace") != (self.password or "")
            ):
                writer.write(bytes((0x01, 0x01)))
                await writer.drain()
                log.warning("SOCKS5 authentication failed for %s", user)
                return False
            writer.write(bytes((0x01, 0x00)))
            await writer.drain()
            return True
        if METHOD_NO_AUTH not in methods:
            writer.write(bytes((SOCKS_VERSION, METHOD_NONE)))
            await writer.drain()
            return False
        writer.write(bytes((SOCKS_VERSION, METHOD_NO_AUTH)))
        await writer.drain()
        return True

    async def _read_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[tuple[int, str, int]]:
        header = await reader.readexactly(4)
        if header[0] != SOCKS_VERSION:
            return None
        command, atyp = header[1], header[3]
        if atyp == ATYP_IPV4:
            host = ".".join(str(byte) for byte in await reader.readexactly(4))
        elif atyp == ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("utf-8", "replace")
        elif atyp == ATYP_IPV6:
            raw = await reader.readexactly(16)
            host = str(ipaddress.IPv6Address(raw))
        else:
            await self._reply(writer, REP_ADDRESS_NOT_SUPPORTED)
            return None
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        if command == CMD_UDP_ASSOCIATE:
            log.debug("UDP ASSOCIATE requested for %s:%d (not supported)", host, port)
        return command, host, port

    async def _resolve(self, host: str, resolver=None) -> Optional[str]:
        resolver = self.resolver if resolver is None else resolver
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            # IPv6 literals are fine now that the stack handles both families:
            # normalise the text so it matches the connection table keys
            return str(address)
        try:
            addresses = await resolver.resolve(host)
            if not addresses:
                # IPv6-only host: ask for AAAA and let the stack route over v6
                addresses = await resolver.resolve_aaaa(host)
                if addresses:
                    log.debug("%s has no A record, using IPv6 %s", host, addresses[0])
        except DnsError as exc:
            log.debug("DNS failure for %s: %s", host, exc)
            return None
        if not addresses:
            log.info("could not resolve %s", host)
            return None
        return addresses[0]

    async def _reply(self, writer: asyncio.StreamWriter, code: int) -> None:
        writer.write(bytes((SOCKS_VERSION, code, 0x00, ATYP_IPV4)) + b"\x00\x00\x00\x00" + b"\x00\x00")
        await writer.drain()

    async def _relay(self, reader, writer, connection) -> None:
        async def upstream() -> None:
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await connection.send(data)
            finally:
                await connection.close()

        async def downstream() -> None:
            while True:
                data = await connection.recv(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()

        tasks = [asyncio.create_task(upstream()), asyncio.create_task(downstream())]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done | pending:
                try:
                    task.exception()
                except (asyncio.CancelledError, Exception):
                    pass
        finally:
            connection.abort()
