"""A dependency-free web UI for the WARP pool.

Dashboard + JSON API built on nothing but ``asyncio`` and the standard library:

    GET  /                     dashboard
    GET  /api/status           pool + per instance status
    GET  /api/settings         routing, placement, scan options
    POST /api/settings         update options (JSON body)
    POST /api/start?name=x     start one instance        (also: stop, restart)
    POST /api/start-all        start every instance      (also: stop-all)
    POST /api/add              add instance(s); JSON {count, endpoint, endpoints}
    POST /api/remove?name=x    remove an instance
    POST /api/batch            {action, names} start/stop/restart/remove
    POST /api/pin              {name, endpoint} pin an instance to an endpoint
    GET  /api/scan             endpoint scan state (live endpoints first)
    POST /api/scan             start a background endpoint scan (JSON options)
    GET  /api/identities       public device summaries
"""

from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__
from .multi import MAX_ADD, WarpPool
from .scan import EndpointScanner

log = logging.getLogger("waygate.webui")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 1_000_000

MIME = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


def _json(payload, code: int = 200) -> tuple[str, str, int]:
    return json.dumps(payload, ensure_ascii=False, default=str), "application/json", code


def _first(query: dict, key: str, default: str = "") -> str:
    values = query.get(key) or [default]
    return values[0] if values else default


def _names_from(query: dict, body: dict) -> list[str]:
    names = body.get("names") if isinstance(body.get("names"), list) else None
    if names:
        return [str(item) for item in names]
    raw = _first(query, "names") or _first(query, "name")
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


class WebUI:
    def __init__(
        self,
        pool: WarpPool,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        scanner: Optional[EndpointScanner] = None,
        on_add: Optional[Callable[[], None]] = None,
    ) -> None:
        self.pool = pool
        self.host = host
        self.port = port
        self.scanner = scanner
        self.on_add = on_add
        self.bound_port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sockets = self._server.sockets or []
        if sockets:
            self.bound_port = sockets[0].getsockname()[1]
        log.info("web UI on http://%s:%d", self.host, self.bound_port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    # ------------------------------------------------------------------ http
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        except Exception:  # noqa: BLE001
            writer.close()
            return
        try:
            head = request.decode("latin-1").split("\r\n")
            method, target, _ = head[0].split(" ", 2)
            headers = {}
            for line in head[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            length = int(headers.get("content-length") or 0)
            body_raw = b""
            if length:
                if length > MAX_BODY:
                    body, ctype, code = _json({"ok": False, "error": "payload too large"}, 413)
                    await self._write(writer, body, ctype, code)
                    return
                body_raw = await asyncio.wait_for(reader.readexactly(length), 10)
            body: dict = {}
            if body_raw:
                try:
                    parsed_body = json.loads(body_raw.decode("utf-8"))
                    if isinstance(parsed_body, dict):
                        body = parsed_body
                except Exception:  # noqa: BLE001
                    body = {}

            parsed = urlparse(target)
            query = parse_qs(parsed.query)
            body, ctype, code = await self._route(method, parsed.path, query, body)
        except Exception as exc:  # noqa: BLE001
            log.exception("web request failed")
            body, ctype, code = _json({"ok": False, "error": str(exc)}, 500)

        await self._write(writer, body, ctype, code)

    async def _write(self, writer: asyncio.StreamWriter, body, ctype: str, code: int) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        reason = {
            200: "OK",
            204: "No Content",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            413: "Payload Too Large",
            500: "Internal Server Error",
        }.get(code, "OK")
        cache = "no-store"
        writer.write(
            f"HTTP/1.1 {code} {reason}\r\n".encode()
            + f"Content-Type: {ctype}; charset=utf-8\r\n".encode()
            + f"Content-Length: {len(payload)}\r\n".encode()
            + f"Cache-Control: {cache}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        writer.close()

    def _static(self, path: str) -> Optional[tuple[bytes, str, int]]:
        relative = path.lstrip("/")
        if path in ("/", "/index.html"):
            relative = "index.html"
        candidate = (STATIC_DIR / relative).resolve()
        try:
            candidate.relative_to(STATIC_DIR)
        except ValueError:
            return None
        if not candidate.is_file():
            return None
        suffix = candidate.suffix.lower()
        ctype = MIME.get(suffix) or mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        return candidate.read_bytes(), ctype, 200

    async def _route(
        self, method: str, path: str, query: dict, body: dict
    ) -> tuple[str | bytes, str, int]:
        if method in ("GET", "HEAD") and not path.startswith("/api/"):
            static = self._static(path)
            if static is not None:
                data, ctype, code = static
                if method == "HEAD":
                    return b"", ctype, code
                return data, ctype, code
            if path == "/favicon.ico":
                return b"", "image/x-icon", 204

        if path == "/api/status":
            payload = self.pool.status()
            payload["version"] = __version__
            return _json(payload)
        if path == "/api/meta":
            return _json({
                "ok": True,
                "version": __version__,
                "settings": self.pool.settings(),
            })
        if path == "/api/settings":
            if method == "GET":
                return _json({"ok": True, **self.pool.settings()})
            if method != "POST":
                return _json({"ok": False, "error": "method not allowed"}, 405)
            try:
                settings = self.pool.apply_settings(body)
            except ValueError as exc:
                return _json({"ok": False, "error": str(exc)}, 400)
            return _json({"ok": True, **settings})
        if path == "/api/identities":
            return _json({"ok": True, "identities": self.pool.identities()})
        if path == "/api/scan":
            if method not in ("GET", "POST"):
                return _json({"ok": False, "error": "method not allowed"}, 405)
            if self.scanner is None:
                payload = {
                    "ok": False, "scanning": False, "scanned": 0, "live": [],
                    "live_count": 0, "failures": {}, "duration": None,
                    "error": "scanner disabled",
                }
                return _json(payload, 400 if method == "POST" else 200)
            started = False
            if method == "POST":
                if not self.scanner.scanning:
                    self.scanner.configure(
                        profile=body.get("profile") or _first(query, "profile") or None,
                        family=body.get("family") or _first(query, "family") or None,
                        ports=body.get("ports") if "ports" in body else (_first(query, "ports") or None),
                        ranges=body.get("ranges") if "ranges" in body else (_first(query, "ranges") or None),
                        concurrency=body.get("concurrency") if "concurrency" in body else (
                            int(_first(query, "concurrency")) if _first(query, "concurrency").isdigit() else None
                        ),
                        whole_range=body.get("whole_range") if "whole_range" in body else None,
                    )
                    asyncio.create_task(self.scanner.scan())
                    started = True
            state = self.scanner.state()
            ranked = self.pool.ranked_endpoints()
            if ranked:
                state["live"] = ranked
            state["ok"] = True
            state["started"] = started
            return _json(state)
        if path == "/api/scan/stop":
            if method != "POST":
                return _json({"ok": False, "error": "method not allowed"}, 405)
            if self.scanner is not None:
                self.scanner.request_stop()
            return _json({"ok": True, "stopping": True})

        if method != "POST":
            return _json({"ok": False, "error": "not found"}, 404)

        name = body.get("name") or _first(query, "name")
        endpoint = body.get("endpoint") or _first(query, "endpoint")
        instance = self.pool.get(name) if name else None

        if path == "/api/start-all":
            asyncio.create_task(self.pool.start_all())
            return _json({"ok": True, "action": "start-all"})
        if path == "/api/stop-all":
            asyncio.create_task(self.pool.stop_all())
            return _json({"ok": True, "action": "stop-all"})
        if path == "/api/ensure-exits":
            raw = body.get("count", _first(query, "count"))
            if raw in (None, "", "auto"):
                count = None
            else:
                count = raw
            result = self.pool.ensure_unique_exits(count)
            return _json(result)
        if path == "/api/refresh-exits":
            result = await self.pool.refresh_exit_ips()
            return _json(result)
        if path == "/api/add":
            endpoints = body.get("endpoints")
            added = []
            if isinstance(endpoints, list) and endpoints:
                for item in endpoints[:MAX_ADD]:
                    target = str(item).strip()
                    new = self.pool.add(target or None)
                    asyncio.create_task(new.start())
                    added.append({"name": new.name, "port": new.port, "endpoint": new.endpoint or "auto"})
            else:
                count = body.get("count") or _first(query, "count") or 1
                try:
                    count = int(count)
                except (TypeError, ValueError):
                    count = 1
                created = self.pool.add_many(count, endpoint or None)
                for new in created:
                    asyncio.create_task(new.start())
                    added.append({"name": new.name, "port": new.port, "endpoint": new.endpoint or "auto"})
            return _json({"ok": True, "added": added, "name": added[0]["name"] if added else None,
                          "port": added[0]["port"] if added else None,
                          "endpoint": added[0]["endpoint"] if added else "auto"})
        if path == "/api/remove":
            if not instance:
                return _json({"ok": False, "error": "unknown instance"}, 404)
            self.pool.remove(name)
            return _json({"ok": True, "removed": name})
        if path == "/api/batch":
            action = body.get("action") or _first(query, "action")
            names = _names_from(query, body)
            try:
                result = await self.pool.batch(action, names)
            except ValueError as exc:
                return _json({"ok": False, "error": str(exc)}, 400)
            return _json(result)
        if path == "/api/pin":
            if not name:
                return _json({"ok": False, "error": "name required"}, 400)
            pinned = self.pool.pin(name, endpoint)
            if pinned is None:
                return _json({"ok": False, "error": "unknown instance"}, 404)
            if body.get("restart") or _first(query, "restart") in ("1", "true", "yes"):
                asyncio.create_task(pinned.restart())
            return _json({"ok": True, "name": pinned.name, "endpoint": pinned.endpoint or ""})
        if path in ("/api/start", "/api/stop", "/api/restart"):
            if not instance:
                return _json({"ok": False, "error": "unknown instance"}, 404)
            action = path.rsplit("/", 1)[1]
            if action == "start":
                asyncio.create_task(instance.start())
            elif action == "stop":
                asyncio.create_task(instance.stop())
            else:
                asyncio.create_task(instance.restart())
            return _json({"ok": True, "action": action, "name": name})
        return _json({"ok": False, "error": "not found"}, 404)
