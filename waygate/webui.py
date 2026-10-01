"""A dependency-free web UI for the WARP pool.

Dashboard + JSON API built on nothing but ``asyncio`` and the standard library:

    GET  /                     dashboard (auto refreshing)
    GET  /api/status           pool + per instance status
    POST /api/start?name=x     start one instance        (also: stop, restart)
    POST /api/start-all        start every instance      (also: stop-all)
    POST /api/add?endpoint=..  add an instance (optionally pinned to an endpoint)
    POST /api/remove?name=x    remove an instance
    GET  /api/scan             endpoint scan state (live endpoints first)
    POST /api/scan             start a background endpoint scan
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

from .multi import WarpPool
from .scan import EndpointScanner

log = logging.getLogger("waygate.webui")

PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Waygate</title>
<link rel="icon" href="data:,">
<style>
:root{color-scheme:dark;--bg:#0b0d12;--card:#141820;--line:#2a3140;--text:#f4f6f8;--muted:#8d95a6;--good:#73d6a8;--warn:#e6c07b;--bad:#f0929c;--ink:#101218}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,"Segoe UI",system-ui,sans-serif}
button,input,select{font:inherit;color:inherit}
button{background:transparent;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 12px;cursor:pointer}
button:hover{background:#1c2230}
button.primary{background:var(--text);color:var(--ink);border-color:var(--text);font-weight:600}
button.primary:hover{background:#e4e7ee}
button.danger{color:var(--bad);border-color:#5a3038}
button.tiny{padding:4px 8px;font-size:12px}
header{position:sticky;top:0;z-index:2;display:flex;gap:16px;align-items:center;justify-content:space-between;padding:14px 22px;background:rgba(11,13,18,.92);border-bottom:1px solid var(--line);backdrop-filter:blur(10px)}
.brand{display:flex;gap:10px;align-items:center}
.mark{width:10px;height:10px;border-radius:99px;background:var(--good);box-shadow:0 0 0 4px rgba(115,214,168,.15)}
h1{font-size:16px;margin:0;font-weight:650;letter-spacing:-.02em}
h2{font-size:13px;margin:0;font-weight:600}
.sub{color:var(--muted);font-size:12px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
main{max-width:1080px;margin:0 auto;padding:22px}
.hero{display:flex;justify-content:space-between;gap:18px;align-items:flex-end;padding:22px;border:1px solid var(--line);border-radius:16px;background:linear-gradient(180deg,#171c27,#12151c)}
.kicker{color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase}
.front-url{font:600 22px/1.3 ui-monospace,"Cascadia Code","Segoe UI Mono",monospace;margin:6px 0 8px;word-break:break-all}
.hero-side{display:flex;flex-direction:column;align-items:flex-end;gap:10px}
.rates{color:var(--muted);font-size:13px;text-align:right}
.rates b{color:var(--text);font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;margin-top:14px}
.card{border:1px solid var(--line);border-radius:14px;padding:14px 14px 12px;background:var(--card);display:flex;flex-direction:column;gap:10px}
.card.running{box-shadow:inset 3px 0 0 var(--good)}
.card.error{box-shadow:inset 3px 0 0 var(--bad)}
.card.starting{box-shadow:inset 3px 0 0 var(--warn)}
.card-top,.addr,.row-actions{display:flex;align-items:center;justify-content:space-between;gap:8px}
.name{font-weight:650}
.addr code,.ep code{font:12px/1.4 ui-monospace,"Cascadia Code","Segoe UI Mono",monospace}
code{background:#0e1218;padding:2px 6px;border-radius:6px}
.err{color:var(--bad);font-size:12px}
dl{display:grid;grid-template-columns:1fr 1fr;gap:8px 12px;margin:0}
dt{color:var(--muted);font-size:11px}
dd{margin:0;font-size:13px}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:650;background:#222733;color:var(--muted)}
.pill.running{background:#143226;color:var(--good)}
.pill.starting{background:#332913;color:var(--warn)}
.pill.error{background:#3a1d24;color:var(--bad)}
.panel{margin-top:18px;border:1px solid var(--line);border-radius:14px;padding:14px 16px;background:var(--card)}
.panel-head{display:flex;justify-content:space-between;gap:8px;align-items:baseline;margin-bottom:8px}
.grid{display:flex;flex-direction:column;gap:8px;margin-top:8px}
.ep{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:#10141b}
#toast{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);background:#f4f6f8;color:#111;padding:8px 14px;border-radius:999px;font-size:13px;opacity:0;pointer-events:none;transition:opacity .2s}
#toast.show{opacity:1}
dialog{background:#141820;color:var(--text);border:1px solid var(--line);border-radius:14px;padding:18px;width:min(440px,calc(100vw - 32px))}
dialog::backdrop{background:rgba(0,0,0,.55)}
label{display:block;margin:12px 0 6px;color:var(--muted);font-size:12px}
select,input{width:100%;background:#0e1218;border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.dlg-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
[hidden]{display:none !important}
@media (max-width:720px){
  header{align-items:flex-start;flex-direction:column}
  .hero{flex-direction:column;align-items:stretch}
  .hero-side{align-items:flex-start}
  .rates{text-align:left}
  .front-url{font-size:16px}
}
@media (prefers-reduced-motion:reduce){#toast{transition:none}}
</style></head><body>
<header>
  <div class="brand"><span class="mark"></span><div><h1>Waygate</h1><div class="sub" id="summary">正在连接…</div></div></div>
  <div class="actions">
    <button id="btn-scan">扫描端点</button>
    <button class="danger" id="btn-scan-stop" hidden>停止扫描</button>
    <button data-act="start-all">全部启动</button>
    <button data-act="stop-all">全部停止</button>
    <button class="primary" id="btn-add">新增实例</button>
  </div>
</header>
<main>
  <section class="hero">
    <div>
      <div class="kicker">统一入口</div>
      <div class="front-url" id="front-url">…</div>
      <p class="sub" id="front-hint">新连接交给当前最空闲的实例。用 socks5h，域名在隧道里解析。</p>
    </div>
    <div class="hero-side">
      <button class="primary" id="btn-copy-front">复制地址</button>
      <div class="rates" id="rates"></div>
    </div>
  </section>
  <section class="cards" id="cards"></section>
  <section class="panel">
    <div class="panel-head"><h2>端点</h2><span class="sub" id="scan-state">还没扫描</span></div>
    <div class="sub">只保留握手成功、并且隧道里真的收到 DNS 回包的地址。</div>
    <div class="grid" id="endpoints"></div>
  </section>
</main>
<div id="toast"></div>
<dialog id="dlg-add">
  <h2>新增实例</h2>
  <label>端点</label>
  <select id="add-endpoint"><option value="">自动，选当前最快的</option></select>
  <label>或手动填写（host 或 host:port）</label>
  <input id="add-manual" placeholder="162.159.198.2:443">
  <div class="dlg-actions">
    <button id="add-cancel">取消</button>
    <button class="primary" id="add-ok">创建并启动</button>
  </div>
</dialog>
<script>
const $ = id => document.getElementById(id);
const LABEL = {running:'运行中', starting:'启动中', stopped:'已停止', error:'出错'};
let frontUrl = '';
let liveEndpoints = [];

function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtRate(n){
  n = Number(n) || 0;
  if (n < 1024) return n + ' B/s';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB/s';
  return (n / 1048576).toFixed(2) + ' MB/s';
}
function toast(text){
  const el = $('toast');
  el.textContent = text;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 1600);
}
async function copyText(text, btn){
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const area = document.createElement('textarea');
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  const old = btn.textContent;
  btn.textContent = '已复制';
  setTimeout(() => { btn.textContent = old; }, 1000);
}
async function api(path, method){
  const r = await fetch(path, {method: method || 'GET'});
  try { return await r.json(); }
  catch (e) { return {ok:false, error:String(e)}; }
}
document.addEventListener('click', async ev => {
  const el = ev.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  const name = el.dataset.name || '';
  if (act === 'copy') { copyText(el.dataset.url || '', el); return; }
  if (act === 'use-endpoint') {
    $('add-manual').value = el.dataset.ep || '';
    $('dlg-add').showModal();
    return;
  }
  if (act === 'remove' && !confirm('删除 ' + name + ' ？这条隧道会立刻停下。')) return;
  const q = name ? ('?name=' + encodeURIComponent(name)) : '';
  const res = await api('/api/' + act + q, 'POST');
  if (res && res.ok === false) toast(res.error || '操作失败');
  refresh();
});
$('btn-copy-front').onclick = () => { if (frontUrl) copyText(frontUrl, $('btn-copy-front')); };
$('btn-scan').onclick = async () => { $('scan-state').textContent = '扫描中…'; await api('/api/scan','POST'); setTimeout(refresh, 400); };
$('btn-scan-stop').onclick = async () => { await api('/api/scan/stop','POST'); refresh(); };
$('btn-add').onclick = () => { $('add-manual').value = ''; $('dlg-add').showModal(); };
$('add-cancel').onclick = () => $('dlg-add').close();
$('add-ok').onclick = async () => {
  const chosen = $('add-manual').value.trim() || $('add-endpoint').value;
  let url = '/api/add';
  if (chosen) url += '?endpoint=' + encodeURIComponent(chosen);
  const res = await api(url, 'POST');
  if (res && res.ok === false) toast(res.error || '创建失败');
  $('dlg-add').close();
  refresh();
};

function card(i){
  const label = LABEL[i.status] || i.status;
  const busy = i.status === 'running' || i.status === 'starting';
  return '<article class="card ' + esc(i.status) + '">'
    + '<div class="card-top"><div><div class="name">' + esc(i.name) + '</div>'
    + '<div class="sub">' + esc(i.endpoint || '等待端点') + (i.device ? ' · ' + esc(i.device) : '') + '</div></div>'
    + '<span class="pill ' + esc(i.status) + '">' + esc(label) + '</span></div>'
    + (i.error ? '<div class="err">' + esc(i.error) + '</div>' : '')
    + '<div class="addr"><code>' + esc(i.socks_url) + '</code>'
    + '<button class="tiny" data-act="copy" data-url="' + esc(i.socks_url) + '">复制</button></div>'
    + '<dl><div><dt>上行</dt><dd>' + fmtRate(i.tx_bps) + '</dd></div>'
    + '<div><dt>下行</dt><dd>' + fmtRate(i.rx_bps) + '</dd></div>'
    + '<div><dt>连接</dt><dd>SOCKS ' + (i.active || 0) + ' · 流 ' + (i.flows || 0) + '</dd></div>'
    + '<div><dt>在线</dt><dd>' + esc(i.uptime_text || '—') + '</dd></div></dl>'
    + '<div class="row-actions"><button class="tiny" data-act="restart" data-name="' + esc(i.name) + '">重启</button>'
    + (busy
        ? '<button class="tiny danger" data-act="stop" data-name="' + esc(i.name) + '">停止</button>'
        : '<button class="tiny primary" data-act="start" data-name="' + esc(i.name) + '">启动</button>')
    + '<button class="tiny danger" data-act="remove" data-name="' + esc(i.name) + '">删除</button></div>'
    + '</article>';
}

async function refresh(){
  let data;
  try { data = await api('/api/status'); }
  catch (e) { $('summary').textContent = '后端无响应'; return; }
  if (!data || !data.instances) { $('summary').textContent = '后端无响应'; return; }
  const front = data.front || {};
  frontUrl = front.url || '';
  $('front-url').textContent = front.enabled ? frontUrl : '入口没有起来';
  $('front-hint').textContent = front.error
    ? front.error
    : '新连接交给当前最空闲的实例。用 socks5h，域名在隧道里解析。';
  $('summary').textContent = data.running + ' / ' + data.total + ' 在运行'
    + (front.active ? ' · 入口 ' + front.active + ' 条' : '');
  $('rates').innerHTML = '<div>上行 <b>' + fmtRate(data.tx_bps) + '</b></div>'
    + '<div>下行 <b>' + fmtRate(data.rx_bps) + '</b></div>';
  $('cards').innerHTML = data.instances.map(card).join('')
    || '<div class="sub">还没有实例</div>';

  const scan = await api('/api/scan');
  const scanning = !!(scan && scan.scanning);
  $('btn-scan-stop').hidden = !scanning;
  $('btn-scan').hidden = scanning;
  if (scanning) {
    $('scan-state').textContent = '扫描中 ' + (scan.scanned || 0) + ' / ' + (scan.total || '?')
      + (scan.stop_requested ? ' · 正在停止' : '');
  } else if (scan && scan.duration != null) {
    $('scan-state').textContent = '可用 ' + scan.live_count + ' / ' + scan.scanned + ' · ' + scan.duration + 's';
  }
  liveEndpoints = (scan && scan.live) || [];
  $('endpoints').innerHTML = liveEndpoints.length
    ? liveEndpoints.map(e =>
        '<div class="ep"><b>#' + (e.rank || '?') + '</b> <code>' + esc(e.target) + '</code>'
        + '<span class="sub">' + esc(e.transport || '') + ' 丢包 ' + (e.loss != null ? e.loss : '?') + '% · '
        + (e.latency != null ? Math.round(e.latency * 1000) + ' ms' : '') + '</span>'
        + ((e.owners && e.owners.length) ? '<span class="pill running">' + esc(e.owners.join(' ')) + '</span>' : '')
        + '<button class="tiny primary" data-act="use-endpoint" data-ep="' + esc(e.target) + '">用它建实例</button></div>'
      ).join('')
    : '<div class="sub">还没有可用端点。点右上角扫描，或新建时自己填。</div>';
  const sel = $('add-endpoint');
  const keep = sel.value;
  sel.innerHTML = '<option value="">自动，选当前最快的</option>'
    + liveEndpoints.map(e => '<option value="' + esc(e.target) + '">#' + (e.rank || '?') + ' ' + esc(e.target)
      + ' · 丢包 ' + (e.loss != null ? e.loss : '?') + '%</option>').join('');
  sel.value = keep;
}
refresh();
setInterval(refresh, 1000);
</script></body></html>
"""


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
            if length:
                await asyncio.wait_for(reader.readexactly(length), 10)

            parsed = urlparse(target)
            query = parse_qs(parsed.query)
            name = (query.get("name") or [""])[0]
            endpoint = (query.get("endpoint") or [""])[0]
            body, ctype, code = await self._route(method, parsed.path, name, endpoint)
        except Exception as exc:  # noqa: BLE001
            log.exception("web request failed")
            body, ctype, code = json.dumps({"ok": False, "error": str(exc)}), "application/json", 500

        payload = body.encode("utf-8") if isinstance(body, str) else body
        reason = {200: "OK", 204: "No Content", 404: "Not Found",
                  405: "Method Not Allowed", 500: "Internal Server Error"}.get(code, "OK")
        writer.write(
            f"HTTP/1.1 {code} {reason}\r\n".encode()
            + f"Content-Type: {ctype}; charset=utf-8\r\n".encode()
            + f"Content-Length: {len(payload)}\r\n".encode()
            + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
            + payload
        )
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        writer.close()

    async def _route(
        self, method: str, path: str, name: str, endpoint: str
    ) -> tuple[str, str, int]:
        if path in ("/", "/index.html"):
            return PAGE, "text/html", 200
        if path == "/api/status":
            return json.dumps(self.pool.status(), ensure_ascii=False), "application/json", 200
        if path == "/api/scan":
            if self.scanner is None:
                return json.dumps({"scanning": False, "scanned": 0, "live": [],
                                   "live_count": 0, "failures": {}, "duration": None,
                                   "error": "scanner disabled"}), "application/json", 200
            if method == "POST" and not self.scanner.scanning:
                asyncio.create_task(self.scanner.scan())
            state = self.scanner.state()
            ranked = self.pool.ranked_endpoints()
            if ranked:
                # best first, with rank and the instance pinned to each
                state["live"] = ranked
            return json.dumps(state, ensure_ascii=False), "application/json", 200
        if path == "/api/scan/stop":
            if self.scanner is not None:
                self.scanner.request_stop()
            return json.dumps({"ok": True, "stopping": True}), "application/json", 200
        if path == "/favicon.ico":
            return "", "image/x-icon", 204

        if method != "POST":
            return json.dumps({"ok": False, "error": "not found"}), "application/json", 404

        instance = self.pool.get(name) if name else None
        if path == "/api/start-all":
            asyncio.create_task(self.pool.start_all())
            return json.dumps({"ok": True, "action": "start-all"}), "application/json", 200
        if path == "/api/stop-all":
            asyncio.create_task(self.pool.stop_all())
            return json.dumps({"ok": True, "action": "stop-all"}), "application/json", 200
        if path == "/api/add":
            new = self.pool.add(endpoint or None)
            asyncio.create_task(new.start())
            return json.dumps({"ok": True, "name": new.name, "port": new.port,
                               "endpoint": new.endpoint or "auto"}), "application/json", 200
        if path == "/api/remove":
            if not instance:
                return json.dumps({"ok": False, "error": "unknown instance"}), "application/json", 404
            # pool.remove() notifies the owner, which persists the new list
            self.pool.remove(name)
            return json.dumps({"ok": True, "removed": name}), "application/json", 200
        if path in ("/api/start", "/api/stop", "/api/restart"):
            if not instance:
                return json.dumps({"ok": False, "error": "unknown instance"}), "application/json", 404
            action = path.rsplit("/", 1)[1]
            if action == "start":
                asyncio.create_task(instance.start())
            elif action == "stop":
                asyncio.create_task(instance.stop())
            else:
                asyncio.create_task(instance.restart())
            return json.dumps({"ok": True, "action": action, "name": name}), "application/json", 200
        return json.dumps({"ok": False, "error": "not found"}), "application/json", 404
