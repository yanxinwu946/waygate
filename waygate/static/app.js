(() => {
  "use strict";

  const THEME_KEY = "waygate-theme";
  const COLLAPSE_KEY = "waygate-sidebar";
  const PAGES = {
    overview: { title: "概览", sub: "运行状态与统一入口" },
    instances: { title: "线路", sub: "实例、批量操作与落地地址" },
    endpoints: { title: "端点", sub: "扫描范围、可用地址与建线" },
    routing: { title: "调度", sub: "入口分发与新线路落地策略" },
    account: { title: "账号", sub: "设备身份、额度与本地权限" },
  };
  const STATUS_LABEL = {
    running: "运行中",
    starting: "启动中",
    stopped: "已停止",
    error: "出错",
  };

  const $ = (id) => document.getElementById(id);
  const main = $("main");
  const sidebar = $("sidebar");
  const shell = $("shell");
  const backdrop = $("nav-backdrop");

  let statusCache = null;
  let settingsCache = null;
  let scanCache = null;
  let identitiesCache = null;
  let lastError = "";
  let loading = true;
  let traffic = [];
  let toastTimer = 0;
  let modalEl = null;
  let popoverEl = null;
  let popoverOnClose = null;
  let instanceQuery = { q: "", status: "", submitted: { q: "", status: "" }, stale: false };
  let instancePage = { page: 1, size: 50, sort: "name", dir: "asc" };
  let endpointPage = { page: 1, size: 20, sort: "rank", dir: "asc" };
  let selectedInstances = new Set();
  let selectedEndpoints = new Set();
  let scanDraft = { profile: "curated", family: "both", ports: "443,500,1701,4500", concurrency: 60 };
  let interactingUntil = 0;
  let refreshInFlight = false;

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));
  }
  function dash(value) {
    if (value == null || value === "" || Number.isNaN(value)) return "—";
    return value;
  }
  function num(value) {
    if (value == null || value === "" || Number.isNaN(Number(value))) return "—";
    return Number(value).toLocaleString("zh-CN");
  }
  function beijing(ts) {
    if (ts == null || ts === "") return "—";
    const date = typeof ts === "number" ? new Date(ts * (ts < 1e12 ? 1000 : 1)) : new Date(ts);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(date);
  }
  function fmtRate(n) {
    n = Number(n) || 0;
    if (n < 1024) return `${Math.round(n)} B/s`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB/s`;
    return `${(n / 1048576).toFixed(2)} MB/s`;
  }
  function routeName() {
    const hash = (location.hash || "#/overview").replace(/^#\/?/, "");
    const name = hash.split("?")[0] || "overview";
    return PAGES[name] ? name : "overview";
  }
  function icon(name) {
    const paths = {
      activity: '<path d="M22 12h-4l-3 7-6-14-3 7H2"/>',
      layers: '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/>',
      globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
      zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
      radio: '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 7.8a6 6 0 0 0 0 8.4M19.1 4.9a10 10 0 0 1 0 14.2M4.9 4.9a10 10 0 0 0 0 14.2"/>',
    };
    return `<span class="metric-icon"><svg viewBox="0 0 24 24">${paths[name] || paths.activity}</svg></span>`;
  }

  function toast(text) {
    const root = $("toast-root");
    root.innerHTML = `<div class="toast">${esc(text)}</div>`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { root.innerHTML = ""; }, 1800);
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    toast("已复制");
  }

  async function api(path, method, payload) {
    const opts = { method: method || "GET", headers: {} };
    if (payload != null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(payload);
    }
    const res = await fetch(path, opts);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); }
    catch { data = { ok: false, error: text || res.statusText }; }
    if (data == null || typeof data !== "object") data = { ok: false, error: String(data) };
    if (!res.ok && data.ok !== true) {
      data.ok = false;
      if (!data.error) data.error = res.statusText || "request failed";
    }
    return data;
  }

  /* ---------- theme ---------- */
  function systemTheme() {
    return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function currentThemePref() {
    return localStorage.getItem(THEME_KEY) || "system";
  }
  function applyTheme() {
    const pref = currentThemePref();
    const resolved = pref === "system" ? systemTheme() : pref;
    document.documentElement.dataset.theme = resolved;
    document.querySelectorAll("[data-theme-set]").forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.themeSet === pref);
    });
  }
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (currentThemePref() === "system") applyTheme();
  });
  document.querySelectorAll("[data-theme-set]").forEach((btn) => {
    btn.addEventListener("click", () => {
      localStorage.setItem(THEME_KEY, btn.dataset.themeSet);
      applyTheme();
    });
  });

  /* ---------- layout ---------- */
  function isDesktop() {
    return matchMedia("(min-width: 961px)").matches;
  }
  function applyCollapse() {
    const collapsed = localStorage.getItem(COLLAPSE_KEY) === "1";
    const rail = collapsed && isDesktop();
    document.documentElement.dataset.nav = rail ? "collapsed" : "expanded";
    sidebar.classList.toggle("is-collapsed", rail);
    const btn = $("btn-collapse");
    const label = rail ? "展开侧栏" : "折叠侧栏";
    btn.setAttribute("aria-label", label);
    btn.setAttribute("title", label);
    btn.setAttribute("aria-expanded", rail ? "false" : "true");
  }
  $("btn-collapse").addEventListener("click", () => {
    if (!isDesktop()) return;
    const next = localStorage.getItem(COLLAPSE_KEY) === "1" ? "0" : "1";
    localStorage.setItem(COLLAPSE_KEY, next);
    applyCollapse();
  });
  function openDrawer() {
    if (isDesktop()) return;
    sidebar.classList.add("is-open");
    backdrop.hidden = false;
    $("btn-menu").setAttribute("aria-expanded", "true");
  }
  function closeDrawer() {
    sidebar.classList.remove("is-open");
    backdrop.hidden = true;
    $("btn-menu").setAttribute("aria-expanded", "false");
  }
  $("btn-menu").addEventListener("click", openDrawer);
  backdrop.addEventListener("click", closeDrawer);
  window.addEventListener("resize", () => {
    applyCollapse();
    if (isDesktop()) closeDrawer();
  });

  function setNav(route) {
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.classList.toggle("is-active", el.dataset.route === route);
    });
    const page = PAGES[route];
    $("page-title").textContent = page.title;
    $("page-sub").textContent = page.sub;
    document.title = `${page.title} · Waygate`;
  }

  /* ---------- overlays ---------- */
  function closePopover() {
    if (popoverEl) popoverEl.remove();
    popoverEl = null;
    if (popoverOnClose) popoverOnClose();
    popoverOnClose = null;
  }
  function openPopover(anchor, html, onClose) {
    closePopover();
    const pop = document.createElement("div");
    pop.className = "popover";
    pop.innerHTML = html;
    document.body.appendChild(pop);
    const rect = anchor.getBoundingClientRect();
    const width = pop.offsetWidth;
    const height = pop.offsetHeight;
    let left = rect.left;
    let top = rect.bottom + 6;
    if (left + width > innerWidth - 8) left = innerWidth - width - 8;
    if (left < 8) left = 8;
    if (top + height > innerHeight - 8) top = rect.top - height - 6;
    if (top < 8) top = 8;
    pop.style.left = `${left}px`;
    pop.style.top = `${top}px`;
    popoverEl = pop;
    popoverOnClose = onClose;
    return pop;
  }

  function closeModal() {
    if (!modalEl) return;
    modalEl.remove();
    modalEl = null;
  }
  function openModal({ title, desc, body, confirm, danger, onConfirm }) {
    closeModal();
    const root = document.createElement("div");
    root.className = "modal-root";
    root.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-labelledby="dlg-title">
      <h2 id="dlg-title">${esc(title)}</h2>
      ${desc ? `<p class="dlg-desc">${esc(desc)}</p>` : ""}
      <div class="dlg-body">${body || ""}</div>
      <div class="dlg-actions">
        <button class="btn" type="button" data-dlg="cancel">取消</button>
        <button class="btn ${danger ? "danger" : "primary"}" type="button" data-dlg="ok">${esc(confirm || "确认")}</button>
      </div>
    </div>`;
    document.body.appendChild(root);
    modalEl = root;
    const dialog = root.querySelector(".modal");
    const first = dialog.querySelector("input,select,textarea,button");
    if (first) first.focus();
    root.addEventListener("click", (ev) => {
      const act = ev.target.closest("[data-dlg]");
      if (ev.target === root) { closeModal(); return; }
      if (!act) return;
      if (act.dataset.dlg === "cancel") closeModal();
      if (act.dataset.dlg === "ok") onConfirm && onConfirm(dialog);
    });
  }
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      if (modalEl) { closeModal(); ev.preventDefault(); }
      else if (popoverEl) { closePopover(); ev.preventDefault(); }
      else closeDrawer();
    }
  });
  document.addEventListener("click", (ev) => {
    if (popoverEl && !popoverEl.contains(ev.target) && !ev.target.closest("#btn-account-menu")) {
      closePopover();
    }
  });

  $("btn-account-menu").addEventListener("click", (ev) => {
    ev.stopPropagation();
    const btn = ev.currentTarget;
    const open = btn.getAttribute("aria-expanded") === "true";
    if (open) { closePopover(); btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    const pop = openPopover(btn, `
      <button type="button" data-acc="copy">复制统一入口</button>
      <button type="button" data-acc="instances">打开线路</button>
      <button type="button" data-acc="account">账号与额度</button>
    `, () => btn.setAttribute("aria-expanded", "false"));
    pop.addEventListener("click", async (e) => {
      const act = e.target.closest("[data-acc]");
      if (!act) return;
      if (act.dataset.acc === "copy" && statusCache?.front?.url) await copyText(statusCache.front.url);
      if (act.dataset.acc === "instances") location.hash = "#/instances";
      if (act.dataset.acc === "account") location.hash = "#/account";
      closePopover();
    });
  });

  /* ---------- data ---------- */
  function recordTraffic(data) {
    traffic.push({ t: Date.now(), tx: data.tx_bps || 0, rx: data.rx_bps || 0 });
    if (traffic.length > 90) traffic = traffic.slice(-90);
  }
  function drawChart(canvas) {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    const style = getComputedStyle(document.documentElement);
    const grid = style.getPropertyValue("--border").trim();
    const up = style.getPropertyValue("--chart").trim();
    const down = style.getPropertyValue("--success").trim();
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    for (let i = 1; i < 4; i++) {
      const y = (h / 4) * i;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    if (traffic.length < 2) return;
    const max = Math.max(1, ...traffic.map((p) => Math.max(p.tx, p.rx)));
    const plot = (key, color) => {
      ctx.beginPath();
      traffic.forEach((p, i) => {
        const x = (i / (traffic.length - 1)) * w;
        const y = h - (p[key] / max) * (h - 8) - 4;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
    };
    plot("tx", up);
    plot("rx", down);
  }

  function sortRows(rows, key, dir) {
    const copy = rows.slice();
    copy.sort((a, b) => {
      const va = a[key]; const vb = b[key];
      const na = Number(va); const nb = Number(vb);
      let cmp;
      if (va == null && vb == null) cmp = 0;
      else if (va == null) cmp = 1;
      else if (vb == null) cmp = -1;
      else if (!Number.isNaN(na) && !Number.isNaN(nb) && va !== "" && vb !== "") cmp = na - nb;
      else cmp = String(va).localeCompare(String(vb), "zh-CN");
      return dir === "desc" ? -cmp : cmp;
    });
    return copy;
  }
  function pageSlice(rows, page, size) {
    const total = rows.length;
    const pages = Math.max(1, Math.ceil(total / size));
    const cur = Math.min(Math.max(1, page), pages);
    const start = (cur - 1) * size;
    return { rows: rows.slice(start, start + size), total, pages, page: cur };
  }
  function pagerHtml(prefix, state, total) {
    const pages = Math.max(1, Math.ceil(total / state.size));
    return `<div class="pager">
      <div class="pager-pages">
        <button class="btn" data-page="${prefix}:prev" ${state.page <= 1 ? "disabled" : ""}>上一页</button>
        <span class="muted">${state.page} / ${pages}</span>
        <button class="btn" data-page="${prefix}:next" ${state.page >= pages ? "disabled" : ""}>下一页</button>
      </div>
      <div class="pager-extra">
        <label class="muted">每页</label>
        <select class="ctl" data-pagesize="${prefix}">
          ${[10, 20, 30, 50].map((n) => `<option value="${n}" ${n === state.size ? "selected" : ""}>${n}</option>`).join("")}
        </select>
        <label class="muted">跳转</label>
        <input class="ctl" data-pagejump="${prefix}" type="number" min="1" max="${pages}" value="${state.page}" style="width:72px">
      </div>
    </div>`;
  }

  function copyCell(text) {
    const shown = dash(text);
    if (shown === "—") return "—";
    return `<span class="cell-copy" title="${esc(text)}"><code>${esc(text)}</code>
      <button class="btn tiny" data-copy="${esc(text)}">复制</button></span>`;
  }

  /* ---------- pages ---------- */
  function renderOverview() {
    const data = statusCache;
    if (!data) return `<div class="state-block">${loading ? "正在加载运行数据…" : (lastError || "后端无响应")}</div>`;
    const front = data.front || {};
    const routing = settingsCache?.routing_modes?.[data.routing_mode]?.label || data.routing_mode || "—";
    return `
      <section class="metrics">
        <article class="metric">${icon("layers")}<div class="metric-top">在运行线路</div>
          <div class="metric-value">${num(data.running)} / ${num(data.total)}</div>
          <div class="metric-hint">启动中 ${num(data.starting)} · 故障 ${num(data.error)}</div></article>
        <article class="metric">${icon("globe")}<div class="metric-top">公网出口</div>
          <div class="metric-value">${num(data.exit_ip_count)} / ${num(data.running)}</div>
          <div class="metric-hint">接入 ${num(data.unique_ip_count)} · 扫描可铺 ${num(data.exit_target)}</div></article>
        <article class="metric">${icon("activity")}<div class="metric-top">入口连接</div>
          <div class="metric-value">${num(front.active)}</div>
          <div class="metric-hint">累计 ${num(front.total)} · 调度 ${esc(routing)}</div></article>
        <article class="metric">${icon("zap")}<div class="metric-top">上行</div>
          <div class="metric-value">${fmtRate(data.tx_bps)}</div>
          <div class="metric-hint">各线路合计，实时采样</div></article>
        <article class="metric">${icon("radio")}<div class="metric-top">下行</div>
          <div class="metric-value">${fmtRate(data.rx_bps)}</div>
          <div class="metric-hint">各线路合计，实时采样</div></article>
      </section>
      <section class="panel">
        <div class="panel-head"><div>
          <h2 class="panel-title">公网出口 IP · ${num((data.exit_ips || []).length)}</h2>
          <p class="panel-desc">每条运行中的隧道向 1.1.1.1 查询自己的公网地址。启动后才会出现。</p>
        </div></div>
        <div class="ip-grid">${(data.exit_ips || []).length
          ? data.exit_ips.map((ip) =>
              `<button type="button" class="ip-chip" data-copy="${esc(ip)}" title="复制 ${esc(ip)}">${esc(ip)}</button>`
            ).join("")
          : `<div class="empty">还没有公网 IP。启动线路或点「刷新公网 IP」。</div>`}</div>
      </section>
      <section class="panel">
        <div class="panel-head"><div>
          <h2 class="panel-title">接入端点 · ${num((data.unique_ips || []).length)}</h2>
          <p class="panel-desc">来自扫描结果或官方 MASQUE anycast，一人一址。</p>
        </div></div>
        <div class="ip-grid">${(data.unique_ips || []).length
          ? data.unique_ips.map((ip) =>
              `<button type="button" class="ip-chip" data-copy="${esc(ip)}" title="复制 ${esc(ip)}">${esc(ip)}</button>`
            ).join("")
          : `<div class="empty">先扫描端点，再补齐差异出口。</div>`}</div>
      </section>
      <section class="hero">
        <article class="panel">
          <div class="kicker">统一入口</div>
          <div class="front-url">${esc(front.enabled ? front.url : "入口没有起来")}</div>
          <p class="hint">${esc(front.error || "客户端填写 socks5h 地址。域名在隧道内解析，不经过本机 DNS。")}</p>
          <div class="row-actions" style="margin-top:12px">
            <button class="btn primary" data-copy="${esc(front.url || "")}" ${front.url ? "" : "disabled"}>复制地址</button>
            <button class="btn" data-act="start-all">全部启动</button>
            <button class="btn" data-act="stop-all">全部停止</button>
            <button class="btn primary" id="btn-ensure-exits">补齐差异出口</button>
            <button class="btn" id="btn-refresh-exits">刷新公网 IP</button>
          </div>
        </article>
        <article class="panel">
          <div class="panel-head"><div><h2 class="panel-title">吞吐</h2><p class="panel-desc">来自 /api/status 的实时采样，非模拟数据</p></div></div>
          <div class="chart-box"><canvas id="traffic-chart"></canvas></div>
          <div class="chart-legend"><span><i class="dot up"></i> 上行</span><span><i class="dot down"></i> 下行</span></div>
        </article>
      </section>`;
  }

  function instanceRows() {
    const all = statusCache?.instances || [];
    const { q, status } = instanceQuery.submitted;
    const needle = q.trim().toLowerCase();
    return all.filter((row) => {
      if (status && row.status !== status) return false;
      if (!needle) return true;
      return [row.name, row.endpoint, row.socks_url, row.device, row.exit_ip]
        .join(" ").toLowerCase().includes(needle);
    });
  }

  function renderInstances() {
    const data = statusCache;
    if (!data) return `<div class="state-block">${loading ? "正在加载线路…" : (lastError || "后端无响应")}</div>`;
    const filtered = sortRows(instanceRows(), instancePage.sort, instancePage.dir);
    const slice = pageSlice(filtered, instancePage.page, instancePage.size);
    instancePage.page = slice.page;
    const allChecked = slice.rows.length && slice.rows.every((r) => selectedInstances.has(r.name));
    const rows = slice.rows.map((row) => {
      const checked = selectedInstances.has(row.name) ? "checked" : "";
      const busy = row.status === "running" || row.status === "starting";
      return `<tr class="${checked ? "is-selected" : ""}">
        <td class="check"><input class="checkbox" type="checkbox" data-sel="${esc(row.name)}" ${checked}></td>
        <td class="name" title="${esc(row.name)}">${esc(row.name)}</td>
        <td><span class="pill ${esc(row.status)}">${esc(STATUS_LABEL[row.status] || row.status)}</span></td>
        <td class="addr">${copyCell(row.endpoint || "")}</td>
        <td class="addr">${copyCell(row.exit_ip || "")}${row.exit_colo ? `<div class="muted" style="font-size:11px">${esc(row.exit_colo)}${row.exit_loc ? " · " + esc(row.exit_loc) : ""}</div>` : ""}</td>
        <td class="addr">${copyCell(row.socks_url)}</td>
        <td class="num">${fmtRate(row.tx_bps)}</td>
        <td class="num">${fmtRate(row.rx_bps)}</td>
        <td class="num">${num(row.active)}</td>
        <td class="time">${esc(dash(row.uptime_text))}</td>
        <td class="ops"><div class="ops-cell">
          ${busy
            ? `<button class="btn tiny" data-act="stop" data-name="${esc(row.name)}">停止</button>`
            : `<button class="btn tiny primary" data-act="start" data-name="${esc(row.name)}">启动</button>`}
          <button class="btn tiny" data-act="restart" data-name="${esc(row.name)}">重启</button>
        </div></td>
      </tr>`;
    }).join("");
    return `
      <section class="panel">
        <div class="panel-head"><div>
          <h2 class="panel-title">检索</h2>
          <p class="panel-desc">条件变更后需重新提交。当前结果对应上次提交条件。</p>
        </div></div>
        ${instanceQuery.stale ? `<div class="banner warn">检索条件已改，当前列表仍对应上次提交：名称「${esc(instanceQuery.submitted.q || "全部")}」、状态「${esc(instanceQuery.submitted.status || "全部")}」。</div>` : ""}
        <div class="form-grid">
          <div class="field"><label for="inst-q">名称 / 地址</label>
            <input class="ctl" id="inst-q" value="${esc(instanceQuery.q)}" placeholder="warp1 或 162.159">
            <p class="hint">匹配线路名、端点、SOCKS 地址。</p></div>
          <div class="field"><label for="inst-status">状态</label>
            <select class="ctl" id="inst-status">
              <option value="">全部</option>
              ${Object.entries(STATUS_LABEL).map(([k, v]) =>
                `<option value="${k}" ${instanceQuery.status === k ? "selected" : ""}>${v}</option>`).join("")}
            </select>
            <p class="hint">仅筛选已知业务状态。</p></div>
        </div>
        <div class="form-actions">
          <button class="btn" type="button" id="inst-reset">重置</button>
          <button class="btn primary" type="button" id="inst-search">检索</button>
        </div>
      </section>
      <section class="panel" id="instance-results">
        <div class="result-bar">
          <h2>线路结果 · ${num(slice.total)}</h2>
          <div class="row-actions">
            <button class="btn" data-batch="start">批量启动</button>
            <button class="btn" data-batch="stop">批量停止</button>
            <button class="btn" data-batch="restart">批量重启</button>
            <button class="btn danger" data-batch="remove">批量删除</button>
            <button class="btn" id="btn-ensure-exits">补齐差异出口</button>
            <button class="btn" id="btn-refresh-exits">刷新公网 IP</button>
            <button class="btn primary" id="btn-add">新增线路</button>
          </div>
        </div>
        <div class="table-wrap" style="margin-top:12px">
          <table class="data">
            <colgroup>
              <col style="width:48px"><col style="width:220px"><col style="width:110px">
              <col style="width:240px"><col style="width:160px"><col style="width:240px"><col style="width:110px">
              <col style="width:110px"><col style="width:80px"><col style="width:160px"><col style="width:132px">
            </colgroup>
            <thead><tr>
              <th class="check"><input class="checkbox" type="checkbox" id="sel-all-inst" ${allChecked ? "checked" : ""}></th>
              <th class="name sortable ${instancePage.sort === "name" ? "is-" + instancePage.dir : ""}" data-sort="name">线路</th>
              <th class="sortable ${instancePage.sort === "status" ? "is-" + instancePage.dir : ""}" data-sort="status">状态</th>
              <th class="addr sortable ${instancePage.sort === "endpoint" ? "is-" + instancePage.dir : ""}" data-sort="endpoint">端点</th>
              <th class="addr sortable ${instancePage.sort === "exit_ip" ? "is-" + instancePage.dir : ""}" data-sort="exit_ip">出口 IP</th>
              <th class="addr">代理地址</th>
              <th class="num">上行</th>
              <th class="num">下行</th>
              <th class="num sortable ${instancePage.sort === "active" ? "is-" + instancePage.dir : ""}" data-sort="active">连接</th>
              <th class="time">在线时长</th>
              <th class="ops">操作</th>
            </tr></thead>
            <tbody>${rows || `<tr><td colspan="11"><div class="empty">没有符合条件的线路。</div></td></tr>`}</tbody>
          </table>
        </div>
        ${pagerHtml("inst", instancePage, slice.total)}
      </section>`;
  }

  function scanStale() {
    const submitted = scanCache?.submitted || {};
    if (!submitted.profile) return false;
    const ports = (scanDraft.ports || "").replace(/\s+/g, "");
    const submittedPorts = (submitted.ports || []).join(",");
    return scanDraft.profile !== submitted.profile
      || scanDraft.family !== (submitted.family || "both")
      || ports !== submittedPorts
      || Number(scanDraft.concurrency) !== Number(submitted.concurrency);
  }

  function renderEndpoints() {
    const scan = scanCache;
    if (!scan) return `<div class="state-block">${loading ? "正在加载端点…" : "扫描器不可用"}</div>`;
    const live = sortRows(scan.live || [], endpointPage.sort, endpointPage.dir);
    const slice = pageSlice(live, endpointPage.page, endpointPage.size);
    endpointPage.page = slice.page;
    const scanning = !!scan.scanning;
    const allChecked = slice.rows.length && slice.rows.every((r) => selectedEndpoints.has(r.target));
    const rows = slice.rows.map((row) => {
      const loss = row.loss == null ? "—" : `${Math.round((row.loss <= 1 ? row.loss * 100 : row.loss))}%`;
      const lat = row.latency == null ? "—" : `${Math.round(row.latency * (row.latency < 10 ? 1000 : 1))} ms`;
      const checked = selectedEndpoints.has(row.target) ? "checked" : "";
      return `<tr class="${checked ? "is-selected" : ""}">
        <td class="check"><input class="checkbox" type="checkbox" data-epsel="${esc(row.target)}" ${checked}></td>
        <td class="num">${num(row.rank)}</td>
        <td class="addr">${copyCell(row.target)}</td>
        <td>${esc(dash(row.transport))}</td>
        <td class="num">${esc(loss)}</td>
        <td class="num">${esc(lat)}</td>
        <td title="${esc((row.owners || []).join(" "))}">${esc((row.owners || []).join(" ") || "—")}</td>
        <td class="ops"><button class="btn tiny primary" data-use-ep="${esc(row.target)}">用它建线</button></td>
      </tr>`;
    }).join("");
    const profiles = scan.profiles || settingsCache?.scan_profiles || {};
    return `
      <section class="panel">
        <div class="panel-head"><div>
          <h2 class="panel-title">扫描范围</h2>
          <p class="panel-desc">扩大候选会显著增加耗时。提交后才会开始新一轮扫描。</p>
        </div>
        <div class="panel-actions">
          <button class="btn danger" id="btn-scan-stop" ${scanning ? "" : "hidden"}>停止扫描</button>
        </div></div>
        ${scan.error ? `<div class="banner err">${esc(scan.error === "scanner disabled" ? "扫描器未启用。请用 waygate webui 启动控制台。" : scan.error)}</div>` : ""}
        ${scanStale() && !scanning ? `<div class="banner warn">扫描条件已改，当前结果仍对应上次提交：${esc(submittedLabel())}。</div>` : ""}
        <div class="form-grid">
          <div class="field"><label for="scan-profile">扫描档案</label>
            <select class="ctl" id="scan-profile">
              ${Object.entries(profiles).map(([id, meta]) =>
                `<option value="${esc(id)}" ${scanDraft.profile === id ? "selected" : ""}>${esc(meta.label || id)}</option>`).join("")}
            </select>
            <p class="hint">${esc(profiles[scanDraft.profile]?.hint || "选择候选规模。")}</p></div>
          <div class="field"><label for="scan-family">地址族</label>
            <select class="ctl" id="scan-family">
              <option value="both" ${scanDraft.family === "both" ? "selected" : ""}>IPv4 与 IPv6</option>
              <option value="v4" ${scanDraft.family === "v4" ? "selected" : ""}>仅 IPv4</option>
              <option value="v6" ${scanDraft.family === "v6" ? "selected" : ""}>仅 IPv6</option>
            </select>
            <p class="hint">差异 IP 池建议同时保留两个地址族。</p></div>
          <div class="field"><label for="scan-ports">端口</label>
            <input class="ctl" id="scan-ports" value="${esc(scanDraft.ports)}" placeholder="443,500,1701">
            <p class="hint">逗号分隔。留空则使用档案默认端口。</p></div>
          <div class="field"><label for="scan-conc">并发</label>
            <input class="ctl" id="scan-conc" type="number" min="1" max="200" value="${esc(scanDraft.concurrency)}">
            <p class="hint">过高会触发设备侧限速。</p></div>
        </div>
        <div class="form-actions">
          <button class="btn" type="button" id="scan-reset">重置</button>
          <button class="btn primary" type="button" id="btn-scan" ${scanning ? "disabled" : ""}>${scanning ? "扫描中…" : "开始扫描"}</button>
        </div>
      </section>
      <section class="panel" id="endpoint-results">
        <div class="result-bar">
          <h2>可用端点 · ${num(slice.total)}${scanning ? ` · 进度 ${num(scan.scanned)} / ${num(scan.total)}` : scan.finished_at ? ` · ${beijing(scan.finished_at)}` : ""}</h2>
          <div class="row-actions">
            <button class="btn primary" id="btn-add-selected-ep">用选中地址建线</button>
          </div>
        </div>
        <p class="hint" style="margin-bottom:12px">只保留握手成功且隧道内收到 DNS 回包的地址。耗时 ${dash(scan.duration)} 秒。</p>
        <div class="table-wrap">
          <table class="data" style="min-width:960px">
            <colgroup>
              <col style="width:48px"><col style="width:72px"><col style="width:240px">
              <col style="width:110px"><col style="width:90px"><col style="width:110px">
              <col style="width:220px"><col style="width:132px">
            </colgroup>
            <thead><tr>
              <th class="check"><input class="checkbox" type="checkbox" id="sel-all-ep" ${allChecked ? "checked" : ""}></th>
              <th class="num sortable ${endpointPage.sort === "rank" ? "is-" + endpointPage.dir : ""}" data-epsort="rank">排名</th>
              <th class="addr sortable ${endpointPage.sort === "target" ? "is-" + endpointPage.dir : ""}" data-epsort="target">地址</th>
              <th>传输</th>
              <th class="num sortable ${endpointPage.sort === "loss" ? "is-" + endpointPage.dir : ""}" data-epsort="loss">丢包</th>
              <th class="num sortable ${endpointPage.sort === "latency" ? "is-" + endpointPage.dir : ""}" data-epsort="latency">时延</th>
              <th>占用线路</th>
              <th class="ops">操作</th>
            </tr></thead>
            <tbody>${rows || `<tr><td colspan="8"><div class="empty">还没有可用端点。提交扫描，或在新增线路时手动填写。</div></td></tr>`}</tbody>
          </table>
        </div>
        ${pagerHtml("ep", endpointPage, slice.total)}
      </section>`;
  }

  function submittedLabel() {
    const s = scanCache?.submitted || {};
    const meta = (scanCache?.profiles || {})[s.profile] || {};
    return `${meta.label || s.profile || "精选"} / ${s.family || "both"} / 并发 ${s.concurrency || "—"}`;
  }

  function renderRouting() {
    const settings = settingsCache || {};
    const routing = settings.routing_mode || "least_load";
    const placement = settings.placement_mode || "unique_ip";
    const rModes = settings.routing_modes || {};
    const pModes = settings.placement_modes || {};
    return `
      <section class="panel">
        <div class="panel-head"><div>
          <h2 class="panel-title">入口分发</h2>
          <p class="panel-desc">点选即生效。差异 IP 优先把流量摊到不同出口。</p>
        </div></div>
        <div class="mode-grid" id="routing-modes">
          ${Object.values(rModes).map((m) => `<button type="button" class="mode-card ${m.id === routing ? "is-active" : ""}" data-routing="${esc(m.id)}">
            <b>${esc(m.label)}</b><span>${esc(m.hint)}</span></button>`).join("")}
        </div>
      </section>
      <section class="panel">
        <div class="panel-head"><div>
          <h2 class="panel-title">新线路落地</h2>
          <p class="panel-desc">点选即生效。差异 IP 会尽量避开已占用地址。</p>
        </div></div>
        <div class="mode-grid" id="placement-modes">
          ${Object.values(pModes).map((m) => `<button type="button" class="mode-card ${m.id === placement ? "is-active" : ""}" data-placement="${esc(m.id)}">
            <b>${esc(m.label)}</b><span>${esc(m.hint)}</span></button>`).join("")}
        </div>
      </section>`;
  }

  function renderAccount() {
    const list = identitiesCache || [];
    const data = statusCache || {};
    const cards = list.length ? list.map((item) => `
      <article class="account-card">
        <div>
          <div class="kicker">设备</div>
          <div class="id-line" title="${esc(item.device_id)}">${esc(item.name)} · ${esc(item.device_id || "未注册")}</div>
        </div>
        <div class="account-sections">
          <section><dt>身份</dt><dd>${esc(item.account_type || "free")} · ${esc(item.transport || "masque")}</dd></section>
          <section><dt>额度</dt><dd>Cloudflare 按设备限流；本控制台不改配额，只展示账号类型。</dd></section>
          <section><dt>隧道地址</dt><dd>${esc(item.address_v4 || "—")}<br>${esc(item.address_v6 || "—")}</dd></section>
          <section><dt>权限</dt><dd>本地操作员可启停、扫描、改调度。密钥留在磁盘，不进入浏览器。</dd></section>
        </div>
        <div class="account-ops">
          <button class="btn" data-copy="${esc(item.device_id || "")}" ${item.device_id ? "" : "disabled"}>复制设备 ID</button>
          <button class="btn" data-act="restart" data-name="${esc(item.name)}">重启线路</button>
        </div>
      </article>`).join("") : `<div class="empty">还没有设备身份。新增线路并启动后会出现在这里。</div>`;
    return `
      <section class="metrics">
        <article class="metric">${icon("layers")}<div class="metric-top">设备数</div>
          <div class="metric-value">${num(list.length)}</div>
          <div class="metric-hint">每条线路独立注册</div></article>
        <article class="metric">${icon("globe")}<div class="metric-top">本机权限</div>
          <div class="metric-value">操作员</div>
          <div class="metric-hint">控制台绑定本机进程</div></article>
        <article class="metric">${icon("zap")}<div class="metric-top">统一入口</div>
          <div class="metric-value" style="font-size:14px">${esc(data.front?.url || "—")}</div>
          <div class="metric-hint">socks5h · 北京时间 ${esc(beijing(Date.now() / 1000))}</div></article>
      </section>
      <section class="account-grid">${cards}</section>`;
  }

  function markInteract() {
    interactingUntil = Date.now() + 2500;
  }
  function captureForm() {
    const q = $("inst-q");
    if (q) instanceQuery.q = q.value;
    const st = $("inst-status");
    if (st) instanceQuery.status = st.value;
    const profile = $("scan-profile");
    if (profile) scanDraft.profile = profile.value;
    const family = $("scan-family");
    if (family) scanDraft.family = family.value;
    const ports = $("scan-ports");
    if (ports) scanDraft.ports = ports.value;
    const conc = $("scan-conc");
    if (conc) scanDraft.concurrency = conc.value;
    instanceQuery.stale = instanceQuery.q !== instanceQuery.submitted.q
      || instanceQuery.status !== instanceQuery.submitted.status;
  }
  function shouldSkipRender() {
    if (modalEl) return true;
    if (Date.now() < interactingUntil) return true;
    const el = document.activeElement;
    if (!el || !main.contains(el)) return false;
    if (el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.tagName === "BUTTON") return true;
    return el.tagName === "INPUT" && el.type !== "checkbox";
  }

  function render(force) {
    if (!force && shouldSkipRender()) return;
    const route = routeName();
    setNav(route);
    const view = {
      overview: renderOverview,
      instances: renderInstances,
      endpoints: renderEndpoints,
      routing: renderRouting,
      account: renderAccount,
    }[route]();
    main.innerHTML = view;
    if (route === "overview") drawChart($("traffic-chart"));
    const summary = statusCache
      ? `${statusCache.running} / ${statusCache.total} 在运行 · ${statusCache.exit_ip_count || 0} 个公网 IP`
      : (lastError || "正在连接…");
    $("toolbar-status").textContent = summary;
    closeDrawer();
  }

  /* ---------- actions ---------- */
  function selectedNames() {
    return [...selectedInstances];
  }
  async function runBatch(action) {
    const names = selectedNames();
    if (!names.length) { toast("先勾选线路"); return; }
    if (action === "remove") {
      openModal({
        title: "删除所选线路",
        desc: `将停止并移除 ${names.length} 条线路，身份文件仍留在磁盘。`,
        confirm: "删除",
        danger: true,
        onConfirm: async () => {
          closeModal();
          const res = await api("/api/batch", "POST", { action, names });
          toast(res.ok === false ? (res.error || "失败") : `已提交 ${action}`);
          selectedInstances.clear();
          refresh();
        },
      });
      return;
    }
    const res = await api("/api/batch", "POST", { action, names });
    toast(res.ok === false ? (res.error || "失败") : `已提交 ${names.length} 条`);
    refresh();
  }

  function openAddDialog() {
    const live = (scanCache && scanCache.live) || [];
    const options = live.map((e) =>
      `<option value="${esc(e.target)}">#${esc(e.rank || "")} ${esc(e.target)}</option>`).join("");
    openModal({
      title: "新增线路",
      desc: "可一次创建多条。落地策略在「调度」页配置，默认优先不同 IP。",
      confirm: "创建并启动",
      body: `
        <div class="form-grid" style="margin-top:12px">
          <div class="field"><label for="add-count">数量</label>
            <input class="ctl" id="add-count" type="number" min="1" max="64" value="1">
            <p class="hint">单次最多 64 条。差异 IP 模式按扫描到的不同地址分配。</p></div>
          <div class="field"><label for="add-endpoint">端点</label>
            <select class="ctl" id="add-endpoint">
              <option value="">按落地策略自动分配</option>${options}
            </select>
            <p class="hint">指定后所有新线路使用同一地址。</p></div>
          <div class="field" style="grid-column:1/-1"><label for="add-manual">或手动填写</label>
            <input class="ctl" id="add-manual" placeholder="162.159.198.2:443">
            <p class="hint">host 或 host:port。IPv6 写成 [addr]:port。</p></div>
        </div>`,
      onConfirm: async (dialog) => {
        const count = Number(dialog.querySelector("#add-count").value || 1);
        const endpoint = (dialog.querySelector("#add-manual").value.trim()
          || dialog.querySelector("#add-endpoint").value);
        closeModal();
        const res = await api("/api/add", "POST", { count, endpoint: endpoint || undefined });
        toast(res.ok === false ? (res.error || "创建失败") : `已创建 ${(res.added || []).length} 条`);
        location.hash = "#/instances";
        refresh();
      },
    });
  }

  main.addEventListener("pointerdown", markInteract);
  main.addEventListener("input", () => { markInteract(); captureForm(); });
  main.addEventListener("change", (ev) => {
    markInteract();
    captureForm();
    if (ev.target.id === "sel-all-inst") {
      const rows = pageSlice(sortRows(instanceRows(), instancePage.sort, instancePage.dir), instancePage.page, instancePage.size).rows;
      rows.forEach((r) => ev.target.checked ? selectedInstances.add(r.name) : selectedInstances.delete(r.name));
      render(true);
    }
    if (ev.target.id === "sel-all-ep") {
      const live = sortRows(scanCache?.live || [], endpointPage.sort, endpointPage.dir);
      const rows = pageSlice(live, endpointPage.page, endpointPage.size).rows;
      rows.forEach((r) => ev.target.checked ? selectedEndpoints.add(r.target) : selectedEndpoints.delete(r.target));
      render(true);
    }
    if (ev.target.dataset.sel) {
      if (ev.target.checked) selectedInstances.add(ev.target.dataset.sel);
      else selectedInstances.delete(ev.target.dataset.sel);
      ev.target.closest("tr").classList.toggle("is-selected", ev.target.checked);
    }
    if (ev.target.dataset.epsel) {
      if (ev.target.checked) selectedEndpoints.add(ev.target.dataset.epsel);
      else selectedEndpoints.delete(ev.target.dataset.epsel);
      ev.target.closest("tr").classList.toggle("is-selected", ev.target.checked);
    }
    if (ev.target.dataset.pagesize) {
      const which = ev.target.dataset.pagesize;
      const size = Number(ev.target.value) || 10;
      if (which === "inst") { instancePage.size = size; instancePage.page = 1; }
      else { endpointPage.size = size; endpointPage.page = 1; }
      render(true);
      scrollResults();
    }
  });

  function scrollResults() {
    const el = $("instance-results") || $("endpoint-results");
    if (!el) return;
    const top = el.getBoundingClientRect().top + window.scrollY - 56;
    window.scrollTo({ top: Math.max(0, top), behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  }

  async function patchSettings(patch) {
    markInteract();
    if (settingsCache) Object.assign(settingsCache, patch);
    document.querySelectorAll("[data-routing]").forEach((el) => {
      el.classList.toggle("is-active", el.dataset.routing === (settingsCache || {}).routing_mode);
    });
    document.querySelectorAll("[data-placement]").forEach((el) => {
      el.classList.toggle("is-active", el.dataset.placement === (settingsCache || {}).placement_mode);
    });
    try {
      const res = await api("/api/settings", "POST", patch);
      if (res.ok === false) {
        toast(res.error || "保存失败");
        return;
      }
      settingsCache = res;
      toast("调度已更新");
    } catch (err) {
      toast(err.message || "保存失败");
    }
  }

  async function startScan() {
    markInteract();
    captureForm();
    const ports = String(scanDraft.ports || "").trim();
    if (scanCache) {
      scanCache.scanning = true;
      scanCache.error = "";
    }
    const btn = $("btn-scan");
    if (btn) { btn.disabled = true; btn.textContent = "扫描中…"; }
    const stop = $("btn-scan-stop");
    if (stop) stop.hidden = false;
    try {
      const res = await api("/api/scan", "POST", {
        profile: scanDraft.profile,
        family: scanDraft.family,
        ports: ports ? ports.split(/[,\s]+/).filter(Boolean) : [],
        concurrency: Number(scanDraft.concurrency) || 60,
      });
      if (res && (res.ok === false || res.error === "scanner disabled")) {
        toast(res.error === "scanner disabled" ? "扫描器未启用" : (res.error || "扫描失败"));
        if (scanCache) { scanCache.scanning = false; scanCache.error = res.error || "扫描失败"; }
      } else {
        scanCache = res;
        toast(res.started === false ? "扫描已在进行" : "已开始扫描");
      }
    } catch (err) {
      toast(err.message || "扫描失败");
      if (scanCache) scanCache.scanning = false;
    }
    render(true);
  }

  main.addEventListener("click", async (ev) => {
    markInteract();
    const copy = ev.target.closest("[data-copy]");
    if (copy) { if (copy.dataset.copy) copyText(copy.dataset.copy); return; }
    if (ev.target.closest("#inst-search")) {
      captureForm();
      instanceQuery.submitted = { q: instanceQuery.q, status: instanceQuery.status };
      instanceQuery.stale = false;
      instancePage.page = 1;
      render(true);
      scrollResults();
      return;
    }
    if (ev.target.closest("#inst-reset")) {
      instanceQuery = { q: "", status: "", submitted: { q: "", status: "" }, stale: false };
      instancePage.page = 1;
      render(true);
      return;
    }
    if (ev.target.closest("#btn-add")) { openAddDialog(); return; }
    if (ev.target.closest("#btn-ensure-exits")) {
      const res = await api("/api/ensure-exits", "POST", {});
      toast(res.ok === false ? (res.error || "失败") : `已按 ${res.available} 个可用地址补齐 ${res.unique_hosts} 条，正在启动并查询公网 IP`);
      location.hash = "#/instances";
      refresh(true);
      return;
    }
    if (ev.target.closest("#btn-refresh-exits")) {
      const res = await api("/api/refresh-exits", "POST", {});
      toast(res.ok === false ? (res.error || "失败") : `已查到 ${res.exit_ip_count || 0} 个公网 IP`);
      refresh(true);
      return;
    }
    if (ev.target.closest("#btn-scan")) { await startScan(); return; }
    if (ev.target.closest("#btn-scan-stop")) {
      await api("/api/scan/stop", "POST");
      toast("正在停止扫描");
      refresh(true);
      return;
    }
    if (ev.target.closest("#scan-reset")) {
      scanDraft = { profile: "curated", family: "both", ports: "443,500,1701,4500", concurrency: 60 };
      render(true);
      return;
    }
    if (ev.target.closest("#btn-add-selected-ep")) {
      const endpoints = [...selectedEndpoints];
      if (!endpoints.length) { toast("先勾选端点"); return; }
      const res = await api("/api/add", "POST", { endpoints });
      toast(res.ok === false ? (res.error || "失败") : `已创建 ${(res.added || []).length} 条`);
      selectedEndpoints.clear();
      location.hash = "#/instances";
      refresh(true);
      return;
    }
    const useEp = ev.target.closest("[data-use-ep]");
    if (useEp) {
      const res = await api("/api/add", "POST", { endpoint: useEp.dataset.useEp, count: 1 });
      toast(res.ok === false ? (res.error || "失败") : "已创建");
      refresh(true);
      return;
    }
    const batch = ev.target.closest("[data-batch]");
    if (batch) { runBatch(batch.dataset.batch); return; }
    const sort = ev.target.closest("[data-sort]");
    if (sort) {
      const key = sort.dataset.sort;
      if (instancePage.sort === key) instancePage.dir = instancePage.dir === "asc" ? "desc" : "asc";
      else { instancePage.sort = key; instancePage.dir = "asc"; }
      render(true);
      return;
    }
    const epsort = ev.target.closest("[data-epsort]");
    if (epsort) {
      const key = epsort.dataset.epsort;
      if (endpointPage.sort === key) endpointPage.dir = endpointPage.dir === "asc" ? "desc" : "asc";
      else { endpointPage.sort = key; endpointPage.dir = "asc"; }
      render(true);
      return;
    }
    const pageBtn = ev.target.closest("[data-page]");
    if (pageBtn && !pageBtn.disabled) {
      const [which, dir] = pageBtn.dataset.page.split(":");
      const state = which === "inst" ? instancePage : endpointPage;
      state.page += dir === "next" ? 1 : -1;
      render(true);
      scrollResults();
      return;
    }
    const routing = ev.target.closest("[data-routing]");
    if (routing) {
      await patchSettings({ routing_mode: routing.dataset.routing });
      return;
    }
    const placement = ev.target.closest("[data-placement]");
    if (placement) {
      await patchSettings({ placement_mode: placement.dataset.placement });
      return;
    }
    const act = ev.target.closest("[data-act]");
    if (!act) return;
    const name = act.dataset.name || "";
    const q = name ? `?name=${encodeURIComponent(name)}` : "";
    const res = await api(`/api/${act.dataset.act}${q}`, "POST");
    if (res && res.ok === false) toast(res.error || "操作失败");
    refresh(true);
  });

  main.addEventListener("keydown", (ev) => {
    markInteract();
    if (ev.key !== "Enter") return;
    const jump = ev.target.dataset.pagejump;
    if (!jump) return;
    const state = jump === "inst" ? instancePage : endpointPage;
    state.page = Number(ev.target.value) || 1;
    render(true);
    scrollResults();
  });

  let refreshQueued = false;
  async function refresh(forceRender) {
    if (refreshInFlight) {
      if (forceRender) refreshQueued = true;
      return;
    }
    refreshInFlight = true;
    try {
      const [status, settings, scan, identities] = await Promise.all([
        api("/api/status"),
        api("/api/settings"),
        api("/api/scan"),
        api("/api/identities"),
      ]);
      if (!status || !status.instances) throw new Error("后端无响应");
      statusCache = status;
      settingsCache = settings;
      scanCache = scan;
      identitiesCache = identities.identities || [];
      lastError = "";
      loading = false;
      recordTraffic(status);
    } catch (err) {
      lastError = err.message || "后端无响应";
      loading = false;
    } finally {
      refreshInFlight = false;
    }
    const summary = statusCache
      ? `${statusCache.running} / ${statusCache.total} 在运行 · ${statusCache.exit_ip_count || 0} 个公网 IP`
      : (lastError || "正在连接…");
    $("toolbar-status").textContent = summary;
    if (refreshQueued) {
      refreshQueued = false;
      return refresh(true);
    }
    if (forceRender) render(true);
    else if (!shouldSkipRender()) render();
    else if (routeName() === "overview") drawChart($("traffic-chart"));
  }

  window.addEventListener("hashchange", () => render(true));
  applyTheme();
  applyCollapse();
  if (!location.hash) location.hash = "#/overview";
  refresh(true);
  setInterval(() => refresh(false), 1000);
})();
