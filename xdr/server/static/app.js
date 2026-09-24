/* SentinelXDR console - SPA sin dependencias. Todo dato externo se escapa con esc(). */
"use strict";
(function () {
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const SEV_LABEL = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", info: "Info" };
  const STATUS_LABEL = { open: "Abierta", investigating: "Investigando", closed: "Cerrada", false_positive: "Falso positivo" };
  const ACTION_LABEL = {
    kill_process: "Matar proceso", suspend_process: "Suspender proceso", quarantine_file: "Cuarentena",
    block_ip: "Bloquear IP", unblock_ip: "Desbloquear IP", isolate_host: "Aislar host", release_host: "Liberar host",
    disable_user: "Bloquear usuario", enable_user: "Desbloquear usuario", kill_user_sessions: "Cerrar sesiones",
    collect_forensics: "Recolección forense", kill_top_writer: "Matar proceso cifrador", scan_path: "Escanear ruta",
    restore_file: "Restaurar de cuarentena", list_quarantine: "Listar cuarentena", run_posture: "Evaluar postura",
    delete_file: "Borrar fichero", resume_process: "Reanudar proceso",
  };
  const VIEWS = {
    overview: ["Resumen", renderOverview], incidents: ["Incidentes", renderIncidents], alerts: ["Alertas", renderAlerts],
    hunt: ["Threat hunting", renderHunt], endpoints: ["Endpoints", renderEndpoints], posture: ["Postura de seguridad", renderPosture],
    mitre: ["Cobertura MITRE ATT&CK", renderMitre], intel: ["Inteligencia de amenazas", renderIntel],
    response: ["Acciones de respuesta", renderResponse], rules: ["Reglas de detección", renderRules],
  };
  let token = null;
  try { token = localStorage.getItem("xdr_token"); } catch (e) { /* almacenamiento no disponible */ }
  let current = "overview";
  let timer = null;
  const $ = (s, r = document) => r.querySelector(s);
  const view = () => $("#view");

  function esc(v) {
    return String(v === undefined || v === null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function ts(t) { return t ? new Date(t * 1000).toLocaleString() : "—"; }
  function ago(t) {
    if (!t) return "nunca";
    const s = Math.max(0, Date.now() / 1000 - t);
    if (s < 60) return `hace ${Math.round(s)} s`;
    if (s < 3600) return `hace ${Math.round(s / 60)} min`;
    if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
    return `hace ${Math.round(s / 86400)} d`;
  }
  const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(SEV_LABEL[s] || s)}</span>`;
  const hours = () => $("#range").value;

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      method: opts.method || "GET",
      headers: Object.assign({ Authorization: `Bearer ${token}` }, opts.body ? { "Content-Type": "application/json" } : {}),
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (res.status === 401) { logout(); throw new Error("no autorizado"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    $("#live").classList.remove("off");
    return data;
  }
  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.remove("hidden");
    clearTimeout(t._h);
    t._h = setTimeout(() => t.classList.add("hidden"), 3500);
  }

  // ------------------------------------------------------------------ auth
  function showLogin() { $("#login").classList.remove("hidden"); $("#app").classList.add("hidden"); }
  function logout() {
    token = null;
    try { localStorage.removeItem("xdr_token"); } catch (e) { /* noop */ }
    clearInterval(timer);
    showLogin();
  }
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    token = $("#token").value.trim();
    try {
      await api("/api/overview?hours=1");
      try { localStorage.setItem("xdr_token", token); } catch (err) { /* noop */ }
      start();
    } catch (err) { $("#login-error").textContent = "Token inválido o servidor no disponible"; }
  });
  $("#logout").addEventListener("click", logout);
  $("#theme-toggle").addEventListener("click", () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("xdr_theme", root.dataset.theme); } catch (e) { /* noop */ }
    render();
  });
  try { const t = localStorage.getItem("xdr_theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* noop */ }

  function start() {
    $("#login").classList.add("hidden");
    $("#app").classList.remove("hidden");
    const hash = location.hash.replace("#", "");
    if (VIEWS[hash]) current = hash;
    render();
    clearInterval(timer);
    timer = setInterval(() => { if ($("#drawer").classList.contains("hidden") && !document.activeElement.matches("input,textarea")) render(true); }, 15000);
  }
  $("#nav").addEventListener("click", (e) => {
    const a = e.target.closest("a[data-view]");
    if (!a) return;
    current = a.dataset.view;
    location.hash = current;
    render();
  });
  $("#range").addEventListener("change", () => render());

  async function render(silent) {
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === current));
    const [title, fn] = VIEWS[current];
    $("#view-title").textContent = title;
    try { await fn(silent); } catch (err) {
      $("#live").classList.add("off");
      if (!silent) view().innerHTML = `<div class="card error">Error: ${esc(err.message)}</div>`;
    }
  }

  // ------------------------------------------------------------- tooltip
  const tip = $("#tooltip");
  document.addEventListener("mousemove", (e) => {
    const el = e.target.closest("[data-tip]");
    if (!el) { tip.classList.add("hidden"); return; }
    tip.innerHTML = el.dataset.tip;
    tip.classList.remove("hidden");
    const x = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8);
    tip.style.left = `${x}px`;
    tip.style.top = `${e.clientY + 14}px`;
  });

  // -------------------------------------------------------------- charts
  function stackedTimeline(timeline, bucket, hrs) {
    const now = Date.now() / 1000;
    const start = Math.floor((now - hrs * 3600) / bucket) * bucket;
    const n = Math.min(200, Math.ceil((now - start) / bucket));
    const buckets = [];
    for (let i = 0; i < n; i++) buckets.push({ t: start + i * bucket, v: {} });
    const idx = new Map(buckets.map((b, i) => [b.t, i]));
    timeline.forEach((r) => { const i = idx.get(r.bucket); if (i !== undefined) buckets[i].v[r.severity] = (buckets[i].v[r.severity] || 0) + r.count; });
    const order = ["info", "low", "medium", "high", "critical"];
    const max = Math.max(1, ...buckets.map((b) => order.reduce((s, k) => s + (b.v[k] || 0), 0)));
    const W = 800, H = 220, L = 34, B = 22, T = 8;
    const bw = (W - L) / n;
    const y = (v) => H - B - (v / max) * (H - B - T);
    let svg = `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Alertas por severidad en el tiempo">`;
    const ticks = [0, Math.ceil(max / 2), max];
    ticks.forEach((t) => { svg += `<line x1="${L}" x2="${W}" y1="${y(t)}" y2="${y(t)}" stroke="var(--grid)" stroke-width="1"/><text x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${t}</text>`; });
    buckets.forEach((b, i) => {
      let acc = 0;
      const x = L + i * bw + Math.min(2, bw * 0.15);
      const w = Math.max(1, bw - Math.min(4, bw * 0.3));
      const total = order.reduce((s, k) => s + (b.v[k] || 0), 0);
      const lines = SEVS.filter((k) => b.v[k]).map((k) => `${esc(SEV_LABEL[k])}: <b>${b.v[k]}</b>`).join("<br>");
      const tipHtml = esc(new Date(b.t * 1000).toLocaleString()) + "<br>" + (lines || "Sin alertas");
      order.forEach((k) => {
        const v = b.v[k] || 0;
        if (!v) return;
        const y0 = y(acc), y1 = y(acc + v);
        const top = acc + v === total;
        const hgt = Math.max(1, y0 - y1 - (acc > 0 ? 2 : 0));
        svg += `<rect x="${x}" y="${y1}" width="${w}" height="${hgt}" rx="${top ? Math.min(4, w / 2) : 0}" fill="var(--sev-${k})"/>`;
        acc += v;
      });
      svg += `<rect x="${L + i * bw}" y="${T}" width="${bw}" height="${H - B - T}" fill="transparent" data-tip="${esc(tipHtml)}"/>`;
    });
    svg += `<line x1="${L}" x2="${W}" y1="${H - B}" y2="${H - B}" stroke="var(--axis)"/>`;
    const labelEvery = Math.ceil(n / 6);
    buckets.forEach((b, i) => {
      if (i % labelEvery) return;
      const d = new Date(b.t * 1000);
      const lbl = bucket >= 3600 && hrs > 24 ? `${d.getDate()}/${d.getMonth() + 1}` : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      svg += `<text x="${L + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${esc(lbl)}</text>`;
    });
    svg += "</svg>";
    const legend = `<div class="legend">${SEVS.map((k) => `<span><i style="--c:var(--sev-${k})"></i>${SEV_LABEL[k]}</span>`).join("")}</div>`;
    return legend + svg;
  }
  function hbars(items, label) {
    if (!items.length) return `<div class="empty">Sin datos</div>`;
    const max = Math.max(...items.map((i) => i.value), 1);
    return items.map((i) => `<div class="hbar" data-tip="${esc(esc(i.name))}: <b>${i.value}</b> ${esc(label)}"><span class="name">${esc(i.name)}</span><span class="track"><span class="fill" style="width:${(i.value / max) * 100}%"></span></span><span class="num">${i.value}</span></div>`).join("");
  }
  function scoreColor(s) { return s === null || s === undefined ? "var(--muted)" : s >= 80 ? "var(--good)" : s >= 60 ? "var(--sev-medium)" : "var(--sev-critical)"; }

  // ------------------------------------------------------------- overview
  async function renderOverview() {
    const o = await api(`/api/overview?hours=${hours()}`);
    const s = o.alerts.by_severity;
    const openAlerts = o.alerts.by_status.open || 0;
    const tactics = Object.entries(o.alerts.by_tactic).map(([k, v]) => ({ name: (o.tactics[k] || {}).name || k, value: v })).sort((a, b) => b.value - a.value);
    const hostsList = Object.entries(o.alerts.by_host).map(([k, v]) => ({ name: k, value: v })).sort((a, b) => b.value - a.value).slice(0, 8);
    const riskCol = o.risk_score >= 60 ? "var(--sev-critical)" : o.risk_score >= 25 ? "var(--sev-medium)" : "var(--good)";
    const evTotal = Object.values(o.events).reduce((a, b) => a + b, 0);
    view().innerHTML = `
      <div class="grid kpis">
        <div class="card kpi"><div class="label">Riesgo actual</div><div class="value">${o.risk_score}<span class="muted" style="font-size:14px">/100</span></div><div class="meter"><span style="width:${o.risk_score}%;background:${riskCol}"></span></div></div>
        <div class="card kpi"><div class="label">Incidentes abiertos</div><div class="value">${o.incidents.open}</div><div class="sub">${o.incidents.critical} críticos</div></div>
        <div class="card kpi"><div class="label">Alertas abiertas</div><div class="value">${openAlerts}</div><div class="sub">${s.critical || 0} críticas · ${s.high || 0} altas en el periodo</div></div>
        <div class="card kpi"><div class="label">Endpoints</div><div class="value">${o.agents.online}<span class="muted" style="font-size:14px">/${o.agents.total}</span></div><div class="sub">en línea · ${o.agents.isolated} aislados</div></div>
        <div class="card kpi"><div class="label">Postura media</div><div class="value" style="color:${scoreColor(o.posture.average)}">${o.posture.average ?? "—"}</div><div class="sub">puntuación de hardening</div></div>
        <div class="card kpi"><div class="label">Telemetría</div><div class="value">${evTotal.toLocaleString()}</div><div class="sub">eventos en el periodo</div></div>
      </div>
      <div class="grid two" style="margin-top:16px">
        <div class="card"><h2>Alertas por severidad</h2>${stackedTimeline(o.timeline, o.bucket, Number(hours()))}</div>
        <div class="card"><h2>Tácticas MITRE observadas</h2>${hbars(tactics, "alertas")}</div>
      </div>
      <div class="grid two" style="margin-top:16px">
        <div class="card"><h2>Incidentes activos</h2>${incidentTable(o.incidents.recent)}</div>
        <div class="card"><h2>Hosts con más alertas</h2>${hbars(hostsList, "alertas")}<h2 style="margin-top:18px">Reglas más activas</h2>${hbars(o.alerts.top_rules.slice(0, 6).map((r) => ({ name: `${r.rule_id} · ${r.title}`, value: r.count })), "alertas")}</div>
      </div>`;
    bindIncidentRows();
  }

  // ------------------------------------------------------------ incidents
  function incidentTable(list) {
    if (!list.length) return `<div class="empty">No hay incidentes abiertos 🎉</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>Severidad</th><th>Incidente</th><th>Hosts</th><th>Tácticas</th><th>Alertas</th><th>Puntuación</th><th>Actualizado</th><th>Estado</th></tr></thead><tbody>${list.map((i) => `
      <tr class="click" data-inc="${esc(i.id)}"><td>${sev(i.severity)}</td><td>${esc(i.title)}</td><td>${esc((i.hosts || []).join(", "))}</td>
      <td>${(i.tactics || []).map((t) => `<span class="pill">${esc(t)}</span>`).join(" ")}</td><td>${i.alerts}</td><td>${i.score}</td><td>${ago(i.ts_update)}</td><td>${esc(STATUS_LABEL[i.status] || i.status)}</td></tr>`).join("")}</tbody></table></div>`;
  }
  function bindIncidentRows() { view().querySelectorAll("tr[data-inc]").forEach((tr) => tr.addEventListener("click", () => openIncident(tr.dataset.inc))); }
  async function renderIncidents() {
    const status = (view().querySelector("#inc-status") || {}).value ?? "";
    const list = await api(`/api/incidents${status ? `?status=${encodeURIComponent(status)}` : ""}`);
    view().innerHTML = `<div class="filters"><select id="inc-status"><option value="">Todos</option>${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}" ${k === status ? "selected" : ""}>${v}</option>`).join("")}</select></div><div class="card">${incidentTable(list)}</div>`;
    $("#inc-status").addEventListener("change", () => renderIncidents());
    bindIncidentRows();
  }
  async function openIncident(id) {
    const inc = await api(`/api/incidents/${id}`);
    openDrawer(`
      <h2>${esc(inc.title)}</h2><div>${sev(inc.severity)} · <span class="pill">${esc(STATUS_LABEL[inc.status] || inc.status)}</span> · puntuación ${inc.score}</div>
      <dl class="kv"><dt>Hosts</dt><dd>${esc(inc.hosts.join(", "))}</dd><dt>Inicio</dt><dd>${ts(inc.ts_start)}</dd><dt>Última actividad</dt><dd>${ts(inc.ts_update)}</dd>
      <dt>Tácticas</dt><dd>${inc.tactics.map((t) => `<span class="pill">${esc(t)}</span>`).join(" ")}</dd>
      <dt>Técnicas</dt><dd>${Object.entries(inc.mitre_names).map(([k, v]) => `<span class="pill" title="${esc(v)}">${esc(k)} ${esc(v)}</span>`).join(" ")}</dd>
      <dt>Entidades</dt><dd class="mono">${esc((inc.entities || []).slice(0, 30).join("  ·  "))}</dd></dl>
      <div class="actions">${["investigating", "closed", "false_positive", "open"].map((s) => `<button class="btn small" data-incstatus="${s}">${STATUS_LABEL[s]}</button>`).join("")}</div>
      <h3>Cronología</h3><div class="timeline">${inc.timeline.slice().reverse().map((t) => `<div class="item" style="--c:var(--sev-${esc(t.severity)})"><a data-alert="${esc(t.alert_id)}">${esc(t.title)}</a><div class="muted">${ts(t.ts)} · ${esc(t.host)} · ${esc(t.tactic || "")}</div></div>`).join("")}</div>`);
    $("#drawer-body").querySelectorAll("[data-incstatus]").forEach((b) => b.addEventListener("click", async () => {
      await api(`/api/incidents/${id}/status`, { method: "POST", body: { status: b.dataset.incstatus } });
      toast("Estado actualizado"); openIncident(id);
    }));
    $("#drawer-body").querySelectorAll("[data-alert]").forEach((a) => a.addEventListener("click", () => openAlert(a.dataset.alert)));
  }

  // --------------------------------------------------------------- alerts
  async function renderAlerts() {
    const prev = { status: $("#f-status")?.value ?? "open", severity: $("#f-sev")?.value ?? "", host: $("#f-host")?.value ?? "" };
    const q = new URLSearchParams({ hours: hours(), limit: 500 });
    if (prev.status) q.set("status", prev.status);
    if (prev.severity) q.set("severity", prev.severity);
    if (prev.host) q.set("host", prev.host);
    const list = await api(`/api/alerts?${q}`);
    view().innerHTML = `
      <div class="filters">
        <select id="f-status"><option value="">Todos los estados</option>${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}" ${k === prev.status ? "selected" : ""}>${v}</option>`).join("")}</select>
        <select id="f-sev"><option value="">Cualquier severidad</option>${SEVS.map((k) => `<option value="${k}" ${k === prev.severity ? "selected" : ""}>≥ ${SEV_LABEL[k]}</option>`).join("")}</select>
        <input id="f-host" placeholder="Host" value="${esc(prev.host)}">
        <button class="btn" id="f-apply">Filtrar</button><span class="muted">${list.length} alertas</span>
      </div>
      <div class="card table-wrap">${list.length ? `<table><thead><tr><th>Severidad</th><th>Hora</th><th>Host</th><th>Regla</th><th>Título</th><th>Detalle</th><th>Respuesta</th><th>Estado</th></tr></thead><tbody>${list.map((a) => `
        <tr class="click" data-alert="${esc(a.id)}"><td>${sev(a.severity)}</td><td>${ts(a.timestamp)}</td><td>${esc(a.host)}</td><td class="mono">${esc(a.rule_id)}</td><td>${esc(a.title)}</td>
        <td class="trunc mono">${esc(alertDetail(a))}</td><td>${(a.response || []).map((r) => `<span class="pill ${r.success ? "on" : "warn"}">${esc(ACTION_LABEL[r.action] || r.action)}</span>`).join(" ")}</td><td>${esc(STATUS_LABEL[a.status] || a.status)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">Sin alertas con estos filtros</div>`}</div>`;
    $("#f-apply").addEventListener("click", () => renderAlerts());
    ["#f-status", "#f-sev"].forEach((s) => $(s).addEventListener("change", () => renderAlerts()));
    view().querySelectorAll("tr[data-alert]").forEach((tr) => tr.addEventListener("click", () => openAlert(tr.dataset.alert)));
  }
  function alertDetail(a) {
    const d = (a.event || {}).data || {};
    return d.cmdline || d.path || d.raw || (d.remote_ip ? `${d.process || ""} → ${d.remote_ip}:${d.remote_port}` : "") || d.module || d.user || a.description || "";
  }
  async function openAlert(id) {
    const a = await api(`/api/alerts/${id}`);
    const d = (a.event || {}).data || {};
    const acts = ["kill_process", "quarantine_file", "block_ip", "disable_user", "isolate_host", "collect_forensics"];
    const fields = ["pid", "name", "exe", "cmdline", "username", "user", "path", "sha256", "exe_hash", "src_ip", "remote_ip", "remote_port", "process", "mechanism", "module", "command"].filter((k) => d[k] !== undefined && d[k] !== "" && d[k] !== null);
    openDrawer(`
      <h2>${esc(a.title)}</h2><div>${sev(a.severity)} · <span class="mono">${esc(a.rule_id)}</span> · ${esc(a.source)} · <span class="pill">${esc(STATUS_LABEL[a.status] || a.status)}</span></div>
      <p>${esc(a.description)}</p>
      <dl class="kv"><dt>Host</dt><dd>${esc(a.host)}</dd><dt>Fecha</dt><dd>${ts(a.timestamp)}</dd><dt>Táctica</dt><dd>${esc(a.tactic)}</dd><dt>MITRE</dt><dd>${(a.mitre || []).map((m) => `<span class="pill">${esc(m)}</span>`).join(" ")}</dd>
      ${fields.map((k) => `<dt>${esc(k)}</dt><dd class="mono">${esc(typeof d[k] === "object" ? JSON.stringify(d[k]) : d[k])}</dd>`).join("")}
      ${a.incident_id ? `<dt>Incidente</dt><dd><a data-inc="${esc(a.incident_id)}">ver incidente</a></dd>` : ""}</dl>
      <h3>Respuesta</h3>
      ${(a.response || []).map((r) => `<div><span class="pill ${r.success ? "on" : "warn"}">${r.automatic ? "auto" : "manual"}</span> ${esc(ACTION_LABEL[r.action] || r.action)} — ${esc(r.message)}</div>`).join("") || `<div class="muted">Sin acciones automáticas.</div>`}
      <div class="actions">${acts.map((x) => `<button class="btn small ${x === "isolate_host" ? "danger" : ""}" data-act="${x}">${ACTION_LABEL[x]}</button>`).join("")}</div>
      <div class="actions">${["investigating", "closed", "false_positive"].map((s) => `<button class="btn small ghost" data-st="${s}">Marcar: ${STATUS_LABEL[s]}</button>`).join("")}</div>
      <h3>Contexto</h3><pre class="json">${esc(JSON.stringify(a.context, null, 2))}</pre>
      <h3>Evento original</h3><pre class="json">${esc(JSON.stringify(a.event, null, 2))}</pre>`);
    const body = $("#drawer-body");
    body.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", async () => {
      if (b.dataset.act === "isolate_host" && !confirm(`¿Aislar de la red el host ${a.host}?`)) return;
      try { await api(`/api/alerts/${id}/respond`, { method: "POST", body: { action: b.dataset.act } }); toast(`${ACTION_LABEL[b.dataset.act]} enviada al agente`); } catch (e) { toast(`Error: ${e.message}`); }
    }));
    body.querySelectorAll("[data-st]").forEach((b) => b.addEventListener("click", async () => {
      await api(`/api/alerts/${id}/status`, { method: "POST", body: { status: b.dataset.st } }); toast("Estado actualizado"); openAlert(id);
    }));
    const inc = body.querySelector("[data-inc]");
    if (inc) inc.addEventListener("click", () => openIncident(inc.dataset.inc));
  }

  // ----------------------------------------------------------------- hunt
  async function renderHunt() {
    const prev = { q: $("#h-q")?.value ?? "", category: $("#h-cat")?.value ?? "", action: $("#h-act")?.value ?? "", host: $("#h-host")?.value ?? "" };
    const qs = new URLSearchParams({ hours: hours(), limit: 300 });
    Object.entries(prev).forEach(([k, v]) => { if (v) qs.set(k, v); });
    const list = await api(`/api/events?${qs}`);
    const cats = ["process", "network", "file", "auth", "persistence", "account", "kernel", "device", "resource", "posture"];
    view().innerHTML = `
      <div class="filters">
        <input id="h-q" placeholder="Buscar texto (cmdline, ruta, IP, usuario...)" value="${esc(prev.q)}" style="min-width:280px">
        <select id="h-cat"><option value="">Categoría</option>${cats.map((c) => `<option ${c === prev.category ? "selected" : ""}>${c}</option>`).join("")}</select>
        <input id="h-act" placeholder="Acción (start, connection...)" value="${esc(prev.action)}">
        <input id="h-host" placeholder="Host" value="${esc(prev.host)}">
        <button class="btn primary" id="h-go">Buscar</button><span class="muted">${list.length} eventos</span>
      </div>
      <div class="card table-wrap">${list.length ? `<table><thead><tr><th>Hora</th><th>Host</th><th>Categoría</th><th>Acción</th><th>Detalle</th></tr></thead><tbody>${list.map((e, i) => `
        <tr class="click" data-ev="${i}"><td>${ts(e.timestamp)}</td><td>${esc(e.host)}</td><td><span class="pill">${esc(e.category)}</span></td><td>${esc(e.action)}</td><td class="trunc mono">${esc(alertDetail({ event: e }) || JSON.stringify(e.data).slice(0, 200))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">Sin resultados</div>`}</div>`;
    $("#h-go").addEventListener("click", () => renderHunt());
    $("#h-q").addEventListener("keydown", (e) => { if (e.key === "Enter") renderHunt(); });
    view().querySelectorAll("tr[data-ev]").forEach((tr) => tr.addEventListener("click", () => openDrawer(`<h2>${esc(list[tr.dataset.ev].category)} / ${esc(list[tr.dataset.ev].action)}</h2><pre class="json">${esc(JSON.stringify(list[tr.dataset.ev], null, 2))}</pre>`)));
  }

  // ------------------------------------------------------------ endpoints
  async function renderEndpoints() {
    const agents = await api("/api/agents");
    view().innerHTML = `<div class="card table-wrap">${agents.length ? `<table><thead><tr><th>Host</th><th>Estado</th><th>SO</th><th>IP</th><th>Versión</th><th>Alertas abiertas</th><th>Postura</th><th>Último contacto</th><th>Acciones</th></tr></thead><tbody>${agents.map((a) => `
      <tr><td><b>${esc(a.hostname)}</b></td><td>${a.online ? `<span class="pill on">● en línea</span>` : `<span class="pill">desconectado</span>`} ${a.isolated ? `<span class="pill warn">aislado</span>` : ""}</td>
      <td>${esc(a.info.os || "")} ${esc(a.info.os_release || "")}</td><td class="mono">${esc(a.info.ip || "")}</td><td>${esc(a.info.version || "")}</td><td>${a.open_alerts}</td>
      <td style="color:${scoreColor(a.posture_score)}">${a.posture_score ?? "—"}</td><td>${ago(a.last_seen)}</td>
      <td class="actions" style="margin:0">
        <button class="btn small" data-agent="${esc(a.id)}" data-a="collect_forensics">Forense</button>
        <button class="btn small" data-agent="${esc(a.id)}" data-a="run_posture">Postura</button>
        <button class="btn small" data-agent="${esc(a.id)}" data-a="scan">Escanear</button>
        ${a.isolated ? `<button class="btn small" data-agent="${esc(a.id)}" data-a="release_host">Liberar</button>` : `<button class="btn small danger" data-agent="${esc(a.id)}" data-a="isolate_host">Aislar</button>`}
        <button class="btn small ghost" data-detail="${esc(a.id)}">Detalle</button>
      </td></tr>`).join("")}</tbody></table>` : `<div class="empty">No hay agentes registrados. Instala uno con <code>sentinel-xdr agent --server URL --enroll-key CLAVE</code></div>`}</div>`;
    view().querySelectorAll("[data-a]").forEach((b) => b.addEventListener("click", async () => {
      let action = b.dataset.a, params = {};
      if (action === "isolate_host" && !confirm("¿Aislar este equipo de la red? Solo podrá comunicarse con el servidor XDR.")) return;
      if (action === "scan") { const p = prompt("Ruta a escanear", "/tmp"); if (!p) return; action = "scan_path"; params = { path: p }; }
      try { await api("/api/commands", { method: "POST", body: { agent_id: b.dataset.agent, action, params } }); toast(`${ACTION_LABEL[action]} en cola`); } catch (e) { toast(`Error: ${e.message}`); }
    }));
    view().querySelectorAll("[data-detail]").forEach((b) => b.addEventListener("click", () => {
      const a = agents.find((x) => x.id === b.dataset.detail);
      const cols = (a.info.collectors || []).map((c) => `<tr><td>${esc(c.name)}</td><td>${c.interval}s</td><td>${c.runs}</td><td>${c.errors}</td><td>${ago(c.last_run)}</td></tr>`).join("");
      openDrawer(`<h2>${esc(a.hostname)}</h2><dl class="kv"><dt>ID</dt><dd class="mono">${esc(a.id)}</dd><dt>Plataforma</dt><dd>${esc(a.info.platform)}</dd><dt>CPU / RAM</dt><dd>${esc(a.info.cpu_count)} CPU · ${Math.round((a.info.memory || 0) / 1073741824)} GB</dd><dt>Detección</dt><dd>${esc(JSON.stringify(a.info.detection))}</dd><dt>Cola / pendientes</dt><dd>${esc(a.info.queue)} / ${esc(a.info.outbox)}</dd></dl><h3>Sensores</h3><table><thead><tr><th>Sensor</th><th>Intervalo</th><th>Ciclos</th><th>Errores</th><th>Última ejecución</th></tr></thead><tbody>${cols}</tbody></table>`);
    }));
  }

  // -------------------------------------------------------------- posture
  async function renderPosture() {
    const items = await api("/api/posture");
    if (!items.length) { view().innerHTML = `<div class="card empty">Aún no hay evaluaciones de postura.</div>`; return; }
    const hosts = [...new Set(items.map((i) => i.host))];
    view().innerHTML = hosts.map((h) => {
      const rows = items.filter((i) => i.host === h);
      const fails = rows.filter((r) => r.status === "fail");
      const pass = rows.filter((r) => r.status === "pass").length;
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      rows.sort((a, b) => (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1) || order[a.severity] - order[b.severity]);
      return `<div class="card" style="margin-bottom:16px"><h2>${esc(h)} — ${fails.length} fallos · ${pass} correctos</h2><div class="table-wrap"><table><thead><tr><th>Resultado</th><th>Severidad</th><th>ID</th><th>Control</th><th>Detalle</th><th>Remediación</th></tr></thead><tbody>${rows.map((r) => `
        <tr><td>${r.status === "fail" ? `<span class="pill warn">✗ Falla</span>` : r.status === "pass" ? `<span class="pill on">✓ OK</span>` : `<span class="pill">N/A</span>`}</td><td>${sev(r.severity)}</td><td class="mono">${esc(r.check_id)}</td><td>${esc(r.title)}</td><td class="trunc mono" title="${esc(r.detail)}">${esc(r.detail)}</td><td>${esc(r.remediation)}</td></tr>`).join("")}</tbody></table></div></div>`;
    }).join("");
  }

  // ---------------------------------------------------------------- mitre
  async function renderMitre() {
    const m = await api(`/api/mitre?hours=${hours()}`);
    const rules = await api("/api/rules");
    const covered = {};
    rules.forEach((r) => (r.mitre || []).forEach((t) => { (covered[r.tactic] = covered[r.tactic] || new Set()).add(t); }));
    const total = new Set(rules.flatMap((r) => r.mitre || [])).size;
    view().innerHTML = `<div class="card"><h2>${total} técnicas cubiertas por ${rules.length} reglas · resaltadas las observadas en el periodo</h2><div class="mitre">${Object.entries(m.tactics).map(([k, t]) => {
      const techs = new Set([...(covered[k] || []), ...Object.keys(m.matrix[k] || {})]);
      return `<div class="col"><h3>${esc(t.name)}<div class="muted mono">${esc(t.id)}</div></h3>${[...techs].sort().map((x) => {
        const hits = (m.matrix[k] || {})[x] || 0;
        return `<div class="tech ${hits ? "hit" : ""}" data-tip="${esc(esc(x))} ${esc(esc(m.techniques[x] || ""))}<br>${hits} alertas"><span class="mono">${esc(x)}</span> ${esc(m.techniques[x] || "")}${hits ? ` <b>(${hits})</b>` : ""}</div>`;
      }).join("") || `<div class="muted">—</div>`}</div>`;
    }).join("")}</div></div>`;
  }

  // ---------------------------------------------------------------- intel
  async function renderIntel() {
    const d = await api("/api/iocs");
    const kinds = Object.keys(d.counts);
    view().innerHTML = `
      <div class="grid kpis">${kinds.map((k) => `<div class="card kpi"><div class="label">${esc(k)}</div><div class="value">${d.counts[k]}</div></div>`).join("")}</div>
      <div class="card" style="margin-top:16px"><h2>Añadir indicador de compromiso (se distribuye a todos los agentes)</h2>
        <div class="filters"><select id="i-type">${kinds.map((k) => `<option>${k}</option>`).join("")}</select><input id="i-value" placeholder="Valor (hash, IP, dominio...)" style="min-width:320px"><input id="i-desc" placeholder="Descripción"><button class="btn primary" id="i-add">Añadir</button><button class="btn" id="i-feeds">Actualizar feeds abuse.ch</button></div>
        <div class="muted">Versión de inteligencia: ${d.version}</div></div>
      <div class="card" style="margin-top:16px"><div class="table-wrap"><table><thead><tr><th>Tipo</th><th>Valor</th><th>Descripción</th><th></th></tr></thead><tbody>${kinds.flatMap((k) => Object.entries(d.iocs[k]).slice(0, 200).map(([v, desc]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td><td>${esc(desc)}</td><td><button class="btn small ghost" data-del="${esc(k)}" data-val="${esc(v)}">Eliminar</button></td></tr>`)).join("")}</tbody></table></div></div>`;
    $("#i-add").addEventListener("click", async () => {
      try { await api("/api/iocs", { method: "POST", body: { type: $("#i-type").value, value: $("#i-value").value, description: $("#i-desc").value } }); toast("IOC añadido"); renderIntel(); } catch (e) { toast(`Error: ${e.message}`); }
    });
    $("#i-feeds").addEventListener("click", async () => { toast("Descargando feeds..."); try { const r = await api("/api/iocs/feeds", { method: "POST", body: {} }); toast(`Feeds: ${JSON.stringify(r)}`); renderIntel(); } catch (e) { toast(`Error: ${e.message}`); } });
    view().querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => { await api("/api/iocs/delete", { method: "POST", body: { type: b.dataset.del, value: b.dataset.val } }); renderIntel(); }));
  }

  // ------------------------------------------------------------- response
  async function renderResponse() {
    const [cmds, agents] = await Promise.all([api("/api/commands?limit=200"), api("/api/agents")]);
    const names = Object.fromEntries(agents.map((a) => [a.id, a.hostname]));
    const actionOpts = Object.entries(ACTION_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
    view().innerHTML = `
      <div class="card"><h2>Lanzar acción manual</h2><div class="filters">
        <select id="r-agent">${agents.map((a) => `<option value="${esc(a.id)}">${esc(a.hostname)}</option>`).join("")}</select>
        <select id="r-action">${actionOpts}</select>
        <input id="r-params" placeholder='Parámetros JSON, p.ej. {"pid": 1234} o {"ip": "1.2.3.4"}' style="min-width:320px">
        <button class="btn primary" id="r-go">Ejecutar</button></div></div>
      <div class="card table-wrap" style="margin-top:16px">${cmds.length ? `<table><thead><tr><th>Hora</th><th>Host</th><th>Acción</th><th>Parámetros</th><th>Estado</th><th>Resultado</th><th>Origen</th></tr></thead><tbody>${cmds.map((c) => `
        <tr class="click" data-cmd="${esc(c.id)}"><td>${ts(c.ts)}</td><td>${esc(names[c.agent_id] || c.agent_id)}</td><td>${esc(ACTION_LABEL[c.action] || c.action)}</td><td class="mono trunc">${esc(JSON.stringify(c.params))}</td>
        <td><span class="pill ${c.status === "done" ? "on" : c.status === "failed" ? "warn" : ""}">${esc(c.status)}</span></td><td class="trunc">${esc((c.result || {}).message || "")}</td><td>${esc(c.requested_by)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No se han ejecutado acciones</div>`}</div>`;
    $("#r-go").addEventListener("click", async () => {
      let params = {};
      try { params = $("#r-params").value.trim() ? JSON.parse($("#r-params").value) : {}; } catch (e) { toast("JSON de parámetros inválido"); return; }
      try { await api("/api/commands", { method: "POST", body: { agent_id: $("#r-agent").value, action: $("#r-action").value, params } }); toast("Acción en cola"); renderResponse(); } catch (e) { toast(`Error: ${e.message}`); }
    });
    view().querySelectorAll("tr[data-cmd]").forEach((tr) => tr.addEventListener("click", () => {
      const c = cmds.find((x) => x.id === tr.dataset.cmd);
      openDrawer(`<h2>${esc(ACTION_LABEL[c.action] || c.action)}</h2><pre class="json">${esc(JSON.stringify(c, null, 2))}</pre>`);
    }));
  }

  // ---------------------------------------------------------------- rules
  async function renderRules() {
    const rules = await api("/api/rules");
    view().innerHTML = `<div class="card table-wrap"><table><thead><tr><th>ID</th><th>Severidad</th><th>Título</th><th>Táctica</th><th>MITRE</th><th>Fuente</th><th>Respuesta automática</th></tr></thead><tbody>${rules.map((r) => `
      <tr><td class="mono">${esc(r.id)}</td><td>${sev(r.severity)}</td><td>${esc(r.title)}<div class="muted">${esc(r.description || "")}</div></td><td>${esc(r.tactic)}</td><td>${(r.mitre || []).map((m) => `<span class="pill">${esc(m)}</span>`).join(" ")}</td><td class="mono">${esc(r.source)}</td><td>${(r.response || []).map((a) => `<span class="pill">${esc(ACTION_LABEL[a] || a)}</span>`).join(" ")}</td></tr>`).join("")}</tbody></table></div>`;
  }

  // --------------------------------------------------------------- drawer
  function openDrawer(html) { $("#drawer-body").innerHTML = html; $("#drawer").classList.remove("hidden"); }
  $("#drawer-close").addEventListener("click", () => $("#drawer").classList.add("hidden"));
  $("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") $("#drawer").classList.add("hidden"); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#drawer").classList.add("hidden"); });

  if (token) { api("/api/overview?hours=1").then(start).catch(showLogin); } else { showLogin(); }
})();
