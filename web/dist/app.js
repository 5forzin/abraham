import { hosts, statuses, FLOORS } from "./data.js";
import { createScene } from "./scene.js";
import { layout, icon } from "./layout.js";
import { createWindows } from "./windows.js";
import { createWorkspaceUI } from "./workspace-ui.js";
const $ = (s) => document.querySelector(s);
const demoHosts = hosts.map((host) => ({ ...host, history: [...host.history] }));
let selected = 7,
  filter = "all",
  query = "",
  sortKey = "id",
  sortDir = 1,
  paused = false,
  floor = "all",
  scene,
  tick = 0;
let dataMode = "demo",
  liveSessionCount = 0,
  refreshingLive = false,
  dataGeneration = 0;
const activeHosts = () =>
  dataMode === "live" ? hosts.filter((host) => !host.placeholder) : hosts;
const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
const events = [
  {
    time: new Date(),
    text: `${hosts.find((h) => h.status === "threat").hostname} · Indicador de ameaça detectado`,
    type: "threat",
  },
  {
    time: new Date(Date.now() - 42000),
    text: `${hosts.find((h) => h.status === "warning").hostname} · CPU acima do limiar`,
    type: "warning",
  },
  {
    time: new Date(Date.now() - 98000),
    text: "Política de proteção sincronizada",
    type: "online",
  },
];
document.getElementById("app").innerHTML = layout(statuses);
const windows = createWindows();
const locationButton = document.createElement("button");
locationButton.className = "document-name";
locationButton.textContent = $(".document-name").textContent;
locationButton.title = "Escolher andar";
locationButton.setAttribute("aria-label", "Escolher andar · Campus Paulista");
locationButton.setAttribute("aria-controls", "layers-window");
locationButton.setAttribute("aria-haspopup", "dialog");
locationButton.onclick = () => windows.toggle("layers");
$(".document-name").replaceWith(locationButton);
locationButton.insertAdjacentHTML(
  "beforebegin",
  `<button id="back-building" hidden title="Voltar ao prédio inteiro · B" aria-label="Voltar ao prédio inteiro">${icon("chevron", 14)}<span>Prédio</span></button>`,
);
$("#back-building").onclick = () => $("#building-view").click();
$("#viewport").setAttribute(
  "aria-label",
  "Campus Paulista em 3D. Clique em um andar para explorá-lo. Ferramentas: Alt e botão direito.",
);
$(".table-toolbar").insertAdjacentHTML(
  "beforeend",
  '<button id="reset-filters" class="reset-filters" hidden>Limpar busca e status</button>',
);
$("#reset-filters").onclick = () => {
  query = "";
  $("#search").value = "";
  setFilter("all");
  $("#search").focus();
};
const helpDialog = $("#help-dialog");
$(".canvas-controls").className = "help-viewtools";
helpDialog.append($(".help-viewtools"), $(".world-status"), $(".top-status"));
$("#reset").title = "Enquadrar infraestrutura";

function metric(value) {
  if (!Number.isFinite(value)) {
    return '<span class="metric unavailable"><span style="width:0"></span></span><span>N/A</span>';
  }
  return `<span class="metric ${value > 80 ? "hot" : ""}"><span style="width:${value}%"></span></span><span>${value}%</span>`;
}
function renderStats() {
  const currentHosts = activeHosts();
  $("#stats").innerHTML = [
    ["Online", currentHosts.filter((h) => h.status === "online").length, "online"],
    ["Atenção", currentHosts.filter((h) => h.status === "warning").length, "warning"],
    ["Ameaças", currentHosts.filter((h) => h.status === "threat").length, "threat"],
    ["Offline", currentHosts.filter((h) => h.status === "offline").length, "offline"],
  ]
    .map(
      ([label, n, cls]) =>
        `<div class="stat"><span><i class="led ${cls}"></i>${label}</span><strong>${n}</strong></div>`,
    )
    .join("");
}
function renderRows() {
  const focused = document.activeElement;
  const focusedRow = focused?.closest("[data-id]");
  renderRows.restore = focusedRow
    ? `[data-id="${focusedRow.dataset.id}"]${focused.dataset.scan ? " [data-scan]" : focused.dataset.focus ? " [data-focus]" : ""}`
    : null;
  const currentHosts = activeHosts();
  const list = currentHosts
    .filter(
      (h) =>
        (filter === "all" || h.status === filter) &&
        (floor === "all" || h.floor === Number(floor)) &&
        `${h.hostname} ${h.ip} ${h.roomName} ${h.user || ""}`
          .toLowerCase()
          .includes(query),
    )
    .sort((a, b) =>
      typeof a[sortKey] === "number"
        ? (a[sortKey] - b[sortKey]) * sortDir
        : String(a[sortKey]).localeCompare(String(b[sortKey]), "pt", {
            numeric: true,
          }) * sortDir,
    );
  $("#rows").innerHTML = list
    .map(
      (h) =>
        `<tr data-id="${h.id}" tabindex="0" aria-selected="${h.id === selected}" class="${h.id === selected ? "selected" : ""}"><td><span class="status-label"><i class="led ${h.status}"></i>${h.isolated ? "Isolado" : escapeHtml(statuses[h.status]?.label || h.status)}</span></td><td class="host">${icon("monitor", 18)} ${escapeHtml(h.hostname)}${h.id === selected ? '<span class="selected-arrow">↗</span>' : ""}</td><td>${escapeHtml(h.ip || "N/A")}</td><td class="os">${escapeHtml(h.os || "N/A")}</td><td><div class="metric-cell">${metric(h.cpu)}</div></td><td><div class="metric-cell">${metric(h.mem)}</div></td><td><i class="agent-dot ${h.status === "offline" ? "muted" : ""}"></i>${h.status === "offline" ? "Desconectado" : h.scanning ? "Verificando" : h.isolated ? "Isolado" : dataMode === "live" ? "Conectado" : "Protegido"} <span class="muted">${escapeHtml(h.agent)}</span></td><td>${h.ping > 60 ? `${Math.floor(h.ping / 60)} min` : `${h.ping}s atrás`}</td><td><button class="row-action" data-focus="${h.id}" title="Focar ${escapeHtml(h.hostname)}">⌖</button><button class="row-action" data-scan="${h.id}" title="${dataMode === "live" ? "Disponível apenas no modo demo" : `Verificar ${escapeHtml(h.hostname)}`}" ${dataMode === "live" || h.status === "offline" || h.scanning ? "disabled" : ""}>⌁</button></td></tr>`,
    )
    .join("");
  $("#empty").hidden = !!list.length;
  $("#reset-filters").hidden = filter === "all" && !query;
  $("#result-count").textContent =
    `${list.length} de ${currentHosts.length} ${dataMode === "live" ? "sessões" : "endpoints"}`;
  if (document.activeElement === document.body && renderRows.restore) {
    document.querySelector(renderRows.restore)?.focus({ preventScroll: true });
  }
  renderRows.restore = null;
}
function chart(h) {
  if (!h.history?.length) {
    return '<div class="telemetry-empty">Telemetria não fornecida pelo implant</div>';
  }
  return `<svg class="telemetry-chart" viewBox="0 0 260 55" preserveAspectRatio="none" aria-label="Histórico de utilização de CPU"><path class="chart-grid" d="M0 15H260M0 35H260M0 54H260"/><path class="chart-line" d="${h.history.map((v, i) => `${i ? "L" : "M"}${(i * 260) / 31},${54 - v * 0.5}`).join(" ")}"/></svg>`;
}
function integrityLabel(level) {
  return ["Desconhecida", "Baixa", "Média", "Alta", "SYSTEM", "Protegida"][level] ||
    "Desconhecida";
}
function activityFor(h) {
  if (dataMode !== "live") return events.slice(0, 3);
  return (h.results || []).slice(0, 5).map((result) => ({
    time: new Date(result.timestamp * 1000),
    text: `Tarefa #${result.task_id} · ${result.summary || "Sem resumo"}`,
    type: result.status === 0 ? "online" : "warning",
  }));
}
function renderInspector() {
  if ($("#inspector").classList.contains("dragging")) return;
  const focusId = [
    "scan",
    "isolate",
    "close-inspector",
    "details-summary",
    "inspector-handle",
  ].includes(document.activeElement?.id)
    ? document.activeElement.id
    : null;
  const h = hosts[selected];
  if (!h || h.placeholder) {
    $("#inspector").innerHTML =
      '<div class="inspector-body"><p class="muted">Nenhuma sessão selecionada.</p></div>';
    return;
  }
  const live = dataMode === "live";
  const activity = activityFor(h);
  const expanded =
    $("#inspector").dataset.host === String(selected) &&
    $("#endpoint-details")?.open;
  $("#inspector").dataset.host = selected;
  $("#inspector").innerHTML =
    `<div class="panel-title" id="inspector-handle" data-window-handle tabindex="0" aria-label="Mover janela do endpoint com as setas"><span class="window-caption">${icon("monitor", 15)} Endpoint</span><button id="close-inspector" class="icon-button" aria-label="Fechar propriedades">${icon("close", 16)}</button></div>
  <div class="inspector-body"><div class="host-heading"><div><h2>${escapeHtml(h.hostname)}</h2><span class="address muted">${escapeHtml(h.ip || "N/A")} <span class="address-divider">·</span> ${h.floor}º · ${escapeHtml(h.roomName)}${live ? " (posição virtual)" : ""}</span></div><span class="led ${h.status}"></span></div>
  <div class="status-banner ${h.status}">${h.isolated ? "Endpoint isolado" : escapeHtml(statuses[h.status]?.label || h.status)}${h.status === "threat" ? " · Revisão necessária" : live ? " · Somente leitura" : ""}</div>
  <div class="usage"><div><span>CPU</span><b>${Number.isFinite(h.cpu) ? `${h.cpu}<small>%</small>` : "N/A"}</b></div><div><span>Memória</span><b>${Number.isFinite(h.mem) ? `${h.mem}<small>%</small>` : "N/A"}</b></div><div><span>Último ping</span><b class="ping-value">${h.ping > 60 ? Math.floor(h.ping / 60) : h.ping}<small>${h.ping > 60 ? "min" : "s"}</small></b></div></div>
  <div class="inspector-actions"><button id="scan" ${live || h.status === "offline" || h.scanning ? "disabled" : ""} title="${live ? "Ações reais não são expostas à interface web" : "Verificar endpoint no laboratório"}">${icon("activity", 14)} ${h.scanning ? "Verificando…" : "Verificar"}</button><button id="isolate" ${live || h.status === "offline" ? "disabled" : ""} title="${live ? "Ações reais não são expostas à interface web" : "Alternar isolamento simulado"}">${icon("shield", 14)} ${h.isolated ? "Reconectar" : "Isolar"}</button></div>
  <details id="endpoint-details" ${expanded ? "open" : ""}><summary id="details-summary">Detalhes e atividade <span>⌄</span></summary><dl><dt>Sistema</dt><dd>${escapeHtml(h.os || "N/A")}</dd><dt>Agente</dt><dd>Abraham ${escapeHtml(h.agent || "N/A")}</dd>${live ? `<dt>Usuário</dt><dd>${escapeHtml(h.user || "N/A")}</dd><dt>Processo</dt><dd>PID ${h.pid || "N/A"} · PPID ${h.ppid || "N/A"} · ${escapeHtml(h.arch || "N/A")}</dd><dt>Integridade</dt><dd>${escapeHtml(integrityLabel(h.integrityLevel))}</dd><dt>Fila</dt><dd>${h.pendingTasks} tarefa(s)</dd><dt>Sessão</dt><dd>#${h.sessionId}</dd>` : ""}</dl><div class="section-label">Histórico da CPU <span>${live ? "Indisponível" : "Últimas 32 amostras"}</span></div>${chart(h)}${live ? "" : '<div class="chart-axis"><span>−96s</span><span>Agora</span></div>'}<div class="section-label event-heading" id="activity">Atividade recente <span>${live ? "Resultados read-only" : "Simulada"}</span></div><div class="events">${activity
    .map(
      (e) =>
        `<div><i class="led ${e.type}"></i><p>${escapeHtml(e.text)}<time>${e.time.toLocaleTimeString("pt-BR")}</time></p></div>`,
    )
    .join("") || '<p class="muted">Nenhum resultado recente.</p>'}</div></details></div>`;
  $("#close-inspector").onclick = () => windows.close("inspector");
  $("#scan").onclick = () => scan(selected);
  $("#isolate").onclick = () => {
    if (live) return;
    h.isolated = !h.isolated;
    record(
      `${h.hostname} · ${h.isolated ? "Isolamento aplicado" : "Conexão restaurada"} no laboratório`,
      h.isolated ? "warning" : "online",
    );
    scene?.update();
    renderRows();
    renderInspector();
  };
  if (focusId) document.getElementById(focusId)?.focus({ preventScroll: true });
}

function record(text, type) {
  events.unshift({ time: new Date(), text, type });
  events.splice(40);
  $("#toast").textContent = text;
  $("#toast").classList.add("show");
  clearTimeout(record.timeout);
  record.timeout = setTimeout(() => $("#toast").classList.remove("show"), 3500);
}
async function loadResults(host) {
  if (dataMode !== "live" || !host?.sessionId) return;
  const sessionId = host.sessionId;
  const generation = dataGeneration;
  try {
    const response = await fetch(
      `/operator-api/sessions/${encodeURIComponent(sessionId)}/results?limit=5`,
      {
        cache: "no-store",
        headers: { "X-Abraham-Client": "operator-ui" },
      },
    );
    if (!response.ok) return;
    const payload = await response.json();
    if (
      dataMode !== "live" ||
      dataGeneration !== generation ||
      host.sessionId !== sessionId
    )
      return;
    host.results = Array.isArray(payload.results) ? payload.results : [];
    if (hosts[selected] === host && !$("#inspector").hidden) renderInspector();
  } catch {}
}
function scan(id) {
  const h = hosts[id];
  if (dataMode === "live" || !h || h.scanning || h.status === "offline") return;
  const generation = dataGeneration;
  h.scanning = true;
  record(`${h.hostname} · Verificação simulada iniciada`, "online");
  renderRows();
  renderInspector();
  setTimeout(() => {
    if (dataMode !== "demo" || generation !== dataGeneration) return;
    h.scanning = false;
    record(
      `${h.hostname} · ${h.status === "threat" ? "Indicador de ameaça confirmado" : "Verificação concluída"}`,
      h.status === "threat" ? "threat" : "online",
    );
    renderRows();
    renderInspector();
  }, 2800);
}
function select(id) {
  if (!hosts[id] || hosts[id].placeholder) return;
  selected = id;
  document.querySelector("main").classList.remove("focus-mode");
  $("#focus-mode").setAttribute("aria-pressed", "false");
  floor = String(hosts[id].floor);
  $("#floor").value = floor;
  syncLayers();
  scene?.select(id);
  renderRows();
  renderInspector();
  windows.open("inspector");
  loadResults(hosts[id]);
}
function syncModeChrome() {
  const currentHosts = activeHosts();
  const live = dataMode === "live";
  $("#data-mode").textContent = live
    ? `Ao vivo · ${liveSessionCount}`
    : "Conectar ao vivo";
  $("#data-mode").setAttribute("aria-pressed", String(live));
  $("#data-mode").title = live
    ? "Voltar ao ambiente simulado"
    : "Conectar às sessões do teamserver";
  $("#connection-label").textContent = live ? "C2 ao vivo" : "Demonstração";
  $("#stream-status").textContent = paused
    ? "Fluxo pausado"
    : live
      ? "Sincronização ativa"
      : "Fluxo ativo";
  $(".workspace-caption span").textContent = `${currentHosts.length} ${live ? "sessões" : "endpoints"}`;
  $(".table-heading .count").textContent = currentHosts.length;
  $(".tool-count").textContent = currentHosts.length;
  $(".selection-hint").textContent = live
    ? "Sessões do teamserver · somente leitura"
    : "Conectados ao seu mundo";
  $("#nav-threats span").textContent = live
    ? "Detecção não fornecida"
    : `Investigar ${currentHosts.filter((host) => host.status === "threat").length} ameaças`;
  $(".table-footer span:last-child").textContent = live
    ? "Sincronização a cada 3 segundos"
    : "Atualização a cada 3 segundos";
}
function restoreDemo() {
  dataGeneration++;
  dataMode = "demo";
  liveSessionCount = 0;
  hosts.forEach((host, index) => {
    Object.assign(host, demoHosts[index], { history: [...demoHosts[index].history] });
    for (const key of [
      "sessionId",
      "user",
      "pid",
      "ppid",
      "arch",
      "integrityLevel",
      "pendingTasks",
      "placeholder",
      "results",
    ])
      delete host[key];
  });
  selected = 7;
  floor = "all";
  $("#floor").value = "all";
  scene?.floor("all");
  scene?.clearSelection();
  scene?.update();
  syncModeChrome();
  syncLayers();
  renderStats();
  renderRows();
  renderInspector();
}
function applyLiveSessions(sessions) {
  const wasLive = dataMode === "live";
  if (!wasLive) dataGeneration++;
  const currentSessionId = hosts[selected]?.sessionId;
  const ordered = [...sessions]
    .filter((session) => Number.isInteger(Number(session.id)) && Number(session.id) > 0)
    .sort((a, b) => Number(a.id) - Number(b.id))
    .slice(0, hosts.length);
  dataMode = "live";
  liveSessionCount = ordered.length;
  hosts.forEach((host, index) => {
    const slot = demoHosts[index];
    const session = ordered[index];
    if (!session) {
      Object.assign(host, slot, {
        status: "offline",
        cpu: null,
        mem: null,
        history: [],
        placeholder: true,
      });
      for (const key of [
        "sessionId",
        "user",
        "pid",
        "ppid",
        "arch",
        "integrityLevel",
        "pendingTasks",
        "results",
      ])
        delete host[key];
      return;
    }
    const previousResults =
      host.sessionId === Number(session.id) && Array.isArray(host.results)
        ? host.results
        : [];
    Object.assign(host, slot, {
      hostname: session.hostname || `Sessão-${session.id}`,
      ip: session.addr || "N/A",
      os: session.os_build ? `Windows · ${session.os_build}` : "N/A",
      status: session.stale ? "offline" : "online",
      cpu: null,
      mem: null,
      agent: session.implant_version || "N/A",
      ping: Math.max(0, Number(session.age) || 0),
      history: [],
      isolated: false,
      scanning: false,
      placeholder: false,
      sessionId: Number(session.id),
      user:
        [session.domain, session.username].filter(Boolean).join("\\") ||
        session.user ||
        "N/A",
      pid: Number(session.pid) || 0,
      ppid: Number(session.ppid) || 0,
      arch: session.arch || "N/A",
      integrityLevel: Number(session.integrity_level) || 0,
      pendingTasks: Number(session.pending_tasks) || 0,
      results: previousResults,
    });
  });
  const retained = hosts.find((host) => host.sessionId === currentSessionId);
  selected = retained?.id ?? (ordered.length ? 0 : -1);
  if (!wasLive || !retained) scene?.clearSelection();
  scene?.update();
  syncModeChrome();
  syncLayers();
  renderStats();
  renderRows();
  renderInspector();
  if (selected >= 0) loadResults(hosts[selected]);
}
async function refreshLiveSessions({ activate = false, silent = false } = {}) {
  if (refreshingLive) return false;
  refreshingLive = true;
  $("#data-mode").disabled = true;
  try {
    const response = await fetch("/operator-api/sessions", {
      cache: "no-store",
      headers: { "X-Abraham-Client": "operator-ui" },
    });
    if (!response.ok) throw new Error("teamserver unavailable");
    const payload = await response.json();
    if (!Array.isArray(payload.sessions)) throw new Error("invalid sessions response");
    if (activate || dataMode === "live") applyLiveSessions(payload.sessions);
    return true;
  } catch {
    if (dataMode === "live") $("#connection-label").textContent = "C2 indisponível";
    if (!silent) record("Teamserver indisponível · modo demo preservado", "warning");
    return false;
  } finally {
    refreshingLive = false;
    $("#data-mode").disabled = false;
  }
}
$("#data-mode").onclick = async () => {
  if (dataMode === "live") {
    restoreDemo();
    record("Ambiente simulado restaurado", "online");
  } else {
    const connected = await refreshLiveSessions({ activate: true });
    if (connected) record(`${liveSessionCount} sessão(ões) carregada(s) em modo read-only`, "online");
  }
};
renderStats();
renderRows();
renderInspector();
syncModeChrome();
syncLayers();
document
  .querySelectorAll("[data-filter]")
  .forEach((b) =>
    b.setAttribute("aria-pressed", String(b.dataset.filter === filter)),
  );
try {
  scene = createScene(
    $("#canvas"),
    hosts,
    select,
    (fps) => ($("#fps").textContent = `${fps} FPS`),
    chooseFloor,
  );
  scene.reset();
} catch (error) {
  $("#canvas").innerHTML =
    '<div class="webgl-error">WebGL indisponível neste dispositivo.<br>A tabela e a telemetria permanecem disponíveis.</div>';
  console.error(error);
}
refreshLiveSessions({ activate: true, silent: true });
$("#rows").onclick = (e) => {
  const focus = e.target.closest("[data-focus]"),
    scanButton = e.target.closest("[data-scan]");
  if (scanButton) {
    scan(Number(scanButton.dataset.scan));
    return;
  }
  const row = e.target.closest("[data-id]");
  if (row) select(Number(row.dataset.id));
};
$("#rows").onkeydown = (e) => {
  if (e.target.closest("button")) return;
  if (e.key === "Enter" || e.key === " ") {
    const row = e.target.closest("[data-id]");
    if (row) {
      e.preventDefault();
      select(Number(row.dataset.id));
    }
  }
};
function setFilter(value) {
  filter = value;
  document.querySelectorAll("[data-filter]").forEach((b) => {
    b.classList.toggle("active", b.dataset.filter === filter);
    b.setAttribute("aria-pressed", String(b.dataset.filter === filter));
  });
  renderRows();
}
document
  .querySelectorAll("[data-filter]")
  .forEach((b) => (b.onclick = () => setFilter(b.dataset.filter)));
document.querySelectorAll("[data-sort]").forEach(
  (b) =>
    (b.onclick = () => {
      sortDir = sortKey === b.dataset.sort ? -sortDir : 1;
      sortKey = b.dataset.sort;
      document
        .querySelectorAll("th[aria-sort]")
        .forEach((th) => th.setAttribute("aria-sort", "none"));
      b.parentElement.setAttribute(
        "aria-sort",
        sortDir === 1 ? "ascending" : "descending",
      );
      renderRows();
    }),
);
$("#search").oninput = (e) => {
  query = e.target.value.toLowerCase().trim();
  renderRows();
};
$("#clear").onclick = () => {
  query = "";
  $("#search").value = "";
  floor = "all";
  $("#floor").value = "all";
  scene?.floor("all");
  syncLayers();
  setFilter("all");
};
function syncLayers() {
  $("#back-building").hidden = floor === "all";
  $(".document-name").textContent =
    floor === "all"
      ? dataMode === "live"
        ? "Abraham · Sessões"
        : "FIAP · Paulista 1106"
      : `${dataMode === "live" ? "Posição virtual" : "FIAP"} · ${floor}º andar`;
  $(".document-name").setAttribute(
    "aria-label",
    `${$(".document-name").textContent} · Escolher andar`,
  );
  document.querySelectorAll("[data-layer]").forEach((b) => {
    b.classList.toggle("active", b.dataset.layer === floor);
    b.setAttribute(
      "aria-current",
      b.dataset.layer === floor ? "location" : "false",
    );
  });
}
function chooseFloor(value) {
  if (value !== "all" && !FLOORS.includes(Number(value))) return;
  floor = value;
  $("#floor").value = value;
  scene?.floor(value);
  syncLayers();
  renderRows();
  if (windows.active === "layers") windows.close("layers");
}
$("#floor").onchange = (e) => chooseFloor(e.target.value);
document
  .querySelectorAll("[data-layer]")
  .forEach((b) => (b.onclick = () => chooseFloor(b.dataset.layer)));
$("#reset").onclick = () => scene?.reset();
$("#zoom-in").onclick = () => scene?.zoom(0.8);
$("#zoom-out").onclick = () => scene?.zoom(1.25);
let exploded = false;
$("#explode").onclick = () => {
  exploded = !exploded;
  $("#explode").setAttribute("aria-pressed", String(exploded));
  $("#explode .toggle").classList.toggle("on", exploded);
  floor = "all";
  $("#floor").value = "all";
  syncLayers();
  scene?.floor("all");
  scene?.explode(exploded);
  renderRows();
};
function tool(pan) {
  scene?.setTool(pan ? "pan" : "select");
  $("#tool-pan").classList.toggle("active", pan);
  $("#tool-select").classList.toggle("active", !pan);
  $("#tool-pan").setAttribute("aria-pressed", String(pan));
  $("#tool-select").setAttribute("aria-pressed", String(!pan));
}
$("#building-view").onclick = () => {
  windows.closeActive();
  exploded = false;
  $("#explode").setAttribute("aria-pressed", "false");
  $("#explode .toggle").classList.remove("on");
  scene?.explode(false);
  chooseFloor("all");
};
$("#plan-view").onclick = () => {
  if (floor === "all") chooseFloor("2");
  scene?.plan();
};
$("#tool-select").onclick = () => tool(false);
$("#tool-pan").onclick = () => tool(true);
function showEndpoints(open) {
  if (open) {
    renderRows();
    windows.open("endpoints");
  } else windows.close("endpoints");
}
$("#nav-endpoints").onclick = () => showEndpoints($("#endpoints").hidden);
$("#close-endpoints").onclick = () => {
  showEndpoints(false);
  $("#tools-toggle").focus();
};
$("#nav-threats").onclick = () => {
  setFilter("threat");
  showEndpoints(true);
};
$("#nav-events").onclick = () => windows.toggle("inspector");
$("#pause").onclick = () => {
  paused = !paused;
  scene?.pause(paused);
  $("#pause").innerHTML = icon(paused ? "play" : "pause", 14);
  $("#pause").setAttribute(
    "aria-label",
    paused ? "Retomar telemetria" : "Pausar telemetria",
  );
  $("#pause").title = paused ? "Retomar telemetria" : "Pausar telemetria";
  $("#stream-status").textContent = paused
    ? "Fluxo pausado"
    : dataMode === "live"
      ? "Sincronização ativa"
      : "Fluxo ativo";
  $(".top-status").classList.toggle("paused", paused);
};
$("#dock").onclick = () => {
  const expanded = $("main").classList.toggle("docked");
  $("#dock").title = expanded ? "Reduzir painel" : "Expandir painel";
  $("#dock").setAttribute("aria-label", $("#dock").title);
};
$("#collapse-layers").onclick = () => windows.close("layers");
$("#restore-layers").onclick = () => windows.toggle("layers");
$("#focus-mode").onclick = () => {
  const focus = $("main").classList.toggle("focus-mode");
  $("#focus-mode").setAttribute("aria-pressed", String(focus));
  $("#focus-mode").setAttribute(
    "aria-label",
    focus ? "Mostrar painéis" : "Ocultar painéis",
  );
};
$("#help").onclick = () => {
  windows.closeActive();
  $("#help-dialog").showModal();
};
$("#close-help").onclick = () => $("#help-dialog").close();
$("#help-dialog").addEventListener("close", () =>
  $("#tools-toggle").focus({ preventScroll: true }),
);
$("#help-dialog").onclick = (e) => {
  if (e.target === $("#help-dialog")) {
    const r = e.target.getBoundingClientRect();
    if (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    )
      e.target.close();
  }
};
async function askAI(message, history) {
  const response = await fetch("/operator-api/assistant", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Abraham-Client": "operator-ui",
    },
    body: JSON.stringify({ message, history, mode: dataMode }),
  });
  if (!response.ok) throw new Error("assistant unavailable");
  const payload = await response.json();
  if (!payload.answer) throw new Error("assistant returned no answer");
  return payload.answer;
}
createWorkspaceUI(async (message, history) => {
  const text = message
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
  const host = activeHosts().find((h) =>
    text
      .split(/[\s,;!?()[\]]+/)
      .some(
        (token) =>
          token.replace(/\.$/, "") === h.hostname.toLowerCase() ||
          token.replace(/\.$/, "") === h.ip,
      ),
  );
  if (host) {
    select(host.id);
    return dataMode === "live"
      ? `${host.hostname} · sessão #${host.sessionId}, ${statuses[host.status].label}, último contato há ${host.ping}s. Selecionei a sessão em uma posição virtual do prédio.`
      : `${host.hostname} · ${host.floor}º andar, ${host.roomName}. ${statuses[host.status].label}. CPU ${host.cpu}%, memória ${host.mem}%. Selecionei o PC no mundo.`;
  }
  const number =
    text.match(/\b(\d{1,2})\s*(?:º|o|°)?\s*andar\b/) ||
    text.match(/\bandar\s*(\d{1,2})\b/);
  if (number) {
    if (!FLOORS.includes(Number(number[1])))
      return "Os andares disponíveis são 2, 3, 4, 5, 6, 7, 10 e 11. Qual deles você quer abrir?";
    windows.closeActive();
    chooseFloor(String(Number(number[1])));
    if (text.includes("planta")) $("#plan-view").click();
    return `Abri somente o ${Number(number[1])}º andar: seis salas, 72 PCs e coworking sem computadores.`;
  }
  if (/predio|edificio|visao geral/.test(text)) {
    $("#building-view").click();
    return "Prédio completo em cena, com os oito andares mobiliados. Clique em um andar para explorá-lo sozinho.";
  }
  if (/planta|vista superior/.test(text)) {
    $("#plan-view").click();
    return `Vista superior do ${floor}º andar aberta.`;
  }
  if (
    /ameaca|offline|warning|alerta|online|endpoint|listar|computador|\bpcs\b/.test(
      text,
    )
  ) {
    const status = /ameaca/.test(text)
      ? "threat"
      : /offline/.test(text)
        ? "offline"
        : /warning|alerta/.test(text)
          ? "warning"
          : /online/.test(text)
            ? "online"
            : "all";
    query = "";
    $("#search").value = "";
    setFilter(status);
    showEndpoints(true);
    const count = activeHosts().filter(
      (h) =>
        (floor === "all" || h.floor === Number(floor)) &&
        (status === "all" || h.status === status),
    ).length;
    return `Lista aberta: ${count} ${dataMode === "live" ? "sessões" : "PCs"} ${floor === "all" ? (dataMode === "live" ? "no teamserver" : "no campus") : `no ${floor}º andar`}${status === "all" ? "" : ` · ${statuses[status].label}`}. ${dataMode === "live" ? "Dados read-only do teamserver." : "Os dados são simulados."}`;
  }
  if (/resumo|status|campus|telemetria/.test(text)) {
    const currentHosts = activeHosts();
    return `${currentHosts.length} ${dataMode === "live" ? "sessões" : "PCs em oito andares"}. ${currentHosts.filter((h) => h.status === "online").length} online, ${currentHosts.filter((h) => h.status === "offline").length} offline, ${currentHosts.filter((h) => h.status === "warning").length} em atenção e ${currentHosts.filter((h) => h.status === "threat").length} com alerta de ameaça. ${dataMode === "live" ? "Dados read-only do teamserver." : "Telemetria simulada."}`;
  }
  if (/andar|infraestrutura/.test(text)) {
    windows.open("layers");
    return "Abri os andares disponíveis. Escolha um para isolá-lo na cena.";
  }
  try {
    return await askAI(message, history);
  } catch {
    return "A IA está indisponível agora. Ainda posso mostrar um andar, abrir o prédio ou a planta, listar endpoints e resumir a telemetria local.";
  }
});

document.addEventListener("keydown", (e) => {
  if (e.defaultPrevented) return;
  if (e.key === "Escape" && !$("#help-dialog").open) {
    if (windows.closeActive()) e.preventDefault();
    else scene?.reset();
    return;
  }
  if (
    e.ctrlKey ||
    e.metaKey ||
    e.altKey ||
    ["INPUT", "SELECT", "TEXTAREA"].includes(e.target.tagName) ||
    $("#help-dialog").open
  )
    return;
  if (e.key === "/") {
    e.preventDefault();
    showEndpoints(true);
    $("#search").focus();
  }
  if (e.key === "?" || e.key === "F1") {
    e.preventDefault();
    $("#help").click();
    return;
  }
  if (e.key.toLowerCase() === "e") showEndpoints($("#endpoints").hidden);
  if (e.key.toLowerCase() === "v") tool(false);
  if (e.key.toLowerCase() === "h") tool(true);
  if (e.key.toLowerCase() === "b") $("#building-view").click();
  if (e.key.toLowerCase() === "p") $("#plan-view").click();
  if (e.key === "Escape") {
    if (!windows.closeActive()) scene?.reset();
  }
});
const splitter = $(".splitter");
function resizePanel(height) {
  document.documentElement.style.setProperty(
    "--table-height",
    Math.max(230, Math.min(window.innerHeight - 150, height)) + "px",
  );
}
splitter.onpointerdown = (e) => {
  splitter.setPointerCapture(e.pointerId);
  const start = e.clientY,
    old = $("#endpoints").clientHeight;
  splitter.onpointermove = (e) => resizePanel(old + start - e.clientY);
  splitter.onpointerup = splitter.onpointercancel = () =>
    (splitter.onpointermove = null);
};
splitter.onkeydown = (e) => {
  if (["ArrowUp", "ArrowDown"].includes(e.key)) {
    e.preventDefault();
    resizePanel(
      $("#endpoints").clientHeight + (e.key === "ArrowUp" ? 20 : -20),
    );
  }
};
setInterval(() => {
  $("#clock").textContent = new Date().toLocaleTimeString("pt-BR") + " BRT";
}, 1000);
setInterval(() => {
  if (paused || document.hidden || dataMode === "live") return;
  tick++;
  hosts.forEach((h) => {
    if (h.status === "offline") {
      h.ping += 3;
      return;
    }
    h.cpu = Math.max(
      2,
      Math.min(98, h.cpu + Math.round(Math.sin(tick + h.id) * 4)),
    );
    h.mem = Math.max(
      9,
      Math.min(96, h.mem + Math.round(Math.sin(tick * 0.2 + h.id))),
    );
    h.ping = 1 + (tick % 3);
    h.history.push(h.cpu);
    h.history.shift();
  });
  if (!$("#endpoints").hidden) renderRows();
  if (!$("#inspector").hidden) renderInspector();
}, 3000);
setInterval(() => {
  if (!paused && !document.hidden && dataMode === "live") {
    refreshLiveSessions({ silent: true });
  }
}, 3000);
