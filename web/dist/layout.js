import { FLOORS, hosts } from "./data.js";
export const icon = (name, size = 18) => {
  const paths = {
    layers:
      '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/>',
    cube: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"/><path d="m4 7.5 8 5 8-5M12 12.5V21M8 5l8 5"/>',
    table:
      '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M9 10v10"/>',
    shield:
      '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="M12 8v5m0 3h.01"/>',
    activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    fit: '<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"/><rect x="8" y="8" width="8" height="8" rx="1"/>',
    pointer: '<path d="m5 3 14 10-7 1-4 7L5 3Z"/>',
    hand: '<path d="M8 12V6a2 2 0 0 1 4 0v6-8a2 2 0 0 1 4 0v8-5a2 2 0 0 1 4 0v8c0 4-2 6-6 6h-1c-3 0-4-1-6-4l-4-5c-1-2 1-4 3-2l2 2Z"/>',
    chevron: '<path d="m9 5 7 7-7 7"/>',
    monitor:
      '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    server:
      '<rect x="4" y="3" width="16" height="8" rx="2"/><rect x="4" y="13" width="16" height="8" rx="2"/><path d="M8 7h.01M8 17h.01M12 7h5M12 17h5"/>',
    expand:
      '<path d="m8 8-5-5m0 5V3h5m8 13 5 5m0-5v5h-5M16 8l5-5m-5 0h5v5M8 16l-5 5m0-5v5h5"/>',
    pause: '<path d="M8 5v14M16 5v14"/>',
    play: '<path d="m8 4 12 8-12 8V4Z"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 1 1 4 3v2m0 3h.01"/>',
  };
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.cube}</svg>`;
};
export function layout(statuses) {
  return `<main class="editor"><section class="viewport-panel"><div class="viewport" id="viewport"><div id="canvas"></div></div></section>
<header class="topbar"><a class="brand" href="./" aria-label="Abraham C2 início"><img src="./logo.svg" width="123" height="29" alt="Abraham"><span class="brand-context">C2</span></a><div class="document-name">FIAP · Paulista 1106 </div><div class="top-status"><span class="live-dot"></span><span id="connection-label">Demonstração</span><span id="clock"></span></div><div class="top-actions"><button id="data-mode" class="mode-toggle" type="button" aria-pressed="false">Conectar ao vivo</button><button id="focus-mode" class="icon-button" title="Ocultar painéis" aria-label="Ocultar painéis" aria-pressed="false">${icon("expand")}</button></div></header>
<aside id="layers-window" class="layers-panel floating-panel" data-window="layers" role="dialog" aria-modal="false" hidden aria-label="Infraestrutura"><div class="panel-title" data-window-handle tabindex="0" aria-label="Mover janela Infraestrutura com as setas"><b>Infraestrutura</b><button id="collapse-layers" class="icon-button" title="Recolher camadas" aria-label="Recolher camadas">${icon("close", 16)}</button></div><div class="layers-content"><div class="workspace-caption">Campus Paulista <span>${hosts.length} endpoints</span></div><button class="building-node active" data-layer="all">${icon("cube")}<span>FIAP · Paulista 1106<small>Fachada e entorno</small></span><span class="tree-chevron">⌄</span></button><div class="floor-tree">${FLOORS.map(
    (f) => [String(f), `${f}º andar`, "6 salas · Coworking"],
  )
    .map(
      ([id, name, desc]) =>
        `<button data-layer="${id}" class="floor-node"><span class="floor-number">${id.padStart(2, "0")}</span><span>${name}<small>${desc}</small></span><i class="led ${hosts.some((h) => h.floor === Number(id) && h.status === "threat") ? "threat" : "online"}"></i></button>`,
    )
    .join(
      "",
    )}</div><div class="layer-options"><button id="explode" aria-pressed="false">${icon("layers", 16)} Separar andares <span class="toggle"></span></button></div><div class="overview-title">Visão geral <span>Agora</span></div><section id="stats" class="stats"></section><button id="nav-threats" class="threat-shortcut">${icon("shield", 17)}<span>Investigar ${hosts.filter((h) => h.status === "threat").length} ameaças</span>${icon("chevron", 14)}</button></div><div class="layers-footer"><span class="live-dot"></span><span id="stream-status">Fluxo ativo</span><button id="pause" class="icon-button" aria-label="Pausar telemetria" title="Pausar telemetria">${icon("pause", 14)}</button></div></aside>

<aside id="inspector" class="inspector floating-panel" data-window="inspector" role="dialog" aria-modal="false" hidden aria-label="Propriedades do endpoint"></aside>

<div class="canvas-controls floating-panel"><button id="zoom-out" class="icon-button" aria-label="Afastar">−</button><span id="view-label">Isométrica</span><button id="zoom-in" class="icon-button" aria-label="Aproximar">＋</button><span class="control-divider"></span><button id="reset" class="icon-button" title="Enquadrar infraestrutura · Esc" aria-label="Enquadrar infraestrutura">${icon("fit", 17)}</button></div>
<div class="bottom-toolbar floating-panel" role="toolbar" aria-label="Ferramentas de visualização"><button id="building-view" class="tool-button" title="Mostrar prédio inteiro · B" aria-label="Mostrar prédio inteiro">${icon("cube")}<span>Prédio</span></button><button id="restore-layers" class="tool-button" aria-label="Abrir infraestrutura" aria-expanded="false" aria-controls="layers-window" title="Infraestrutura">${icon("layers")}</button><button id="plan-view" class="tool-button" title="Planta do andar · P" aria-label="Vista superior da planta">${icon("table")}</button><button id="tool-select" class="tool-button active" aria-pressed="true" title="Selecionar e orbitar · V" aria-label="Selecionar e orbitar">${icon("pointer")}<span>Selecionar</span></button><button id="tool-pan" class="tool-button" aria-label="Mover câmera" aria-pressed="false" title="Mover câmera · H">${icon("hand")}</button><span class="control-divider"></span><button id="nav-endpoints" class="tool-button" aria-expanded="false" aria-controls="endpoints" title="Endpoints · E" aria-label="Abrir endpoints">${icon("table")}<span>Endpoints</span><span class="tool-count">${hosts.length}</span></button><button id="nav-events" class="tool-button" title="Inspecionar endpoint" aria-label="Inspecionar endpoint">${icon("activity")}</button><span class="control-divider"></span><button id="help" class="tool-button" aria-label="Ajuda e atalhos" title="Ajuda e atalhos">${icon("help")}</button></div>
<div class="world-status"><span class="legend">${Object.entries(statuses)
    .map(([k, v]) => `<span><i class="led ${k}"></i>${v.label}</span>`)
    .join("")}</span><span id="fps">— FPS</span></div>
<section class="endpoints floating-panel" id="endpoints" data-window="endpoints" role="dialog" aria-modal="false" hidden aria-label="Lista de endpoints"><div class="splitter" role="separator" aria-label="Redimensionar painel de endpoints" tabindex="0" aria-orientation="horizontal"></div><div class="table-heading" data-window-handle tabindex="0" aria-label="Mover janela Endpoints com as setas"><div>${icon("table", 17)}<b>Endpoints</b><span class="count">${hosts.length}</span><span class="muted selection-hint">Conectados ao seu mundo</span></div><div class="table-actions"><button id="dock" class="icon-button" title="Expandir painel" aria-label="Expandir painel">${icon("expand", 16)}</button><button id="close-endpoints" class="icon-button" aria-label="Fechar endpoints">${icon("close", 17)}</button></div></div><div class="table-toolbar"><label class="search">${icon("search", 16)}<input id="search" aria-label="Buscar hostname ou IP" placeholder="Buscar PC, IP ou sala"><kbd>/</kbd></label><div class="tabs" role="group" aria-label="Filtrar status">${[
    ["all", "Todos"],
    ["online", "Online"],
    ["warning", "Atenção"],
    ["threat", "Ameaças"],
    ["offline", "Offline"],
  ]
    .map(
      ([k, v]) =>
        `<button data-filter="${k}" class="${k === "all" ? "active" : ""}">${v}</button>`,
    )
    .join(
      "",
    )}</div><label class="table-floor"><select id="floor" aria-label="Filtrar andar"><option value="all">Todos os andares</option>${FLOORS.map((f) => `<option value="${f}">${f}º andar</option>`).join("")}</select></label></div><div class="table-scroll"><table><thead><tr>${[
    ["status", "Status"],
    ["hostname", "Hostname"],
    ["ip", "Endereço"],
    ["os", "OS / Build"],
    ["cpu", "CPU %"],
    ["mem", "Memória %"],
    ["agent", "Agente Abraham"],
    ["ping", "Último ping"],
  ]
    .map(
      ([k, v]) =>
        `<th scope="col" aria-sort="none"><button data-sort="${k}">${v}<span>↕</span></button></th>`,
    )
    .join(
      "",
    )}<th scope="col">Ações</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" hidden>Nenhum endpoint encontrado. <button id="clear">Limpar filtros</button></div></div><div class="table-footer"><span id="result-count"></span><span>Atualização a cada 3 segundos</span></div></section>
<dialog id="help-dialog"><div class="panel-title"><b>Seu espaço de trabalho</b><button id="close-help" class="icon-button" aria-label="Fechar ajuda">${icon("close")}</button></div><p>Use Prédio para enquadrar o edifício inteiro. Clique em um andar na fachada ou escolha-o em Infraestrutura para mostrar somente esse andar. Use Prédio para retornar aos oito andares mobiliados. Planta alterna para a vista superior do andar. Cada andar tem seis salas com 12 PCs e um coworking sem computadores. Selecione uma máquina para inspecioná-la.</p><dl><dt>Dados</dt><dd>Conectar ao vivo alterna entre o campus simulado e as sessões read-only do teamserver. A posição de uma sessão real no prédio é apenas visual.</dd><dt>IA</dt><dd>O assistente consulta sessões e resumos recentes, mas não executa tarefas nem altera endpoints.</dd><dt>Ferramentas</dt><dd>Alt + botão direito · arraste e solte. Ou use o botão de ferramentas no topo.</dd><dt>Conversa</dt><dd>Clique no campo para reabrir o histórico ou use ↑ com o campo vazio.</dd><dt>Ajuda</dt><dd><kbd>?</kbd> ou <kbd>F1</kbd></dd><dt>Orbitar</dt><dd>Arraste com o botão esquerdo</dd><dt>Mover</dt><dd>Botão direito ou ferramenta Mover</dd><dt>Zoom</dt><dd>Role o mouse ou use dois dedos</dd><dt>Prédio inteiro</dt><dd><kbd>B</kbd></dd><dt>Planta do andar</dt><dd><kbd>P</kbd></dd><dt>Selecionar / Mover</dt><dd><kbd>V</kbd> / <kbd>H</kbd></dd><dt>Endpoints / Busca</dt><dd><kbd>E</kbd> / <kbd>/</kbd></dd><dt>Visão sem painéis</dt><dd>Botão expandir no topo</dd><dt>Fechar / Enquadrar</dt><dd><kbd>Esc</kbd></dd></dl><small>Planta baseada no desenho fornecido: coworking ao fundo, salas laterais, circulação cinza e elevadores A–F. Fachada inspirada nas fotos da Paulista 1106. Em modo demo, telemetria e ações são simuladas; no modo ao vivo, o painel é somente leitura.</small></dialog></main><div id="toast" role="status"></div>`;
}
