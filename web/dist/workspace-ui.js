import { icon } from "./layout.js";

export function sectorAt(x, y) {
  const distance = Math.hypot(x, y);
  if (distance < 36 || distance > 230) return -1;
  return (
    Math.round((Math.atan2(y, x) + Math.PI / 2 + Math.PI * 2) / (Math.PI / 4)) %
    8
  );
}

export function createWorkspaceUI(answer) {
  const root = document.querySelector(".editor");
  const toolbar = document.querySelector(".bottom-toolbar");
  const buttons = [...toolbar.querySelectorAll("button")];
  const labels = [
    "Prédio",
    "Andares",
    "Planta",
    "Selecionar",
    "Mover",
    "Endpoints",
    "Inspecionar",
    "Ajuda",
  ];
  toolbar.className = "radial-menu";
  toolbar.id = "radial-menu";
  toolbar.hidden = true;
  toolbar.setAttribute("role", "menu");
  toolbar.replaceChildren(...buttons);
  buttons.forEach((button, i) => {
    button.className = `radial-action${button.classList.contains("active") ? " active" : ""}`;
    button.setAttribute("role", "menuitem");
    button.innerHTML =
      button.querySelector("svg").outerHTML + `<span>${labels[i]}</span>`;
    button.style.setProperty("--x", `${Math.sin((i * Math.PI) / 4) * 116}px`);
    button.style.setProperty("--y", `${-Math.cos((i * Math.PI) / 4) * 116}px`);
  });
  const center = document.createElement("div");
  center.className = "radial-center";
  center.innerHTML = "<span>Ferramentas</span><small>Arraste e solte</small>";
  toolbar.append(center);
  root.insertAdjacentHTML(
    "beforeend",
    `<section class="assistant-dock" aria-label="Assistente Abraham"><div class="chat-panel" id="chat-panel" hidden><header><div><b>Abraham</b><span>IA · acesso read-only</span></div><button class="icon-button" id="chat-close" aria-label="Recolher conversa">${icon("close", 16)}</button></header><div class="chat-messages" role="log" aria-live="polite" aria-relevant="additions"></div><div class="chat-suggestions"><button data-prompt="Mostrar o 7º andar">7º andar</button><button data-prompt="Resumo do campus">Resumo do campus</button><button data-prompt="Mostrar o prédio">Prédio inteiro</button><button data-prompt="Analise os acessos implantados">Analisar acessos</button></div></div><form class="chat-composer"><input id="chat-input" maxlength="500" autocomplete="off" aria-label="Mensagem para o assistente Abraham" placeholder="Peça ao Abraham…"><button type="submit" id="chat-send" aria-label="Enviar mensagem" disabled>↑</button><span class="composer-divider"></span><button type="button" id="tools-toggle" class="icon-button" aria-label="Abrir ferramentas" aria-haspopup="menu" aria-controls="radial-menu" aria-expanded="false" title="Ferramentas · Alt + botão direito">${icon("layers", 19)}</button></form><div class="gesture-hint">Ferramentas <span>Alt + botão direito</span></div></section>`,
  );
  const $ = (s) => root.querySelector(s);
  const trigger = $("#tools-toggle");
  const panel = $("#chat-panel");
  const input = $("#chat-input");
  input.setAttribute("aria-controls", "chat-panel");
  input.setAttribute("aria-expanded", "false");
  input.title = "Escreva uma mensagem. Seta para cima reabre a conversa.";
  $(".top-actions").prepend(trigger);
  $(".composer-divider").remove();
  $(".gesture-hint").remove();
  input.placeholder = "Peça qualquer coisa";
  $("#chat-send").insertAdjacentHTML(
    "afterend",
    '<button type="button" id="chat-mic" class="icon-button" aria-label="Ditar mensagem" title="Ditar mensagem" aria-pressed="false"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><rect x="9" y="3" width="6" height="12" rx="3"/><path d="M5.5 10.5v1a6.5 6.5 0 0 0 13 0v-1M12 18v3m-3 0h6"/></svg></button>',
  );
  const mic = $("#chat-mic");
  let recognition = null;
  let answering = false;
  function syncComposer() {
    const hasText = !!input.value.trim();
    $("#chat-send").disabled = !hasText || answering;
    $("#chat-send").hidden = !hasText;
    mic.hidden = hasText && !recognition;
  }
  function stopDictation() {
    const session = recognition;
    recognition = null;
    session?.abort();
    mic.setAttribute("aria-pressed", "false");
    mic.setAttribute("aria-label", "Ditar mensagem");
    input.placeholder = "Peça qualquer coisa";
    syncComposer();
  }
  mic.onclick = () => {
    if (recognition) {
      stopDictation();
      return;
    }
    const Speech = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!Speech) {
      conversation(true);
      message(
        "Ditado por voz indisponível neste navegador. Você pode escrever sua mensagem abaixo.",
        "assistant",
      );
      input.focus();
      return;
    }
    const session = new Speech();
    recognition = session;
    session.lang = "pt-BR";
    session.continuous = false;
    session.interimResults = false;
    session.onresult = (e) => {
      input.value = e.results[0][0].transcript.slice(0, 500);
      syncComposer();
    };
    session.onerror = (e) => {
      if (e.error === "aborted") return;
      conversation(true);
      message(
        e.error === "not-allowed"
          ? "O microfone não foi autorizado. Libere o acesso no navegador ou digite sua mensagem."
          : "Não consegui transcrever o áudio. Tente novamente ou digite sua mensagem.",
        "assistant",
      );
    };
    session.onend = () => {
      if (recognition === session) {
        recognition = null;
        stopDictation();
      }
    };
    try {
      session.start();
      mic.setAttribute("aria-pressed", "true");
      mic.setAttribute("aria-label", "Cancelar ditado");
      input.placeholder = "Ouvindo…";
    } catch {
      stopDictation();
      conversation(true);
      message(
        "Não foi possível iniciar o microfone. Digite sua mensagem para continuar.",
        "assistant",
      );
    }
  };
  window.addEventListener("blur", stopDictation);
  window.addEventListener("pagehide", stopDictation);
  syncComposer();
  let active = -1,
    dragging = false,
    pointerId = null,
    cx = 0,
    cy = 0,
    startX = 0,
    startY = 0,
    menuScale = 1,
    origin = null;
  function highlight(index) {
    active = index;
    buttons.forEach((b, i) => b.classList.toggle("hovered", i === index));
    center.firstElementChild.textContent =
      index < 0 ? "Ferramentas" : labels[index];
    center.lastElementChild.textContent =
      index < 0
        ? "Esc cancela"
        : dragging
          ? "Solte para abrir"
          : "Enter para abrir";
  }
  function close(restore = true) {
    toolbar.hidden = true;
    dragging = false;
    pointerId = null;
    trigger.setAttribute("aria-expanded", "false");
    if (restore)
      (origin?.isConnected && !origin.closest("[hidden]")
        ? origin
        : trigger
      ).focus({ preventScroll: true });
  }
  function open(x, y, gesture = false) {
    root.classList.remove("focus-mode");
    $("#focus-mode").setAttribute("aria-pressed", "false");
    origin = document.activeElement;
    startX = x;
    startY = y;
    menuScale = Math.min(
      1,
      (window.innerWidth - 16) / 340,
      (window.innerHeight - 16) / 340,
    );
    const edge = 170 * menuScale + 8;
    cx = Math.max(edge, Math.min(window.innerWidth - edge, x));
    cy = Math.max(edge, Math.min(window.innerHeight - edge, y));
    toolbar.style.setProperty("--menu-scale", String(menuScale));
    toolbar.style.left = `${cx}px`;
    toolbar.style.top = `${cy}px`;
    toolbar.hidden = false;
    dragging = gesture;
    trigger.setAttribute("aria-expanded", "true");
    highlight(-1);
    if (!gesture) {
      highlight(0);
      buttons[0].focus();
    }
  }
  trigger.onclick = () => {
    if (!toolbar.hidden) return close();
    const rect = trigger.getBoundingClientRect();
    open(rect.left + rect.width / 2, rect.top - 180);
  };
  toolbar.addEventListener(
    "click",
    (e) => {
      if (e.target.closest("button")) close();
    },
    true,
  );
  buttons.forEach((b, i) => {
    b.addEventListener("pointerenter", () => {
      if (!dragging) highlight(i);
    });
    b.addEventListener("focus", () => highlight(i));
  });
  document.addEventListener(
    "pointerdown",
    (e) => {
      if (e.altKey && e.button === 2 && e.target.closest("#viewport")) {
        e.preventDefault();
        e.stopImmediatePropagation();
        open(e.clientX, e.clientY, true);
        pointerId = e.pointerId;
      } else if (
        !toolbar.hidden &&
        !toolbar.contains(e.target) &&
        !trigger.contains(e.target)
      )
        close(false);
    },
    true,
  );
  document.addEventListener(
    "contextmenu",
    (e) => {
      if (
        (e.altKey && e.target.closest("#viewport")) ||
        !toolbar.hidden ||
        toolbar.contains(e.target)
      )
        e.preventDefault();
    },
    true,
  );
  document.addEventListener(
    "pointermove",
    (e) => {
      if (!dragging || e.pointerId !== pointerId) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      highlight(
        sectorAt((e.clientX - cx) / menuScale, (e.clientY - cy) / menuScale),
      );
    },
    true,
  );
  document.addEventListener(
    "pointerup",
    (e) => {
      if (!dragging || e.pointerId !== pointerId) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      const index =
        Math.hypot(e.clientX - startX, e.clientY - startY) < 12
          ? -1
          : sectorAt(
              (e.clientX - cx) / menuScale,
              (e.clientY - cy) / menuScale,
            );
      close();
      if (index >= 0) buttons[index].click();
    },
    true,
  );
  document.addEventListener("pointercancel", () => {
    if (!toolbar.hidden) close();
  });
  window.addEventListener("blur", () => close(false));
  window.addEventListener("resize", () => close(false));
  document.addEventListener(
    "keydown",
    (e) => {
      if (toolbar.hidden) return;
      e.stopImmediatePropagation();
      if (e.key === "Escape" || e.key === "Tab") {
        close();
        if (e.key === "Escape") e.preventDefault();
      }
      if (e.key.startsWith("Arrow")) {
        e.preventDefault();
        highlight(
          (active + (["ArrowLeft", "ArrowUp"].includes(e.key) ? 7 : 1)) % 8,
        );
        buttons[active].focus();
      }
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        const index = active;
        close();
        if (index >= 0) buttons[index].click();
      }
    },
    true,
  );
  function conversation(open) {
    panel.hidden = !open;
    input.setAttribute("aria-expanded", String(open));
    if (open)
      document.dispatchEvent(new window.CustomEvent("workspace:chat-open"));
  }
  document.addEventListener("workspace:window-open", () => conversation(false));
  document.addEventListener("pointerdown", (e) => {
    if (!e.target.closest(".assistant-dock") && !panel.hidden)
      conversation(false);
  });
  input.addEventListener("click", () => {
    if ($(".chat-messages").children.length > 1) conversation(true);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp" && !input.value) {
      e.preventDefault();
      conversation(true);
    }
  });
  function fitKeyboard() {
    const viewport = window.visualViewport;
    const inset = viewport
      ? Math.max(0, window.innerHeight - viewport.height - viewport.offsetTop)
      : 0;
    root.style.setProperty("--keyboard-inset", `${inset}px`);
    root.style.setProperty(
      "--usable-height",
      `${viewport?.height || window.innerHeight}px`,
    );
  }
  window.visualViewport?.addEventListener("resize", fitKeyboard);
  window.visualViewport?.addEventListener("scroll", fitKeyboard);
  fitKeyboard();
  function message(text, author) {
    const element = document.createElement("p");
    element.className = `chat-message ${author}`;
    element.textContent = text;
    const log = $(".chat-messages");
    log.append(element);
    while (log.children.length > 40) log.firstElementChild.remove();
    log.scrollTop = log.scrollHeight;
    return element;
  }
  message(
    "Posso navegar pelo campus e analisar, em modo somente leitura, as sessões conectadas ao teamserver.",
    "assistant",
  );
  $("#chat-close").onclick = () => {
    stopDictation();
    conversation(false);
    input.focus();
  };
  input.oninput = syncComposer;
  const transcript = [];
  $(".chat-composer").onsubmit = async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || answering) return;
    stopDictation();
    conversation(true);
    $(".chat-suggestions").hidden = true;
    message(text, "user");
    const priorHistory = transcript.slice(-8);
    transcript.push({ role: "user", content: text });
    input.value = "";
    answering = true;
    input.disabled = true;
    syncComposer();
    const pending = message("Consultando…", "assistant pending");
    try {
      const response = await answer(text, priorHistory);
      pending.textContent = response;
      pending.classList.remove("pending");
      transcript.push({ role: "assistant", content: response });
      transcript.splice(0, Math.max(0, transcript.length - 12));
    } catch {
      pending.textContent =
        "Não consegui consultar o assistente agora. O campus e as ferramentas locais continuam disponíveis.";
      pending.classList.remove("pending");
    } finally {
      answering = false;
      input.disabled = false;
      syncComposer();
      input.focus();
    }
  };
  $(".chat-suggestions").onclick = (e) => {
    const button = e.target.closest("[data-prompt]");
    if (button) {
      input.value = button.dataset.prompt;
      $(".chat-composer").requestSubmit();
    }
  };
  $(".assistant-dock").addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      stopDictation();
      e.stopPropagation();
      conversation(false);
      input.blur();
    }
  });
}
