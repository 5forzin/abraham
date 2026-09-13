export function createWindows() {
  const root = document.querySelector(".editor");
  const elements = {
    layers: document.querySelector(".layers-panel"),
    inspector: document.querySelector("#inspector"),
    endpoints: document.querySelector("#endpoints"),
  };
  const triggers = {
    layers: "#restore-layers",
    inspector: "#nav-events",
    endpoints: "#nav-endpoints",
  };
  let active = null;
  let origin = null;
  let drag = null;

  function sync() {
    root.classList.toggle("table-open", active === "endpoints");
    document
      .querySelector(".document-name")
      ?.setAttribute("aria-expanded", String(active === "layers"));
    for (const [name, selector] of Object.entries(triggers)) {
      const button = document.querySelector(selector);
      button?.setAttribute("aria-expanded", String(active === name));
      button?.classList.toggle("active", active === name);
    }
  }
  function constrain(element, left, top) {
    const rect = element.getBoundingClientRect();
    element.style.left = `${Math.max(8, Math.min(window.innerWidth - rect.width - 8, left))}px`;
    element.style.top = `${Math.max(68, Math.min(window.innerHeight - 86 - Math.min(rect.height, window.innerHeight - 154), top))}px`;
    element.style.right = "auto";
    element.style.bottom = "auto";
    element.style.transform = "none";
  }
  const api = {
    open(name, focus = true) {
      if (!elements[name]) return;
      origin = document.activeElement;
      active = name;
      for (const [key, element] of Object.entries(elements))
        element.hidden = key !== name;
      root.classList.remove("focus-mode");
      document
        .querySelector("#focus-mode")
        .setAttribute("aria-pressed", "false");
      sync();
      document.dispatchEvent(new window.CustomEvent("workspace:window-open"));
      if (focus)
        elements[name]
          .querySelector("[data-window-handle]")
          ?.focus({ preventScroll: true });
    },
    close(name = active, restore = true) {
      if (!elements[name]) return;
      elements[name].hidden = true;
      if (active === name) active = null;
      sync();
      if (restore) {
        const target =
          origin?.isConnected &&
          !origin.closest("[hidden]") &&
          origin !== document.body
            ? origin
            : document.querySelector("#tools-toggle") ||
              document.querySelector(triggers[name]);
        target?.focus({ preventScroll: true });
      }
    },
    toggle(name) {
      elements[name].hidden ? api.open(name) : api.close(name);
    },
    closeActive() {
      if (!active) return false;
      api.close();
      return true;
    },
    get active() {
      return active;
    },
  };
  document.addEventListener("pointerdown", (event) => {
    const handle = event.target.closest("[data-window-handle]");
    if (
      !handle ||
      event.target.closest("button, input, select") ||
      event.button !== 0
    )
      return;
    const element = handle.closest("[data-window]");
    const rect = element.getBoundingClientRect();
    drag = {
      element,
      handle,
      pointerId: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      left: rect.left,
      top: rect.top,
    };
    handle.setPointerCapture(event.pointerId);
    element.classList.add("dragging");
    event.preventDefault();
  });
  document.addEventListener("pointermove", (event) => {
    if (drag && drag.pointerId === event.pointerId)
      constrain(
        drag.element,
        drag.left + event.clientX - drag.x,
        drag.top + event.clientY - drag.y,
      );
  });
  function endDrag() {
    if (drag) drag.element.classList.remove("dragging");
    drag = null;
  }
  document.addEventListener("pointerup", endDrag);
  document.addEventListener("pointercancel", endDrag);
  document.addEventListener("lostpointercapture", endDrag);
  window.addEventListener("blur", endDrag);
  document.addEventListener("workspace:chat-open", () => {
    if (active) api.close(active, false);
  });
  document.addEventListener("keydown", (event) => {
    const handle = event.target.closest("[data-window-handle]");
    if (
      event.target !== handle ||
      !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)
    )
      return;
    event.preventDefault();
    const element = handle.closest("[data-window]"),
      rect = element.getBoundingClientRect();
    constrain(
      element,
      rect.left +
        (event.key === "ArrowLeft" ? -20 : event.key === "ArrowRight" ? 20 : 0),
      rect.top +
        (event.key === "ArrowUp" ? -20 : event.key === "ArrowDown" ? 20 : 0),
    );
  });
  window.addEventListener("resize", () => {
    for (const element of Object.values(elements))
      if (!element.hidden && element.style.left) {
        const rect = element.getBoundingClientRect();
        constrain(element, rect.left, rect.top);
      }
  });
  return api;
}
