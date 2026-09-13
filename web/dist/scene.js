import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { FLOORS, FLOOR_HEIGHT, statuses } from "./data.js";
import { buildCampus } from "./building.js";
import { createBuildingContext, applyBuildingView } from "./building-view.js";
export function createScene(
  container,
  hosts,
  onSelect,
  onFps,
  onFloor = () => {},
) {
  const scene = new THREE.Scene();
  scene.background = new THREE.Color("#102a49");
  scene.fog = new THREE.Fog("#102a49", 155, 330);
  const coarse = matchMedia("(pointer: coarse)").matches;
  const maxPixelRatio = Math.min(devicePixelRatio, coarse ? 1 : 1.25);
  const renderer = new THREE.WebGLRenderer({
    antialias: false,
    powerPreference: "high-performance",
  });
  renderer.setPixelRatio(maxPixelRatio);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.04;
  renderer.shadowMap.enabled = false;
  container.appendChild(renderer.domElement);
  renderer.domElement.style.touchAction = "none";
  renderer.domElement.setAttribute(
    "aria-label",
    "Campus FIAP Paulista. Clique na fachada ou escolha um andar em Infraestrutura; selecione um computador para inspecioná-lo.",
  );
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 500);
  camera.position.set(79, 64, 100);
  const controls = new OrbitControls(camera, renderer.domElement);
  controls.target.set(2, 27, 0);
  controls.enableDamping = true;
  controls.dampingFactor = 0.085;
  controls.rotateSpeed = 0.55;
  controls.panSpeed = 0.8;
  controls.zoomSpeed = 0.85;
  controls.screenSpacePanning = true;
  controls.zoomToCursor = true;
  controls.minDistance = 4;
  controls.maxDistance = 210;
  controls.minPolarAngle = 0.13;
  controls.maxPolarAngle = Math.PI * 0.49;
  controls.minAzimuthAngle = -Math.PI * 0.85;
  controls.maxAzimuthAngle = Math.PI * 0.85;
  controls.mouseButtons = {
    LEFT: THREE.MOUSE.ROTATE,
    MIDDLE: THREE.MOUSE.PAN,
    RIGHT: THREE.MOUSE.PAN,
  };
  scene.add(new THREE.HemisphereLight("#d9edfb", "#142b3e", 1.65));
  const sun = new THREE.DirectionalLight("#e7f2fb", 3.15);
  sun.position.set(-52, 88, 68);
  scene.add(sun);
  const fill = new THREE.DirectionalLight("#7ca8c8", 0.72);
  fill.position.set(48, 32, -55);
  scene.add(fill);
  const grid = new THREE.GridHelper(180, 90, "#34577a", "#203d5b");
  grid.position.y = -0.7;
  scene.add(grid);
  const campus = buildCampus(hosts);
  campus.context = createBuildingContext();
  campus.root.add(campus.context.group);
  scene.add(campus.root);
  const selection = new THREE.LineSegments(
    new THREE.EdgesGeometry(new THREE.BoxGeometry(1.95, 1.8, 1.65)),
    new THREE.LineBasicMaterial({ color: "#f0d185" }),
  );
  selection.visible = false;
  selection.material.transparent = true;
  selection.material.depthWrite = false;
  selection.renderOrder = 6;
  scene.add(selection);
  const hoverSelection = new THREE.LineSegments(
    new THREE.EdgesGeometry(new THREE.BoxGeometry(1.95, 1.8, 1.65)),
    new THREE.LineBasicMaterial({
      color: "#b8d8ed",
      transparent: true,
      opacity: 0.82,
      depthWrite: false,
    }),
  );
  hoverSelection.visible = false;
  hoverSelection.renderOrder = 5;
  scene.add(hoverSelection);
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let selected = null,
    focus = null,
    viewFloor = "all",
    exploded = false,
    planMode = false,
    panMode = false,
    paused = false,
    frame = 0,
    running = true,
    last = performance.now(),
    sample = last,
    count = 0,
    lastScreenUpdate = -Infinity,
    lastHoverTime = -Infinity,
    lowFpsSamples = 0,
    highFpsSamples = 0;
  const screenColor = new THREE.Color();
  function updateScreens(t = 0, force = false) {
    for (const mesh of campus.screenMeshes) {
      if (!mesh.parent.visible && !force) continue;
      let changed = false;
      mesh.userData.hosts.forEach((h, i) => {
        if (!force && h.status !== "threat") return;
        screenColor.set(h.isolated ? "#b291ed" : statuses[h.status].color);
        if (h.status === "offline") screenColor.multiplyScalar(0.18);
        else if (h.status === "threat" && !paused && !reduced)
          screenColor.multiplyScalar(0.78 + 0.22 * Math.sin(t * 0.005));
        mesh.setColorAt(i, screenColor);
        changed = true;
      });
      if (changed) mesh.instanceColor.needsUpdate = true;
    }
  }
  function setVisibility() {
    applyBuildingView(campus, { floor: viewFloor, exploded, plan: planMode });
    grid.visible = !planMode;
    positionSelection();
    clearHover();
    updateScreens(performance.now(), true);
  }
  function positionSelection() {
    selection.visible =
      selected !== null &&
      (viewFloor === "all" || Number(viewFloor) === hosts[selected].floor);
    if (selected !== null) {
      const h = hosts[selected],
        g = campus.floorGroups.get(h.floor);
      selection.position.set(h.x, g.position.y + 0.95 * h.scale + 0.17, h.z);
      selection.scale.setScalar(h.scale);
    }
  }
  function reset() {
    if (planMode && viewFloor !== "all") {
      const y = campus.floorGroups.get(Number(viewFloor)).position.y;
      focus = {
        position: new THREE.Vector3(0, y + 53, 6.95),
        target: new THREE.Vector3(0, y, 0),
      };
    } else if (viewFloor !== "all") {
      focus = {
        position: new THREE.Vector3(27, 35, 35),
        target: new THREE.Vector3(0, 0, 0),
      };
    } else {
      focus = {
        position: new THREE.Vector3(85, exploded ? 80 : 72, 116),
        target: new THREE.Vector3(2, exploded ? 32 : 27, 0),
      };
    }
  }
  const ray = new THREE.Raycaster(),
    pointer = new THREE.Vector2();
  const towerBounds = new THREE.Box3(
    new THREE.Vector3(-16.2, 4.5, -12.2),
    new THREE.Vector3(16.2, 58.5, 12.2),
  );
  const pickPoint = new THREE.Vector3(),
    slabBounds = new THREE.Box3();
  const floorPick = { userData: { floor: 0 } };
  function hitAt(e) {
    const rect = renderer.domElement.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    pointer.set(
      ((e.clientX - rect.left) / rect.width) * 2 - 1,
      (-(e.clientY - rect.top) / rect.height) * 2 + 1,
    );
    ray.setFromCamera(pointer, camera);
    if (viewFloor === "all") {
      if (!exploded) {
        if (!ray.ray.intersectBox(towerBounds, pickPoint)) return null;
        const floor = Math.floor(pickPoint.y / FLOOR_HEIGHT);
        if (!FLOORS.includes(floor)) return null;
        floorPick.userData.floor = floor;
        return { object: floorPick };
      }
      let nearest = Infinity,
        chosen = null;
      for (const [floor, g] of campus.floorGroups) {
        slabBounds.min.set(-16, g.position.y - 0.2, -12);
        slabBounds.max.set(16, g.position.y + 3, 12);
        if (ray.ray.intersectBox(slabBounds, pickPoint)) {
          const distance = ray.ray.origin.distanceToSquared(pickPoint);
          if (distance < nearest) {
            nearest = distance;
            chosen = floor;
          }
        }
      }
      if (chosen === null) return null;
      floorPick.userData.floor = chosen;
      return { object: floorPick };
    }
    const objects = campus.pcTargets.filter((m) => m.parent.visible);
    return ray.intersectObjects(objects, false)[0] || null;
  }
  function hostFromHit(hit) {
    const host = hit?.object.userData.hosts?.[hit.instanceId];
    return host?.placeholder ? null : host || null;
  }
  function floorFromHit(hit) {
    if (!hit) return null;
    if (hit.object.userData.floor !== undefined)
      return hit.object.userData.floor;
    return hit.object.userData.floors?.[hit.instanceId] ?? null;
  }
  function clearHover() {
    hoverSelection.visible = false;
    renderer.domElement.style.cursor = panMode ? "grab" : "default";
  }
  function showHover(hit) {
    clearHover();
    const host = hostFromHit(hit),
      floor = floorFromHit(hit);
    if (host) {
      const group = campus.floorGroups.get(host.floor);
      hoverSelection.position.set(
        host.x,
        group.position.y + 0.95 * host.scale + 0.17,
        host.z,
      );
      hoverSelection.scale.setScalar(host.scale);
      hoverSelection.visible = host.id !== selected;
    }
    if (host || FLOORS.includes(floor))
      renderer.domElement.style.cursor = "pointer";
  }
  let down;
  renderer.domElement.addEventListener("pointerdown", (e) => {
    down = [e.clientX, e.clientY];
    focus = null;
  });
  renderer.domElement.addEventListener("pointerup", (e) => {
    if (
      !down ||
      e.button !== 0 ||
      panMode ||
      Math.hypot(e.clientX - down[0], e.clientY - down[1]) > 5
    )
      return;
    const hit = hitAt(e);
    if (!hit) return;
    if (hit.object.userData.floor !== undefined) {
      onFloor(String(hit.object.userData.floor));
    } else if (hit.object.userData.floors) {
      const floor = hit.object.userData.floors[hit.instanceId];
      if (FLOORS.includes(floor)) onFloor(String(floor));
    } else {
      const h = hit.object.userData.hosts[hit.instanceId];
      if (h) onSelect(h.id);
    }
  });
  renderer.domElement.addEventListener("pointermove", (e) => {
    if (e.buttons || panMode) return clearHover();
    const time = performance.now();
    if (time - lastHoverTime < 50) return;
    lastHoverTime = time;
    showHover(hitAt(e));
  });
  renderer.domElement.addEventListener("pointerleave", clearHover);
  controls.addEventListener("start", clearHover);
  const observer = new ResizeObserver(() => {
    const w = container.clientWidth,
      h = container.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  });
  observer.observe(container);
  function animate(t) {
    if (!running) return;
    frame = requestAnimationFrame(animate);
    const delta = Math.min(0.08, (t - last) / 1000);
    last = t;
    if (document.hidden) {
      sample = t;
      count = 0;
      return;
    }
    count++;
    if (t - sample >= 1000) {
      const fps = Math.round((count * 1000) / (t - sample));
      onFps(fps);
      const ratio = renderer.getPixelRatio();
      lowFpsSamples = fps < 46 ? lowFpsSamples + 1 : 0;
      highFpsSamples = fps > 57 ? highFpsSamples + 1 : 0;
      if (lowFpsSamples >= 2 && ratio > 0.75) {
        renderer.setPixelRatio(Math.max(0.75, ratio - 0.25));
        renderer.setSize(container.clientWidth, container.clientHeight, false);
        lowFpsSamples = 0;
      } else if (highFpsSamples >= 5 && ratio < maxPixelRatio) {
        renderer.setPixelRatio(Math.min(maxPixelRatio, ratio + 0.25));
        renderer.setSize(container.clientWidth, container.clientHeight, false);
        highFpsSamples = 0;
      }
      count = 0;
      sample = t;
    }
    if (focus) {
      const alpha = reduced ? 1 : 1 - Math.exp(-6 * delta);
      camera.position.lerp(focus.position, alpha);
      controls.target.lerp(focus.target, alpha);
      if (
        camera.position.distanceTo(focus.position) < 0.02 &&
        controls.target.distanceTo(focus.target) < 0.02
      )
        focus = null;
    }
    if (t - lastScreenUpdate > 160) {
      updateScreens(t);
      lastScreenUpdate = t;
    }
    if (selection.visible && !reduced)
      selection.material.opacity = 0.72 + Math.sin(t * 0.004) * 0.2;
    controls.update();
    renderer.render(scene, camera);
  }
  setVisibility();
  updateScreens(0, true);
  frame = requestAnimationFrame(animate);
  return {
    setTool(mode) {
      panMode = mode === "pan";
      controls.mouseButtons.LEFT = panMode
        ? THREE.MOUSE.PAN
        : THREE.MOUSE.ROTATE;
      renderer.domElement.style.cursor = panMode ? "grab" : "default";
      clearHover();
    },
    explode(value) {
      exploded = value;
      planMode = false;
      setVisibility();
      reset();
    },
    floor(value) {
      if (value !== "all" && !FLOORS.includes(Number(value))) return;
      viewFloor = value;
      planMode = false;
      setVisibility();
      reset();
    },
    select(id) {
      if (!hosts[id]) return;
      selected = id;
      viewFloor = String(hosts[id].floor);
      planMode = false;
      setVisibility();
      const h = hosts[id],
        y = campus.floorGroups.get(h.floor).position.y;
      focus = {
        target: new THREE.Vector3(h.x, y + 1, h.z),
        position: new THREE.Vector3(h.x + 7, y + 9, h.z + 10),
      };
    },
    clearSelection() {
      selected = null;
      positionSelection();
    },
    reset,
    plan() {
      if (viewFloor === "all") return;
      planMode = true;
      setVisibility();
      reset();
    },
    zoom(delta) {
      const offset = camera.position
        .clone()
        .sub(controls.target)
        .multiplyScalar(delta)
        .clampLength(4, 210);
      focus = {
        target: controls.target.clone(),
        position: controls.target.clone().add(offset),
      };
    },
    update() {
      updateScreens(performance.now(), true);
    },
    pause(value) {
      paused = value;
    },
    dispose() {
      running = false;
      cancelAnimationFrame(frame);
      observer.disconnect();
      controls.dispose();
      const geometries = new Set(),
        materials = new Set(),
        textures = new Set();
      scene.traverse((o) => {
        if (o.geometry) geometries.add(o.geometry);
        if (o.material)
          (Array.isArray(o.material) ? o.material : [o.material]).forEach(
            (m) => {
              materials.add(m);
              if (m.map) textures.add(m.map);
            },
          );
      });
      geometries.forEach((g) => g.dispose());
      materials.forEach((m) => m.dispose());
      textures.forEach((t) => t.dispose());
      renderer.dispose();
    },
  };
}
