import * as THREE from "three";
import { FLOORS, FLOOR_HEIGHT } from "./data.js";
import { buildFloorPlan } from "./floor-plan.js";
import { buildStreetscape } from "./streetscape.js";
import { consolidateStatic } from "./mesh-batching.js";

export function buildCampus(hosts) {
  const root = new THREE.Group(),
    exterior = new THREE.Group(),
    facade = new THREE.Group();
  const floorGroups = new Map(),
    screenMeshes = [],
    pcTargets = [],
    facadeTargets = [];
  root.add(exterior, facade);
  const cube = new THREE.BoxGeometry(1, 1, 1),
    dummy = new THREE.Object3D();
  const materials = new Map();
  function material(color, opacity = 1) {
    const key = color + "/" + opacity;
    if (!materials.has(key))
      materials.set(
        key,
        new THREE.MeshStandardMaterial({
          color,
          roughness: 0.8,
          metalness: 0.06,
          transparent: opacity < 1,
          opacity,
          depthWrite: opacity === 1,
        }),
      );
    return materials.get(key);
  }
  function box(parent, x, y, z, w, h, d, color, opacity = 1) {
    const mesh = new THREE.Mesh(cube, material(color, opacity));
    mesh.position.set(x, y, z);
    mesh.scale.set(w, h, d);
    parent.add(mesh);
    return mesh;
  }
  function batch(parent, items, mat) {
    const mesh = new THREE.InstancedMesh(cube, mat, items.length);
    items.forEach((a, i) => {
      dummy.position.set(a[0], a[1], a[2]);
      dummy.scale.set(a[3], a[4], a[5]);
      dummy.rotation.set(0, 0, 0);
      dummy.updateMatrix();
      mesh.setMatrixAt(i, dummy.matrix);
    });
    mesh.computeBoundingSphere();
    parent.add(mesh);
    return mesh;
  }
  function label(
    parent,
    text,
    x,
    y,
    z,
    width,
    color = "#d7e6f3",
    flat = false,
  ) {
    const canvas = document.createElement("canvas");
    canvas.width = text.length <= 4 ? Math.max(96, text.length * 30 + 26) : 512;
    canvas.height = 96;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "rgba(12,29,45,.85)";
    ctx.fillRect(0, 0, canvas.width, 96);
    ctx.fillStyle = color;
    ctx.font = "500 43px Arial";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(text, canvas.width / 2, 50);
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = 2;
    const mesh = new THREE.Mesh(
      new THREE.PlaneGeometry(width, (width * 96) / canvas.width),
      new THREE.MeshBasicMaterial({
        map: texture,
        transparent: true,
        side: THREE.DoubleSide,
        depthWrite: false,
      }),
    );
    mesh.position.set(x, y, z);
    if (flat) mesh.rotation.x = -Math.PI / 2;
    mesh.userData.label = text;
    parent.add(mesh);
    return mesh;
  }
  for (const floor of FLOORS) {
    const g = new THREE.Group();
    g.position.y = floor * FLOOR_HEIGHT;
    g.userData.floor = floor;
    root.add(g);
    floorGroups.set(floor, g);
    const { screens, picks } = buildFloorPlan(g, floor, hosts, {
      box,
      batch,
      material,
      label,
    });
    g.userData.labels = [];
    g.traverse((o) => {
      if (o.userData.label) g.userData.labels.push(o);
    });
    consolidateStatic(g);
    screenMeshes.push(screens);
    pcTargets.push(picks);
  }
  const glass = [],
    glassFloors = [],
    mullions = [];
  for (let floor = 1; floor <= 12; floor++) {
    const y = floor * FLOOR_HEIGHT + FLOOR_HEIGHT / 2;
    for (let col = 0; col < 16; col++)
      for (const z of [-10.09, 10.09]) {
        glass.push([-15 + col * 2, y, z, 1.96, 4.38, 0.08]);
        glassFloors.push(floor);
      }
    for (let col = 0; col < 10; col++)
      for (const x of [-16.09, 16.09]) {
        glass.push([x, y, -9 + col * 2, 0.08, 4.38, 1.96]);
        glassFloors.push(floor);
      }
    mullions.push(
      [0, floor * FLOOR_HEIGHT, 10.13, 32, 0.055, 0.06],
      [0, floor * FLOOR_HEIGHT, -10.13, 32, 0.055, 0.06],
      [16.13, floor * FLOOR_HEIGHT, 0, 0.06, 0.055, 20],
      [-16.13, floor * FLOOR_HEIGHT, 0, 0.06, 0.055, 20],
    );
    if (!FLOORS.includes(floor))
      box(facade, 0, floor * FLOOR_HEIGHT, 0, 32, 0.18, 20, "#3c5368");
  }
  const glassMesh = batch(
    facade,
    glass,
    new THREE.MeshStandardMaterial({
      color: "#a8bfcd",
      metalness: 0.12,
      roughness: 0.4,
      transparent: true,
      opacity: 0.12,
      depthWrite: false,
    }),
  );
  const color = new THREE.Color();
  glass.forEach((_, i) =>
    glassMesh.setColorAt(
      i,
      color.set(i % 13 === 0 ? "#739dbb" : i % 7 === 0 ? "#c3d4dd" : "#a3b9ca"),
    ),
  );
  glassMesh.userData.floors = glassFloors;
  facadeTargets.push(glassMesh);
  for (let x = -16; x <= 16; x += 2)
    mullions.push(
      [x, 31.5, 10.15, 0.045, 54, 0.055],
      [x, 31.5, -10.15, 0.045, 54, 0.055],
    );
  for (let z = -10; z <= 10; z += 2)
    mullions.push(
      [-16.15, 31.5, z, 0.055, 54, 0.045],
      [16.15, 31.5, z, 0.055, 54, 0.045],
    );
  batch(facade, mullions, material("#8ca4b7"));
  box(facade, 0, 58.6, 0, 32.4, 0.45, 20.4, "#788f9f");
  box(facade, 0, 59.8, -3, 14, 2, 9, "#425e74");
  consolidateStatic(facade);
  facade.scale.z = 1.2;
  buildStreetscape(exterior, { box, label });
  return {
    root,
    exterior,
    facade,
    floorGroups,
    screenMeshes,
    pcTargets,
    facadeTargets,
  };
}
