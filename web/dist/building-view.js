import * as THREE from "three";
import { FLOORS, FLOOR_HEIGHT } from "./data.js";

export function createBuildingContext() {
  const group = new THREE.Group(),
    targets = [];
  for (let floor = 0; floor <= 13; floor++) {
    const y = floor * FLOOR_HEIGHT,
      vertices = [
        -16,
        y,
        -12,
        16,
        y,
        -12,
        16,
        y,
        -12,
        16,
        y,
        12,
        16,
        y,
        12,
        -16,
        y,
        12,
        -16,
        y,
        12,
        -16,
        y,
        -12,
      ];
    const ring = new THREE.LineSegments(
      new THREE.BufferGeometry().setAttribute(
        "position",
        new THREE.Float32BufferAttribute(vertices, 3),
      ),
      new THREE.LineBasicMaterial({
        color: "#91b5d3",
        transparent: true,
        opacity: 0.25,
        depthWrite: false,
      }),
    );
    ring.userData.floor = floor;
    group.add(ring);
    if (FLOORS.includes(floor)) targets.push(ring);
  }
  const posts = [];
  for (const x of [-16, 16])
    for (const z of [-12, 12]) posts.push(x, 0, z, x, 13 * FLOOR_HEIGHT, z);
  group.add(
    new THREE.LineSegments(
      new THREE.BufferGeometry().setAttribute(
        "position",
        new THREE.Float32BufferAttribute(posts, 3),
      ),
      new THREE.LineBasicMaterial({
        color: "#9dbcd5",
        transparent: true,
        opacity: 0.4,
        depthWrite: false,
      }),
    ),
  );
  return { group, targets };
}

export function applyBuildingView(
  campus,
  { floor = "all", exploded = false, plan = false },
) {
  const all = floor === "all";
  for (const [number, g] of campus.floorGroups) {
    g.visible = all || number === Number(floor);
    g.position.y = all
      ? number * FLOOR_HEIGHT + (exploded ? FLOORS.indexOf(number) * 2.2 : 0)
      : 0;
    for (const label of g.userData.labels || []) label.visible = !all;
    g.traverse((o) => {
      if (o.userData.kind === "ceiling-lights") o.visible = all;
    });
  }
  campus.facade.visible = all && !exploded && !plan;
  campus.exterior.visible = all;
  campus.context.group.visible = false;
  for (const ring of campus.context.targets) {
    const selected = ring.userData.floor === Number(floor);
    ring.material.color.set(selected ? "#f1ce8a" : "#91b5d3");
    ring.material.opacity = selected ? 1 : 0.25;
  }
  campus.root.updateMatrixWorld(true);
}
