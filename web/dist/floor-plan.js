import * as THREE from "three";
import { ROOMS, ELEVATORS, roomLabel, statuses } from "./data.js";

const cushionGeometry = new THREE.BoxGeometry(1, 1, 1, 5, 5, 5);
const vertex = new THREE.Vector3(),
  inner = new THREE.Vector3();
for (let i = 0; i < cushionGeometry.attributes.position.count; i++) {
  vertex.fromBufferAttribute(cushionGeometry.attributes.position, i);
  inner.copy(vertex).clampScalar(-0.34, 0.34);
  vertex.sub(inner).normalize().multiplyScalar(0.16).add(inner);
  cushionGeometry.attributes.position.setXYZ(i, vertex.x, vertex.y, vertex.z);
}
cushionGeometry.computeVertexNormals();
const plantGeometry = new THREE.IcosahedronGeometry(1, 0);

export function buildFloorPlan(
  g,
  floor,
  hosts,
  { box, batch, material, label },
) {
  g.userData.layout = "Paulista circulation and six classrooms";
  g.userData.rooms = ROOMS.map((r) => ({
    id: r.id,
    name: roomLabel(floor, r),
  }));
  g.userData.elevators = ELEVATORS.map((e) => ({ ...e }));
  const walls = [],
    glass = [],
    trim = [],
    desks = [],
    legs = [],
    monitors = [],
    keyboards = [],
    chairs = [],
    wheels = [],
    ceilingLights = [];
  box(g, 0, 0, 0, 32, 0.2, 24, "#65717a");
  box(g, 0, -0.15, 0, 32.2, 0.15, 24.2, "#233e55");
  // The broad grey floor remains unobstructed between classroom strips and lift banks.
  box(g, 0, 0.115, 3, 22.3, 0.025, 17.9, "#7b838a");
  const guideVertices = [];
  const rectangle = (x, z, w, d, y = 0.19) =>
    guideVertices.push(
      x - w / 2,
      y,
      z - d / 2,
      x + w / 2,
      y,
      z - d / 2,
      x + w / 2,
      y,
      z - d / 2,
      x + w / 2,
      y,
      z + d / 2,
      x + w / 2,
      y,
      z + d / 2,
      x - w / 2,
      y,
      z + d / 2,
      x - w / 2,
      y,
      z + d / 2,
      x - w / 2,
      y,
      z - d / 2,
    );
  for (const room of ROOMS.filter((r) => r.id < 7)) {
    const side = room.x < 0 ? -1 : 1,
      edge = side * 11.2,
      number = floor * 100 + room.id;
    rectangle(room.x, room.z, 4.82, 5.98);
    for (const x of [room.x - 1.35, room.x, room.x + 1.35])
      for (const z of [
        room.z - 1.72,
        room.z - 0.57,
        room.z + 0.58,
        room.z + 1.73,
      ])
        ceilingLights.push([x, 2.86, z, 0.75, 0.025, 0.16]);
    box(g, room.x, 0.12, room.z, 4.65, 0.04, 5.84, "#b1a887");
    box(g, room.x, 0.15, room.z - 2.82, 4.5, 0.025, 0.09, "#e1bc66");
    walls.push(
      [side * 15.95, 0.58, room.z, 0.12, 1.15, 6],
      [room.x, 0.58, room.z - 2.98, 4.8, 1.15, 0.12],
    );
    if (room.z === 9) walls.push([room.x, 0.58, 11.95, 4.8, 1.15, 0.12]);
    // Two wall sections leave a real door opening on the circulation side.
    walls.push(
      [edge, 0.58, room.z - 1.2, 0.13, 1.15, 3.5],
      [edge, 0.58, room.z + 2.6, 0.13, 1.15, 0.6],
    );
    glass.push(
      [edge, 1.65, room.z - 1.2, 0.045, 1.2, 3.5],
      [side * 15.95, 1.65, room.z, 0.045, 1.2, 6],
    );
    trim.push(
      [edge, 2.27, room.z + 1.65, 0.24, 0.12, 1.3],
      [edge, 1.1, room.z + 1.01, 0.17, 2.2, 0.09],
      [edge, 1.1, room.z + 2.29, 0.17, 2.2, 0.09],
    );
    const door = box(
      g,
      edge - side * 0.34,
      1.05,
      room.z + 2.14,
      0.065,
      2.05,
      1.1,
      "#477084",
      0.42,
    );
    door.rotation.y = -side * 0.6;
    box(g, room.x, 1.55, room.z - 2.89, 2.8, 1.04, 0.05, "#cfd6d6");
    box(g, room.x, 1.55, room.z - 2.845, 2.56, 0.82, 0.025, "#253d50");
    label(
      g,
      String(number),
      side * 10.22,
      0.155,
      room.z + 1.6,
      2.2,
      "#f4d885",
      true,
    );
    const sign = label(
      g,
      String(number),
      edge - side * 0.13,
      2.07,
      room.z - 1.55,
      1.25,
      "#f4d885",
    );
    sign.rotation.y = (-side * Math.PI) / 2;
  }
  batch(g, walls, material("#cad0cc"));
  batch(g, glass, material("#92b8c8", 0.14));
  batch(g, trim, material("#dfbd73"));
  const guides = new THREE.LineSegments(
    new THREE.BufferGeometry().setAttribute(
      "position",
      new THREE.Float32BufferAttribute(guideVertices, 3),
    ),
    new THREE.LineBasicMaterial({
      color: "#d4e2e9",
      transparent: true,
      opacity: 0.42,
      depthWrite: false,
    }),
  );
  guides.renderOrder = 2;
  guides.userData.kind = "architectural-guides";
  g.add(guides);
  const lights = batch(
    g,
    ceilingLights,
    new THREE.MeshBasicMaterial({
      color: "#dbe9e9",
      transparent: true,
      opacity: 0.76,
      toneMapped: false,
    }),
  );
  lights.userData.kind = "ceiling-lights";

  // The rear band spans the complete floor width, as in the supplied plan.
  box(g, 0, 0.125, -9.03, 31.7, 0.045, 5.8, "#79565d");
  box(g, 0, 0.17, -6.13, 31.7, 0.035, 0.14, "#db657d");
  box(g, 0, 0.66, -11.95, 32, 1.32, 0.13, "#d5cfca");
  for (const x of [-15.95, 15.95]) box(g, x, 0.65, -9, 0.12, 1.3, 6, "#d5cfca");
  label(g, "COWORKING", 0, 0.205, -6.65, 6, "#f5bec8", true);
  box(g, -10.4, 0.68, -10.08, 7.9, 0.12, 1.13, "#d4b898");
  box(g, -10.4, 0.68, -8.08, 7.9, 0.12, 1.13, "#d4b898");
  for (const x of [-14, -10.4, -6.8])
    for (const z of [-10.08, -8.08])
      box(g, x, 0.34, z, 0.09, 0.68, 0.87, "#59646d");

  const lounge = new THREE.Group();
  lounge.userData.kind = "coworking-lounge";
  g.add(lounge);
  function soft(parent, x, y, z, w, h, d, color, kind = "upholstery") {
    const mesh = new THREE.Mesh(cushionGeometry, material(color));
    mesh.position.set(x, y, z);
    mesh.scale.set(w, h, d);
    mesh.userData.kind = kind;
    parent.add(mesh);
    return mesh;
  }
  function sofa(x, z, rotation = 0, width = 3.4) {
    const group = new THREE.Group();
    group.position.set(x, 0.17, z);
    group.rotation.y = rotation;
    group.userData.kind = "sofa";
    lounge.add(group);
    soft(group, 0, 0.3, 0, width, 0.44, 1.04, "#c1b3b0");
    soft(group, 0, 0.76, -0.46, width, 0.92, 0.24, "#ab9295");
    for (const side of [-1, 1]) {
      soft(
        group,
        side * (width / 2 - 0.13),
        0.58,
        0,
        0.26,
        0.6,
        1.08,
        "#ab9295",
      );
      for (const depth of [-0.35, 0.35])
        box(
          group,
          side * (width / 2 - 0.35),
          0.08,
          depth,
          0.09,
          0.18,
          0.09,
          "#374657",
        );
    }
    for (let i = 0; i < 3; i++) {
      soft(
        group,
        (i - 1) * 0.93,
        0.57,
        0.04,
        0.88,
        0.18,
        0.77,
        "#d3c4bc",
        "seat-cushion",
      );
      const cushion = soft(
        group,
        (i - 1) * 0.94,
        0.86,
        -0.24,
        0.53,
        0.52,
        0.18,
        i === 1 ? "#b65473" : "#e4c5bd",
        "loose-cushion",
      );
      cushion.rotation.set(-0.17, 0, (i - 1) * 0.15);
    }
  }
  sofa(3.3, -10.55);
  sofa(12.3, -9.5, -Math.PI / 2);
  function armchair(x, z, rotation, color) {
    const chair = new THREE.Group();
    chair.position.set(x, 0.16, z);
    chair.rotation.y = rotation;
    chair.userData.kind = "lounge-chair";
    lounge.add(chair);
    soft(chair, 0, 0.4, 0, 0.9, 0.33, 0.84, color);
    soft(chair, 0, 0.85, -0.35, 0.92, 0.84, 0.24, color);
    for (const side of [-1, 1]) {
      soft(chair, side * 0.43, 0.67, 0, 0.17, 0.4, 0.86, color);
      box(chair, side * 0.32, 0.16, 0, 0.065, 0.32, 0.62, "#57616b");
    }
    const cushion = soft(
      chair,
      0,
      0.86,
      -0.12,
      0.4,
      0.42,
      0.14,
      "#e6b8bd",
      "loose-cushion",
    );
    cushion.rotation.z = 0.16;
  }
  armchair(2, -7.6, Math.PI, "#ab6177");
  armchair(6, -7.6, Math.PI, "#998da0");
  armchair(9.2, -7.45, Math.PI * 0.85, "#b78380");
  box(lounge, 5.7, 0.19, -9.15, 6.4, 0.028, 3.35, "#987984");
  soft(lounge, 5.8, 0.55, -9.3, 2.3, 0.12, 1.08, "#bdab98", "coffee-table");
  for (const x of [5, 6.6])
    box(lounge, x, 0.34, -9.3, 0.06, 0.5, 0.7, "#4a4650");
  for (let i = 0; i < 3; i++) {
    const book = box(
      lounge,
      5.5,
      0.64 + i * 0.035,
      -9.3,
      0.44,
      0.028,
      0.29,
      ["#526d82", "#dad0b9", "#b87181"][i],
    );
    book.rotation.y = 0.15 * i;
  }
  for (const x of [8.3, 9.7]) {
    const pouf = soft(
      lounge,
      x,
      0.4,
      -10.65,
      0.9,
      0.6,
      0.88,
      x === 8.3 ? "#b55678" : "#e1bdb2",
      "pouf",
    );
    pouf.rotation.y = 0.2;
  }
  function plant(x, z) {
    const pot = new THREE.Mesh(
      new THREE.CylinderGeometry(0.3, 0.23, 0.52, 10),
      material("#cbbcb1"),
    );
    pot.position.set(x, 0.43, z);
    lounge.add(pot);
    for (let i = 0; i < 5; i++) {
      const leaf = new THREE.Mesh(
        plantGeometry,
        material(i % 2 ? "#6b998a" : "#4a7d74"),
      );
      leaf.position.set(
        x + Math.sin(i * 2) * 0.22,
        0.95 + i * 0.08,
        z + Math.cos(i * 2) * 0.17,
      );
      leaf.scale.set(0.16, 0.55, 0.23);
      leaf.rotation.z = Math.sin(i * 2) * 0.5;
      lounge.add(leaf);
    }
  }
  plant(14.7, -11);
  plant(-1, -10.9);
  plant(14.7, -7);
  box(lounge, -2.5, 0.91, -11.3, 2.3, 1.5, 0.5, "#8a766a");
  for (const y of [0.45, 0.94, 1.43]) {
    box(lounge, -2.5, y, -10.99, 2.14, 0.07, 0.12, "#ddc9b0");
    for (let k = 0; k < 5; k++)
      box(
        lounge,
        -3.27 + k * 0.34,
        y + 0.18,
        -11,
        0.2,
        0.32,
        0.22,
        k % 2 ? "#a45e72" : "#899aac",
      );
  }

  const core = new THREE.Group();
  core.userData.kind = "lift-core";
  g.add(core);
  box(core, -5.55, 0.7, 3.65, 4.1, 1.4, 11.55, "#d6d5cf");
  box(core, 6.55, 0.7, 3.65, 5.8, 1.4, 11.55, "#d6d5cf");
  box(core, 0.5, 0.68, 9.4, 18.1, 1.36, 0.15, "#c6cac7");
  for (const elevator of ELEVATORS) {
    const signX = elevator.entryX,
      side = signX > 0 ? -1 : 1;
    const entry = new THREE.Group();
    entry.position.set(signX, 0, elevator.z);
    entry.userData.kind = "elevator";
    entry.userData.elevator = elevator.id;
    core.add(entry);
    box(entry, 0, 1.3, 0, 0.18, 2.6, 1.95, "#a96782");
    box(entry, side * 0.105, 1.14, -0.43, 0.025, 2.22, 0.81, "#acb7bd");
    box(entry, side * 0.105, 1.14, 0.43, 0.025, 2.22, 0.81, "#acb7bd");
    box(entry, side * 0.125, 1.15, 0, 0.035, 2.23, 0.025, "#415566");
    box(entry, side * 0.16, 2.45, 0, 0.04, 0.28, 1.56, "#e49ab3");
    box(entry, side * 0.23, 1.2, 1.14, 0.09, 0.38, 0.14, "#3a4758");
    box(entry, side * 0.285, 1.22, 1.14, 0.025, 0.045, 0.06, "#9cddc2");
    box(entry, side * 0.55, 0.157, 0, 0.95, 0.035, 1.68, "#b6748c");
    const vertical = label(
      entry,
      elevator.id,
      side * 0.19,
      2.47,
      0,
      0.74,
      "#ffe0e8",
    );
    vertical.rotation.y = (side * Math.PI) / 2;
    label(
      core,
      elevator.id,
      elevator.x,
      1.42,
      elevator.z,
      1.72,
      "#f5bed0",
      true,
    );
  }
  label(g, "ELEVADORES", 0.2, 0.156, -0.3, 3.8, "#d5dfe7", true);
  label(g, `${floor}º ANDAR`, 0, 0.157, 10.7, 4.2, "#cbd8e5", true);
  const circulation = [];
  for (const x of [-9.5, 10.25])
    for (let z = -4.5; z < 11; z += 1.6)
      circulation.push([x, 0.15, z, 0.032, 0.012, 0.7]);
  batch(g, circulation, material("#a9b4bd"));

  // Shared benches retain their seating independently of endpoint inventory.
  for (let seat = 0; seat < 8; seat++) {
    const x = -13.4 + (seat % 4) * 2,
      z = -10.05 + Math.floor(seat / 4) * 2,
      s = 0.88;
    chairs.push(
      [x, 0.46 * s + 0.17, z + 0.85 * s, 0.65 * s, 0.12 * s, 0.6 * s],
      [x, 0.8 * s + 0.17, z + 1.1 * s, 0.65 * s, 0.65 * s, 0.08 * s],
    );
    legs.push([x, 0.23 * s + 0.17, z + 0.85 * s, 0.06 * s, 0.4 * s, 0.06 * s]);
    wheels.push(
      [x, 0.05 * s + 0.17, z + 0.85 * s, 0.57 * s, 0.065 * s, 0.065 * s],
      [x, 0.05 * s + 0.17, z + 0.85 * s, 0.065 * s, 0.065 * s, 0.53 * s],
    );
  }
  const local = hosts.filter((h) => h.floor === floor);
  for (const h of local) {
    const { x, z, scale: s } = h;
    const add = (list, dx, y, dz, w, ht, d) =>
      list.push([x + dx * s, y * s + 0.17, z + dz * s, w * s, ht * s, d * s]);
    if (h.room !== 7) add(desks, 0, 0.78, 0, 1.65, 0.1, 1.05);
    add(legs, -0.63, 0.39, 0, 0.055, 0.78, 0.7);
    add(legs, 0.63, 0.39, 0, 0.055, 0.78, 0.7);
    add(legs, 0, 0.98, -0.2, 0.07, 0.38, 0.09);
    add(monitors, 0, 1.24, -0.22, 0.86, 0.54, 0.09);
    add(keyboards, 0, 0.845, 0.2, 0.57, 0.025, 0.2);
    add(chairs, 0, 0.46, 0.85, 0.65, 0.12, 0.6);
    add(chairs, 0, 0.8, 1.1, 0.65, 0.65, 0.08);
    add(legs, 0, 0.23, 0.85, 0.06, 0.4, 0.06);
    add(wheels, 0, 0.05, 0.85, 0.57, 0.065, 0.065);
    add(wheels, 0, 0.05, 0.85, 0.065, 0.065, 0.53);
  }
  batch(g, desks, material("#c8b895"));
  batch(g, legs, material("#7e8b95"));
  batch(g, monitors, material("#152737"));
  batch(g, keyboards, material("#9fadb6"));
  batch(g, chairs, material("#475666"));
  batch(g, wheels, material("#2b3c4b"));
  const screens = batch(
    g,
    local.map((h) => [
      h.x,
      1.25 * h.scale + 0.17,
      h.z - 0.167 * h.scale,
      0.73 * h.scale,
      0.4 * h.scale,
      0.015,
    ]),
    new THREE.MeshBasicMaterial({
      color: "#ffffff",
      toneMapped: false,
      vertexColors: true,
    }),
  );
  screens.userData.hosts = local;
  local.forEach((h, i) =>
    screens.setColorAt(i, new THREE.Color(statuses[h.status].color)),
  );
  const picks = batch(
    g,
    local.map((h) => [
      h.x,
      0.95 * h.scale + 0.17,
      h.z,
      0.98 * h.scale,
      1.65 * h.scale,
      0.9 * h.scale,
    ]),
    new THREE.MeshBasicMaterial({ visible: false }),
  );
  picks.userData.hosts = local;
  g.userData.furniture = {};
  const groups = new Map();
  g.updateMatrixWorld(true);
  const inverse = g.matrixWorld.clone().invert();
  g.traverse((o) => {
    if (o.userData.kind)
      g.userData.furniture[o.userData.kind] =
        (g.userData.furniture[o.userData.kind] || 0) + 1;
    if (!o.isMesh || o.isInstancedMesh || o.material.map) return;
    const key = o.geometry.uuid + o.material.uuid;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(o);
  });
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const merged = new THREE.InstancedMesh(
      members[0].geometry,
      members[0].material,
      members.length,
    );
    members.forEach((o, i) => {
      merged.setMatrixAt(
        i,
        new THREE.Matrix4().multiplyMatrices(inverse, o.matrixWorld),
      );
      o.removeFromParent();
    });
    merged.computeBoundingSphere();
    g.add(merged);
  }
  return { screens, picks };
}
