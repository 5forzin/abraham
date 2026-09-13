import * as THREE from "three";

export function addPalms(parent, placements) {
  const wood = [],
    leaves = [],
    leafColors = [];
  const triangle = (target, a, b, c) => target.push(...a, ...b, ...c);
  const ring = (y, a) => {
    const radius = (0.22 - y * 0.013) * (1 + 0.07 * Math.sin(y * 18));
    return [0.5 * (y / 7) ** 2 + Math.cos(a) * radius, y, Math.sin(a) * radius];
  };
  for (let j = 0; j < 28; j++)
    for (let i = 0; i < 9; i++) {
      const a = (i * Math.PI * 2) / 9,
        b = ((i + 1) * Math.PI * 2) / 9,
        y = j / 4;
      triangle(wood, ring(y, a), ring(y + 0.25, a), ring(y + 0.25, b));
      triangle(wood, ring(y, a), ring(y + 0.25, b), ring(y, b));
    }
  for (let frond = 0; frond < 14; frond++) {
    const a = frond * 2.39996,
      length = 2.7 + (frond % 4) * 0.3;
    const at = (t) => [
      0.5 + Math.cos(a) * length * t,
      7.05 + Math.sin(t * Math.PI) * (0.9 + (frond % 3) * 0.16) - t * t * 1.3,
      Math.sin(a) * length * t,
    ];
    const tint = new THREE.Color(
      ["#507e71", "#65927d", "#416d66", "#789985"][frond % 4],
    );
    for (let step = 1; step < 15; step++) {
      const t = step / 15,
        p = at(t),
        next = at(Math.min(1, t + 0.08));
      const width = 0.62 * Math.sin(Math.PI * t) ** 0.7;
      for (const side of [-1, 1]) {
        const tip = [
          p[0] + Math.cos(a) * 0.18 - Math.sin(a) * width * side,
          p[1] - 0.15 - width * 0.35,
          p[2] + Math.sin(a) * 0.18 + Math.cos(a) * width * side,
        ];
        const ridge = [(p[0] + tip[0]) / 2, p[1] + 0.035, (p[2] + tip[2]) / 2];
        triangle(leaves, p, ridge, tip);
        triangle(leaves, ridge, next, tip);
        for (let k = 0; k < 6; k++) leafColors.push(tint.r, tint.g, tint.b);
      }
    }
  }
  const geometry = (vertices) => {
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.Float32BufferAttribute(vertices, 3));
    g.computeVertexNormals();
    return g;
  };
  const crown = geometry(leaves);
  crown.setAttribute("color", new THREE.Float32BufferAttribute(leafColors, 3));
  const trunks = new THREE.InstancedMesh(
    geometry(wood),
    new THREE.MeshStandardMaterial({ color: "#8c8d7b", roughness: 1 }),
    placements.length,
  );
  const foliage = new THREE.InstancedMesh(
    crown,
    new THREE.MeshStandardMaterial({
      color: "#ffffff",
      vertexColors: true,
      side: THREE.DoubleSide,
      roughness: 1,
    }),
    placements.length,
  );
  const dummy = new THREE.Object3D();
  placements.forEach(([x, y, z, scale = 1], i) => {
    dummy.position.set(x, y, z);
    dummy.scale.setScalar(scale);
    dummy.rotation.y = i * 1.37;
    dummy.updateMatrix();
    trunks.setMatrixAt(i, dummy.matrix);
    foliage.setMatrixAt(i, dummy.matrix);
  });
  trunks.name = "Palmeiras · troncos";
  foliage.name = "Palmeiras · folhas";
  trunks.computeBoundingSphere();
  foliage.computeBoundingSphere();
  parent.add(trunks, foliage);
  parent.userData.palms = placements.length;
}
