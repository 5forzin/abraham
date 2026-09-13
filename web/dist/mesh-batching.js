import * as THREE from "three";

// Color is stored per instance so static objects can share a draw call.
export function consolidateStatic(parent) {
  parent.updateMatrixWorld(true);
  const inverse = parent.matrixWorld.clone().invert();
  const buckets = new Map();
  parent.traverse((object) => {
    if (
      !object.isMesh ||
      object.userData.hosts ||
      Array.isArray(object.material)
    )
      return;
    const material = object.material;
    if (
      !material.isMeshStandardMaterial ||
      material.map ||
      material.transparent ||
      material.visible === false
    )
      return;
    const key = `${object.geometry.uuid}/${material.roughness}/${material.metalness}/${material.side}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(object);
  });
  const instance = new THREE.Matrix4(),
    world = new THREE.Matrix4(),
    color = new THREE.Color();
  for (const members of buckets.values()) {
    if (members.length < 2) continue;
    const count = members.reduce(
      (n, o) => n + (o.isInstancedMesh ? o.count : 1),
      0,
    );
    const material = members[0].material.clone();
    material.color.set("#ffffff");
    const mesh = new THREE.InstancedMesh(members[0].geometry, material, count);
    let index = 0;
    for (const object of members) {
      world.multiplyMatrices(inverse, object.matrixWorld);
      for (let i = 0; i < (object.isInstancedMesh ? object.count : 1); i++) {
        if (object.isInstancedMesh) {
          object.getMatrixAt(i, instance);
          instance.premultiply(world);
        } else instance.copy(world);
        color.copy(object.material.color);
        if (object.instanceColor) {
          object.getColorAt(i, color);
          color.multiply(object.material.color);
        }
        mesh.setMatrixAt(index, instance);
        mesh.setColorAt(index++, color);
      }
      object.removeFromParent();
    }
    mesh.name = "Static architecture";
    mesh.computeBoundingBox();
    mesh.computeBoundingSphere();
    parent.add(mesh);
  }
}
