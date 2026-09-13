import * as THREE from "three";
import { addPalms } from "./palms.js";
import { consolidateStatic } from "./mesh-batching.js";

export function buildStreetscape(exterior, { box, label }) {
  const b = (x, y, z, w, h, d, color) => box(exterior, x, y, z, w, h, d, color);
  // Avenida, pavements and protected central cycle lane.
  b(0, -0.4, 2, 146, 0.6, 108, "#203647");
  b(0, -0.045, 7, 144, 0.16, 25, "#6b7880");
  b(0, -0.11, 35, 144, 0.12, 30, "#27353f");
  b(0, -0.035, 53, 144, 0.18, 6, "#737f85");
  for (const z of [19.5, 50]) b(0, 0.015, z, 144, 0.22, 0.4, "#a1aaa9");
  for (let x = -70; x < 72; x += 7)
    for (const z of [25, 44]) b(x, -0.037, z, 3.6, 0.012, 0.14, "#c5cdc7");
  b(0, -0.01, 34.5, 144, 0.07, 3.3, "#803f50");
  for (const z of [32.6, 36.4]) {
    b(0, 0.04, z, 144, 0.16, 0.35, "#a2aaa4");
    for (let x = -67; x < 72; x += 9) b(x, 0.25, z, 0.1, 0.45, 0.1, "#b8bec0");
  }
  for (let z = 20.5; z < 50; z += 1.25) {
    b(-25, -0.025, z, 4.8, 0.012, 0.5, "#cbd0c9");
    b(49, -0.025, z, 4.8, 0.012, 0.5, "#cbd0c9");
  }
  for (let x = -71; x < 72; x += 3)
    b(x, 0.043, 15, 0.025, 0.01, 8.5, "#566874");
  for (const z of [12, 16.5]) b(0, 0.046, z, 144, 0.008, 0.024, "#536674");
  // Tactile strip and clear path from the crossing to the entrance.
  for (let z = 13; z < 19; z += 0.5)
    b(0, 0.05, z, 0.55, 0.015, 0.34, "#c4af75");
  for (const x of [-26, 48])
    for (const z of [18.7, 50.8]) {
      b(x, 2.5, z, 0.1, 5, 0.1, "#536977");
      b(x, 4.6, z + 0.22, 0.4, 0.85, 0.35, "#172935");
      b(x, 4.8, z + 0.41, 0.16, 0.16, 0.025, "#b97a73");
      b(x, 4.42, z + 0.41, 0.16, 0.16, 0.025, "#7dbca5");
    }
  for (const x of [-60, -34, 36, 64]) {
    b(x, 3.8, 18, 0.13, 7.6, 0.13, "#617782");
    b(x, 7.5, 19.2, 0.12, 0.1, 2.5, "#617782");
    b(x, 7.42, 20.3, 0.4, 0.09, 0.7, "#c1cbbb");
  }
  // FIAP podium: open central hall, portal and reception visible from the street.
  b(0, 2.2, -11.5, 32, 4.4, 0.28, "#3e5362");
  for (const x of [-15.85, 15.85]) b(x, 2.2, 0, 0.3, 4.4, 23, "#435968");
  b(0, 0.22, 4, 31.6, 0.2, 15, "#aeb3ac");
  for (const x of [-10.2, 10.2]) {
    b(x, 2.05, 3, 11.1, 4.1, 17, "#253e4b");
    b(x, 2.7, 12.1, 7.8, 4.9, 0.55, "#ad354b");
    b(x, 1.8, 12.4, 5.8, 3.25, 0.08, "#18313d");
  }
  b(0, 4.35, 12.5, 9.6, 0.8, 1.15, "#d1d4cf");
  for (const x of [-4.45, 4.45]) b(x, 2.1, 12.5, 0.7, 4.2, 1.15, "#d1d4cf");
  b(0, 3.7, 10.8, 8.4, 0.16, 4.5, "#bac1bc");
  for (const x of [-3.1, 3.1]) b(x, 2.02, 10.1, 0.06, 3.5, 0.06, "#829997");
  for (const x of [-1.48, 1.48])
    box(exterior, x, 1.9, 10, 2.9, 3.4, 0.045, "#91b2b9", 0.12);
  for (const x of [-0.12, 0.12]) b(x, 1.8, 10.08, 0.035, 0.8, 0.04, "#d1d9d0");
  b(0, 3.2, 2.7, 8.4, 0.15, 1.3, "#718b96");
  for (const x of [-2.5, 0, 2.5]) {
    b(x, 0.95, 5.2, 0.55, 1.35, 0.65, "#849899");
    box(exterior, x + 0.55, 1.1, 5.2, 0.68, 0.7, 0.04, "#9ec0c2", 0.28);
  }
  b(2.8, 0.8, 1.8, 2.4, 1.2, 1.1, "#b6a995");
  b(2.8, 1.43, 1.8, 2.55, 0.09, 1.2, "#d1c6af");
  b(-2.6, 0.6, 2.2, 1.8, 0.7, 0.7, "#5d7180");
  b(-2.6, 1, 1.88, 1.8, 0.65, 0.12, "#6e8593");
  label(exterior, "PAULISTA 1106", 0, 4.35, 13.1, 6.8, "#eef0e6");
  label(exterior, "FIAP", -10.2, 3.55, 12.47, 3.4, "#dc7991");
  label(exterior, "RECEPÇÃO", 2.8, 2.05, 1.74, 2.2, "#cad9d9");
  // Neighboring shopping: stepped massing, recessed entry and retail glazing.
  b(25, 4.9, -0.2, 15, 9.8, 24, "#3b5464");
  b(26, 11.2, -3, 12, 2.8, 17, "#526c7c");
  b(25, 4.5, 12, 15, 0.7, 1.8, "#95a7aa");
  b(25, 8.3, 12, 15, 1.05, 0.25, "#738e9d");
  for (const x of [19, 22, 28, 31]) {
    b(x, 1.9, 12.13, 2.6, 3.8, 0.08, "#294b5b");
    b(x, 3.7, 12.21, 2.5, 0.2, 0.1, "#b3bdad");
  }
  for (let x = 18; x <= 32; x += 1.5)
    b(x, 6.1, 12.16, 0.055, 2.9, 0.08, "#a0b5be");
  for (const y of [5, 7.3]) b(25, y, 12.18, 14.8, 0.055, 0.08, "#91a8b1");
  b(25, 1.9, 11.95, 2.8, 3.8, 0.09, "#142c38");
  b(25, 0.06, 14.1, 7, 0.13, 4, "#909c9d");
  b(25, 3.5, 13.5, 6, 0.15, 3.3, "#a2b2b1");
  label(exterior, "SHOPPING", 25, 8.35, 12.2, 7, "#dce5df");
  // Secondary buildings use solid masses and batched facade strips only.
  const neighbors = [
    [-41, -3, 21, 41, 24],
    [-63, -9, 17, 29, 27],
    [47, -6, 20, 35, 27],
    [67, -12, 14, 47, 23],
    [-35, -37, 25, 50, 22],
    [0, -39, 24, 35, 22],
    [32, -39, 21, 43, 22],
  ];
  for (const [x, z, w, h, d] of neighbors) {
    b(x, h / 2, z, w, h, d, "#30495d");
    b(x, h + 0.2, z, w + 0.4, 0.4, d + 0.4, "#657e8c");
    b(x, h + 1.3, z - 2, w * 0.46, 2.2, d * 0.45, "#3f5869");
    b(x, h / 2, z + d / 2 + 0.025, w - 0.8, h - 0.7, 0.04, "#375d73");
    for (let y = 3.4; y < h; y += 3.4)
      b(x, y, z + d / 2 + 0.055, w, 0.085, 0.04, "#7592a2");
    for (let dx = -w / 2 + 2; dx < w / 2; dx += 3.5)
      b(x + dx, h / 2, z + d / 2 + 0.085, 0.06, h, 0.035, "#617d90");
    b(x, 1.3, z + d / 2 + 0.1, 2.2, 2.6, 0.12, "#183443");
  }
  exterior.userData.neighborBuildings = neighbors.length;
  exterior.userData.hall = {
    entrance: [0, 1.9, 10],
    reception: [2.8, 0.8, 1.8],
    turnstiles: 3,
  };
  const palms = [];
  for (const x of [-14, -9, 9, 14, 20, 31, -44, -36, 42, 58]) {
    b(x, 0.27, 16.5, 2.5, 0.5, 2.3, "#7c8b86");
    b(x, 0.54, 16.5, 2.3, 0.04, 2.1, "#365c53");
    palms.push([x, 0.55, 16.5, 0.85 + (Math.abs(x) % 4) * 0.08]);
  }
  for (const x of [-19, 35]) {
    b(x, 0.4, 16.5, 3, 0.15, 0.65, "#aa9c84");
    for (const dx of [-1, 1]) b(x + dx, 0.2, 16.5, 0.12, 0.4, 0.6, "#475d67");
  }
  consolidateStatic(exterior);
  addPalms(exterior, palms);
}
