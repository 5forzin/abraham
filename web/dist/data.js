export const statuses = {
  online: { label: "Online", color: "#6be6b6" },
  offline: { label: "Offline", color: "#6b8098" },
  warning: { label: "Warning", color: "#edc96c" },
  threat: { label: "Threat Detected", color: "#ff746f" },
};
export const FLOORS = [2, 3, 4, 5, 6, 7, 10, 11];
export const FLOOR_HEIGHT = 4.5;
export const ROOMS = [
  { id: 1, name: "Sala 1", x: -13.6, z: -3, width: 4.8, depth: 6, count: 12 },
  { id: 2, name: "Sala 2", x: -13.6, z: 3, width: 4.8, depth: 6, count: 12 },
  { id: 3, name: "Sala 3", x: -13.6, z: 9, width: 4.8, depth: 6, count: 12 },
  { id: 4, name: "Sala 4", x: 13.6, z: 9, width: 4.8, depth: 6, count: 12 },
  { id: 5, name: "Sala 5", x: 13.6, z: 3, width: 4.8, depth: 6, count: 12 },
  { id: 6, name: "Sala 6", x: 13.6, z: -3, width: 4.8, depth: 6, count: 12 },
  { id: 7, name: "Coworking", x: 0, z: -9, width: 32, depth: 6, count: 0 },
];
export const ELEVATORS = [
  { id: "A", x: 6.55, z: -0.2, entryX: 3.6 },
  { id: "B", x: 6.55, z: 2.3, entryX: 3.6 },
  { id: "C", x: 6.55, z: 4.8, entryX: 3.6 },
  { id: "D", x: 6.55, z: 7.3, entryX: 3.6 },
  { id: "F", x: -5.5, z: 4.8, entryX: -3.5 },
  { id: "E", x: -5.5, z: 7.3, entryX: -3.5 },
];
export const HOSTS_PER_FLOOR = ROOMS.reduce((n, r) => n + r.count, 0);
export const roomLabel = (floor, room) =>
  room.id === 7 ? "Coworking" : `Sala ${floor * 100 + room.id}`;
export const hosts = FLOORS.flatMap((floor) =>
  ROOMS.flatMap((room) =>
    Array.from({ length: room.count }, (_, seat) => {
      const local =
          ROOMS.slice(0, room.id - 1).reduce((sum, r) => sum + r.count, 0) +
          seat,
        i = FLOORS.indexOf(floor) * HOSTS_PER_FLOOR + local;
      const status =
          i % 137 === 17
            ? "threat"
            : i % 43 === 12
              ? "warning"
              : i % 79 === 21
                ? "offline"
                : "online",
        cowork = room.id === 7;
      return {
        id: i,
        hostname: `FIAP-${String(floor).padStart(2, "0")}-${cowork ? "CW" : floor * 100 + room.id}-PC${String(seat + 1).padStart(2, "0")}`,
        ip: `10.110.${floor}.${local + 10}`,
        os: cowork && seat % 4 === 0 ? "macOS 15.6" : "Windows 11 / 26100",
        status,
        cpu: 18 + ((i * 13) % 65),
        mem: 24 + ((i * 17) % 65),
        floor,
        room: room.id,
        roomName: roomLabel(floor, room),
        seat: seat + 1,
        x: cowork ? -13.4 + (seat % 4) * 2 : room.x - 1.3 + (seat % 3) * 1.3,
        z: cowork
          ? -10.05 + Math.floor(seat / 4) * 2
          : room.z - 1.7 + Math.floor(seat / 3) * 1.15,
        scale: cowork ? 0.88 : 0.66,
        agent: "4.8.2",
        ping: status === "offline" ? 920 : 1 + (i % 4),
        isolated: false,
        scanning: false,
        history: Array.from(
          { length: 32 },
          (_, j) => 18 + ((i * 13 + j * 7) % 48),
        ),
      };
    }),
  ),
);
