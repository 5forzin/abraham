# Abraham Teamserver

Rust (`tokio`) server component.

- c2 listener (TCP; HTTPS outer layer is the next milestone) + JSON-lines
  management API on a separate localhost port
- Session manager, task queue and result/loot storage
- Ed25519 pinned identity (`server.key` / `server.pub`), per-session
  AES-256-GCM channels

Status: Phase 1 core implemented and smoke tested.
