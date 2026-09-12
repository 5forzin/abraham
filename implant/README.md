# Abraham Implant

Windows implant, written in Rust on top of `windows-rs`.

- Transport: Abraham wire protocol (`docs/protocol.md`) with E2E encryption
  (X25519 ECDHE + Ed25519 pinned server key + AES-256-GCM)
- Tasking: SHELL, UPLOAD, DOWNLOAD, SLEEP, EXIT (Phase 1)
- Every capability implemented here MUST have an entry in
  `registry/techniques.yaml` with a mapped detection

Status: Phase 1 core implemented and smoke tested.
