# Lab journal — 2026-09-13: the C2 maturity run (T028–T035)

Live validation of the full run against https://avln.nora.systems
(Azure origin behind Cloudflare, Let's Encrypt cert on the origin —
which is why the new `avln2` backup front needed its own
Configuration Rule with `ssl=full`: the LE SAN covers avln only).

## Deployed state

- Teamserver rebuilt on the VM via `deploy/avln/push.sh` (BUILD-STATUS
  gate), now with `--mgmt-token` (systemd `EnvironmentFile=/opt/avln/
  mgmt.env` — **systemd does not expand `$(...)` in ExecStart**, the
  first attempt passed the literal string `"$(cat"` as the token and
  every mgmt client got unauthorized; the EnvironmentFile shape is
  the fix) and the audit log at `state/audit.jsonl`.
- Backup front `avln2.nora.systems` — A record, proxied, same origin.
- Operational stage sha256 `88c4652c11269e6875b8b3874388bfde0c4427e73a
  759346b2e8814f0934236f` (implant 0.2.0, embed with servers
  [avln, avln2], kill date +90d).
- mgmt.py speaks the two-stage auth (fetch token file on the VM, then
  auth+request in one socket read).

## Live evidence

1. **Session 2 (0.2.0, pid 32408)** registered from the host through
   the CF edge — speaking ONLY the cookie demux (the build has no
   X-Session header at all): cookie routing carries the whole
   protocol. Task round-trips executed:
   - `module domain` — survey result back (join=workgroup, DC none)
   - `collect screenshot` — 5.3 MB BMP (1536×864) chunked through the
     CDN into `loot/session-2/task-3.bin`; **WIC-PNG fell back to
     BMP** in the operational context (follow-up: find why the WIC
     path declines under the release build — the host test accepts
     either; BMP is the honest fallback).
   - `persist install/list/remove` run-key "OneSyncSvcHelper" — full
     cycle, `%APPDATA%` copy swept afterwards (T030 hygiene).
2. **Session 3 (0.2.0)** registered through **avln2** — the backup
   front serves handshake + cookie demux + registration end-to-end.
3. **Session 1 (0.1.0)** shows `stale: true` after its demo died —
   the staleness marker works on real data.
4. **Audit log** on the VM: `task_queued` → `task_delivered` →
   `task_result` → `download_loot` with timestamps for every command
   above — the after-action mapping source.

## Unit-side (host-executed tests, same session)

- minidump self-dump parses back as MDMP (regions, PEB modules,
  directory, Memory64 descriptors)
- BOF: rustc-compiled no_std object linked and executed through the
  loader — found TWO live bugs on the way: unlinked COFF sections all
  carry VirtualAddress 0 (the loader must assign the layout), and far
  REL32 targets need in-image trampolines (the private image sits
  terabytes from ntdll; the raw disp32 cannot reach — first run
  segfaulted on the truncated delta)
- registry FFI gotcha worth remembering: legacy `RegSetValueW`
  treats its string as a SUBKEY (it creates one) — the ExW variants
  are the value API
- services enumeration stride: ENUM_SERVICE_STATUS_PROCESSW is 56
  bytes on x64 (52 + alignment), state at +20, pid at +44 — a 64
  stride walked garbage pointers into a host crash until fixed

## Known follow-ups

- WIC PNG decline in release builds (BMP fallback is live)
- schtasks (ITaskService) and WMI event-subscription COM persistence
  vectors; keylogger per-cycle sampling → syscalls-only stub thread
- BeaconPrintf forwarding; LSASS live dumps on the elevated lab host
  (both variants are elevation-gated #[ignore] there)
