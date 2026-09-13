# ABR-T023 — Operational build hardening: detection guidance

## Technique summary

Operational implant artifacts are produced with the configuration
compiled in (`ABRAHAM_EMBED` at build time: server address, Ed25519
public key, optional TLS pin, evasion flags, malleable profile), under a
build-random XOR keystream read through `volatile` so the optimizer
cannot constant-fold the decode into a plaintext `.rdata` constant
(this exact fold was observed and fixed — see the lab report). The
command-line parser, stderr logging and every project-identifying
string live behind the `lab-args`/`lab-log` features and are absent
from operational builds:

- zero occurrences of the project name, the binary name, a PDB path
  (`/DEBUG:NONE`; `strip = "symbols"` alone does not remove the RSDS
  record on MSVC), CLI flags, log strings or the builder's username
  (`--remap-path-prefix` over the cargo home and workspace);
- `panic = "abort"` + a silent panic hook, so panics never print
  sources, locations or toolchain paths;
- reconnect backoff doubles per consecutive failure (5s → 300s cap,
  jittered) instead of a fixed retry interval;
- no default server: a build without embedded configuration and without
  CLI flags exits instead of beaconing to localhost.

## What telemetry remains (the detection side)

1. **Legacy/lab builds are loud.** Any artifact still reading flags
   advertises the entire configuration on the process command line —
   Sigma rule `abr-t023_implant_cli_flags.yml` (Sysmon EID 1,
   `--server`+`--key` or `--evasion ekko`/`--tls-pin`). This rule is
   the paired detection for this technique and must stay in the pack:
   it catches every build that did not get the hardening.
2. **Rust toolchain residue.** `/rustc/<hash>/library/...` paths from
   standard-library panic locations remain embedded (75 occurrences in
   the audited build). They identify the language and toolchain family,
   not the operator; removing them needs `-Zlocation-detail` (nightly).
   YARA can key on them for *Rust implant* triage, with heavy
   false-positive pressure from legitimate Rust software.
3. **Runtime behavior is unchanged.** The hardening removes static and
   command-line surface only; every behavioral technique (T005–T021)
   keeps its own paired detection.

## Residual static surface after hardening (audited 2026-09-12)

- `/rustc/...` paths (std panic locations — inherent, documented).
- Technique-inherent data: the embedded kernel-payload image, the
  `\KnownDlls\ntdll.dll` object name, the phantom-DLL candidate names
  (`colorui.dll`), NT API names resolved at runtime. Each belongs to
  its own technique's detection story.
- Dependency strings indistinguishable from benign Rust software,
  e.g. mio's internal `127.0.0.1:0` wakeup socket name — not a
  project IOC.
