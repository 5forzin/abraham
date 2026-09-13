# ABR-T025 — Execute-assembly via bare CLR hosting: detection guidance

## Technique summary

The `EXECASM` task (`task_type 0x09`) runs an operator-supplied .NET
Framework assembly inside the implant with no `powershell.exe` and no
`dotnet.exe`:

1. optional ABR-T024 pass (AMSI/ETW patch);
2. the assembly bytes are written to a randomly named `.dll` under the
   process temp directory;
3. `mscoree!CLRCreateInstance` → `ICLRMetaHost::GetRuntime("v4.0.30319")`
   → `ICLRRuntimeInfo::GetInterface` → `ICLRRuntimeHost::Start()` —
   all through the manual export resolver (no IAT entries, no
   loader involvement for mscoree);
4. `ICLRRuntimeHost::ExecuteInDefaultAppDomain(path, type, method, arg)`
   invokes the operator convention `public static int Go(string)` and
   returns its exit code; the temp file is deleted, marked
   delete-on-close, or its residue path reported — whichever the CLR's
   file sharing allows (the loader keeps the assembly mapped without
   FILE_SHARE_DELETE for the process lifetime).

## Detection anchors

1. **The disk flash is real and irreducible.** Sysmon EID 11 catches
   the temp-file creation (sigma rule below); because the CLR pins the
   file, the artifact PERSISTS after the task — collect it, it is the
   operator's assembly verbatim.
2. **CLR loaded into a non-.NET process.** Sysmon EID 7 image-load of
   `clr.dll`/`clrjit.dll`/`mscoreei.dll` into a process whose image is
   not a known .NET host is the classic execute-assembly analytic
   (level: high; tune against plugins/hosts that legitimately load the
   CLR late).
3. **No child process.** Unlike `dotnet.exe`/`powershell.exe`
   execution there is no EID 1, and unlike ABR-T022 there is no RX
   private allocation — the code lives in a loaded, signed runtime.
   What remains in memory is the assembly itself: a .NET metadata
   scanner (e.g. reflective checks for `Go(string)` entry shapes)
   attributes it precisely.
4. **AMSI/ETW state.** When the ABR-T024 pass runs first, the
   abr-t024.md analytics apply to the same process.

## Sigma

`detections/sigma/abr-t025_clr_assembly_written_to_temp.yml` — EID 11
`.dll` creation under the temp directory by a process that is not an
installer/browser/updater (level: low on its own; correlate with a
subsequent `clr.dll` load in the same process — that correlation is
the high-fidelity hunt documented above).

## Convention

Assemblies must expose `public static int <Method>(string)` — the
proof class and every usage example ship in `docs/usage.md` and the
unit test compiles its own with the in-box `csc.exe`.
