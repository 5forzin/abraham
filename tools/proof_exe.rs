// ABR-T027 proof payload (console EXE, no_std): calls ExitProcess with
// a magic code straight from its IAT — the implant's import redirect
// must turn that into ExitThread so the hosting process survives with
// the exit code observable on the payload thread.
// Built by the test with:
//   rustc --crate-type bin -C link-args="/ENTRY:start /SUBSYSTEM:CONSOLE"
#![no_std]
#![no_main]

#[link(name = "kernel32")]
extern "system" {
    fn ExitProcess(code: u32) -> !;
}

#[no_mangle]
pub extern "win64" fn start() -> u32 {
    unsafe { ExitProcess(0x1337) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
