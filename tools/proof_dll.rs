// ABR-T027 proof payload (DLL, no_std): DllMain terminates through
// ExitThread with the magic code — the real payload exit contract
// (an entry's plain return does NOT become the thread exit code on
// NT, so well-formed payloads exit explicitly). Built by the test
// with: rustc --crate-type=cdylib -C panic=abort
//   -C link-args="/ENTRY:DllMain /DYNAMICBASE"
#![no_std]

#[link(name = "kernel32")]
extern "system" {
    fn ExitThread(code: u32) -> !;
}

#[no_mangle]
pub extern "system" fn DllMain(_instance: *const u8, _reason: u32, _reserved: *const u8) -> u32 {
    unsafe { ExitThread(0x1337) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
