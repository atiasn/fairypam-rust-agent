use crate::RealtimeError;

pub trait PixelProbe: Send {
    fn sample_blue(&mut self) -> Result<u8, RealtimeError>;
}

#[cfg(windows)]
pub mod windows {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{GetDC, GetPixel, ReleaseDC, CLR_INVALID, HDC};
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    use super::PixelProbe;
    use crate::RealtimeError;

    pub struct GdiPixelProbe {
        hwnd: HWND,
        dc: HDC,
        x: i32,
        y: i32,
    }

    unsafe impl Send for GdiPixelProbe {}

    impl GdiPixelProbe {
        pub fn new(hwnd: HWND, x: i32, y: i32) -> Result<Self, RealtimeError> {
            let dc = unsafe { GetDC(Some(hwnd)) };
            if dc.is_invalid() {
                return Err(RealtimeError::new(
                    "realtime.pixel_probe_failed",
                    "GetDC failed for realtime target",
                ));
            }
            Ok(Self { hwnd, dc, x, y })
        }
    }

    impl PixelProbe for GdiPixelProbe {
        fn sample_blue(&mut self) -> Result<u8, RealtimeError> {
            if unsafe { GetForegroundWindow() } != self.hwnd {
                return Err(RealtimeError::new(
                    "realtime.target_not_foreground",
                    "realtime target is no longer foreground",
                ));
            }
            let color = unsafe { GetPixel(self.dc, self.x, self.y) };
            if color.0 == CLR_INVALID {
                return Err(RealtimeError::new(
                    "realtime.pixel_probe_failed",
                    "GetPixel failed for realtime target",
                ));
            }
            Ok(((color.0 >> 16) & 0xff) as u8)
        }
    }

    impl Drop for GdiPixelProbe {
        fn drop(&mut self) {
            let _ = unsafe { ReleaseDC(Some(self.hwnd), self.dc) };
        }
    }
}
