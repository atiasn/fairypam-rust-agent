#[cfg(windows)]
use fairypam_agent_core::target::TargetBinding;

#[cfg(windows)]
use crate::WindowsError;

#[cfg(any(windows, test))]
fn blue_channel(colorref: u32) -> u8 {
    ((colorref >> 16) & 0xff) as u8
}

#[cfg(windows)]
pub struct ClientPixelSampler {
    hwnd: isize,
}

#[cfg(windows)]
impl ClientPixelSampler {
    pub const fn new(binding: &TargetBinding) -> Self {
        Self {
            hwnd: binding.window_handle as isize,
        }
    }

    pub fn sample_blue<const N: usize>(
        &self,
        points: &[(i32, i32); N],
    ) -> Result<[u8; N], WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{GetDC, GetPixel, ReleaseDC, CLR_INVALID};
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        if unsafe { GetForegroundWindow() } != hwnd {
            return Err(WindowsError::new(
                "music.autoplay_target_not_foreground",
                "music autoplay target is not the foreground window",
            ));
        }
        let dc = unsafe { GetDC(Some(hwnd)) };
        if dc.is_invalid() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "GetDC failed for the signed music target",
            ));
        }
        let result = (|| {
            let mut blue = [0; N];
            for (index, (x, y)) in points.iter().copied().enumerate() {
                let color = unsafe { GetPixel(dc, x, y) };
                if color.0 == CLR_INVALID {
                    return Err(WindowsError::new(
                        "music.autoplay_sample_failed",
                        "GetPixel failed for a signed music lane point",
                    ));
                }
                blue[index] = blue_channel(color.0);
            }
            Ok(blue)
        })();
        unsafe { ReleaseDC(Some(hwnd), dc) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colorref_blue_uses_the_high_color_byte() {
        assert_eq!(blue_channel(0x00dc_8040), 220);
    }
}
