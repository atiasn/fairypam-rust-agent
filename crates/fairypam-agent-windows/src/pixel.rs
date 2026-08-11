#[cfg(windows)]
use fairypam_agent_core::target::TargetBinding;

#[cfg(any(windows, test))]
use crate::WindowsError;

#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PixelRowPlan<const N: usize> {
    left: i32,
    y: i32,
    width: i32,
    offsets: [usize; N],
    byte_len: usize,
}

#[cfg(any(windows, test))]
impl<const N: usize> PixelRowPlan<N> {
    fn new(points: &[(i32, i32); N], client_size: (u32, u32)) -> Result<Self, WindowsError> {
        let Some((_, y)) = points.first().copied() else {
            return Err(invalid_points("music sampler requires at least one point"));
        };
        let client_width = i32::try_from(client_size.0)
            .map_err(|_| invalid_points("music sampler client width overflow"))?;
        let client_height = i32::try_from(client_size.1)
            .map_err(|_| invalid_points("music sampler client height overflow"))?;
        let mut left = i32::MAX;
        let mut right = i32::MIN;
        for (x, point_y) in points.iter().copied() {
            if point_y != y {
                return Err(invalid_points("music sampler points must share one row"));
            }
            if x < 0 || x >= client_width || point_y < 0 || point_y >= client_height {
                return Err(invalid_points(
                    "music sampler point is outside the client area",
                ));
            }
            left = left.min(x);
            right = right.max(x);
        }
        let width = right
            .checked_sub(left)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| invalid_points("music sampler row width overflow"))?;
        let byte_len = usize::try_from(width)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or_else(|| invalid_points("music sampler row byte length overflow"))?;
        let mut offsets = [0; N];
        for (index, (x, _)) in points.iter().copied().enumerate() {
            offsets[index] = usize::try_from(x - left)
                .map_err(|_| invalid_points("music sampler point offset overflow"))?;
        }
        Ok(Self {
            left,
            y,
            width,
            offsets,
            byte_len,
        })
    }

    fn blue_channels(&self, bgra: &[u8]) -> Result<[u8; N], WindowsError> {
        if bgra.len() < self.byte_len {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "music sampler row buffer is incomplete",
            ));
        }
        let mut blue = [0; N];
        for (index, offset) in self.offsets.iter().copied().enumerate() {
            blue[index] = bgra[offset * 4];
        }
        Ok(blue)
    }
}

#[cfg(any(windows, test))]
fn invalid_points(message: &'static str) -> WindowsError {
    WindowsError::new("music.autoplay_sample_failed", message)
}

#[cfg(windows)]
pub struct ClientPixelSampler<const N: usize> {
    hwnd: isize,
    plan: PixelRowPlan<N>,
    source_dc: isize,
    target_dc: isize,
    bitmap: isize,
    previous_bitmap: isize,
    bits: usize,
}

#[cfg(windows)]
impl<const N: usize> ClientPixelSampler<N> {
    pub fn new(binding: &TargetBinding, points: &[(i32, i32); N]) -> Result<Self, WindowsError> {
        let mut sampler = Self {
            hwnd: binding.window_handle as isize,
            plan: PixelRowPlan::new(
                points,
                (binding.client_rect.width, binding.client_rect.height),
            )?,
            source_dc: 0,
            target_dc: 0,
            bitmap: 0,
            previous_bitmap: 0,
            bits: 0,
        };
        sampler.initialize_resources()?;
        Ok(sampler)
    }

    fn initialize_resources(&mut self) -> Result<(), WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{
            CreateCompatibleDC, CreateDIBSection, GetDC, SelectObject, BITMAPINFO,
            BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        };

        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        let source_dc = unsafe { GetDC(Some(hwnd)) };
        if source_dc.is_invalid() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "GetDC failed for the signed music target",
            ));
        }
        self.source_dc = source_dc.0 as isize;

        let target_dc = unsafe { CreateCompatibleDC(Some(source_dc)) };
        if target_dc.is_invalid() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "CreateCompatibleDC failed for the signed music target",
            ));
        }
        self.target_dc = target_dc.0 as isize;

        let bitmap_info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: self.plan.width,
                biHeight: -1,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..BITMAPINFOHEADER::default()
            },
            ..BITMAPINFO::default()
        };
        let mut bits = std::ptr::null_mut();
        let bitmap = unsafe {
            CreateDIBSection(
                Some(target_dc),
                &bitmap_info,
                DIB_RGB_COLORS,
                &mut bits,
                None,
                0,
            )
        }
        .map_err(|error| WindowsError::new("music.autoplay_sample_failed", error.to_string()))?;
        self.bitmap = bitmap.0 as isize;
        if bits.is_null() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "CreateDIBSection returned no music sampler buffer",
            ));
        }
        self.bits = bits as usize;

        let previous_bitmap = unsafe { SelectObject(target_dc, bitmap.into()) };
        if previous_bitmap.is_invalid() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "SelectObject failed for the music sampler bitmap",
            ));
        }
        self.previous_bitmap = previous_bitmap.0 as isize;
        Ok(())
    }

    pub fn sample_blue(&self) -> Result<[u8; N], WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{BitBlt, GdiFlush, HDC, SRCCOPY};
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        if unsafe { GetForegroundWindow() } != hwnd {
            return Err(WindowsError::new(
                "music.autoplay_target_not_foreground",
                "music autoplay target is not the foreground window",
            ));
        }
        unsafe {
            BitBlt(
                HDC(self.target_dc as *mut std::ffi::c_void),
                0,
                0,
                self.plan.width,
                1,
                Some(HDC(self.source_dc as *mut std::ffi::c_void)),
                self.plan.left,
                self.plan.y,
                SRCCOPY,
            )
        }
        .map_err(|error| WindowsError::new("music.autoplay_sample_failed", error.to_string()))?;
        if !unsafe { GdiFlush() }.as_bool() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "GdiFlush failed after music sampler BitBlt",
            ));
        }
        let bgra =
            unsafe { std::slice::from_raw_parts(self.bits as *const u8, self.plan.byte_len) };
        self.plan.blue_channels(bgra)
    }

    fn release_resources(&mut self) {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{
            DeleteDC, DeleteObject, ReleaseDC, SelectObject, HDC, HGDIOBJ,
        };

        unsafe {
            if self.target_dc != 0 && self.previous_bitmap != 0 {
                SelectObject(
                    HDC(self.target_dc as *mut std::ffi::c_void),
                    HGDIOBJ(self.previous_bitmap as *mut std::ffi::c_void),
                );
            }
            if self.bitmap != 0 {
                let _ = DeleteObject(HGDIOBJ(self.bitmap as *mut std::ffi::c_void));
            }
            if self.target_dc != 0 {
                let _ = DeleteDC(HDC(self.target_dc as *mut std::ffi::c_void));
            }
            if self.source_dc != 0 {
                ReleaseDC(
                    Some(HWND(self.hwnd as *mut std::ffi::c_void)),
                    HDC(self.source_dc as *mut std::ffi::c_void),
                );
            }
        }
        self.source_dc = 0;
        self.target_dc = 0;
        self.bitmap = 0;
        self.previous_bitmap = 0;
        self.bits = 0;
    }
}

#[cfg(windows)]
impl<const N: usize> Drop for ClientPixelSampler<N> {
    fn drop(&mut self) {
        self.release_resources();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_plan_reads_six_blue_channels_from_one_bgra_row() {
        let points = [
            (417, 921),
            (628, 921),
            (844, 921),
            (1061, 921),
            (1277, 921),
            (1493, 921),
        ];
        let plan = PixelRowPlan::new(&points, (1920, 1080)).unwrap();
        assert_eq!(plan.left, 417);
        assert_eq!(plan.width, 1077);
        assert_eq!(plan.offsets, [0, 211, 427, 644, 860, 1076]);

        let mut bgra = vec![0; plan.byte_len];
        for (index, offset) in plan.offsets.iter().copied().enumerate() {
            bgra[offset * 4] = 10 + index as u8;
        }
        assert_eq!(plan.blue_channels(&bgra).unwrap(), [10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn row_plan_rejects_multiple_rows_and_out_of_bounds_points() {
        assert_eq!(
            PixelRowPlan::new(&[(10, 20), (30, 21)], (1920, 1080))
                .unwrap_err()
                .code(),
            "music.autoplay_sample_failed"
        );
        assert_eq!(
            PixelRowPlan::new(&[(10, 20), (1920, 20)], (1920, 1080))
                .unwrap_err()
                .code(),
            "music.autoplay_sample_failed"
        );
    }
}
