#[cfg(windows)]
use fairypam_agent_core::target::TargetBinding;

#[cfg(any(windows, test))]
use crate::WindowsError;

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PointPixelSampleTiming {
    pub foreground: std::time::Duration,
    pub get_pixel: std::time::Duration,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PixelPointPlan {
    x: i32,
    y: i32,
}

#[cfg(any(windows, test))]
impl PixelPointPlan {
    fn new(point: (i32, i32), client_size: (u32, u32)) -> Result<Self, WindowsError> {
        let width = i32::try_from(client_size.0)
            .map_err(|_| invalid_points("music sampler client width overflow"))?;
        let height = i32::try_from(client_size.1)
            .map_err(|_| invalid_points("music sampler client height overflow"))?;
        if point.0 < 0 || point.0 >= width || point.1 < 0 || point.1 >= height {
            return Err(invalid_points(
                "music sampler point is outside the client area",
            ));
        }
        Ok(Self {
            x: point.0,
            y: point.1,
        })
    }
}

#[cfg(any(windows, test))]
fn invalid_points(message: &'static str) -> WindowsError {
    WindowsError::new("music.autoplay_sample_failed", message)
}

#[cfg(windows)]
pub struct ClientPointSampler {
    hwnd: isize,
    point: PixelPointPlan,
    source_dc: isize,
}

#[cfg(windows)]
impl ClientPointSampler {
    pub fn new(binding: &TargetBinding, point: (i32, i32)) -> Result<Self, WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::GetDC;

        let point = PixelPointPlan::new(
            point,
            (binding.client_rect.width, binding.client_rect.height),
        )?;
        let hwnd = binding.window_handle as isize;
        let source_dc = unsafe { GetDC(Some(HWND(hwnd as *mut std::ffi::c_void))) };
        if source_dc.is_invalid() {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "GetDC failed for the signed music target",
            ));
        }
        Ok(Self {
            hwnd,
            point,
            source_dc: source_dc.0 as isize,
        })
    }

    pub const fn source_dc(&self) -> isize {
        self.source_dc
    }

    pub fn sample_blue_timed(&self) -> Result<(u8, PointPixelSampleTiming), WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{GetPixel, CLR_INVALID, HDC};
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        let foreground_started = std::time::Instant::now();
        if unsafe { GetForegroundWindow() } != hwnd {
            return Err(WindowsError::new(
                "music.autoplay_target_not_foreground",
                "music autoplay target is not the foreground window",
            ));
        }
        let foreground = foreground_started.elapsed();
        let get_pixel_started = std::time::Instant::now();
        let color = unsafe {
            GetPixel(
                HDC(self.source_dc as *mut std::ffi::c_void),
                self.point.x,
                self.point.y,
            )
        };
        let get_pixel = get_pixel_started.elapsed();
        if color.0 == CLR_INVALID {
            return Err(WindowsError::new(
                "music.autoplay_sample_failed",
                "GetPixel failed for the signed music target",
            ));
        }
        Ok((
            (color.0 >> 16) as u8,
            PointPixelSampleTiming {
                foreground,
                get_pixel,
            },
        ))
    }
}

#[cfg(windows)]
impl Drop for ClientPointSampler {
    fn drop(&mut self) {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{ReleaseDC, HDC};

        if self.source_dc != 0 {
            unsafe {
                ReleaseDC(
                    Some(HWND(self.hwnd as *mut std::ffi::c_void)),
                    HDC(self.source_dc as *mut std::ffi::c_void),
                );
            }
            self.source_dc = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_plan_accepts_frozen_lane_and_rejects_bounds() {
        assert_eq!(
            PixelPointPlan::new((417, 921), (1920, 1080)).unwrap(),
            PixelPointPlan { x: 417, y: 921 }
        );
        assert_eq!(
            PixelPointPlan::new((1920, 921), (1920, 1080))
                .unwrap_err()
                .code(),
            "music.autoplay_sample_failed"
        );
    }
}
