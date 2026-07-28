//! Screen/window capture and JPEG encoding.

#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::Result;
use tracing::debug;

use crate::config::CaptureConfig;

pub struct CapturedFrame {
    pub jpeg: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

pub struct ScreenCapture {
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    config: CaptureConfig,
}

impl ScreenCapture {
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn new(config: &CaptureConfig) -> Result<Self> {
        debug!(
            "init screen capture: display={}, fps={}, quality={}",
            config.target_display, config.fps, config.jpeg_quality
        );

        if config.fps == 0 {
            anyhow::bail!("capture.fps 必须大于 0");
        }
        if !(1..=100).contains(&config.jpeg_quality) {
            anyhow::bail!("capture.jpeg_quality 必须在 1..=100 范围内");
        }

        Ok(Self {
            config: config.clone(),
        })
    }

    #[allow(dead_code)]
    pub fn capture_frame(&self) -> Result<Vec<u8>> {
        #[cfg(target_os = "windows")]
        {
            Ok(capture_monitor_xcap(self.config.target_display, self.config.jpeg_quality)?.jpeg)
        }

        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("屏幕捕获仅支持 Windows")
        }
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code, unused_variables))]
    pub fn capture_window(&self, hwnd: isize) -> Result<CapturedFrame> {
        #[cfg(target_os = "windows")]
        {
            capture_window_xcap(hwnd, self.config.jpeg_quality)
        }

        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("窗口截图仅支持 Windows")
        }
    }

    #[allow(dead_code)]
    #[cfg_attr(not(target_os = "windows"), allow(unused_variables))]
    pub fn capture_target_window(&self, pid: u32, executable: &str) -> Result<CapturedFrame> {
        #[cfg(target_os = "windows")]
        {
            capture_target_window_xcap(pid, executable, self.config.jpeg_quality)
        }

        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("窗口截图仅支持 Windows")
        }
    }
}

#[cfg(target_os = "windows")]
fn capture_monitor_xcap(target_display: u32, jpeg_quality: u8) -> Result<CapturedFrame> {
    let monitors = xcap::Monitor::all().context("枚举显示器失败")?;
    let monitor = monitors
        .get(target_display as usize)
        .or_else(|| monitors.first())
        .ok_or_else(|| anyhow::anyhow!("未找到可截图显示器"))?;
    let image = monitor.capture_image().context("显示器截图失败")?;

    encode_rgba_as_jpeg(image, jpeg_quality)
}

#[cfg(target_os = "windows")]
fn capture_window_xcap(hwnd: isize, jpeg_quality: u8) -> Result<CapturedFrame> {
    let windows = xcap::Window::all().context("枚举窗口失败")?;
    for window in windows {
        let Ok(id) = window.id() else {
            continue;
        };
        if id as isize != hwnd {
            continue;
        }
        if window.is_minimized().unwrap_or(true) {
            anyhow::bail!("目标窗口已最小化，无法截图");
        }

        let image = match window.capture_image() {
            Ok(image) => image,
            Err(err) => {
                debug!("xcap window capture failed: {err}; trying GDI fallback");
                return capture_window_gdi(hwnd, jpeg_quality);
            }
        };
        return encode_rgba_as_jpeg(image, jpeg_quality);
    }

    debug!("xcap did not list HWND {hwnd}; trying GDI fallback");
    capture_window_gdi(hwnd, jpeg_quality)
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn capture_target_window_xcap(
    pid: u32,
    executable: &str,
    jpeg_quality: u8,
) -> Result<CapturedFrame> {
    let window = crate::window::find_target_window(pid, None)
        .or_else(|_| crate::window::find_target_window(pid, Some(executable)))
        .with_context(|| format!("未找到 PID {pid} / {executable} 的目标窗口"))?;

    capture_window_xcap(window.hwnd, jpeg_quality)
}

#[cfg(target_os = "windows")]
mod gdi {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        DeleteDC, DeleteObject, ReleaseDC, SelectObject, HBITMAP, HDC, HGDIOBJ,
    };

    pub struct DcGuard {
        hwnd: HWND,
        dc: HDC,
    }

    impl DcGuard {
        pub fn new(hwnd: HWND, dc: HDC) -> Self {
            Self { hwnd, dc }
        }

        pub fn get(&self) -> HDC {
            self.dc
        }
    }

    impl Drop for DcGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = ReleaseDC(self.hwnd, self.dc);
            }
        }
    }

    pub struct CompatibleDcGuard {
        dc: HDC,
    }

    impl CompatibleDcGuard {
        pub fn new(dc: HDC) -> Self {
            Self { dc }
        }

        pub fn get(&self) -> HDC {
            self.dc
        }
    }

    impl Drop for CompatibleDcGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = DeleteDC(self.dc);
            }
        }
    }

    pub struct BitmapGuard {
        bitmap: HBITMAP,
    }

    impl BitmapGuard {
        pub fn new(bitmap: HBITMAP) -> Self {
            Self { bitmap }
        }

        pub fn get(&self) -> HBITMAP {
            self.bitmap
        }
    }

    impl Drop for BitmapGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = DeleteObject(HGDIOBJ(self.bitmap.0));
            }
        }
    }

    pub struct SelectedObjectGuard {
        dc: HDC,
        old: HGDIOBJ,
    }

    impl SelectedObjectGuard {
        pub fn new(dc: HDC, old: HGDIOBJ) -> Self {
            Self { dc, old }
        }
    }

    impl Drop for SelectedObjectGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = SelectObject(self.dc, self.old);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn capture_window_gdi(hwnd: isize, jpeg_quality: u8) -> Result<CapturedFrame> {
    use gdi::{BitmapGuard, CompatibleDcGuard, DcGuard, SelectedObjectGuard};
    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, GetWindowDC, SelectObject, HGDIOBJ,
        SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetWindowRect;

    unsafe {
        let hwnd = HWND(hwnd as *mut std::ffi::c_void);
        let mut rect = RECT::default();
        GetWindowRect(hwnd, &mut rect)?;
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        if width <= 0 || height <= 0 {
            anyhow::bail!("目标窗口尺寸无效");
        }

        let window_dc = GetWindowDC(hwnd);
        if window_dc.0.is_null() {
            anyhow::bail!("GetWindowDC 失败");
        }
        let window_dc = DcGuard::new(hwnd, window_dc);

        let memory_dc = CreateCompatibleDC(window_dc.get());
        if memory_dc.0.is_null() {
            anyhow::bail!("CreateCompatibleDC 失败");
        }
        let memory_dc = CompatibleDcGuard::new(memory_dc);

        let bitmap = CreateCompatibleBitmap(window_dc.get(), width, height);
        if bitmap.0.is_null() {
            anyhow::bail!("CreateCompatibleBitmap 失败");
        }
        let bitmap = BitmapGuard::new(bitmap);

        let old_object = SelectObject(memory_dc.get(), HGDIOBJ(bitmap.get().0));
        let _selected = SelectedObjectGuard::new(memory_dc.get(), old_object);
        BitBlt(
            memory_dc.get(),
            0,
            0,
            width,
            height,
            window_dc.get(),
            0,
            0,
            SRCCOPY,
        )?;

        read_bitmap_as_jpeg(memory_dc.get(), bitmap.get(), width, height, jpeg_quality)
    }
}

#[cfg(target_os = "windows")]
fn read_bitmap_as_jpeg(
    memory_dc: windows::Win32::Graphics::Gdi::HDC,
    bitmap: windows::Win32::Graphics::Gdi::HBITMAP,
    width: i32,
    height: i32,
    jpeg_quality: u8,
) -> Result<CapturedFrame> {
    use image::codecs::jpeg::JpegEncoder;
    use image::ColorType;
    use windows::Win32::Graphics::Gdi::{
        GetDIBits, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, RGBQUAD,
    };

    unsafe {
        let mut bitmap_info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            bmiColors: [RGBQUAD::default(); 1],
        };

        let pixel_count = width as usize * height as usize;
        let mut bgra = vec![0u8; pixel_count * 4];
        let scan_lines = GetDIBits(
            memory_dc,
            bitmap,
            0,
            height as u32,
            Some(bgra.as_mut_ptr().cast()),
            &mut bitmap_info,
            DIB_RGB_COLORS,
        );
        if scan_lines == 0 {
            anyhow::bail!("GetDIBits 失败");
        }

        let mut rgb = Vec::with_capacity(pixel_count * 3);
        for pixel in bgra.chunks_exact(4) {
            rgb.push(pixel[2]);
            rgb.push(pixel[1]);
            rgb.push(pixel[0]);
        }

        let mut jpeg = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut jpeg, jpeg_quality);
        encoder.encode(&rgb, width as u32, height as u32, ColorType::Rgb8.into())?;

        Ok(CapturedFrame {
            jpeg,
            width: width as u32,
            height: height as u32,
        })
    }
}

#[cfg(target_os = "windows")]
fn encode_rgba_as_jpeg(image: image::RgbaImage, jpeg_quality: u8) -> Result<CapturedFrame> {
    use image::codecs::jpeg::JpegEncoder;
    use image::ColorType;

    let width = image.width();
    let height = image.height();
    let rgba = image.into_raw();
    let mut rgb = Vec::with_capacity((width * height * 3) as usize);
    for pixel in rgba.chunks_exact(4) {
        rgb.extend_from_slice(&pixel[..3]);
    }

    let mut jpeg = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut jpeg, jpeg_quality);
    encoder.encode(&rgb, width, height, ColorType::Rgb8.into())?;

    Ok(CapturedFrame {
        jpeg,
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_creation() {
        let config = CaptureConfig {
            target_display: 0,
            fps: 30,
            jpeg_quality: 90,
            encoder: "media_foundation".into(),
        };
        let result = ScreenCapture::new(&config);
        assert!(result.is_ok());
    }
}
