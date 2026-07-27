use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use fairypam_agent_core::profile::CaptureRegion;
#[cfg(windows)]
use fairypam_agent_core::target::TargetBinding;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::{ColorType, ImageEncoder};

use crate::{validate_dpi, Rect, WindowsError};
#[cfg(windows)]
use crate::{NativeWindows, TargetIdentity, WindowsTargetPlatform};

const NORMALIZED_SCALE_PPM: u64 = 1_000_000;
const MAX_RAW_FRAME_BYTES: usize = 128 * 1024 * 1024;
const MAX_ENCODED_FRAME_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureEncoding {
    Png,
    Jpeg { quality: u8 },
}

#[derive(Clone, Debug)]
pub struct CapturedBgraFrame {
    pub pixels: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub captured_at: Instant,
}

#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub sequence: u64,
    pub captured_at: Instant,
    pub encoding: CaptureEncoding,
}

pub trait CaptureBackend: Send {
    fn next_bgra(&mut self, deadline: Instant) -> Result<CapturedBgraFrame, WindowsError>;
    fn rebuild(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError>;
}

pub trait CaptureSession: Send {
    fn next_frame(&mut self, deadline: Instant) -> Result<CapturedFrame, WindowsError>;
    fn resize(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError>;
}

pub struct CapturePipeline<B> {
    backend: B,
    client_rect: Rect,
    dpi: u32,
    region: CaptureRegion,
    encoding: CaptureEncoding,
    sequence: u64,
}

impl<B: CaptureBackend> CapturePipeline<B> {
    pub fn new(
        backend: B,
        client_rect: Rect,
        dpi: u32,
        region: CaptureRegion,
        encoding: CaptureEncoding,
    ) -> Result<Self, WindowsError> {
        validate_dpi(dpi)?;
        validate_encoding(encoding)?;
        Ok(Self {
            backend,
            client_rect,
            dpi,
            region,
            encoding,
            sequence: 0,
        })
    }

    pub const fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: CaptureBackend> CaptureSession for CapturePipeline<B> {
    fn next_frame(&mut self, deadline: Instant) -> Result<CapturedFrame, WindowsError> {
        if Instant::now() >= deadline {
            return Err(WindowsError::new(
                "capture.deadline",
                "capture deadline expired before work started",
            ));
        }
        let frame = self.backend.next_bgra(deadline)?;
        validate_raw_frame(&frame)?;
        let (pixels, width, height) =
            crop_bgra(frame.pixels, frame.width, frame.height, &self.region)?;
        let bytes = encode_bgra(&pixels, width, height, self.encoding)?;
        if bytes.len() > MAX_ENCODED_FRAME_BYTES {
            return Err(WindowsError::new(
                "capture.frame_too_large",
                "encoded frame exceeds the configured safety limit",
            ));
        }
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            WindowsError::new("capture.sequence_exhausted", "frame sequence exhausted")
        })?;
        Ok(CapturedFrame {
            bytes,
            width,
            height,
            sequence: self.sequence,
            captured_at: frame.captured_at,
            encoding: self.encoding,
        })
    }

    fn resize(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError> {
        validate_dpi(dpi)?;
        let changed = self.client_rect != client_rect || self.dpi != dpi;
        if changed {
            self.backend.rebuild(client_rect, dpi)?;
            self.client_rect = client_rect;
            self.dpi = dpi;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct WindowsTargetCapture {
    targets: WindowsTargetPlatform<NativeWindows>,
    binding: TargetBinding,
    capture: CapturePipeline<DxgiCaptureBackend>,
}

#[cfg(windows)]
impl WindowsTargetCapture {
    pub(crate) fn new(
        binding: TargetBinding,
        identity: TargetIdentity,
        region: CaptureRegion,
        encoding: CaptureEncoding,
    ) -> Result<Self, WindowsError> {
        let backend = DxgiCaptureBackend::new(&identity)?;
        let capture = CapturePipeline::new(
            backend,
            identity.client_rect,
            identity.dpi,
            region,
            encoding,
        )?;
        Ok(Self {
            targets: WindowsTargetPlatform::new(NativeWindows),
            binding,
            capture,
        })
    }
}

#[cfg(windows)]
impl CaptureSession for WindowsTargetCapture {
    fn next_frame(&mut self, deadline: Instant) -> Result<CapturedFrame, WindowsError> {
        let identity = self
            .targets
            .capture_identity(&self.binding)
            .map_err(|error| WindowsError::new(error.code(), error.to_string()))?;
        self.capture.resize(identity.client_rect, identity.dpi)?;
        self.capture.next_frame(deadline)
    }

    fn resize(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError> {
        self.capture.resize(client_rect, dpi)
    }
}

#[derive(Default)]
pub struct LatestFrameSlot {
    frame: Mutex<Option<CapturedFrame>>,
    overwritten: AtomicU64,
}

impl LatestFrameSlot {
    pub fn publish(&self, frame: CapturedFrame) {
        let mut slot = self
            .frame
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.replace(frame).is_some() {
            self.overwritten.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn take(&self) -> Option<CapturedFrame> {
        self.frame
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    pub fn overwritten(&self) -> u64 {
        self.overwritten.load(Ordering::Relaxed)
    }
}

fn validate_encoding(encoding: CaptureEncoding) -> Result<(), WindowsError> {
    if matches!(encoding, CaptureEncoding::Jpeg { quality } if !(1..=100).contains(&quality)) {
        return Err(WindowsError::new(
            "capture.encoding_invalid",
            "JPEG quality must be between 1 and 100",
        ));
    }
    Ok(())
}

fn validate_raw_frame(frame: &CapturedBgraFrame) -> Result<(), WindowsError> {
    let expected = checked_bgra_len(frame.width, frame.height)?;
    if frame.pixels.len() != expected {
        return Err(WindowsError::new(
            "capture.frame_invalid",
            "raw BGRA frame dimensions do not match its buffer",
        ));
    }
    Ok(())
}

fn crop_bgra(
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    region: &CaptureRegion,
) -> Result<(Vec<u8>, u32, u32), WindowsError> {
    let CaptureRegion::NormalizedRoi {
        x_ppm,
        y_ppm,
        width_ppm,
        height_ppm,
    } = region
    else {
        return Ok((pixels, width, height));
    };
    let x = scale_dimension(width, *x_ppm)?;
    let y = scale_dimension(height, *y_ppm)?;
    let roi_width = scale_dimension(width, *width_ppm)?;
    let roi_height = scale_dimension(height, *height_ppm)?;
    if roi_width == 0
        || roi_height == 0
        || x.checked_add(roi_width).is_none_or(|right| right > width)
        || y.checked_add(roi_height)
            .is_none_or(|bottom| bottom > height)
    {
        return Err(WindowsError::new(
            "capture.roi_invalid",
            "normalized ROI is outside the captured client area",
        ));
    }
    let row_bytes = usize::try_from(roi_width)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| WindowsError::new("capture.frame_too_large", "ROI row overflow"))?;
    let mut cropped = Vec::with_capacity(row_bytes * roi_height as usize);
    for row in y..y + roi_height {
        let start = ((row as usize * width as usize) + x as usize) * 4;
        cropped.extend_from_slice(&pixels[start..start + row_bytes]);
    }
    Ok((cropped, roi_width, roi_height))
}

fn scale_dimension(value: u32, ppm: u32) -> Result<u32, WindowsError> {
    let scaled = u64::from(value)
        .checked_mul(u64::from(ppm))
        .ok_or_else(|| WindowsError::new("capture.roi_invalid", "ROI scale overflow"))?
        / NORMALIZED_SCALE_PPM;
    u32::try_from(scaled)
        .map_err(|_| WindowsError::new("capture.roi_invalid", "ROI scale overflow"))
}

fn encode_bgra(
    bgra: &[u8],
    width: u32,
    height: u32,
    encoding: CaptureEncoding,
) -> Result<Vec<u8>, WindowsError> {
    let rgb_len = checked_rgb_len(width, height)?;
    let mut rgb = Vec::with_capacity(rgb_len);
    for pixel in bgra.chunks_exact(4) {
        rgb.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
    }
    let mut bytes = Cursor::new(Vec::new());
    let result = match encoding {
        CaptureEncoding::Png => {
            PngEncoder::new(&mut bytes).write_image(&rgb, width, height, ColorType::Rgb8.into())
        }
        CaptureEncoding::Jpeg { quality } => JpegEncoder::new_with_quality(&mut bytes, quality)
            .write_image(&rgb, width, height, ColorType::Rgb8.into()),
    };
    result.map_err(|error| WindowsError::new("capture.encode_failed", error.to_string()))?;
    Ok(bytes.into_inner())
}

fn checked_bgra_len(width: u32, height: u32) -> Result<usize, WindowsError> {
    checked_frame_len(width, height, 4, MAX_RAW_FRAME_BYTES, "raw BGRA frame")
}

fn checked_rgb_len(width: u32, height: u32) -> Result<usize, WindowsError> {
    checked_frame_len(
        width,
        height,
        3,
        MAX_ENCODED_FRAME_BYTES,
        "encoded RGB source",
    )
}

#[cfg(any(windows, test))]
fn client_crop_box(
    capture_bounds: Rect,
    client_rect: Rect,
    source_width: u32,
    source_height: u32,
) -> Result<(u32, u32, u32, u32), WindowsError> {
    let x = u32::try_from(client_rect.left - capture_bounds.left).map_err(|_| {
        WindowsError::new(
            "capture.client_bounds_invalid",
            "client left is outside capture frame",
        )
    })?;
    let y = u32::try_from(client_rect.top - capture_bounds.top).map_err(|_| {
        WindowsError::new(
            "capture.client_bounds_invalid",
            "client top is outside capture frame",
        )
    })?;
    if x.checked_add(client_rect.width)
        .is_none_or(|right| right > source_width)
        || y.checked_add(client_rect.height)
            .is_none_or(|bottom| bottom > source_height)
    {
        return Err(WindowsError::new(
            "capture.client_bounds_invalid",
            format!(
                "client rectangle ({x},{y} {}x{}) exceeds capture frame {source_width}x{source_height}",
                client_rect.width, client_rect.height
            ),
        ));
    }
    Ok((x, y, client_rect.width, client_rect.height))
}

fn checked_frame_len(
    width: u32,
    height: u32,
    channels: usize,
    maximum: usize,
    label: &str,
) -> Result<usize, WindowsError> {
    let length = usize::try_from(width)
        .ok()
        .and_then(|width| {
            usize::try_from(height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(channels))
        .ok_or_else(|| {
            WindowsError::new("capture.frame_too_large", format!("{label} size overflow"))
        })?;
    if length == 0 || length > maximum {
        return Err(WindowsError::new(
            "capture.frame_too_large",
            format!("{label} exceeds the configured safety limit"),
        ));
    }
    Ok(length)
}

#[cfg(windows)]
pub struct DxgiCaptureBackend {
    hwnd: isize,
    monitor_bounds: Rect,
    client_rect: Rect,
    capture: windows_capture::dxgi_duplication_api::DxgiDuplicationApi,
    scratch: Vec<u8>,
}

#[cfg(windows)]
impl DxgiCaptureBackend {
    pub fn new(identity: &crate::TargetIdentity) -> Result<Self, WindowsError> {
        use windows_capture::dxgi_duplication_api::{DxgiDuplicationApi, DxgiDuplicationFormat};
        use windows_capture::monitor::Monitor;

        let hwnd = windows::Win32::Foundation::HWND(identity.hwnd as *mut std::ffi::c_void);
        let (monitor, monitor_bounds) = target_monitor(hwnd)?;
        client_crop_box(
            monitor_bounds,
            identity.client_rect,
            monitor_bounds.width,
            monitor_bounds.height,
        )?;
        let capture = DxgiDuplicationApi::new_options(
            Monitor::from_raw_hmonitor(monitor.0),
            &[DxgiDuplicationFormat::Bgra8],
        )
        .map_err(|error| WindowsError::new("capture.session_failed", error.to_string()))?;
        Ok(Self {
            hwnd: identity.hwnd,
            monitor_bounds,
            client_rect: identity.client_rect,
            capture,
            scratch: Vec::new(),
        })
    }
}

#[cfg(windows)]
impl CaptureBackend for DxgiCaptureBackend {
    fn next_bgra(&mut self, deadline: Instant) -> Result<CapturedBgraFrame, WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
        use windows_capture::dxgi_duplication_api::{DxgiDuplicationFormat, Error};

        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        if unsafe { GetForegroundWindow() } != hwnd {
            return Err(WindowsError::new(
                "capture.target_not_foreground",
                "desktop capture requires the signed target window to be foreground",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(WindowsError::new(
                "capture.deadline",
                "capture deadline expired before DXGI frame acquisition",
            ));
        }
        let timeout_ms = u32::try_from(remaining.as_millis().max(1)).unwrap_or(u32::MAX);
        let mut frame =
            self.capture
                .acquire_next_frame(timeout_ms)
                .map_err(|error| match error {
                    Error::Timeout => WindowsError::new(
                        "capture.deadline",
                        "no DXGI frame arrived before deadline",
                    ),
                    Error::AccessLost => {
                        WindowsError::new("capture.access_lost", "DXGI duplication access was lost")
                    }
                    error => WindowsError::new("capture.map_failed", error.to_string()),
                })?;
        if frame.format() != DxgiDuplicationFormat::Bgra8 {
            return Err(WindowsError::new(
                "capture.format_unsupported",
                "DXGI capture did not provide BGRA8 pixels",
            ));
        }
        let (x, y, width, height) = client_crop_box(
            self.monitor_bounds,
            self.client_rect,
            frame.width(),
            frame.height(),
        )?;
        checked_bgra_len(width, height)?;
        let buffer = frame
            .buffer_crop(x, y, x + width, y + height)
            .map_err(|error| WindowsError::new("capture.map_failed", error.to_string()))?;
        let pixels = buffer.as_nopadding_buffer(&mut self.scratch).to_vec();
        Ok(CapturedBgraFrame {
            pixels,
            width,
            height,
            captured_at: Instant::now(),
        })
    }

    fn rebuild(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError> {
        validate_dpi(dpi)?;
        client_crop_box(
            self.monitor_bounds,
            client_rect,
            self.monitor_bounds.width,
            self.monitor_bounds.height,
        )?;
        self.client_rect = client_rect;
        Ok(())
    }
}

#[cfg(windows)]
fn target_monitor(
    hwnd: windows::Win32::Foundation::HWND,
) -> Result<(windows::Win32::Graphics::Gdi::HMONITOR, Rect), WindowsError> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONULL,
    };

    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) };
    if monitor.is_invalid() {
        return Err(WindowsError::new(
            "capture.target_unavailable",
            "target window is not on an active monitor",
        ));
    }
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..MONITORINFO::default()
    };
    if !unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
        return Err(WindowsError::new(
            "capture.target_unavailable",
            "failed to resolve target monitor bounds",
        ));
    }
    let bounds: RECT = info.rcMonitor;
    let width = u32::try_from(bounds.right - bounds.left)
        .map_err(|_| WindowsError::new("capture.target_unavailable", "negative monitor width"))?;
    let height = u32::try_from(bounds.bottom - bounds.top)
        .map_err(|_| WindowsError::new("capture.target_unavailable", "negative monitor height"))?;
    let bounds = Rect::new(bounds.left, bounds.top, width, height)
        .map_err(|error| WindowsError::new("capture.target_unavailable", error.to_string()))?;
    Ok((monitor, bounds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let error = checked_bgra_len(u32::MAX, u32::MAX).unwrap_err();
        assert_eq!(error.code(), "capture.frame_too_large");
    }

    #[test]
    fn oversized_encoding_source_is_rejected_before_encoding() {
        let error = checked_rgb_len(16_384, 16_384).unwrap_err();
        assert_eq!(error.code(), "capture.frame_too_large");
    }

    #[test]
    fn client_crop_rejects_source_bounds_that_exclude_the_client() {
        let client = Rect::new(108, 131, 784, 561).unwrap();
        let visible_dwm_bounds = Rect::new(108, 108, 784, 584).unwrap();
        assert_eq!(
            client_crop_box(visible_dwm_bounds, client, 784, 584).unwrap(),
            (0, 23, 784, 561)
        );

        let get_window_rect_bounds = Rect::new(100, 100, 800, 600).unwrap();
        assert_eq!(
            client_crop_box(get_window_rect_bounds, client, 784, 584)
                .unwrap_err()
                .code(),
            "capture.client_bounds_invalid"
        );
    }
}
