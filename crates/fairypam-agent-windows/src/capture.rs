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
    capture: CapturePipeline<BitBltCaptureBackend>,
}

#[cfg(windows)]
impl WindowsTargetCapture {
    pub(crate) fn new(
        binding: TargetBinding,
        identity: TargetIdentity,
        region: CaptureRegion,
        encoding: CaptureEncoding,
    ) -> Result<Self, WindowsError> {
        let backend = BitBltCaptureBackend::new(&identity)?;
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
pub struct BitBltCaptureBackend {
    hwnd: isize,
    client_rect: Rect,
    source_dc: isize,
    target_dc: isize,
    bitmap: isize,
    previous_bitmap: isize,
    bits: usize,
}

#[cfg(windows)]
impl BitBltCaptureBackend {
    pub fn new(identity: &crate::TargetIdentity) -> Result<Self, WindowsError> {
        checked_bgra_len(identity.client_rect.width, identity.client_rect.height)?;
        Ok(Self {
            hwnd: identity.hwnd,
            client_rect: identity.client_rect,
            source_dc: 0,
            target_dc: 0,
            bitmap: 0,
            previous_bitmap: 0,
            bits: 0,
        })
    }

    fn initialize_resources(&mut self) -> Result<(), WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{
            CreateCompatibleDC, CreateDIBSection, DeleteDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
            DIB_RGB_COLORS, GetDC, HGDIOBJ, ReleaseDC, SelectObject,
        };

        if self.source_dc != 0 {
            return Ok(());
        }
        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        let source_dc = unsafe { GetDC(Some(hwnd)) };
        if source_dc.is_invalid() {
            return Err(WindowsError::new(
                "capture.session_failed",
                "GetDC failed for the signed target window",
            ));
        }
        let target_dc = unsafe { CreateCompatibleDC(Some(source_dc)) };
        if target_dc.is_invalid() {
            unsafe { ReleaseDC(Some(hwnd), source_dc) };
            return Err(WindowsError::new(
                "capture.session_failed",
                "CreateCompatibleDC failed for the signed target window",
            ));
        }
        let width = i32::try_from(self.client_rect.width)
            .map_err(|_| WindowsError::new("capture.frame_too_large", "client width overflow"))?;
        let height = i32::try_from(self.client_rect.height)
            .map_err(|_| WindowsError::new("capture.frame_too_large", "client height overflow"))?;
        let bitmap_info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height,
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
        };
        let bitmap = match bitmap {
            Ok(bitmap) if !bits.is_null() => bitmap,
            Ok(bitmap) => {
                unsafe {
                    windows::Win32::Graphics::Gdi::DeleteObject(bitmap.into());
                    DeleteDC(target_dc);
                    ReleaseDC(Some(hwnd), source_dc);
                }
                return Err(WindowsError::new(
                    "capture.session_failed",
                    "CreateDIBSection returned no pixel buffer",
                ));
            }
            Err(error) => {
                unsafe {
                    DeleteDC(target_dc);
                    ReleaseDC(Some(hwnd), source_dc);
                }
                return Err(WindowsError::new("capture.session_failed", error.to_string()));
            }
        };
        let previous_bitmap = unsafe { SelectObject(target_dc, bitmap.into()) };
        if previous_bitmap.is_invalid() {
            unsafe {
                windows::Win32::Graphics::Gdi::DeleteObject(HGDIOBJ(bitmap.0));
                DeleteDC(target_dc);
                ReleaseDC(Some(hwnd), source_dc);
            }
            return Err(WindowsError::new(
                "capture.session_failed",
                "SelectObject failed for the capture bitmap",
            ));
        }
        self.source_dc = source_dc.0 as isize;
        self.target_dc = target_dc.0 as isize;
        self.bitmap = bitmap.0 as isize;
        self.previous_bitmap = previous_bitmap.0 as isize;
        self.bits = bits as usize;
        Ok(())
    }

    fn release_resources(&mut self) {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{
            DeleteDC, DeleteObject, HDC, HGDIOBJ, ReleaseDC, SelectObject,
        };

        unsafe {
            if self.target_dc != 0 && self.previous_bitmap != 0 {
                SelectObject(
                    HDC(self.target_dc as *mut std::ffi::c_void),
                    HGDIOBJ(self.previous_bitmap as *mut std::ffi::c_void),
                );
            }
            if self.bitmap != 0 {
                DeleteObject(HGDIOBJ(self.bitmap as *mut std::ffi::c_void));
            }
            if self.target_dc != 0 {
                DeleteDC(HDC(self.target_dc as *mut std::ffi::c_void));
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
impl CaptureBackend for BitBltCaptureBackend {
    fn next_bgra(&mut self, deadline: Instant) -> Result<CapturedBgraFrame, WindowsError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::{BitBlt, GdiFlush, HDC, SRCCOPY};
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        if unsafe { GetForegroundWindow() } != hwnd {
            return Err(WindowsError::new(
                "capture.target_not_foreground",
                "desktop capture requires the signed target window to be foreground",
            ));
        }
        if Instant::now() >= deadline {
            return Err(WindowsError::new(
                "capture.deadline",
                "capture deadline expired before BitBlt",
            ));
        }
        self.initialize_resources()?;
        let width = i32::try_from(self.client_rect.width)
            .map_err(|_| WindowsError::new("capture.frame_too_large", "client width overflow"))?;
        let height = i32::try_from(self.client_rect.height)
            .map_err(|_| WindowsError::new("capture.frame_too_large", "client height overflow"))?;
        unsafe {
            BitBlt(
                HDC(self.target_dc as *mut std::ffi::c_void),
                0,
                0,
                width,
                height,
                Some(HDC(self.source_dc as *mut std::ffi::c_void)),
                0,
                0,
                SRCCOPY,
            )
        }
        .map_err(|error| WindowsError::new("capture.map_failed", error.to_string()))?;
        if !unsafe { GdiFlush() }.as_bool() {
            return Err(WindowsError::new(
                "capture.map_failed",
                "GdiFlush failed after BitBlt",
            ));
        }
        let length = checked_bgra_len(self.client_rect.width, self.client_rect.height)?;
        let pixels = unsafe { std::slice::from_raw_parts(self.bits as *const u8, length) }.to_vec();
        Ok(CapturedBgraFrame {
            pixels,
            width: self.client_rect.width,
            height: self.client_rect.height,
            captured_at: Instant::now(),
        })
    }

    fn rebuild(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError> {
        validate_dpi(dpi)?;
        checked_bgra_len(client_rect.width, client_rect.height)?;
        if self.client_rect.width != client_rect.width
            || self.client_rect.height != client_rect.height
        {
            self.release_resources();
        }
        self.client_rect = client_rect;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for BitBltCaptureBackend {
    fn drop(&mut self) {
        self.release_resources();
    }
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

}
