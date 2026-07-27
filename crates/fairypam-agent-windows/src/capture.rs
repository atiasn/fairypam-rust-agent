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
    capture: CapturePipeline<WgcCaptureBackend>,
}

#[cfg(windows)]
impl WindowsTargetCapture {
    pub(crate) fn new(
        binding: TargetBinding,
        identity: TargetIdentity,
        region: CaptureRegion,
        encoding: CaptureEncoding,
    ) -> Result<Self, WindowsError> {
        let backend = WgcCaptureBackend::new(&identity)?;
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
            "client left is outside WGC frame",
        )
    })?;
    let y = u32::try_from(client_rect.top - capture_bounds.top).map_err(|_| {
        WindowsError::new(
            "capture.client_bounds_invalid",
            "client top is outside WGC frame",
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
                "client rectangle ({x},{y} {}x{}) exceeds WGC frame {source_width}x{source_height}",
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
    fn client_crop_uses_visible_dwm_bounds_instead_of_invisible_resize_border() {
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

#[cfg(windows)]
pub struct WgcCaptureBackend {
    requests: std::sync::mpsc::SyncSender<WgcRequest>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
enum WgcRequest {
    Next {
        deadline: Instant,
        reply: std::sync::mpsc::SyncSender<Result<CapturedBgraFrame, WindowsError>>,
    },
    Rebuild {
        client_rect: Rect,
        reply: std::sync::mpsc::SyncSender<Result<(), WindowsError>>,
    },
    Stop,
}

#[cfg(windows)]
impl WgcCaptureBackend {
    pub fn new(identity: &crate::TargetIdentity) -> Result<Self, WindowsError> {
        let identity = identity.clone();
        let (requests, receiver) = std::sync::mpsc::sync_channel(1);
        let (initialized, initialized_receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("fairypam-wgc-capture".into())
            .spawn(move || {
                match native_wgc::initialize_apartment().and_then(|apartment| {
                    native_wgc::create(&identity).map(|state| (apartment, state))
                }) {
                    Ok((_apartment, mut state)) => {
                        let _ = initialized.send(Ok(()));
                        while let Ok(request) = receiver.recv() {
                            match request {
                                WgcRequest::Next { deadline, reply } => {
                                    let _ = reply.send(native_wgc::next_bgra(&mut state, deadline));
                                }
                                WgcRequest::Rebuild { client_rect, reply } => {
                                    let _ =
                                        reply.send(native_wgc::rebuild(&mut state, client_rect));
                                }
                                WgcRequest::Stop => break,
                            }
                        }
                        native_wgc::close(&state);
                    }
                    Err(error) => {
                        let _ = initialized.send(Err(error));
                    }
                }
            })
            .map_err(|error| WindowsError::new("capture.worker_failed", error.to_string()))?;
        initialized_receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(map_worker_wait_error)??;
        Ok(Self {
            requests,
            worker: Some(worker),
        })
    }
}

#[cfg(windows)]
impl CaptureBackend for WgcCaptureBackend {
    fn next_bgra(&mut self, deadline: Instant) -> Result<CapturedBgraFrame, WindowsError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(WindowsError::new(
                "capture.deadline",
                "capture deadline expired before dispatch",
            ));
        }
        let (reply, receiver) = std::sync::mpsc::sync_channel(1);
        self.requests
            .try_send(WgcRequest::Next { deadline, reply })
            .map_err(map_worker_send_error)?;
        receiver.recv().map_err(|_| {
            WindowsError::new("capture.worker_failed", "capture worker disconnected")
        })?
    }

    fn rebuild(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError> {
        validate_dpi(dpi)?;
        let (reply, receiver) = std::sync::mpsc::sync_channel(1);
        self.requests
            .try_send(WgcRequest::Rebuild { client_rect, reply })
            .map_err(map_worker_send_error)?;
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(map_worker_wait_error)?
    }
}

#[cfg(windows)]
impl Drop for WgcCaptureBackend {
    fn drop(&mut self) {
        let _ = self.requests.send(WgcRequest::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
fn map_worker_send_error<T>(error: std::sync::mpsc::TrySendError<T>) -> WindowsError {
    match error {
        std::sync::mpsc::TrySendError::Full(_) => WindowsError::new(
            "capture.worker_busy",
            "capture worker is still handling a request",
        ),
        std::sync::mpsc::TrySendError::Disconnected(_) => {
            WindowsError::new("capture.worker_failed", "capture worker disconnected")
        }
    }
}

#[cfg(windows)]
fn map_worker_wait_error(error: std::sync::mpsc::RecvTimeoutError) -> WindowsError {
    match error {
        std::sync::mpsc::RecvTimeoutError::Timeout => {
            WindowsError::new("capture.deadline", "capture worker exceeded its deadline")
        }
        std::sync::mpsc::RecvTimeoutError::Disconnected => {
            WindowsError::new("capture.worker_failed", "capture worker disconnected")
        }
    }
}

#[cfg(windows)]
mod native_wgc {
    use std::ffi::c_void;
    use std::time::Instant;

    use windows::core::{factory, IInspectable, Interface};
    use windows::Foundation::TypedEventHandler;
    use windows::Graphics::Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem};
    use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
    use windows::Graphics::DirectX::DirectXPixelFormat;
    use windows::Win32::Foundation::{HMODULE, HWND, RECT};
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
        D3D11_BOX, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
        D3D11_USAGE_STAGING,
    };
    use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
    use windows::Win32::Graphics::Dxgi::IDXGIDevice;
    use windows::Win32::System::WinRT::Direct3D11::{
        CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
    };
    use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
    use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};

    use super::{client_crop_box, CapturedBgraFrame, Rect, WindowsError};

    pub(super) struct WgcState {
        hwnd: isize,
        item: GraphicsCaptureItem,
        device: IDirect3DDevice,
        d3d_device: ID3D11Device,
        d3d_context: ID3D11DeviceContext,
        frame_pool: Direct3D11CaptureFramePool,
        frame_arrived: std::sync::mpsc::Receiver<()>,
        frame_arrived_token: i64,
        session: windows::Graphics::Capture::GraphicsCaptureSession,
        client_rect: Rect,
    }

    pub(super) struct WinRtApartment;

    impl Drop for WinRtApartment {
        fn drop(&mut self) {
            unsafe { RoUninitialize() };
        }
    }

    pub(super) fn initialize_apartment() -> Result<WinRtApartment, WindowsError> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .map_err(|error| win_error("capture.com_initialization_failed", error))?;
        Ok(WinRtApartment)
    }

    pub(super) fn create(identity: &crate::TargetIdentity) -> Result<WgcState, WindowsError> {
        let (d3d_device, d3d_context, device) = create_device()?;
        let interop = factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
            .map_err(|error| win_error("capture.wgc_unavailable", error))?;
        let hwnd = HWND(identity.hwnd as *mut c_void);
        let item: GraphicsCaptureItem = unsafe { interop.CreateForWindow(hwnd) }
            .map_err(|error| win_error("capture.target_unavailable", error))?;
        let size = item
            .Size()
            .map_err(|error| win_error("capture.target_unavailable", error))?;
        let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            &device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            1,
            size,
        )
        .map_err(|error| win_error("capture.frame_pool_failed", error))?;
        let (frame_arrived_sender, frame_arrived) = std::sync::mpsc::sync_channel(1);
        let frame_arrived_token = frame_pool
            .FrameArrived(
                &TypedEventHandler::<Direct3D11CaptureFramePool, IInspectable>::new(move |_, _| {
                    let _ = frame_arrived_sender.try_send(());
                    Ok(())
                }),
            )
            .map_err(|error| win_error("capture.frame_pool_failed", error))?;
        let session = frame_pool
            .CreateCaptureSession(&item)
            .map_err(|error| win_error("capture.session_failed", error))?;
        let _ = session.SetIsCursorCaptureEnabled(false);
        session
            .StartCapture()
            .map_err(|error| win_error("capture.session_failed", error))?;
        Ok(WgcState {
            hwnd: identity.hwnd,
            item,
            device,
            d3d_device,
            d3d_context,
            frame_pool,
            frame_arrived,
            frame_arrived_token,
            session,
            client_rect: identity.client_rect,
        })
    }

    pub(super) fn rebuild(backend: &mut WgcState, client_rect: Rect) -> Result<(), WindowsError> {
        let size = backend
            .item
            .Size()
            .map_err(|error| win_error("capture.target_unavailable", error))?;
        backend
            .frame_pool
            .Recreate(
                &backend.device,
                DirectXPixelFormat::B8G8R8A8UIntNormalized,
                1,
                size,
            )
            .map_err(|error| win_error("capture.frame_pool_failed", error))?;
        backend.client_rect = client_rect;
        Ok(())
    }

    pub(super) fn next_bgra(
        backend: &mut WgcState,
        deadline: Instant,
    ) -> Result<CapturedBgraFrame, WindowsError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(WindowsError::new(
                    "capture.deadline",
                    "no WGC frame arrived before deadline",
                ));
            }
            backend
                .frame_arrived
                .recv_timeout(remaining)
                .map_err(|error| match error {
                    std::sync::mpsc::RecvTimeoutError::Timeout => WindowsError::new(
                        "capture.deadline",
                        "no WGC frame arrived before deadline",
                    ),
                    std::sync::mpsc::RecvTimeoutError::Disconnected => WindowsError::new(
                        "capture.worker_failed",
                        "WGC frame arrival handler disconnected",
                    ),
                })?;
            match backend.frame_pool.TryGetNextFrame() {
                Ok(frame) => {
                    let result = copy_client_frame(backend, &frame);
                    let _ = frame.Close();
                    return result;
                }
                Err(_) if Instant::now() < deadline => continue,
                Err(error) => {
                    return Err(WindowsError::new(
                        "capture.deadline",
                        format!("no WGC frame before deadline: {error}"),
                    ));
                }
            }
        }
    }

    fn create_device() -> Result<(ID3D11Device, ID3D11DeviceContext, IDirect3DDevice), WindowsError>
    {
        let mut d3d_device = None;
        let mut d3d_context = None;
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut d3d_device),
                None,
                Some(&mut d3d_context),
            )
            .map_err(|error| win_error("capture.d3d_device_failed", error))?;
        }
        let d3d_device = d3d_device.ok_or_else(|| {
            WindowsError::new("capture.d3d_device_failed", "D3D11 device is null")
        })?;
        let d3d_context = d3d_context.ok_or_else(|| {
            WindowsError::new("capture.d3d_device_failed", "D3D11 context is null")
        })?;
        let dxgi: IDXGIDevice = d3d_device
            .cast()
            .map_err(|error| win_error("capture.d3d_device_failed", error))?;
        let inspectable = unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi) }
            .map_err(|error| win_error("capture.d3d_device_failed", error))?;
        let device = inspectable
            .cast::<IDirect3DDevice>()
            .map_err(|error| win_error("capture.d3d_device_failed", error))?;
        Ok((d3d_device, d3d_context, device))
    }

    fn copy_client_frame(
        backend: &WgcState,
        frame: &windows::Graphics::Capture::Direct3D11CaptureFrame,
    ) -> Result<CapturedBgraFrame, WindowsError> {
        let surface = frame
            .Surface()
            .map_err(|error| win_error("capture.frame_invalid", error))?;
        let access = surface
            .cast::<IDirect3DDxgiInterfaceAccess>()
            .map_err(|error| win_error("capture.frame_invalid", error))?;
        let source = unsafe { access.GetInterface::<ID3D11Texture2D>() }
            .map_err(|error| win_error("capture.frame_invalid", error))?;
        copy_texture_client(backend, &source)
    }

    fn copy_texture_client(
        backend: &WgcState,
        source: &ID3D11Texture2D,
    ) -> Result<CapturedBgraFrame, WindowsError> {
        let hwnd = HWND(backend.hwnd as *mut c_void);
        let capture_bounds = capture_bounds(hwnd)?;
        let mut source_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { source.GetDesc(&mut source_desc) };
        let (x, y, width, height) = client_crop_box(
            capture_bounds,
            backend.client_rect,
            source_desc.Width,
            source_desc.Height,
        )?;
        let frame_len = super::checked_bgra_len(width, height)?;
        let mut staging_desc = source_desc;
        staging_desc.Width = width;
        staging_desc.Height = height;
        staging_desc.BindFlags = 0;
        staging_desc.MiscFlags = 0;
        staging_desc.Usage = D3D11_USAGE_STAGING;
        staging_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        let mut staging = None;
        unsafe {
            backend
                .d3d_device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
                .map_err(|error| win_error("capture.staging_failed", error))?;
        }
        let staging = staging.ok_or_else(|| {
            WindowsError::new("capture.staging_failed", "staging texture is null")
        })?;
        let region = D3D11_BOX {
            left: x,
            top: y,
            right: x + width,
            bottom: y + height,
            front: 0,
            back: 1,
        };
        let source_resource: ID3D11Resource = source
            .cast()
            .map_err(|error| win_error("capture.frame_invalid", error))?;
        let staging_resource: ID3D11Resource = staging
            .cast()
            .map_err(|error| win_error("capture.staging_failed", error))?;
        unsafe {
            backend.d3d_context.CopySubresourceRegion(
                &staging_resource,
                0,
                0,
                0,
                0,
                &source_resource,
                0,
                Some(&region),
            );
        }
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe {
            backend
                .d3d_context
                .Map(&staging_resource, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|error| win_error("capture.map_failed", error))?;
        }
        let row_bytes = width as usize * 4;
        if mapped.pData.is_null() || (mapped.RowPitch as usize) < row_bytes {
            unsafe { backend.d3d_context.Unmap(&staging_resource, 0) };
            return Err(WindowsError::new(
                "capture.map_failed",
                "mapped texture has a null pointer or short row pitch",
            ));
        }
        let mut pixels = vec![0_u8; frame_len];
        for row in 0..height as usize {
            let source_row = unsafe {
                std::slice::from_raw_parts(
                    (mapped.pData as *const u8).add(row * mapped.RowPitch as usize),
                    row_bytes,
                )
            };
            pixels[row * row_bytes..(row + 1) * row_bytes].copy_from_slice(source_row);
        }
        unsafe { backend.d3d_context.Unmap(&staging_resource, 0) };
        Ok(CapturedBgraFrame {
            pixels,
            width,
            height,
            captured_at: Instant::now(),
        })
    }

    fn capture_bounds(hwnd: HWND) -> Result<Rect, WindowsError> {
        let mut bounds = RECT::default();
        unsafe {
            DwmGetWindowAttribute(
                hwnd,
                DWMWA_EXTENDED_FRAME_BOUNDS,
                (&mut bounds as *mut RECT).cast(),
                std::mem::size_of::<RECT>() as u32,
            )
        }
        .map_err(|error| win_error("capture.target_unavailable", error))?;
        let width = u32::try_from(bounds.right - bounds.left).map_err(|_| {
            WindowsError::new("capture.target_unavailable", "negative DWM frame width")
        })?;
        let height = u32::try_from(bounds.bottom - bounds.top).map_err(|_| {
            WindowsError::new("capture.target_unavailable", "negative DWM frame height")
        })?;
        Rect::new(bounds.left, bounds.top, width, height)
            .map_err(|error| WindowsError::new("capture.target_unavailable", error.to_string()))
    }

    fn win_error(code: &'static str, error: windows::core::Error) -> WindowsError {
        WindowsError::new(code, error.to_string())
    }

    pub(super) fn close(state: &WgcState) {
        let _ = state
            .frame_pool
            .RemoveFrameArrived(state.frame_arrived_token);
        let _ = state.session.Close();
        let _ = state.frame_pool.Close();
    }
}
