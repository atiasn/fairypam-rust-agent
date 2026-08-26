#[cfg(windows)]
mod windows_impl {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{fence, AtomicU64, Ordering};

    use fairypam_agent_maa::MaaRuntimeError;
    use fairypam_agent_protocol::worker_v1::{FrameEncoding, PixelFormat};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{CreateEventW, SetEvent};

    const MAGIC: [u8; 8] = *b"FPRING1\0";
    const SLOT_COUNT: usize = 2;

    #[repr(C)]
    struct RingHeader {
        magic: [u8; 8],
        schema_version: u32,
        slot_count: u32,
        slot_bytes: u64,
        published_sequence: AtomicU64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FrameHeader {
        schema_version: u32,
        worker_generation: [u8; 64],
        frame_sequence: u64,
        captured_at_unix_us: i64,
        width: u32,
        height: u32,
        stride: u32,
        pixel_format: i32,
        encoding: i32,
        payload_size: u64,
        backend: [u8; 64],
        health_flags: u64,
    }

    pub struct FrameRing {
        mapping: HANDLE,
        event: HANDLE,
        view: *mut u8,
        slot_payload_bytes: usize,
        worker_generation: [u8; 64],
    }

    unsafe impl Send for FrameRing {}

    impl FrameRing {
        pub fn create(
            mapping_name: &str,
            event_name: &str,
            slot_payload_bytes: usize,
            worker_generation: &str,
        ) -> Result<Self, MaaRuntimeError> {
            if slot_payload_bytes == 0 || worker_generation.len() >= 64 {
                return Err(invalid("frame ring configuration is invalid"));
            }
            let slot_bytes = std::mem::size_of::<FrameHeader>()
                .checked_add(slot_payload_bytes)
                .ok_or_else(|| invalid("frame ring size overflow"))?;
            let total = std::mem::size_of::<RingHeader>()
                .checked_add(
                    SLOT_COUNT
                        .checked_mul(slot_bytes)
                        .ok_or_else(|| invalid("frame ring size overflow"))?,
                )
                .ok_or_else(|| invalid("frame ring size overflow"))?;
            let total_u64 = u64::try_from(total).map_err(|_| invalid("frame ring is too large"))?;
            let mapping_name = wide(mapping_name);
            let mapping = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    (total_u64 >> 32) as u32,
                    total_u64 as u32,
                    PCWSTR(mapping_name.as_ptr()),
                )
            }
            .map_err(|error| MaaRuntimeError::new("worker.frame_map_failed", error.to_string()))?;
            let view = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, total) };
            if view.Value.is_null() {
                let _ = unsafe { CloseHandle(mapping) };
                return Err(MaaRuntimeError::new(
                    "worker.frame_map_failed",
                    "MapViewOfFile returned null",
                ));
            }
            let event_name = wide(event_name);
            let event = unsafe { CreateEventW(None, false, false, PCWSTR(event_name.as_ptr())) }
                .map_err(|error| {
                    let _ = unsafe { UnmapViewOfFile(view) };
                    let _ = unsafe { CloseHandle(mapping) };
                    MaaRuntimeError::new("worker.frame_event_failed", error.to_string())
                })?;
            let mut generation = [0; 64];
            generation[..worker_generation.len()].copy_from_slice(worker_generation.as_bytes());
            let ring = Self {
                mapping,
                event,
                view: view.Value.cast(),
                slot_payload_bytes,
                worker_generation: generation,
            };
            unsafe {
                ring.view.cast::<RingHeader>().write(RingHeader {
                    magic: MAGIC,
                    schema_version: 1,
                    slot_count: SLOT_COUNT as u32,
                    slot_bytes: slot_bytes as u64,
                    published_sequence: AtomicU64::new(0),
                });
            }
            Ok(ring)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn publish(
            &mut self,
            frame_sequence: u64,
            captured_at_unix_us: i64,
            width: u32,
            height: u32,
            stride: u32,
            pixel_format: PixelFormat,
            encoding: FrameEncoding,
            backend: &str,
            health_flags: u64,
            payload: &[u8],
        ) -> Result<(), MaaRuntimeError> {
            if frame_sequence == 0 || payload.len() > self.slot_payload_bytes || backend.len() >= 64
            {
                return Err(invalid("frame does not fit the shared ring"));
            }
            let slot_bytes = std::mem::size_of::<FrameHeader>() + self.slot_payload_bytes;
            let index = frame_sequence as usize % SLOT_COUNT;
            let slot = unsafe {
                self.view
                    .add(std::mem::size_of::<RingHeader>() + index * slot_bytes)
            };
            let payload_target = unsafe { slot.add(std::mem::size_of::<FrameHeader>()) };
            unsafe {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), payload_target, payload.len())
            };
            let mut backend_bytes = [0; 64];
            backend_bytes[..backend.len()].copy_from_slice(backend.as_bytes());
            unsafe {
                slot.cast::<FrameHeader>().write(FrameHeader {
                    schema_version: 1,
                    worker_generation: self.worker_generation,
                    frame_sequence,
                    captured_at_unix_us,
                    width,
                    height,
                    stride,
                    pixel_format: pixel_format as i32,
                    encoding: encoding as i32,
                    payload_size: payload.len() as u64,
                    backend: backend_bytes,
                    health_flags,
                });
            }
            fence(Ordering::Release);
            unsafe {
                (*self.view.cast::<RingHeader>())
                    .published_sequence
                    .store(frame_sequence, Ordering::Release);
            }
            unsafe { SetEvent(self.event) }.map_err(|error| {
                MaaRuntimeError::new("worker.frame_event_failed", error.to_string())
            })
        }
    }

    impl Drop for FrameRing {
        fn drop(&mut self) {
            let _ = unsafe {
                UnmapViewOfFile(windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.view.cast::<c_void>(),
                })
            };
            let _ = unsafe { CloseHandle(self.event) };
            let _ = unsafe { CloseHandle(self.mapping) };
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    fn invalid(message: &str) -> MaaRuntimeError {
        MaaRuntimeError::new("worker.frame_invalid", message)
    }
}

#[cfg(windows)]
pub use windows_impl::FrameRing;
