use std::fmt;

use prost::Message;

use crate::local_v1::{LocalControlEnvelope, LocalControlRequest};

pub const LOCAL_CONTROL_PROTOCOL_MAJOR: u32 = 2;
pub const LOCAL_CONTROL_PROTOCOL_MINOR: u32 = 0;
pub const LOCAL_AGENT_PIPE_NAME: &str = r"\\.\pipe\FairyPam.Agent.Control.v1";
const MAX_LOCAL_CONTROL_BYTES: usize = 1024 * 1024;
const MAX_LOCAL_DEADLINE_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalControlProtocolError(&'static str);

impl LocalControlProtocolError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for LocalControlProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for LocalControlProtocolError {}

pub fn encode_local_control_envelope(
    envelope: &LocalControlEnvelope,
) -> Result<Vec<u8>, LocalControlProtocolError> {
    let payload = envelope.encode_to_vec();
    if payload.len() > MAX_LOCAL_CONTROL_BYTES {
        return Err(LocalControlProtocolError("local.message_too_large"));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| LocalControlProtocolError("local.message_too_large"))?;
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&length.to_le_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

pub fn decode_local_control_envelope(
    framed: &[u8],
) -> Result<LocalControlEnvelope, LocalControlProtocolError> {
    let length = framed
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(LocalControlProtocolError("local.frame_invalid"))? as usize;
    if length > MAX_LOCAL_CONTROL_BYTES || framed.len() != length + 4 {
        return Err(LocalControlProtocolError("local.frame_invalid"));
    }
    let envelope = LocalControlEnvelope::decode(&framed[4..])
        .map_err(|_| LocalControlProtocolError("local.protobuf_invalid"))?;
    if envelope.protocol_major != LOCAL_CONTROL_PROTOCOL_MAJOR
        || envelope.protocol_minor > LOCAL_CONTROL_PROTOCOL_MINOR
        || envelope.payload.is_none()
    {
        return Err(LocalControlProtocolError("local.protocol_incompatible"));
    }
    Ok(envelope)
}

pub fn validate_local_control_request(
    request: &LocalControlRequest,
    now_unix_ms: i64,
) -> Result<(), LocalControlProtocolError> {
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err(LocalControlProtocolError("local.request_id_invalid"));
    }
    if request.deadline_unix_ms <= now_unix_ms {
        return Err(LocalControlProtocolError("local.deadline_expired"));
    }
    if request.deadline_unix_ms.saturating_sub(now_unix_ms) > MAX_LOCAL_DEADLINE_MS {
        return Err(LocalControlProtocolError("local.deadline_invalid"));
    }
    if request.command.is_none() {
        return Err(LocalControlProtocolError("local.command_missing"));
    }
    Ok(())
}

#[cfg(windows)]
mod windows_pipe {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::time::{Duration, Instant};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        LocalFree, ERROR_PIPE_CONNECTED, HLOCAL, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PeekNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    use crate::local_v1::LocalControlEnvelope;

    use super::{
        decode_local_control_envelope, encode_local_control_envelope, MAX_LOCAL_CONTROL_BYTES,
    };

    pub struct SecureLocalPipeListener {
        name: String,
        pending: Option<File>,
    }

    impl SecureLocalPipeListener {
        pub fn bind(name: &str) -> io::Result<Self> {
            Ok(Self {
                name: name.to_owned(),
                pending: Some(create_pipe(name)?),
            })
        }

        pub fn accept(&mut self) -> io::Result<File> {
            let pipe = match self.pending.take() {
                Some(pipe) => pipe,
                None => create_pipe(&self.name)?,
            };
            let handle = windows::Win32::Foundation::HANDLE(
                std::os::windows::io::AsRawHandle::as_raw_handle(&pipe),
            );
            if let Err(error) = unsafe { ConnectNamedPipe(handle, None) } {
                if error.code() != windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                    return Err(io::Error::other(error));
                }
            }
            Ok(pipe)
        }
    }

    pub fn connect_local_agent_pipe(name: &str, timeout: Duration) -> io::Result<File> {
        let deadline = Instant::now() + timeout;
        loop {
            match OpenOptions::new().read(true).write(true).open(name) {
                Ok(pipe) => return Ok(pipe),
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn read_local_control_frame(
        pipe: &mut File,
        timeout: Duration,
    ) -> io::Result<LocalControlEnvelope> {
        let deadline = Instant::now() + timeout;
        let mut length = [0_u8; 4];
        read_exact_until(pipe, &mut length, deadline)?;
        let length = u32::from_le_bytes(length) as usize;
        if length > MAX_LOCAL_CONTROL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local.message_too_large",
            ));
        }
        let mut framed = vec![0_u8; length + 4];
        framed[..4].copy_from_slice(&(length as u32).to_le_bytes());
        read_exact_until(pipe, &mut framed[4..], deadline)?;
        decode_local_control_envelope(&framed)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.code()))
    }

    pub fn write_local_control_frame(
        pipe: &mut File,
        envelope: &LocalControlEnvelope,
    ) -> io::Result<()> {
        let mut framed = encode_local_control_envelope(envelope)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.code()))?;
        let result = pipe.write_all(&framed).and_then(|_| pipe.flush());
        framed.fill(0);
        result
    }

    fn read_exact_until(pipe: &mut File, output: &mut [u8], deadline: Instant) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;

        let mut offset = 0;
        while offset < output.len() {
            let mut available = 0;
            let handle = windows::Win32::Foundation::HANDLE(pipe.as_raw_handle());
            unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) }
                .map_err(io::Error::other)?;
            if available > 0 {
                let take = (available as usize).min(output.len() - offset);
                let read = pipe.read(&mut output[offset..offset + take])?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "local pipe closed",
                    ));
                }
                offset += read;
            } else if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local pipe deadline expired",
                ));
            } else {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(())
    }

    fn create_pipe(name: &str) -> io::Result<File> {
        let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)");
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(io::Error::other)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let name = wide(name);
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                4,
                64 * 1024,
                64 * 1024,
                0,
                Some(&attributes),
            )
        };
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(windows)]
pub use windows_pipe::{
    connect_local_agent_pipe, read_local_control_frame, write_local_control_frame,
    SecureLocalPipeListener,
};

#[cfg(test)]
mod tests {
    use crate::local_v1::{
        local_control_envelope, local_control_request, GetStatus, LocalControlEnvelope,
        LocalControlRequest,
    };

    use super::*;

    fn request(deadline_unix_ms: i64) -> LocalControlRequest {
        LocalControlRequest {
            request_id: "shell-1".into(),
            deadline_unix_ms,
            command: Some(local_control_request::Command::GetStatus(GetStatus {})),
        }
    }

    #[test]
    fn local_control_proto_round_trips() {
        let envelope = LocalControlEnvelope {
            protocol_major: LOCAL_CONTROL_PROTOCOL_MAJOR,
            protocol_minor: LOCAL_CONTROL_PROTOCOL_MINOR,
            payload: Some(local_control_envelope::Payload::Request(request(2_000))),
        };
        assert_eq!(
            encode_local_control_envelope(&envelope)
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            include_str!("../../../proto/fairypam/local/v1/testdata/local-control-v1.hex").trim()
        );
        assert_eq!(
            decode_local_control_envelope(&encode_local_control_envelope(&envelope).unwrap())
                .unwrap(),
            envelope
        );
    }

    #[test]
    fn local_control_rejects_retired_shell_protocol() {
        let envelope = LocalControlEnvelope {
            protocol_major: 1,
            protocol_minor: 0,
            payload: Some(local_control_envelope::Payload::Request(request(2_000))),
        };
        assert_eq!(
            decode_local_control_envelope(&encode_local_control_envelope(&envelope).unwrap())
                .unwrap_err()
                .code(),
            "local.protocol_incompatible"
        );
    }

    #[test]
    fn retired_emergency_release_wire_command_is_rejected() {
        let mut retired = request(2_000);
        retired.command = None;
        let mut encoded = retired.encode_to_vec();
        encoded.extend_from_slice(&[0x6a, 0]); // Retired field 13, empty message.
        let decoded = LocalControlRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            validate_local_control_request(&decoded, 1_000)
                .unwrap_err()
                .code(),
            "local.command_missing"
        );
    }

    #[test]
    fn local_control_rejects_expired_or_unbounded_requests() {
        assert_eq!(
            validate_local_control_request(&request(1_000), 1_000)
                .unwrap_err()
                .code(),
            "local.deadline_expired"
        );
        assert_eq!(
            validate_local_control_request(&request(61_001), 1_000)
                .unwrap_err()
                .code(),
            "local.deadline_invalid"
        );
    }
}
