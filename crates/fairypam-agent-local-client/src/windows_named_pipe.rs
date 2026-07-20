use std::io;

use fairypam_agent_local_protocol::MAX_FRAME_BYTES;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
};

use crate::{LocalClientError, LocalTransport};

/// The Windows-only client transport. It depends solely on Tokio's Named Pipe
/// APIs and does not pull in the Agent's input, capture or server crate.
pub struct WindowsNamedPipeClientTransport {
    pipe_name: String,
    pipe: Option<NamedPipeClient>,
}

impl WindowsNamedPipeClientTransport {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            pipe: None,
        }
    }

    fn pipe_mut(&mut self) -> Result<&mut NamedPipeClient, LocalClientError> {
        self.pipe
            .as_mut()
            .ok_or_else(LocalClientError::disconnected)
    }
}

impl LocalTransport for WindowsNamedPipeClientTransport {
    async fn connect(&mut self) -> Result<(), LocalClientError> {
        if self.pipe.is_none() {
            self.pipe = Some(
                ClientOptions::new()
                    .open(&self.pipe_name)
                    .map_err(pipe_error)?,
            );
        }
        Ok(())
    }

    async fn send(&mut self, frame: Vec<u8>) -> Result<(), LocalClientError> {
        let pipe = self.pipe_mut()?;
        pipe.write_all(&frame).await.map_err(pipe_error)?;
        pipe.flush().await.map_err(pipe_error)
    }

    async fn receive(&mut self) -> Result<Vec<u8>, LocalClientError> {
        let pipe = self.pipe_mut()?;
        let mut prefix = [0_u8; 4];
        pipe.read_exact(&mut prefix).await.map_err(pipe_error)?;
        let payload_length = u32::from_le_bytes(prefix) as usize;
        if payload_length > MAX_FRAME_BYTES {
            return Err(LocalClientError::protocol_message(
                "local.protocol.frame_too_large",
                "response frame exceeded the local protocol limit",
            ));
        }

        let mut frame = Vec::with_capacity(4 + payload_length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + payload_length, 0);
        pipe.read_exact(&mut frame[4..]).await.map_err(pipe_error)?;
        Ok(frame)
    }

    async fn close(&mut self) {
        self.pipe.take();
    }
}

fn pipe_error(error: io::Error) -> LocalClientError {
    match error.kind() {
        io::ErrorKind::NotFound => LocalClientError::pipe_not_found(),
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof => LocalClientError::disconnected(),
        _ => LocalClientError::transport("local.transport.pipe_io", error.to_string()),
    }
}
