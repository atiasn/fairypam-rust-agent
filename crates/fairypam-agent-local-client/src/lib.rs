#[cfg(any(windows, test))]
use std::collections::HashMap;
use std::io;
#[cfg(any(windows, test))]
use std::sync::Arc;
#[cfg(any(windows, test))]
use std::sync::Mutex;
use std::time::Duration;
#[cfg(any(windows, test))]
use std::time::Instant;

#[cfg(any(windows, test))]
use fairypam_agent_local_protocol::{
    decode_request, decode_response, encode_request, encode_response, new_request_id, random_nonce,
    LocalResult, ReplayGuard, MAX_MESSAGE_BYTES, MAX_NONCE_ENTRIES, MAX_RESPONSE_BYTES,
    PROTOCOL_MAJOR, PROTOCOL_MINOR, REPLAY_WINDOW,
};
use fairypam_agent_local_protocol::{
    LocalCommand, LocalErrorCode, LocalPayload, LocalRequest, LocalResponse, ProtocolError,
};
use thiserror::Error;
#[cfg(any(windows, test))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{PipeFlavor, PipeIdentity};

#[cfg(windows)]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(windows, test))]
const MAX_CACHED_RESPONSES: usize = 1_024;
#[cfg(any(windows, test))]
// ponytail: two slots match the client's two-attempt retry; widen only with that contract.
const RELEASE_ALL_CACHE_RESERVE: usize = 2;
#[cfg(any(windows, test))]
const SERVER_IDENTITY_REJECTION: &str = "server_identity_rejected";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerIdentity {
    pub process_id: u32,
    pub user_sid_hash: String,
    pub logon_sid_hash: String,
    pub session_id: u32,
    pub integrity: ClientIntegrity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIntegrity {
    Low,
    Medium,
    High,
    System,
    Unknown,
}

pub trait LocalRequestHandler: Send + Sync + 'static {
    fn server_version(&self) -> &str;

    fn handle(&self, caller: &CallerIdentity, request: &LocalRequest) -> LocalResponse;

    fn client_disconnected(&self, _caller: &CallerIdentity) {}
}

#[derive(Clone)]
pub struct LocalClient {
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    client_name: String,
    #[cfg(windows)]
    client_version: String,
    #[cfg(windows)]
    timeout: Duration,
    #[cfg(windows)]
    expected_server_process_id: Option<u32>,
}

#[cfg(windows)]
pub struct LocalConnection {
    pipe: tokio::net::windows::named_pipe::NamedPipeClient,
    timeout: Duration,
}

#[cfg(windows)]
impl LocalConnection {
    pub async fn request(
        &mut self,
        command: LocalCommand,
        cancellation: CancellationToken,
    ) -> Result<LocalPayload, LocalClientError> {
        let request = LocalRequest::new(
            new_request_id().map_err(LocalClientError::from)?,
            random_nonce().map_err(LocalClientError::from)?,
            command,
        );
        tokio::select! {
            _ = cancellation.cancelled() => Err(LocalClientError::Cancelled),
            result = tokio::time::timeout(self.timeout, send_request(&mut self.pipe, &request)) => {
                result.map_err(|_| LocalClientError::Timeout)?
            }
        }
    }
}

impl LocalClient {
    #[cfg(windows)]
    pub fn production(client_name: impl Into<String>) -> Result<Self, LocalClientError> {
        Self::for_identity(PipeIdentity::current(PipeFlavor::Production)?, client_name, None)
    }

    #[cfg(all(windows, feature = "dev-automation"))]
    pub fn development(client_name: impl Into<String>) -> Result<Self, LocalClientError> {
        Self::for_identity(PipeIdentity::current(PipeFlavor::Development)?, client_name, None)
    }

    #[cfg(all(windows, feature = "dev-automation"))]
    pub fn production_for_test_process(
        process_id: u32,
        client_name: impl Into<String>,
    ) -> Result<Self, LocalClientError> {
        // ponytail: this test-only route changes pipe selection, never server authorization.
        Self::for_identity(
            PipeIdentity::for_process_id(process_id, PipeFlavor::Production)?,
            client_name,
            Some(process_id),
        )
    }

    #[cfg(windows)]
    fn for_identity(
        identity: PipeIdentity,
        client_name: impl Into<String>,
        expected_server_process_id: Option<u32>,
    ) -> Result<Self, LocalClientError> {
        Ok(Self {
            pipe_name: identity.pipe_name().to_owned(),
            client_name: client_name.into(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            timeout: DEFAULT_TIMEOUT,
            expected_server_process_id,
        })
    }

    #[cfg(not(windows))]
    pub fn production(_client_name: impl Into<String>) -> Result<Self, LocalClientError> {
        Err(LocalClientError::UnsupportedPlatform)
    }

    #[cfg(all(not(windows), feature = "dev-automation"))]
    pub fn development(_client_name: impl Into<String>) -> Result<Self, LocalClientError> {
        Err(LocalClientError::UnsupportedPlatform)
    }

    pub fn with_timeout(self, timeout: Duration) -> Result<Self, LocalClientError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(LocalClientError::Protocol(
                "timeout must be between 1 ms and 30 seconds".into(),
            ));
        }
        #[cfg(windows)]
        {
            let mut client = self;
            client.timeout = timeout;
            Ok(client)
        }
        #[cfg(not(windows))]
        Ok(self)
    }

    pub async fn request(
        &self,
        command: LocalCommand,
        cancellation: CancellationToken,
    ) -> Result<LocalPayload, LocalClientError> {
        #[cfg(windows)]
        {
            let request_id = new_request_id().map_err(LocalClientError::from)?;
            let operation = async {
                let mut last_error = None;
                for _attempt in 0..2 {
                    let request = LocalRequest::new(
                        request_id.clone(),
                        random_nonce().map_err(LocalClientError::from)?,
                        command.clone(),
                    );
                    match windows::open_client(
                        &self.pipe_name,
                        &cancellation,
                        self.expected_server_process_id,
                    )
                    .await
                    {
                        Ok(mut pipe) => {
                            match exchange(
                                &mut pipe,
                                &self.client_name,
                                &self.client_version,
                                &request,
                            )
                            .await
                            {
                                Ok(payload) => return Ok(payload),
                                Err(error) if error.retryable_transport() => {
                                    last_error = Some(error)
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) if error.retryable_transport() => last_error = Some(error),
                        Err(error) => return Err(error),
                    }
                }
                Err(last_error.unwrap_or(LocalClientError::Unavailable))
            };
            tokio::select! {
                _ = cancellation.cancelled() => Err(LocalClientError::Cancelled),
                result = tokio::time::timeout(self.timeout, operation) => {
                    result.map_err(|_| LocalClientError::Timeout)?
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (command, cancellation);
            Err(LocalClientError::UnsupportedPlatform)
        }
    }

    #[cfg(windows)]
    pub async fn connect(
        &self,
        cancellation: CancellationToken,
    ) -> Result<LocalConnection, LocalClientError> {
        let operation = async {
            let mut pipe = windows::open_client(
                &self.pipe_name,
                &cancellation,
                self.expected_server_process_id,
            )
            .await?;
            handshake(&mut pipe, &self.client_name, &self.client_version).await?;
            Ok(LocalConnection {
                pipe,
                timeout: self.timeout,
            })
        };
        tokio::select! {
            _ = cancellation.cancelled() => Err(LocalClientError::Cancelled),
            result = tokio::time::timeout(self.timeout, operation) => {
                result.map_err(|_| LocalClientError::Timeout)?
            }
        }
    }
}

#[cfg(any(windows, test))]
async fn exchange<S>(
    stream: &mut S,
    client_name: &str,
    client_version: &str,
    request: &LocalRequest,
) -> Result<LocalPayload, LocalClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(stream, client_name, client_version).await?;
    send_request(stream, request).await
}

#[cfg(any(windows, test))]
async fn handshake<S>(
    stream: &mut S,
    client_name: &str,
    client_version: &str,
) -> Result<(), LocalClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = LocalRequest::new(
        new_request_id().map_err(LocalClientError::from)?,
        random_nonce().map_err(LocalClientError::from)?,
        LocalCommand::Hello {
            client_name: client_name.to_owned(),
            client_version: client_version.to_owned(),
        },
    );
    write_request(stream, &hello).await?;
    let hello_response = read_response(stream).await?;
    match hello_response.result {
        LocalResult::Ok {
            payload:
                LocalPayload::Hello {
                    protocol_major,
                    protocol_minor,
                    ..
                },
        } if protocol_major == PROTOCOL_MAJOR && protocol_minor == PROTOCOL_MINOR => {}
        LocalResult::Error {
            code,
            message,
            retryable,
        } => return Err(map_remote(code, message, retryable)),
        _ => {
            return Err(LocalClientError::Protocol(
                "invalid server handshake".into(),
            ))
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
async fn send_request<S>(
    stream: &mut S,
    request: &LocalRequest,
) -> Result<LocalPayload, LocalClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_request(stream, request).await?;
    let response = read_response(stream).await?;
    if response.request_id != request.request_id {
        return Err(LocalClientError::Protocol(
            "local response request id mismatch".into(),
        ));
    }
    match response.result {
        LocalResult::Ok { payload } => Ok(payload),
        LocalResult::Error {
            code,
            message,
            retryable,
        } => Err(map_remote(code, message, retryable)),
    }
}

#[cfg(any(windows, test))]
fn map_remote(code: LocalErrorCode, message: String, retryable: bool) -> LocalClientError {
    match code {
        LocalErrorCode::PermissionDenied if message == SERVER_IDENTITY_REJECTION => {
            LocalClientError::ServerIdentityRejected
        }
        LocalErrorCode::PermissionDenied => LocalClientError::PermissionDenied,
        LocalErrorCode::AgentUnavailable => LocalClientError::Unavailable,
        LocalErrorCode::ProtocolVersionMismatch | LocalErrorCode::ProtocolViolation => {
            LocalClientError::Protocol(message)
        }
        _ => LocalClientError::Remote {
            code,
            message,
            retryable,
        },
    }
}

#[derive(Debug, Error)]
pub enum LocalClientError {
    #[error("local Agent is unavailable")]
    Unavailable,
    #[error("local Agent rejected the caller identity")]
    PermissionDenied,
    #[error("local Agent rejected the connected caller identity")]
    ServerIdentityRejected,
    #[error("target process identity is unavailable")]
    TargetProcessUnavailable,
    #[error("local Agent request timed out")]
    Timeout,
    #[error("local Agent request was cancelled")]
    Cancelled,
    #[error("local Agent protocol error: {0}")]
    Protocol(String),
    #[error("local Agent capability is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local Agent returned {code:?}: {message}")]
    Remote {
        code: LocalErrorCode,
        message: String,
        retryable: bool,
    },
    #[error("local Agent I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl LocalClientError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Unavailable => "agent_unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::ServerIdentityRejected => "server_identity_rejected",
            Self::TargetProcessUnavailable => "target_process_unavailable",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Protocol(_) => "protocol_error",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Remote { .. } => "agent_error",
            Self::Io(_) => "io_error",
        }
    }

    #[cfg(windows)]
    fn retryable_transport(&self) -> bool {
        matches!(self, Self::Unavailable | Self::Io(_))
    }
}

impl From<ProtocolError> for LocalClientError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error.to_string())
    }
}

#[cfg(any(windows, test))]
async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &LocalRequest,
) -> Result<(), LocalClientError> {
    write_frame(stream, &encode_request(request)?).await?;
    Ok(())
}

#[cfg(any(windows, test))]
async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<LocalResponse, LocalClientError> {
    let frame = read_frame(stream, MAX_RESPONSE_BYTES)
        .await?
        .ok_or(LocalClientError::Unavailable)?;
    Ok(decode_response(&frame)?)
}

#[cfg(any(windows, test))]
async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame is too large"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[cfg(any(windows, test))]
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local protocol frame exceeds its size limit",
        ));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct ServerState {
    replay: ReplayGuard,
    responses: HashMap<String, CachedResponse>,
}

#[cfg(any(windows, test))]
struct CachedResponse {
    accepted_at: Instant,
    state: CachedResponseState,
}

#[cfg(any(windows, test))]
enum CachedResponseState {
    InFlight,
    Complete(LocalResponse),
}

#[cfg(any(windows, test))]
enum DispatchPlan {
    Respond(LocalResponse),
    Handle { cacheable: bool },
}

#[cfg(any(windows, test))]
impl ServerState {
    fn prepare(&mut self, request: &LocalRequest, now: Instant) -> DispatchPlan {
        let release_all = matches!(request.command, LocalCommand::ReleaseAll {});
        let replay_capacity = MAX_NONCE_ENTRIES
            - if release_all {
                0
            } else {
                RELEASE_ALL_CACHE_RESERVE
            };
        if let Err(error) = self
            .replay
            .accept_with_capacity(&request.nonce, now, replay_capacity)
        {
            return DispatchPlan::Respond(LocalResponse::error(request.request_id.clone(), error));
        }
        // ponytail: keep uncertain in-flight mutations reserved; process restart is the retry boundary.
        self.responses.retain(|_, response| {
            matches!(response.state, CachedResponseState::InFlight)
                || now.saturating_duration_since(response.accepted_at) < REPLAY_WINDOW
        });
        let cacheable = request.command.mutates_state();
        if cacheable {
            if let Some(response) = self.responses.get(&request.request_id) {
                return DispatchPlan::Respond(match &response.state {
                    CachedResponseState::Complete(response) => response.clone(),
                    CachedResponseState::InFlight => LocalResponse::error(
                        request.request_id.clone(),
                        ProtocolError::new(
                            LocalErrorCode::OperationFailed,
                            "request is already in progress",
                        )
                        .retryable(true),
                    ),
                });
            }
            let response_capacity = MAX_CACHED_RESPONSES
                - if release_all {
                    0
                } else {
                    RELEASE_ALL_CACHE_RESERVE
                };
            if self.responses.len() >= response_capacity {
                return DispatchPlan::Respond(LocalResponse::error(
                    request.request_id.clone(),
                    ProtocolError::new(
                        LocalErrorCode::OperationFailed,
                        "idempotency cache is at capacity",
                    )
                    .retryable(true),
                ));
            }
            self.responses.insert(
                request.request_id.clone(),
                CachedResponse {
                    accepted_at: now,
                    state: CachedResponseState::InFlight,
                },
            );
        }
        DispatchPlan::Handle { cacheable }
    }

    fn complete(&mut self, request_id: &str, response: LocalResponse) {
        if let Some(cached) = self.responses.get_mut(request_id) {
            cached.state = CachedResponseState::Complete(response);
        }
    }
}

#[cfg(any(windows, test))]
fn dispatch_request(
    state: &Mutex<ServerState>,
    handler: &dyn LocalRequestHandler,
    caller: &CallerIdentity,
    request: &LocalRequest,
    now: Instant,
) -> Result<LocalResponse, LocalClientError> {
    let plan = state
        .lock()
        .map_err(|_| LocalClientError::Protocol("local server state is poisoned".into()))?
        .prepare(request, now);
    match plan {
        DispatchPlan::Respond(response) => Ok(response),
        DispatchPlan::Handle { cacheable } => {
            let response = handler.handle(caller, request);
            if cacheable {
                state
                    .lock()
                    .map_err(|_| {
                        LocalClientError::Protocol("local server state is poisoned".into())
                    })?
                    .complete(&request.request_id, response.clone());
            }
            Ok(response)
        }
    }
}

#[cfg(windows)]
pub async fn serve(
    identity: PipeIdentity,
    handler: Arc<dyn LocalRequestHandler>,
    cancellation: CancellationToken,
) -> Result<(), LocalClientError> {
    let state = Arc::new(Mutex::new(ServerState::default()));
    let mut first = true;
    loop {
        let server = windows::create_server(&identity, first)?;
        first = false;
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            connected = server.connect() => connected?,
        }
        let caller = match windows::validate_client(&server, &identity) {
            Ok(caller) => caller,
            Err(error) => {
                tracing_permission_denied(&error);
                tokio::spawn(reject_identity(server));
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(server, &caller, handler.as_ref(), &state).await {
                let _ = error;
            }
            handler.client_disconnected(&caller);
        });
    }
}

#[cfg(windows)]
async fn reject_identity<S>(mut stream: S) -> Result<(), LocalClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(hello) = read_request_or_error(&mut stream).await? else {
        return Ok(());
    };
    write_response(
        &mut stream,
        &LocalResponse::error(
            hello.request_id,
            ProtocolError::new(
                LocalErrorCode::PermissionDenied,
                SERVER_IDENTITY_REJECTION,
            ),
        ),
    )
    .await
}

#[cfg(windows)]
fn tracing_permission_denied(_error: &LocalClientError) {
    // The Agent integration emits the request audit; rejected identities never reach it.
}

#[cfg(any(windows, test))]
async fn serve_connection<S>(
    mut stream: S,
    caller: &CallerIdentity,
    handler: &dyn LocalRequestHandler,
    state: &Mutex<ServerState>,
) -> Result<(), LocalClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(hello) = read_request_or_error(&mut stream).await? else {
        return Ok(());
    };
    if !matches!(hello.command, LocalCommand::Hello { .. }) {
        write_response(
            &mut stream,
            &LocalResponse::error(
                hello.request_id,
                ProtocolError::new(
                    LocalErrorCode::ProtocolViolation,
                    "hello must be the first local request",
                ),
            ),
        )
        .await?;
        return Ok(());
    }
    write_response(
        &mut stream,
        &LocalResponse::ok(
            hello.request_id,
            LocalPayload::Hello {
                server_version: handler.server_version().to_owned(),
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
            },
        ),
    )
    .await?;

    while let Some(request) = read_request_or_error(&mut stream).await? {
        if matches!(request.command, LocalCommand::Hello { .. }) {
            write_response(
                &mut stream,
                &LocalResponse::error(
                    request.request_id,
                    ProtocolError::new(
                        LocalErrorCode::ProtocolViolation,
                        "hello may only be sent once per connection",
                    ),
                ),
            )
            .await?;
            continue;
        }
        let response = dispatch_request(state, handler, caller, &request, Instant::now())?;
        write_response(&mut stream, &response).await?;
    }
    Ok(())
}

#[cfg(any(windows, test))]
async fn read_request_or_error<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<Option<LocalRequest>, LocalClientError> {
    let Some(frame) = read_frame(stream, MAX_MESSAGE_BYTES).await? else {
        return Ok(None);
    };
    match decode_request(&frame) {
        Ok(request) => Ok(Some(request)),
        Err(error) => {
            let request_id = error.request_id.clone().unwrap_or_else(|| "invalid".into());
            write_response(stream, &LocalResponse::error(request_id, error)).await?;
            Ok(None)
        }
    }
}

#[cfg(any(windows, test))]
async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &LocalResponse,
) -> Result<(), LocalClientError> {
    write_frame(stream, &encode_response(response)?).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    struct Handler {
        calls: AtomicUsize,
    }

    impl LocalRequestHandler for Handler {
        fn server_version(&self) -> &str {
            "test"
        }

        fn handle(&self, _caller: &CallerIdentity, request: &LocalRequest) -> LocalResponse {
            self.calls.fetch_add(1, Ordering::Relaxed);
            LocalResponse::ok(
                request.request_id.clone(),
                LocalPayload::Released {
                    holds: 0,
                    state: "safe".into(),
                },
            )
        }
    }

    struct BlockingHandler {
        blocked_command: &'static str,
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        calls: AtomicUsize,
    }

    impl LocalRequestHandler for BlockingHandler {
        fn server_version(&self) -> &str {
            "test"
        }

        fn handle(&self, _caller: &CallerIdentity, request: &LocalRequest) -> LocalResponse {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if request.command.name() == self.blocked_command {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
            LocalResponse::ok(
                request.request_id.clone(),
                LocalPayload::Released {
                    holds: 0,
                    state: "safe".into(),
                },
            )
        }
    }

    fn caller() -> CallerIdentity {
        CallerIdentity {
            process_id: 42,
            user_sid_hash: "user".into(),
            logon_sid_hash: "logon".into(),
            session_id: 1,
            integrity: ClientIntegrity::Medium,
        }
    }

    #[tokio::test]
    async fn client_and_server_share_handshake_and_error_semantics() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let handler = Arc::new(Handler {
            calls: AtomicUsize::new(0),
        });
        let server_handler = Arc::clone(&handler);
        let task = tokio::spawn(async move {
            serve_connection(
                server,
                &caller(),
                server_handler.as_ref(),
                &Mutex::new(ServerState::default()),
            )
            .await
            .unwrap();
        });
        let request = LocalRequest::new(
            "req-0123456789abcdef".into(),
            "01".repeat(32),
            LocalCommand::ReleaseAll {},
        );
        let payload = exchange(&mut client, "agentctl", "test", &request)
            .await
            .unwrap();
        assert!(matches!(payload, LocalPayload::Released { .. }));
        drop(client);
        task.await.unwrap();
        assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn hello_flood_does_not_consume_release_all_replay_capacity() {
        let handler = Arc::new(Handler {
            calls: AtomicUsize::new(0),
        });
        let state = Arc::new(Mutex::new(ServerState::default()));

        for index in 0..=MAX_NONCE_ENTRIES {
            let (mut client, server) = tokio::io::duplex(16 * 1024);
            let server_handler = Arc::clone(&handler);
            let server_state = Arc::clone(&state);
            let task = tokio::spawn(async move {
                serve_connection(
                    server,
                    &caller(),
                    server_handler.as_ref(),
                    server_state.as_ref(),
                )
                .await
                .unwrap();
            });
            write_request(
                &mut client,
                &LocalRequest::new(
                    format!("req-hello-{index:016x}"),
                    format!("{index:064x}"),
                    LocalCommand::Hello {
                        client_name: "agentctl".into(),
                        client_version: "test".into(),
                    },
                ),
            )
            .await
            .unwrap();
            assert!(matches!(
                read_response(&mut client).await.unwrap().result,
                LocalResult::Ok {
                    payload: LocalPayload::Hello { .. }
                }
            ));
            drop(client);
            task.await.unwrap();
        }

        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let server_handler = Arc::clone(&handler);
        let server_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            serve_connection(
                server,
                &caller(),
                server_handler.as_ref(),
                server_state.as_ref(),
            )
            .await
            .unwrap();
        });
        write_request(
            &mut client,
            &LocalRequest::new(
                "req-hello-release".into(),
                format!("{:064x}", MAX_NONCE_ENTRIES + 1),
                LocalCommand::Hello {
                    client_name: "agentctl".into(),
                    client_version: "test".into(),
                },
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            read_response(&mut client).await.unwrap().result,
            LocalResult::Ok {
                payload: LocalPayload::Hello { .. }
            }
        ));
        write_request(
            &mut client,
            &LocalRequest::new(
                "req-release-after-hello".into(),
                format!("{:064x}", 0),
                LocalCommand::ReleaseAll {},
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            read_response(&mut client).await.unwrap().result,
            LocalResult::Ok {
                payload: LocalPayload::Released { .. }
            }
        ));
        drop(client);
        task.await.unwrap();
        assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn idempotency_cache_returns_one_mutation_for_reconnect_request_id() {
        let handler = Handler {
            calls: AtomicUsize::new(0),
        };
        let state = Mutex::new(ServerState::default());
        let first = LocalRequest::new(
            "req-0123456789abcdef".into(),
            "01".repeat(32),
            LocalCommand::ReleaseAll {},
        );
        let retry = LocalRequest {
            nonce: "02".repeat(32),
            ..first.clone()
        };
        let now = Instant::now();
        let first_response = dispatch_request(&state, &handler, &caller(), &first, now).unwrap();
        assert!(matches!(
            dispatch_request(&state, &handler, &caller(), &first, now)
                .unwrap()
                .result,
            LocalResult::Error {
                code: LocalErrorCode::ReplayDetected,
                retryable: false,
                ..
            }
        ));
        assert_eq!(
            first_response,
            dispatch_request(&state, &handler, &caller(), &retry, now).unwrap()
        );
        assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn read_only_responses_do_not_fill_the_idempotency_cache() {
        let handler = Handler {
            calls: AtomicUsize::new(0),
        };
        let state = Mutex::new(ServerState::default());
        let request = LocalRequest::new(
            "req-0123456789abcdef".into(),
            "01".repeat(32),
            LocalCommand::Status {},
        );
        dispatch_request(&state, &handler, &caller(), &request, Instant::now()).unwrap();
        assert!(state.lock().unwrap().responses.is_empty());
    }

    #[test]
    fn blocked_handler_does_not_delay_independent_release_all() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (unblock_tx, unblock_rx) = mpsc::sync_channel(1);
        let handler = Arc::new(BlockingHandler {
            blocked_command: "capture_preview",
            entered: entered_tx,
            release: Mutex::new(unblock_rx),
            calls: AtomicUsize::new(0),
        });
        let state = Arc::new(Mutex::new(ServerState::default()));
        let slow_request = LocalRequest::new(
            "req-slow-0123456789".into(),
            "03".repeat(32),
            LocalCommand::CapturePreview { quality: 75 },
        );
        let release_request = LocalRequest::new(
            "req-release-0123456".into(),
            "04".repeat(32),
            LocalCommand::ReleaseAll {},
        );

        let slow_handler = Arc::clone(&handler);
        let slow_state = Arc::clone(&state);
        let slow = thread::spawn(move || {
            dispatch_request(
                slow_state.as_ref(),
                slow_handler.as_ref(),
                &caller(),
                &slow_request,
                Instant::now(),
            )
            .unwrap()
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let state_was_unlocked = state.try_lock().is_ok();
        let result = state_was_unlocked.then(|| {
            dispatch_request(
                state.as_ref(),
                handler.as_ref(),
                &caller(),
                &release_request,
                Instant::now(),
            )
            .unwrap()
        });

        unblock_tx.send(()).unwrap();
        slow.join().unwrap();
        assert!(state_was_unlocked);
        assert!(matches!(
            result.unwrap().result,
            LocalResult::Ok {
                payload: LocalPayload::Released { .. }
            }
        ));
    }

    #[test]
    fn concurrent_duplicate_request_id_is_retryable_and_not_reexecuted() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (unblock_tx, unblock_rx) = mpsc::sync_channel(1);
        let handler = Arc::new(BlockingHandler {
            blocked_command: "close_target",
            entered: entered_tx,
            release: Mutex::new(unblock_rx),
            calls: AtomicUsize::new(0),
        });
        let state = Arc::new(Mutex::new(ServerState::default()));
        let first = LocalRequest::new(
            "req-duplicate-01234".into(),
            "05".repeat(32),
            LocalCommand::CloseTarget { timeout_ms: 1_000 },
        );
        let duplicate = LocalRequest {
            nonce: "06".repeat(32),
            ..first.clone()
        };

        let first_handler = Arc::clone(&handler);
        let first_state = Arc::clone(&state);
        let first_request = first.clone();
        let running = thread::spawn(move || {
            dispatch_request(
                first_state.as_ref(),
                first_handler.as_ref(),
                &caller(),
                &first_request,
                Instant::now(),
            )
            .unwrap()
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let duplicate_response = dispatch_request(
            state.as_ref(),
            handler.as_ref(),
            &caller(),
            &duplicate,
            Instant::now(),
        )
        .unwrap();
        assert!(matches!(
            duplicate_response.result,
            LocalResult::Error {
                code: LocalErrorCode::OperationFailed,
                retryable: true,
                ..
            }
        ));

        unblock_tx.send(()).unwrap();
        let first_response = running.join().unwrap();
        let replay = dispatch_request(
            state.as_ref(),
            handler.as_ref(),
            &caller(),
            &LocalRequest {
                nonce: "07".repeat(32),
                ..first
            },
            Instant::now(),
        )
        .unwrap();
        assert_eq!(first_response, replay);
        assert_eq!(handler.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn release_all_uses_reserved_capacity_after_ordinary_caches_saturate() {
        let handler = Handler {
            calls: AtomicUsize::new(0),
        };
        let state = Mutex::new(ServerState::default());
        let now = Instant::now();
        for index in 0..MAX_CACHED_RESPONSES {
            let request = LocalRequest::new(
                format!("req-{index:016x}"),
                format!("{index:064x}"),
                LocalCommand::SetAutostart {
                    enabled: index % 2 == 0,
                },
            );
            dispatch_request(&state, &handler, &caller(), &request, now).unwrap();
        }
        let calls_before_release = handler.calls.load(Ordering::Relaxed);
        assert_eq!(
            calls_before_release,
            MAX_CACHED_RESPONSES - RELEASE_ALL_CACHE_RESERVE
        );
        assert_eq!(
            state.lock().unwrap().responses.len(),
            MAX_CACHED_RESPONSES - RELEASE_ALL_CACHE_RESERVE
        );

        let ordinary_at_capacity = dispatch_request(
            &state,
            &handler,
            &caller(),
            &LocalRequest::new(
                "req-ordinary-full".into(),
                format!("{:064x}", MAX_CACHED_RESPONSES + 1),
                LocalCommand::SetAutostart { enabled: true },
            ),
            now,
        )
        .unwrap();
        assert!(matches!(
            ordinary_at_capacity.result,
            LocalResult::Error {
                code: LocalErrorCode::OperationFailed,
                retryable: true,
                ..
            }
        ));
        let replayed_ordinary = dispatch_request(
            &state,
            &handler,
            &caller(),
            &LocalRequest::new(
                "req-replayed-ordinary".into(),
                format!("{:064x}", 0),
                LocalCommand::SetAutostart { enabled: false },
            ),
            now,
        )
        .unwrap();
        assert!(matches!(
            replayed_ordinary.result,
            LocalResult::Error {
                code: LocalErrorCode::ReplayDetected,
                retryable: false,
                ..
            }
        ));

        let release = LocalRequest::new(
            "req-release-reserved".into(),
            format!("{:064x}", MAX_CACHED_RESPONSES + 2),
            LocalCommand::ReleaseAll {},
        );
        let response = dispatch_request(&state, &handler, &caller(), &release, now).unwrap();
        assert!(matches!(
            response.result,
            LocalResult::Ok {
                payload: LocalPayload::Released { .. }
            }
        ));
        let retry = LocalRequest {
            nonce: format!("{:064x}", MAX_CACHED_RESPONSES + 3),
            ..release
        };
        assert_eq!(
            response,
            dispatch_request(&state, &handler, &caller(), &retry, now).unwrap()
        );
        assert_eq!(
            handler.calls.load(Ordering::Relaxed),
            calls_before_release + 1
        );
    }
}
