use std::thread::JoinHandle;
use std::time::Duration;

use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::local_v1::{
    local_control_envelope, LocalControlEnvelope, LocalControlResponse,
};
use fairypam_agent_protocol::{
    connect_local_agent_pipe, read_local_control_frame, validate_local_control_request,
    write_local_control_frame, SecureLocalPipeListener, LOCAL_AGENT_PIPE_NAME,
    LOCAL_CONTROL_PROTOCOL_MAJOR, LOCAL_CONTROL_PROTOCOL_MINOR,
};
use tokio_util::sync::CancellationToken;

use crate::runtime::LocalControlRuntime;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_CLIENTS: usize = 4;

pub(crate) struct LocalControlServer {
    stop: CancellationToken,
    thread: Option<JoinHandle<()>>,
}

impl LocalControlServer {
    pub(crate) fn start(
        runtime: LocalControlRuntime,
        runtime_shutdown: CancellationToken,
    ) -> Result<Self, AgentError> {
        let listener = SecureLocalPipeListener::bind(LOCAL_AGENT_PIPE_NAME)
            .map_err(|error| AgentError::new("local.pipe_bind_failed", error.to_string()))?;
        let stop = CancellationToken::new();
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("fairypam-local-control".into())
            .spawn(move || serve(listener, runtime, thread_stop, runtime_shutdown))
            .map_err(|error| AgentError::new("local.pipe_start_failed", error.to_string()))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub(crate) fn stop(mut self) -> Result<(), AgentError> {
        self.stop.cancel();
        let _ = connect_local_agent_pipe(LOCAL_AGENT_PIPE_NAME, Duration::from_secs(1));
        self.thread
            .take()
            .expect("local control thread is owned")
            .join()
            .map_err(|_| AgentError::new("local.pipe_join_failed", "local control thread panicked"))
    }
}

fn serve(
    mut listener: SecureLocalPipeListener,
    runtime: LocalControlRuntime,
    stop: CancellationToken,
    runtime_shutdown: CancellationToken,
) {
    let mut handlers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.is_cancelled() {
        let mut index = 0;
        while index < handlers.len() {
            if handlers[index].is_finished() {
                let _ = handlers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        if handlers.len() >= MAX_CONCURRENT_CLIENTS {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        let pipe = match listener.accept() {
            Ok(pipe) => pipe,
            Err(error) => {
                tracing::error!(code = "local.pipe_accept_failed", %error);
                runtime_shutdown.cancel();
                return;
            }
        };
        if stop.is_cancelled() {
            break;
        }
        let runtime = runtime.clone();
        match std::thread::Builder::new()
            .name("fairypam-local-client".into())
            .spawn(move || handle_client(pipe, &runtime))
        {
            Ok(handler) => handlers.push(handler),
            Err(error) => tracing::warn!(code = "local.client_start_failed", %error),
        }
    }
    for handler in handlers {
        let _ = handler.join();
    }
}

fn handle_client(mut pipe: std::fs::File, runtime: &LocalControlRuntime) {
    let Ok(envelope) = read_local_control_frame(&mut pipe, REQUEST_TIMEOUT) else {
        return;
    };
    let Some(local_control_envelope::Payload::Request(request)) = envelope.payload else {
        return;
    };
    let response = match validate_local_control_request(&request, now_unix_ms()) {
        Ok(()) => runtime.handle_local_request(request),
        Err(error) => LocalControlResponse {
            request_id: request.request_id,
            outcome: fairypam_agent_protocol::local_v1::LocalCommandOutcome::NotApplied as i32,
            error_code: Some(error.code().to_owned()),
            result: None,
        },
    };
    let envelope = LocalControlEnvelope {
        protocol_major: LOCAL_CONTROL_PROTOCOL_MAJOR,
        protocol_minor: LOCAL_CONTROL_PROTOCOL_MINOR,
        payload: Some(local_control_envelope::Payload::Response(response)),
    };
    let _ = write_local_control_frame(&mut pipe, &envelope);
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_clock_is_positive() {
        assert!(now_unix_ms() > 0);
    }

    #[cfg(windows)]
    #[test]
    fn slow_clients_at_capacity_do_not_stop_agent() {
        use fairypam_agent_protocol::local_v1::{
            local_control_request, GetStatus, LocalCommandOutcome, LocalControlRequest,
        };

        let pipe_name = format!(
            r"\\.\pipe\FairyPam.Agent.Control.Test.{}.{}",
            std::process::id(),
            now_unix_ms()
        );
        let listener = SecureLocalPipeListener::bind(&pipe_name).unwrap();
        let driver = crate::runtime::GrpcSessionDriver::for_test();
        let stop = CancellationToken::new();
        let runtime_shutdown = CancellationToken::new();
        let server_stop = stop.clone();
        let server_shutdown = runtime_shutdown.clone();
        let server = std::thread::spawn(move || {
            serve(
                listener,
                driver.local_control(),
                server_stop,
                server_shutdown,
            )
        });

        let mut slow_clients = (0..MAX_CONCURRENT_CLIENTS)
            .map(|_| connect_local_agent_pipe(&pipe_name, Duration::from_secs(2)).unwrap())
            .collect::<Vec<_>>();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!runtime_shutdown.is_cancelled());

        drop(slow_clients.pop());
        let mut client = connect_local_agent_pipe(&pipe_name, Duration::from_secs(2)).unwrap();
        let request = LocalControlRequest {
            request_id: "capacity-recovery".into(),
            deadline_unix_ms: now_unix_ms() + 2_000,
            command: Some(local_control_request::Command::GetStatus(GetStatus {})),
        };
        write_local_control_frame(
            &mut client,
            &LocalControlEnvelope {
                protocol_major: LOCAL_CONTROL_PROTOCOL_MAJOR,
                protocol_minor: LOCAL_CONTROL_PROTOCOL_MINOR,
                payload: Some(local_control_envelope::Payload::Request(request)),
            },
        )
        .unwrap();
        let response = read_local_control_frame(&mut client, Duration::from_secs(2)).unwrap();
        let Some(local_control_envelope::Payload::Response(response)) = response.payload else {
            panic!("local control did not return a response");
        };
        assert_eq!(response.request_id, "capacity-recovery");
        assert_eq!(response.outcome, LocalCommandOutcome::Applied as i32);
        assert!(!runtime_shutdown.is_cancelled());

        drop(client);
        drop(slow_clients);
        stop.cancel();
        let _ = connect_local_agent_pipe(&pipe_name, Duration::from_secs(1));
        server.join().unwrap();
    }
}
