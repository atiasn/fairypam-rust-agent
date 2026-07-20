use std::{
    collections::VecDeque,
    future::pending,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use fairypam_agent_local_client::{LocalClient, LocalClientError, LocalTransport};
use fairypam_agent_local_protocol::{encode_frame, LocalCommand, LocalResponse, ResponseEnvelope};
use serde_json::json;

struct FakeTransport {
    connect_results: VecDeque<Result<(), LocalClientError>>,
    receive_results: VecDeque<Result<Vec<u8>, LocalClientError>>,
    connects: Arc<AtomicUsize>,
    close_calls: Arc<AtomicUsize>,
}

impl FakeTransport {
    fn with_response(request_id: &str) -> Self {
        let response = ResponseEnvelope {
            request_id: request_id.to_owned(),
            result: Ok(LocalResponse {
                body: json!({"status":"ready"}),
            }),
        };
        Self {
            connect_results: VecDeque::new(),
            receive_results: VecDeque::from([Ok(encode_frame(&response).unwrap())]),
            connects: Arc::new(AtomicUsize::new(0)),
            close_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn never_responds() -> Self {
        Self {
            connect_results: VecDeque::new(),
            receive_results: VecDeque::new(),
            connects: Arc::new(AtomicUsize::new(0)),
            close_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl LocalTransport for FakeTransport {
    async fn connect(&mut self) -> Result<(), LocalClientError> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        self.connect_results.pop_front().unwrap_or(Ok(()))
    }

    async fn send(&mut self, _frame: Vec<u8>) -> Result<(), LocalClientError> {
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, LocalClientError> {
        match self.receive_results.pop_front() {
            Some(result) => result,
            None => pending().await,
        }
    }

    async fn close(&mut self) {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn timeout_cancel_and_pipe_absent_have_stable_categories() {
    let mut client = LocalClient::new(FakeTransport::never_responds());
    assert_eq!(
        client
            .request(LocalCommand::Status, Duration::from_millis(1))
            .await
            .unwrap_err()
            .code(),
        "local.transport.timeout"
    );
    assert_eq!(
        LocalClientError::pipe_not_found().code(),
        "local.transport.pipe_not_found"
    );
    assert_eq!(
        LocalClientError::identity("sid_mismatch").code(),
        "local.identity.sid_mismatch"
    );

    client.cancel("cancelled-request");
    assert_eq!(
        client
            .request_with_id(
                "cancelled-request",
                LocalCommand::Status,
                Duration::from_secs(1),
            )
            .await
            .unwrap_err()
            .code(),
        "local.transport.cancelled"
    );
}

#[tokio::test]
async fn reconnect_is_bounded_to_connection_establishment() {
    let mut transport = FakeTransport::with_response("request-1");
    let connects = Arc::clone(&transport.connects);
    transport.connect_results = VecDeque::from([
        Err(LocalClientError::pipe_not_found()),
        Err(LocalClientError::disconnected()),
        Ok(()),
    ]);
    let mut client = LocalClient::new(transport);

    let response = client
        .request_with_id("request-1", LocalCommand::Status, Duration::from_secs(1))
        .await
        .unwrap();

    assert_eq!(response.body, json!({"status":"ready"}));
    assert_eq!(connects.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn domain_errors_and_request_ids_are_not_rewritten() {
    let response = ResponseEnvelope {
        request_id: "request-1".to_owned(),
        result: Err(fairypam_agent_local_protocol::LocalError {
            code: "local.domain.target_not_found".to_owned(),
            message: "target is no longer available".to_owned(),
        }),
    };
    let transport = FakeTransport {
        connect_results: VecDeque::new(),
        receive_results: VecDeque::from([Ok(encode_frame(&response).unwrap())]),
        connects: Arc::new(AtomicUsize::new(0)),
        close_calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut client = LocalClient::new(transport);

    assert_eq!(
        client
            .request_with_id("request-1", LocalCommand::Status, Duration::from_secs(1))
            .await
            .unwrap_err()
            .code(),
        "local.domain.target_not_found"
    );
}
