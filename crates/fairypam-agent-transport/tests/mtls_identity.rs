use std::pin::Pin;
use std::time::Duration;

use fairypam_agent_protocol::v2::agent_control_service_server::{
    AgentControlService, AgentControlServiceServer,
};
use fairypam_agent_protocol::v2::{
    agent_control_event, hub_control_command, AgentControlEvent, AgentHello, HubControlCommand,
    HubHello, SessionRef,
};
use fairypam_agent_transport::{
    connect_control, control_queue, open_control_tunnel, receive_hub_hello, TransportConfig,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::Stream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

const AGENT_A: &str = "11111111-1111-1111-1111-111111111111";
const AGENT_B: &str = "22222222-2222-2222-2222-222222222222";

#[derive(Default)]
struct HelloService;

#[tonic::async_trait]
impl AgentControlService for HelloService {
    type ControlTunnelStream =
        Pin<Box<dyn Stream<Item = Result<HubControlCommand, Status>> + Send + 'static>>;

    async fn control_tunnel(
        &self,
        request: Request<Streaming<AgentControlEvent>>,
    ) -> Result<Response<Self::ControlTunnelStream>, Status> {
        assert!(request.peer_certs().is_some());
        let mut inbound = request.into_inner();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let event = inbound.message().await.expect("read AgentHello");
            assert!(event.is_some());
            sender
                .send(Ok(HubControlCommand {
                    payload: Some(hub_control_command::Payload::Hello(HubHello {
                        session: Some(SessionRef {
                            agent_id: AGENT_A.into(),
                            session_id: "session-1".into(),
                            generation: 1,
                        }),
                        heartbeat_interval_ms: 1_000,
                        max_input_lease_ms: 500,
                        max_frame_bytes: 1_024,
                        accepted_protocol_minor: 8,
                    })),
                }))
                .await
                .expect("send HubHello");
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

#[tokio::test]
async fn control_mtls_is_agent_bound_and_independent_from_frame_availability() {
    let certificates = Certificates::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            certificates.server_cert.as_bytes(),
            certificates.server_key.as_bytes(),
        ))
        .client_ca_root(Certificate::from_pem(certificates.ca_cert.as_bytes()));
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentControlServiceServer::new(HelloService))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_shutdown.cancelled_owned(),
            )
            .await
            .unwrap();
    });

    let config = certificates.config(address.port(), AGENT_A);
    let connection = connect_control(&config).await.unwrap();
    let (sender, receiver) = control_queue();
    sender
        .send(AgentControlEvent {
            payload: Some(agent_control_event::Payload::Hello(AgentHello {
                agent_id: AGENT_A.into(),
                agent_version: "0.1.0".into(),
                protocol_major: 2,
                protocol_minor: 8,
                build_commit: "test".into(),
                installed_profiles: Vec::new(),
                agent_process_generation_id: "11111111-1111-4111-8111-111111111111".into(),
                ..Default::default()
            })),
        })
        .await
        .unwrap();
    let pending = open_control_tunnel(&connection, receiver).await.unwrap();
    let session = receive_hub_hello(pending).await.unwrap();
    assert_eq!(session.verified_session().agent_id(), AGENT_A);

    let wrong_identity = certificates.config(address.port(), AGENT_B);
    let error = connect_control(&wrong_identity).await.unwrap_err();
    assert_eq!(error.code(), "transport.identity_agent_mismatch");

    shutdown.cancel();
    server.await.unwrap();
}

struct Certificates {
    _directory: TempDir,
    ca_cert: String,
    server_cert: String,
    server_key: String,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    ca_path: std::path::PathBuf,
}

impl Certificates {
    fn new() -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = CertifiedIssuer::self_signed(ca_params, &ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca).unwrap().pem();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.distinguished_name = rcgen::DistinguishedName::new();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, AGENT_A);
        client_params.subject_alt_names.push(SanType::URI(
            format!("spiffe://fairypam/agent/{AGENT_A}")
                .try_into()
                .unwrap(),
        ));
        client_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        client_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        let client_cert = client_params.signed_by(&client_key, &ca).unwrap().pem();

        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("ca.pem");
        let client_cert_path = directory.path().join("agent.pem");
        let client_key_path = directory.path().join("agent-key.pem");
        std::fs::write(&ca_path, ca.pem()).unwrap();
        std::fs::write(&client_cert_path, client_cert).unwrap();
        std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
        Self {
            _directory: directory,
            ca_cert: ca.pem(),
            server_cert,
            server_key: server_key.serialize_pem(),
            client_cert_path,
            client_key_path,
            ca_path,
        }
    }

    fn config(&self, control_port: u16, agent_id: &str) -> TransportConfig {
        TransportConfig {
            control_endpoint: format!("https://127.0.0.1:{control_port}").parse().unwrap(),
            frame_endpoint: "https://127.0.0.1:1".parse().unwrap(),
            server_name: "localhost".into(),
            agent_id: agent_id.into(),
            ca_pem: self.ca_path.clone(),
            identity_cert_pem: self.client_cert_path.clone(),
            identity_key_pem: self.client_key_path.clone(),
            connect_timeout: Duration::from_secs(2),
        }
    }
}
