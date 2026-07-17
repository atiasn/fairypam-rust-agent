use std::path::PathBuf;
use std::time::Duration;

use http::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;

use crate::TransportError;

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub control_endpoint: Uri,
    pub frame_endpoint: Uri,
    pub server_name: String,
    pub agent_id: String,
    pub ca_pem: PathBuf,
    pub identity_cert_pem: PathBuf,
    pub identity_key_pem: PathBuf,
    pub connect_timeout: Duration,
}

/// An authenticated Control connection. The underlying tonic Channel and the
/// certificate-bound agent id stay private so callers cannot separate them.
#[derive(Clone, Debug)]
pub struct ControlChannel {
    pub(crate) channel: Channel,
    pub(crate) agent_id: String,
}

/// An authenticated Frame connection. It can only be opened for a
/// `VerifiedSession` carrying the same certificate-bound agent id.
#[derive(Clone, Debug)]
pub struct FrameChannel {
    pub(crate) channel: Channel,
    pub(crate) agent_id: String,
}

pub async fn connect_control(config: &TransportConfig) -> Result<ControlChannel, TransportError> {
    let tls = load_identity(config).await?;
    let channel = endpoint(&config.control_endpoint, &tls, config.connect_timeout)?
        .connect()
        .await
        .map_err(|error| {
            TransportError::new("transport.control_connect_failed", error.to_string())
        })?;
    Ok(ControlChannel {
        channel,
        agent_id: config.agent_id.clone(),
    })
}

pub async fn connect_frame(config: &TransportConfig) -> Result<FrameChannel, TransportError> {
    let tls = load_identity(config).await?;
    let channel = endpoint(&config.frame_endpoint, &tls, config.connect_timeout)?
        .connect()
        .await
        .map_err(|error| {
            TransportError::new("transport.frame_connect_failed", error.to_string())
        })?;
    Ok(FrameChannel {
        channel,
        agent_id: config.agent_id.clone(),
    })
}

async fn load_identity(config: &TransportConfig) -> Result<ClientTlsConfig, TransportError> {
    validate_config(config)?;
    let ca = tokio::fs::read(&config.ca_pem)
        .await
        .map_err(|error| TransportError::new("transport.ca_read_failed", error.to_string()))?;
    let certificate = tokio::fs::read(&config.identity_cert_pem)
        .await
        .map_err(|error| TransportError::new("transport.cert_read_failed", error.to_string()))?;
    let key = tokio::fs::read(&config.identity_key_pem)
        .await
        .map_err(|error| TransportError::new("transport.key_read_failed", error.to_string()))?;
    if ca.is_empty() || certificate.is_empty() || key.is_empty() {
        return Err(TransportError::new(
            "transport.identity_invalid",
            "mTLS CA, certificate, and private key must be non-empty",
        ));
    }
    verify_agent_uri_san(&certificate, &config.agent_id)?;
    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(certificate, key))
        .domain_name(config.server_name.clone()))
}

pub(crate) fn verify_agent_uri_san(
    certificate_pem: &[u8],
    agent_id: &str,
) -> Result<(), TransportError> {
    let (_, pem) = parse_x509_pem(certificate_pem)
        .map_err(|error| TransportError::new("transport.identity_invalid", error.to_string()))?;
    let certificate = pem
        .parse_x509()
        .map_err(|error| TransportError::new("transport.identity_invalid", error.to_string()))?;
    let expected = format!("spiffe://fairypam/agent/{agent_id}");
    let matches = certificate
        .subject_alternative_name()
        .map_err(|error| TransportError::new("transport.identity_invalid", error.to_string()))?
        .is_some_and(|extension| {
            extension
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::URI(uri) if *uri == expected))
        });
    if !matches {
        return Err(TransportError::new(
            "transport.identity_agent_mismatch",
            "client certificate URI SAN does not match configured agent id",
        ));
    }
    Ok(())
}

fn endpoint(
    uri: &Uri,
    tls: &ClientTlsConfig,
    connect_timeout: Duration,
) -> Result<Endpoint, TransportError> {
    Endpoint::from_shared(uri.to_string())
        .map_err(|error| TransportError::new("transport.endpoint_invalid", error.to_string()))?
        .connect_timeout(connect_timeout)
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(5))
        .tls_config(tls.clone())
        .map_err(|error| TransportError::new("transport.tls_invalid", error.to_string()))
}

fn validate_config(config: &TransportConfig) -> Result<(), TransportError> {
    if config.agent_id.is_empty()
        || uuid::Uuid::parse_str(&config.agent_id).is_err()
        || config.server_name.is_empty()
        || config.connect_timeout.is_zero()
        || config.control_endpoint.scheme_str() != Some("https")
        || config.frame_endpoint.scheme_str() != Some("https")
    {
        return Err(TransportError::new(
            "transport.config_invalid",
            "Agent id, HTTPS endpoints, server name, and connect timeout are required",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_endpoint_is_rejected_before_identity_files_are_read() {
        let config = TransportConfig {
            control_endpoint: "http://127.0.0.1:50051".parse().unwrap(),
            frame_endpoint: "https://127.0.0.1:50052".parse().unwrap(),
            server_name: "localhost".into(),
            agent_id: "agent-a".into(),
            ca_pem: "missing-ca.pem".into(),
            identity_cert_pem: "missing-cert.pem".into(),
            identity_key_pem: "missing-key.pem".into(),
            connect_timeout: Duration::from_secs(1),
        };

        let error = validate_config(&config).unwrap_err();

        assert_eq!(error.code(), "transport.config_invalid");
    }

    #[test]
    fn client_certificate_uri_san_must_bind_agent_id() {
        const AGENT_A: &str = "11111111-1111-1111-1111-111111111111";
        const AGENT_B: &str = "22222222-2222-2222-2222-222222222222";
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("spiffe://fairypam/agent/{AGENT_A}")
                .try_into()
                .unwrap(),
        ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap().pem();

        let error = verify_agent_uri_san(cert.as_bytes(), AGENT_B).unwrap_err();

        assert_eq!(error.code(), "transport.identity_agent_mismatch");
    }
}
