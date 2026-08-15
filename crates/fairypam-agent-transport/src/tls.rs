use std::path::PathBuf;
use std::time::Duration;

use http::Uri;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::sign::CertifiedKey;
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

#[derive(Clone, Debug)]
pub struct TelemetryChannel {
    pub(crate) channel: Channel,
}

pub async fn connect_control(config: &TransportConfig) -> Result<ControlChannel, TransportError> {
    let channel = connect_channel(
        &config.control_endpoint,
        config,
        "transport.control_connect_failed",
    )
    .await?;
    Ok(ControlChannel {
        channel,
        agent_id: config.agent_id.clone(),
    })
}

pub async fn connect_frame(config: &TransportConfig) -> Result<FrameChannel, TransportError> {
    let channel = connect_channel(
        &config.frame_endpoint,
        config,
        "transport.frame_connect_failed",
    )
    .await?;
    Ok(FrameChannel {
        channel,
        agent_id: config.agent_id.clone(),
    })
}

pub async fn connect_telemetry(
    config: &TransportConfig,
) -> Result<TelemetryChannel, TransportError> {
    let channel = connect_channel(
        &config.control_endpoint,
        config,
        "transport.telemetry_connect_failed",
    )
    .await?;
    Ok(TelemetryChannel { channel })
}

async fn connect_channel(
    uri: &Uri,
    config: &TransportConfig,
    error_code: &'static str,
) -> Result<Channel, TransportError> {
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
    validate_pem_identity(&ca, &certificate, &key, &config.agent_id)?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(certificate, key))
        .domain_name(config.server_name.clone());
    endpoint(uri, config.connect_timeout)?
        .tls_config(tls)
        .map_err(|error| TransportError::new("transport.tls_invalid", error.to_string()))?
        .connect()
        .await
        .map_err(|error| TransportError::new(error_code, error.to_string()))
}

/// Validate a persisted enrollment candidate without opening a network
/// connection. The Agent uses this before publishing the active generation.
pub fn validate_transport_config(config: &TransportConfig) -> Result<(), TransportError> {
    validate_config(config)?;
    let ca = std::fs::read(&config.ca_pem)
        .map_err(|error| TransportError::new("transport.ca_read_failed", error.to_string()))?;
    let certificate = std::fs::read(&config.identity_cert_pem)
        .map_err(|error| TransportError::new("transport.cert_read_failed", error.to_string()))?;
    let key = std::fs::read(&config.identity_key_pem)
        .map_err(|error| TransportError::new("transport.key_read_failed", error.to_string()))?;
    validate_pem_identity(&ca, &certificate, &key, &config.agent_id)
}

fn validate_pem_identity(
    ca_pem: &[u8],
    certificate_pem: &[u8],
    key_pem: &[u8],
    agent_id: &str,
) -> Result<(), TransportError> {
    let (remaining_ca, ca) = parse_x509_pem(ca_pem)
        .map_err(|_| TransportError::new("transport.identity_invalid", "invalid CA PEM"))?;
    if !remaining_ca.is_empty() {
        return Err(identity_invalid("CA PEM contains trailing data"));
    }
    let ca = ca
        .parse_x509()
        .map_err(|_| TransportError::new("transport.identity_invalid", "invalid CA certificate"))?;
    let (remaining_certificate, parsed_certificate) =
        parse_x509_pem(certificate_pem).map_err(|_| {
            TransportError::new(
                "transport.identity_invalid",
                "invalid client certificate PEM",
            )
        })?;
    if !remaining_certificate.is_empty() {
        return Err(identity_invalid(
            "client certificate PEM contains trailing data",
        ));
    }
    let certificate = parsed_certificate.parse_x509().map_err(|_| {
        TransportError::new("transport.identity_invalid", "invalid client certificate")
    })?;
    validate_certificate_chain(&ca, &certificate)?;
    verify_agent_certificate(&certificate, agent_id)?;
    let certificates = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            TransportError::new("transport.identity_invalid", "invalid certificate PEM")
        })?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| {
        TransportError::new("transport.identity_invalid", "invalid private key PEM")
    })?;
    let certified_key =
        CertifiedKey::from_der(certificates, key, &rustls::crypto::ring::default_provider())
            .map_err(identity_key_error)?;
    certified_key.keys_match().map_err(identity_key_error)?;
    Ok(())
}

fn validate_certificate_chain(
    ca: &x509_parser::certificate::X509Certificate<'_>,
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), TransportError> {
    let invalid = || {
        TransportError::new(
            "transport.identity_invalid",
            "client certificate chain is invalid",
        )
    };
    if !ca.validity().is_valid()
        || !certificate.validity().is_valid()
        || ca
            .basic_constraints()
            .map_err(|_| invalid())?
            .is_none_or(|constraints| !constraints.value.ca)
        || certificate
            .basic_constraints()
            .map_err(|_| invalid())?
            .is_some_and(|constraints| constraints.value.ca)
        || certificate.issuer() != ca.subject()
        || certificate
            .extended_key_usage()
            .map_err(|_| invalid())?
            .is_none_or(|usage| {
                let usage = usage.value;
                !usage.client_auth
                    || usage.any
                    || usage.server_auth
                    || usage.code_signing
                    || usage.email_protection
                    || usage.time_stamping
                    || usage.ocsp_signing
                    || !usage.other.is_empty()
            })
    {
        return Err(invalid());
    }
    certificate
        .verify_signature(Some(ca.public_key()))
        .map_err(|_| invalid())
}

fn identity_key_error(error: rustls::Error) -> TransportError {
    if matches!(error, rustls::Error::InconsistentKeys(_)) {
        TransportError::new(
            "transport.identity_key_mismatch",
            "client certificate and private key do not match",
        )
    } else {
        TransportError::new("transport.identity_invalid", "invalid client identity")
    }
}

#[cfg(test)]
pub(crate) fn verify_agent_uri_san(
    certificate_pem: &[u8],
    agent_id: &str,
) -> Result<(), TransportError> {
    let (_, pem) = parse_x509_pem(certificate_pem)
        .map_err(|error| TransportError::new("transport.identity_invalid", error.to_string()))?;
    let certificate = pem
        .parse_x509()
        .map_err(|error| TransportError::new("transport.identity_invalid", error.to_string()))?;
    verify_agent_certificate(&certificate, agent_id)
}

fn verify_agent_certificate(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    agent_id: &str,
) -> Result<(), TransportError> {
    let subject_matches = certificate.subject().iter_attributes().count() == 1
        && certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|name| name.as_str().ok())
            == Some(agent_id);
    let expected = format!("spiffe://fairypam/agent/{agent_id}");
    let uri_names = certificate
        .subject_alternative_name()
        .map_err(|error| TransportError::new("transport.identity_invalid", error.to_string()))?
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::URI(uri) => Some(*uri),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !subject_matches || uri_names.as_slice() != [expected.as_str()] {
        return Err(TransportError::new(
            "transport.identity_agent_mismatch",
            "client certificate subject or URI SAN does not match configured agent id",
        ));
    }
    Ok(())
}

fn identity_invalid(message: impl Into<String>) -> TransportError {
    TransportError::new("transport.identity_invalid", message)
}

fn endpoint(uri: &Uri, connect_timeout: Duration) -> Result<Endpoint, TransportError> {
    Ok(Endpoint::from_shared(uri.to_string())
        .map_err(|error| TransportError::new("transport.endpoint_invalid", error.to_string()))?
        .connect_timeout(connect_timeout)
        .tcp_keepalive(Some(Duration::from_secs(30))))
}

fn validate_config(config: &TransportConfig) -> Result<(), TransportError> {
    if config.agent_id.is_empty()
        || uuid::Uuid::parse_str(&config.agent_id).is_err()
        || config.server_name.is_empty()
        || config.connect_timeout.is_zero()
        || config.control_endpoint.scheme_str() != Some("https")
        || config.frame_endpoint.scheme_str() != Some("https")
        || config.control_endpoint.authority().is_none()
        || config.frame_endpoint.authority().is_none()
        || config.control_endpoint.query().is_some()
        || config.frame_endpoint.query().is_some()
        || config
            .control_endpoint
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || config
            .frame_endpoint
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || ServerName::try_from(config.server_name.clone()).is_err()
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
    use std::fs;

    fn client_identity(agent_id: &str) -> (String, String, String) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let mut client_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.distinguished_name = rcgen::DistinguishedName::new();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, agent_id);
        client_params.subject_alt_names.push(rcgen::SanType::URI(
            format!("spiffe://fairypam/agent/{agent_id}")
                .try_into()
                .unwrap(),
        ));
        client_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        client_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client_certificate = client_params.signed_by(&client_key, &issuer).unwrap();
        (
            ca_certificate.pem(),
            client_certificate.pem(),
            client_key.serialize_pem(),
        )
    }

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
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, AGENT_A);
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

    #[test]
    fn client_certificate_subject_must_be_the_single_agent_common_name() {
        const AGENT_ID: &str = "11111111-1111-1111-1111-111111111111";
        for extra_subject in [false, true] {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name = rcgen::DistinguishedName::new();
            if extra_subject {
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, AGENT_ID);
                params
                    .distinguished_name
                    .push(rcgen::DnType::OrganizationName, "unexpected");
            }
            params.subject_alt_names.push(rcgen::SanType::URI(
                format!("spiffe://fairypam/agent/{AGENT_ID}")
                    .try_into()
                    .unwrap(),
            ));
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap().pem();

            let error = verify_agent_uri_san(cert.as_bytes(), AGENT_ID).unwrap_err();
            assert_eq!(error.code(), "transport.identity_agent_mismatch");
        }
    }

    #[test]
    fn persisted_transport_validation_rejects_bad_key_pem() {
        const AGENT_ID: &str = "11111111-1111-1111-1111-111111111111";
        let directory = tempfile::tempdir().unwrap();
        let (ca_pem, certificate, key) = client_identity(AGENT_ID);
        let ca = directory.path().join("ca.pem");
        let cert = directory.path().join("client-cert.pem");
        let private_key = directory.path().join("client-key.pem");
        fs::write(&ca, ca_pem).unwrap();
        fs::write(&cert, &certificate).unwrap();
        fs::write(&private_key, key).unwrap();
        let config = TransportConfig {
            control_endpoint: "https://hub.example/control".parse().unwrap(),
            frame_endpoint: "https://hub.example/frame".parse().unwrap(),
            server_name: "hub.example".into(),
            agent_id: AGENT_ID.into(),
            ca_pem: ca,
            identity_cert_pem: cert,
            identity_key_pem: private_key,
            connect_timeout: Duration::from_secs(1),
        };

        validate_transport_config(&config).unwrap();
        fs::write(
            &config.identity_key_pem,
            rcgen::KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        let mismatch = validate_transport_config(&config).unwrap_err();
        assert_eq!(mismatch.code(), "transport.identity_key_mismatch");
        fs::write(&config.identity_key_pem, "not a private key").unwrap();
        let error = validate_transport_config(&config).unwrap_err();

        assert_eq!(error.code(), "transport.identity_invalid");
    }

    #[test]
    fn persisted_transport_validation_rejects_an_unrelated_ca() {
        const AGENT_ID: &str = "11111111-1111-1111-1111-111111111111";
        let directory = tempfile::tempdir().unwrap();
        let (_, certificate, key) = client_identity(AGENT_ID);
        let (unrelated_ca, _, _) = client_identity(AGENT_ID);
        let ca = directory.path().join("ca.pem");
        let cert = directory.path().join("client-cert.pem");
        let private_key = directory.path().join("client-key.pem");
        fs::write(&ca, unrelated_ca).unwrap();
        fs::write(&cert, certificate).unwrap();
        fs::write(&private_key, key).unwrap();
        let config = TransportConfig {
            control_endpoint: "https://hub.example/control".parse().unwrap(),
            frame_endpoint: "https://hub.example/frame".parse().unwrap(),
            server_name: "hub.example".into(),
            agent_id: AGENT_ID.into(),
            ca_pem: ca,
            identity_cert_pem: cert,
            identity_key_pem: private_key,
            connect_timeout: Duration::from_secs(1),
        };

        let error = validate_transport_config(&config).unwrap_err();

        assert_eq!(error.code(), "transport.identity_invalid");
    }
}
