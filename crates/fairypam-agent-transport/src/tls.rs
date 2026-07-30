use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
#[cfg(windows)]
use hyper_util::rt::TokioIo;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::sign::CertifiedKey;
#[cfg(windows)]
use rustls::sign::SingleCertAndKey;
#[cfg(windows)]
use rustls::{ClientConfig, RootCertStore};
#[cfg(windows)]
use rustls_cng::key::{AlgorithmGroup, NCryptKey};
#[cfg(windows)]
use rustls_cng::signer::CngSigningKey;
#[cfg(windows)]
use rustls_cng::store::{CertStore, CertStoreType};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use tokio::net::TcpStream;
#[cfg(windows)]
use tokio_rustls::TlsConnector;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
#[cfg(windows)]
use tower::service_fn;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{LocalFree, NTE_BAD_KEYSET, NTE_NOT_FOUND};
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptGenRandom, BCryptImportKeyPair,
    BCryptOpenAlgorithmProvider, BCryptVerifySignature, CertAddEncodedCertificateToStore,
    CertCloseStore, CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
    CertFreeCertificateContext, CertOpenStore, CertSetCertificateContextProperty,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, NCryptSignHash, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_PAD_PKCS1,
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RSAKEY_BLOB, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPUBLIC_MAGIC,
    BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CERT_KEY_PROV_INFO_PROP_ID, CERT_NCRYPT_KEY_SPEC, CERT_STORE_ADD_NEW, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_KEY_PROV_INFO, CRYPT_MACHINE_KEYSET,
    MS_KEY_STORAGE_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY, NCRYPT_MACHINE_KEY_FLAG,
    NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PERSIST_FLAG, NCRYPT_SECURITY_DESCR_PROPERTY, NCRYPT_SILENT_FLAG,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorLength, IsValidAcl, IsValidSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
#[cfg(windows)]
use x509_parser::public_key::PublicKey;

use crate::TransportError;

#[derive(Clone, Debug)]
pub enum IdentityKey {
    Pem(PathBuf),
    #[cfg(windows)]
    CngMachine {
        key_name: String,
        authorized_user_sid: String,
        certificate_sha256: [u8; 32],
        expires_at_unix_seconds: i64,
    },
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub control_endpoint: Uri,
    pub frame_endpoint: Uri,
    pub server_name: String,
    pub agent_id: String,
    pub ca_pem: PathBuf,
    pub identity_cert_pem: PathBuf,
    pub identity_key: IdentityKey,
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
    match &config.identity_key {
        IdentityKey::Pem(path) => {
            let key = tokio::fs::read(path).await.map_err(|error| {
                TransportError::new("transport.key_read_failed", error.to_string())
            })?;
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
        #[cfg(windows)]
        IdentityKey::CngMachine {
            key_name,
            authorized_user_sid,
            certificate_sha256,
            expires_at_unix_seconds,
        } => {
            let tls = cng_client_config(
                &ca,
                &certificate,
                key_name,
                authorized_user_sid,
                certificate_sha256,
                *expires_at_unix_seconds,
                &config.agent_id,
            )?;
            connect_cng(uri, config, tls)
                .await
                .map_err(|error| TransportError::new(error_code, error.to_string()))
        }
    }
}

/// Validate a persisted enrollment candidate without opening a network
/// connection. The Agent uses this before publishing the active generation.
pub fn validate_transport_config(config: &TransportConfig) -> Result<(), TransportError> {
    validate_config(config)?;
    let ca = std::fs::read(&config.ca_pem)
        .map_err(|error| TransportError::new("transport.ca_read_failed", error.to_string()))?;
    let certificate = std::fs::read(&config.identity_cert_pem)
        .map_err(|error| TransportError::new("transport.cert_read_failed", error.to_string()))?;
    match &config.identity_key {
        IdentityKey::Pem(path) => {
            let key = std::fs::read(path).map_err(|error| {
                TransportError::new("transport.key_read_failed", error.to_string())
            })?;
            validate_pem_identity(&ca, &certificate, &key, &config.agent_id)
        }
        #[cfg(windows)]
        IdentityKey::CngMachine {
            key_name,
            authorized_user_sid,
            certificate_sha256,
            expires_at_unix_seconds,
        } => validate_cng_identity(
            &ca,
            &certificate,
            key_name,
            authorized_user_sid,
            certificate_sha256,
            *expires_at_unix_seconds,
            &config.agent_id,
        ),
    }
}

/// Validate an enrollment response against the named CNG key before writing
/// the certificate to LocalMachine\My.
#[cfg(windows)]
pub fn validate_transport_candidate(config: &TransportConfig) -> Result<(), TransportError> {
    validate_config(config)?;
    let ca = std::fs::read(&config.ca_pem)
        .map_err(|error| TransportError::new("transport.ca_read_failed", error.to_string()))?;
    let certificate = std::fs::read(&config.identity_cert_pem)
        .map_err(|error| TransportError::new("transport.cert_read_failed", error.to_string()))?;
    match &config.identity_key {
        IdentityKey::Pem(path) => {
            let key = std::fs::read(path).map_err(|error| {
                TransportError::new("transport.key_read_failed", error.to_string())
            })?;
            validate_pem_identity(&ca, &certificate, &key, &config.agent_id)
        }
        IdentityKey::CngMachine {
            key_name,
            authorized_user_sid,
            certificate_sha256,
            expires_at_unix_seconds,
        } => validate_cng_candidate(
            &ca,
            &certificate,
            key_name,
            authorized_user_sid,
            certificate_sha256,
            *expires_at_unix_seconds,
            &config.agent_id,
        ),
    }
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

pub fn certificate_sha256(certificate_pem: &[u8]) -> Result<[u8; 32], TransportError> {
    let (remaining, certificate) = parse_x509_pem(certificate_pem).map_err(|_| {
        TransportError::new(
            "transport.identity_invalid",
            "invalid client certificate PEM",
        )
    })?;
    if !remaining.is_empty() {
        return Err(identity_invalid(
            "client certificate PEM contains trailing data",
        ));
    }
    Ok(Sha256::digest(&certificate.contents).into())
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

#[cfg(windows)]
fn validate_cng_identity(
    ca_pem: &[u8],
    certificate_pem: &[u8],
    key_name: &str,
    authorized_user_sid: &str,
    expected_fingerprint: &[u8; 32],
    expires_at_unix_seconds: i64,
    agent_id: &str,
) -> Result<(), TransportError> {
    validate_cng_candidate(
        ca_pem,
        certificate_pem,
        key_name,
        authorized_user_sid,
        expected_fingerprint,
        expires_at_unix_seconds,
        agent_id,
    )?;
    let (_, certificate_pem) =
        parse_x509_pem(certificate_pem).map_err(|_| identity_invalid("invalid client PEM"))?;
    let certificate = certificate_pem
        .parse_x509()
        .map_err(|_| identity_invalid("invalid client certificate"))?;
    let installed = installed_certificate(expected_fingerprint, &certificate_pem.contents)?;
    let installed_key = installed
        .acquire_key(true)
        .map_err(|_| identity_invalid("installed certificate private key is unavailable"))?;
    validate_cng_key(&installed_key, &certificate, authorized_user_sid)
}

#[cfg(windows)]
fn validate_cng_candidate(
    ca_pem: &[u8],
    certificate_pem: &[u8],
    key_name: &str,
    authorized_user_sid: &str,
    expected_fingerprint: &[u8; 32],
    expires_at_unix_seconds: i64,
    agent_id: &str,
) -> Result<(), TransportError> {
    validate_cng_key_name(key_name)?;
    let (remaining_ca, ca_pem) =
        parse_x509_pem(ca_pem).map_err(|_| identity_invalid("invalid CA PEM"))?;
    let (remaining_certificate, certificate_pem) =
        parse_x509_pem(certificate_pem).map_err(|_| identity_invalid("invalid client PEM"))?;
    if !remaining_ca.is_empty() || !remaining_certificate.is_empty() {
        return Err(identity_invalid("certificate PEM contains trailing data"));
    }
    let ca = ca_pem
        .parse_x509()
        .map_err(|_| identity_invalid("invalid CA certificate"))?;
    let certificate = certificate_pem
        .parse_x509()
        .map_err(|_| identity_invalid("invalid client certificate"))?;
    validate_certificate_chain(&ca, &certificate)?;
    verify_agent_certificate(&certificate, agent_id)?;
    if certificate.validity().not_after.timestamp() != expires_at_unix_seconds {
        return Err(identity_invalid(
            "client certificate expiration does not match enrollment response",
        ));
    }
    let actual_fingerprint: [u8; 32] = Sha256::digest(&certificate_pem.contents).into();
    if &actual_fingerprint != expected_fingerprint {
        return Err(identity_invalid("client certificate fingerprint mismatch"));
    }

    let named_key = open_cng_machine_key(key_name)?;
    validate_cng_key(&named_key, &certificate, authorized_user_sid)
}

#[cfg(windows)]
fn cng_client_config(
    ca_pem: &[u8],
    certificate_pem: &[u8],
    key_name: &str,
    authorized_user_sid: &str,
    fingerprint: &[u8; 32],
    expires_at_unix_seconds: i64,
    agent_id: &str,
) -> Result<ClientConfig, TransportError> {
    validate_cng_identity(
        ca_pem,
        certificate_pem,
        key_name,
        authorized_user_sid,
        fingerprint,
        expires_at_unix_seconds,
        agent_id,
    )?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem) {
        roots
            .add(certificate.map_err(|_| identity_invalid("invalid CA PEM"))?)
            .map_err(|_| identity_invalid("invalid CA certificate"))?;
    }
    let certificates = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| identity_invalid("invalid client certificate PEM"))?;
    let (_, parsed) = parse_x509_pem(certificate_pem)
        .map_err(|_| identity_invalid("invalid client certificate PEM"))?;
    let installed = installed_certificate(fingerprint, &parsed.contents)?;
    let signing_key = CngSigningKey::new(
        installed
            .acquire_key(true)
            .map_err(|_| identity_invalid("installed certificate private key is unavailable"))?,
    )
    .map_err(|_| identity_invalid("installed certificate signing key is invalid"))?;
    let resolver = SingleCertAndKey::from(CertifiedKey::new(certificates, Arc::new(signing_key)));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| identity_invalid("TLS protocol configuration is invalid"))?
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(resolver));
    config.alpn_protocols.push(b"h2".to_vec());
    Ok(config)
}

#[cfg(windows)]
async fn connect_cng(
    uri: &Uri,
    config: &TransportConfig,
    tls: ClientConfig,
) -> Result<Channel, TransportError> {
    let address = socket_address(uri)?;
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| TransportError::new("transport.config_invalid", "invalid TLS server name"))?;
    let tls = TlsConnector::from(Arc::new(tls));
    let connector = service_fn(move |_uri: Uri| {
        let address = address.clone();
        let server_name = server_name.clone();
        let tls = tls.clone();
        async move {
            let tcp = TcpStream::connect(address).await?;
            let stream = tls.connect(server_name, tcp).await?;
            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(std::io::Error::other("TLS peer did not negotiate HTTP/2"));
            }
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }
    });
    endpoint(uri, config.connect_timeout)?
        .connect_with_connector(connector)
        .await
        .map_err(|error| TransportError::new("transport.tls_connect_failed", error.to_string()))
}

#[cfg(windows)]
fn socket_address(uri: &Uri) -> Result<String, TransportError> {
    let authority = uri
        .authority()
        .ok_or_else(|| TransportError::new("transport.endpoint_invalid", "missing authority"))?;
    let host = authority.host();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(format!("{host}:{}", authority.port_u16().unwrap_or(443)))
}

#[cfg(windows)]
fn installed_certificate(
    fingerprint: &[u8; 32],
    expected_der: &[u8],
) -> Result<rustls_cng::cert::CertContext, TransportError> {
    let store = CertStore::open(CertStoreType::LocalMachine, "MY")
        .map_err(|_| identity_invalid("LocalMachine certificate store is unavailable"))?;
    let certificates = store
        .find_by_sha256(fingerprint)
        .map_err(|_| identity_invalid("installed certificate lookup failed"))?;
    let [certificate] = certificates.as_slice() else {
        return Err(identity_invalid(
            "installed certificate is missing or ambiguous",
        ));
    };
    if certificate.as_der() != expected_der {
        return Err(identity_invalid("installed certificate content mismatch"));
    }
    Ok(certificate.clone())
}

#[cfg(windows)]
fn open_cng_machine_key(key_name: &str) -> Result<NCryptKey, TransportError> {
    validate_cng_key_name(key_name)?;
    let mut provider = 0;
    if unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) } != 0 {
        return Err(identity_invalid("Microsoft Software KSP is unavailable"));
    }
    let wide_name = key_name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut key = 0;
    let status = unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            wide_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    let _ = unsafe { NCryptFreeObject(provider) };
    if status != 0 {
        return Err(identity_invalid("CNG machine key is unavailable"));
    }
    Ok(NCryptKey::new_owned(key))
}

#[cfg(windows)]
pub fn create_cng_machine_key(
    key_name: &str,
    authorized_user_sid: &str,
) -> Result<(), TransportError> {
    validate_cng_key_name(key_name)?;
    validate_windows_sid(authorized_user_sid)?;
    let mut provider = 0;
    if unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) } != 0 {
        return Err(identity_invalid("Microsoft Software KSP is unavailable"));
    }
    let wide_name = key_name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut handle = 0;
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut handle,
            BCRYPT_RSA_ALGORITHM,
            wide_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG,
        )
    };
    let _ = unsafe { NCryptFreeObject(provider) };
    if status != 0 {
        return Err(identity_invalid("CNG machine key creation failed"));
    }
    let key = NCryptKey::new_owned(handle);
    let descriptor = cng_security_descriptor(authorized_user_sid)?;
    let bits = 2048_u32;
    let export_policy = 0_u32;
    let usage = NCRYPT_ALLOW_SIGNING_FLAG;
    let security_flags = NCRYPT_PERSIST_FLAG | DACL_SECURITY_INFORMATION;
    let result = (|| {
        set_cng_property(&key, NCRYPT_LENGTH_PROPERTY, &bits.to_ne_bytes(), 0)?;
        set_cng_property(
            &key,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &export_policy.to_ne_bytes(),
            0,
        )?;
        set_cng_property(&key, NCRYPT_KEY_USAGE_PROPERTY, &usage.to_ne_bytes(), 0)?;
        if unsafe { NCryptFinalizeKey(key.inner(), NCRYPT_SILENT_FLAG) } != 0 {
            return Err(identity_invalid("CNG machine key finalization failed"));
        }
        set_cng_property(
            &key,
            NCRYPT_SECURITY_DESCR_PROPERTY,
            &descriptor,
            security_flags,
        )?;
        validate_cng_key_policy(&key, authorized_user_sid)
    })();
    if result.is_err() {
        let raw = key.inner();
        std::mem::forget(key);
        if unsafe { NCryptDeleteKey(raw, NCRYPT_SILENT_FLAG) } != 0 {
            let _ = unsafe { NCryptFreeObject(raw) };
        }
    }
    result
}

#[cfg(windows)]
pub fn validate_cng_machine_key_policy(
    key_name: &str,
    authorized_user_sid: &str,
) -> Result<(), TransportError> {
    let key = open_cng_machine_key(key_name)?;
    validate_cng_key_policy(&key, authorized_user_sid)
}

#[cfg(windows)]
pub fn cng_machine_rsa_public_key_der(key_name: &str) -> Result<Vec<u8>, TransportError> {
    let key = open_cng_machine_key(key_name)?;
    let (exponent, modulus) = cng_rsa_parts(&key)?;
    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bigint_bytes(&modulus, true);
            writer.next().write_bigint_bytes(&exponent, true);
        });
    }))
}

#[cfg(windows)]
pub fn sign_cng_machine_key_sha256(
    key_name: &str,
    message: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let key = open_cng_machine_key(key_name)?;
    let digest = Sha256::digest(message);
    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
    };
    let mut size = 0_u32;
    let status = unsafe {
        NCryptSignHash(
            key.inner(),
            (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
            digest.as_ptr(),
            digest.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut size,
            NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 || size == 0 || size > 1024 {
        return Err(identity_invalid("CNG signing failed"));
    }
    let mut signature = vec![0_u8; size as usize];
    let status = unsafe {
        NCryptSignHash(
            key.inner(),
            (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_mut_ptr(),
            signature.len() as u32,
            &mut size,
            NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    if status != 0 || size as usize != signature.len() {
        return Err(identity_invalid("CNG signing failed"));
    }
    Ok(signature)
}

#[cfg(windows)]
pub fn prove_cng_machine_key_signature(key_name: &str) -> Result<(), TransportError> {
    let key = open_cng_machine_key(key_name)?;
    let mut challenge = [0_u8; 32];
    if unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            challenge.as_mut_ptr(),
            challenge.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err(identity_invalid(
            "CNG signature challenge generation failed",
        ));
    }
    let signature = sign_cng_machine_key_sha256(key_name, &challenge)?;
    let public_blob = cng_rsa_public_blob(&key)?;
    let digest = Sha256::digest(challenge);
    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
    };
    let mut algorithm: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    if unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_RSA_ALGORITHM, std::ptr::null(), 0)
    } != 0
    {
        return Err(identity_invalid("RSA signature verifier is unavailable"));
    }
    let mut public_key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let imported = unsafe {
        BCryptImportKeyPair(
            algorithm,
            std::ptr::null_mut(),
            BCRYPT_RSAPUBLIC_BLOB,
            &mut public_key,
            public_blob.as_ptr(),
            public_blob.len() as u32,
            0,
        )
    };
    let verified = imported == 0
        && unsafe {
            BCryptVerifySignature(
                public_key,
                (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                BCRYPT_PAD_PKCS1,
            )
        } == 0;
    if !public_key.is_null() {
        let _ = unsafe { BCryptDestroyKey(public_key) };
    }
    let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
    verified
        .then_some(())
        .ok_or_else(|| identity_invalid("CNG signature challenge verification failed"))
}

#[cfg(windows)]
pub fn install_local_machine_certificate(
    certificate_pem: &[u8],
    key_name: &str,
    expected_fingerprint: &[u8; 32],
) -> Result<(), TransportError> {
    let (remaining, certificate) =
        parse_x509_pem(certificate_pem).map_err(|_| identity_invalid("invalid client PEM"))?;
    if !remaining.is_empty()
        || Sha256::digest(&certificate.contents).as_slice() != expected_fingerprint
    {
        return Err(identity_invalid("client certificate fingerprint mismatch"));
    }
    let existing = CertStore::open(CertStoreType::LocalMachine, "MY")
        .map_err(|_| identity_invalid("LocalMachine certificate store is unavailable"))?
        .find_by_sha256(expected_fingerprint)
        .map_err(|_| identity_invalid("installed certificate lookup failed"))?;
    if !existing.is_empty() {
        return Err(identity_invalid("client certificate already exists"));
    }
    let store_name = "MY".encode_utf16().chain([0]).collect::<Vec<_>>();
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            store_name.as_ptr().cast(),
        )
    };
    if store.is_null() {
        return Err(identity_invalid(
            "LocalMachine certificate store is unavailable",
        ));
    }
    let mut context = std::ptr::null_mut();
    let added = unsafe {
        CertAddEncodedCertificateToStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            certificate.contents.as_ptr(),
            certificate.contents.len() as u32,
            CERT_STORE_ADD_NEW,
            &mut context,
        )
    } != 0;
    if !added || context.is_null() {
        let _ = unsafe { CertCloseStore(store, 0) };
        return Err(identity_invalid("client certificate installation failed"));
    }
    let mut container = key_name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut provider = "Microsoft Software Key Storage Provider"
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    let key_info = CRYPT_KEY_PROV_INFO {
        pwszContainerName: container.as_mut_ptr(),
        pwszProvName: provider.as_mut_ptr(),
        dwProvType: 0,
        dwFlags: CRYPT_MACHINE_KEYSET,
        cProvParam: 0,
        rgProvParam: std::ptr::null_mut(),
        dwKeySpec: CERT_NCRYPT_KEY_SPEC,
    };
    let associated = unsafe {
        CertSetCertificateContextProperty(
            context,
            CERT_KEY_PROV_INFO_PROP_ID,
            0,
            (&key_info as *const CRYPT_KEY_PROV_INFO).cast(),
        )
    } != 0;
    if !associated {
        let _ = unsafe { CertDeleteCertificateFromStore(context) };
        let _ = unsafe { CertCloseStore(store, 0) };
        return Err(identity_invalid(
            "client certificate key association failed",
        ));
    }
    let _ = unsafe { CertFreeCertificateContext(context) };
    let _ = unsafe { CertCloseStore(store, 0) };
    Ok(())
}

#[cfg(windows)]
fn set_cng_property(
    key: &NCryptKey,
    property: windows_sys::core::PCWSTR,
    value: &[u8],
    flags: u32,
) -> Result<(), TransportError> {
    if unsafe {
        NCryptSetProperty(
            key.inner(),
            property,
            value.as_ptr(),
            value.len() as u32,
            flags,
        )
    } != 0
    {
        return Err(identity_invalid("CNG key property could not be applied"));
    }
    Ok(())
}

#[cfg(windows)]
fn cng_security_descriptor(authorized_user_sid: &str) -> Result<Vec<u8>, TransportError> {
    validate_windows_sid(authorized_user_sid)?;
    let sddl = format!("D:P(A;;0x1f019b;;;SY)(A;;0x1f019b;;;{authorized_user_sid})");
    let wide = sddl.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(identity_invalid("CNG key security descriptor is invalid"));
    }
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    let bytes = if length == 0 {
        Err(identity_invalid("CNG key security descriptor is empty"))
    } else {
        Ok(unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) }.to_vec())
    };
    let _ = unsafe { LocalFree(descriptor) };
    bytes
}

#[cfg(windows)]
fn validate_cng_key_policy(
    key: &NCryptKey,
    authorized_user_sid: &str,
) -> Result<(), TransportError> {
    if key.algorithm_group().ok() != Some(AlgorithmGroup::Rsa) {
        return Err(identity_invalid("CNG key algorithm policy is invalid"));
    }
    if key.bits().ok() != Some(2048) {
        return Err(identity_invalid("CNG key length policy is invalid"));
    }
    if cng_u32_property(key, NCRYPT_EXPORT_POLICY_PROPERTY)? != 0 {
        return Err(identity_invalid("CNG key export policy is invalid"));
    }
    if cng_u32_property(key, NCRYPT_KEY_USAGE_PROPERTY)? != NCRYPT_ALLOW_SIGNING_FLAG {
        return Err(identity_invalid("CNG key usage policy is invalid"));
    }
    if !cng_key_security_matches(key, authorized_user_sid)? {
        return Err(identity_invalid("CNG key DACL policy is invalid"));
    }
    Ok(())
}

#[cfg(windows)]
fn cng_key_security_matches(
    key: &NCryptKey,
    authorized_user_sid: &str,
) -> Result<bool, TransportError> {
    validate_windows_sid(authorized_user_sid)?;
    let flags = DACL_SECURITY_INFORMATION;
    let mut size = 0_u32;
    if unsafe {
        NCryptGetProperty(
            key.inner(),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            std::ptr::null_mut(),
            0,
            &mut size,
            flags,
        )
    } != 0
        || size == 0
        || size > 64 * 1024
    {
        return Err(identity_invalid(
            "CNG key security descriptor is unavailable",
        ));
    }
    let mut descriptor = vec![0_u8; size as usize];
    if unsafe {
        NCryptGetProperty(
            key.inner(),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            descriptor.as_mut_ptr(),
            descriptor.len() as u32,
            &mut size,
            flags,
        )
    } != 0
        || size as usize != descriptor.len()
    {
        return Err(identity_invalid(
            "CNG key security descriptor is unavailable",
        ));
    }
    let mut expected_descriptor = cng_security_descriptor(authorized_user_sid)?;
    if cng_security_descriptors_match(
        descriptor.as_mut_ptr().cast(),
        expected_descriptor.as_mut_ptr().cast(),
    )? {
        Ok(true)
    } else {
        let value = security_descriptor_to_sddl(&mut descriptor, flags)?;
        Err(identity_invalid(format!(
            "CNG key DACL policy is invalid ({})",
            cng_security_sddl_summary(&value, authorized_user_sid)
        )))
    }
}

#[cfg(windows)]
fn security_descriptor_to_sddl(
    descriptor: &mut [u8],
    flags: u32,
) -> Result<String, TransportError> {
    let mut text = std::ptr::null_mut();
    let mut text_length = 0_u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.as_mut_ptr().cast(),
            SDDL_REVISION_1,
            flags,
            &mut text,
            &mut text_length,
        )
    } == 0
        || text.is_null()
        || text_length == 0
    {
        return Err(identity_invalid(
            "CNG key security descriptor cannot be verified",
        ));
    }
    let text_slice = unsafe { std::slice::from_raw_parts(text, text_length as usize) };
    let text_slice = &text_slice[..text_slice
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(text_slice.len())];
    let value = String::from_utf16(text_slice)
        .map_err(|_| identity_invalid("CNG key security descriptor cannot be verified"));
    let _ = unsafe { LocalFree(text.cast()) };
    value
}

#[cfg(windows)]
fn cng_security_descriptors_match(
    actual: PSECURITY_DESCRIPTOR,
    expected: PSECURITY_DESCRIPTOR,
) -> Result<bool, TransportError> {
    let actual = cng_dacl_sids(actual)?;
    let expected = cng_dacl_sids(expected)?;
    Ok((unsafe { EqualSid(actual[0], expected[0]) } != 0
        && unsafe { EqualSid(actual[1], expected[1]) } != 0)
        || (unsafe { EqualSid(actual[0], expected[1]) } != 0
            && unsafe { EqualSid(actual[1], expected[0]) } != 0))
}

#[cfg(windows)]
fn cng_dacl_sids(descriptor: PSECURITY_DESCRIPTOR) -> Result<[PSID; 2], TransportError> {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(identity_invalid("CNG key DACL policy is invalid"));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
        || unsafe { (*acl).AceCount } != 2
    {
        return Err(identity_invalid("CNG key DACL policy is invalid"));
    }
    let mut sids: [PSID; 2] = [std::ptr::null_mut(); 2];
    for (index, sid) in sids.iter_mut().enumerate() {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut raw) } == 0 || raw.is_null() {
            return Err(identity_invalid("CNG key DACL policy is invalid"));
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceType != 0
            || header.AceFlags != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(identity_invalid("CNG key DACL policy is invalid"));
        }
        let ace = raw.cast::<ACCESS_ALLOWED_ACE>();
        let mask = unsafe { (*ace).Mask };
        if mask != 0x1f019b {
            return Err(identity_invalid(format!(
                "CNG key DACL policy is invalid (reason=mask,index={index},value=0x{mask:08x})"
            )));
        }
        *sid = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast() };
        let sid_offset = std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>();
        let sid_bytes = usize::from(header.AceSize).saturating_sub(sid_offset);
        if sid_bytes < 8
            || 8 + 4 * unsafe { *sid.cast::<u8>().add(1) } as usize != sid_bytes
            || unsafe { IsValidSid(*sid) } == 0
        {
            return Err(identity_invalid(format!(
                "CNG key DACL policy is invalid (reason=sid_shape,index={index},bytes={sid_bytes})"
            )));
        }
    }
    Ok(sids)
}

#[cfg(any(windows, test))]
fn cng_security_sddl_summary(value: &str, authorized_user_sid: &str) -> String {
    let dacl_flags = value
        .strip_prefix("D:")
        .map(|value| value.split_once('(').map_or(value, |(flags, _)| flags))
        .unwrap_or("");
    let mut ace_count = 0;
    let mut summaries = Vec::new();
    for raw in value.split('(').skip(1) {
        ace_count += 1;
        if summaries.len() == 4 {
            continue;
        }
        let Some(body) = raw.strip_suffix(')') else {
            summaries.push("invalid".to_owned());
            continue;
        };
        let fields = body.split(';').collect::<Vec<_>>();
        if fields.len() != 6 {
            summaries.push("invalid".to_owned());
            continue;
        }
        let rights = match fields[2] {
            "GA" => "GA",
            "FA" => "FA",
            value
                if value.strip_prefix("0x").is_some_and(|hex| {
                    !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                }) =>
            {
                "HEX"
            }
            _ => "OTHER",
        };
        let principal = if fields[5] == "SY" {
            "SYSTEM"
        } else if fields[5] == authorized_user_sid {
            "USER"
        } else {
            "OTHER"
        };
        summaries.push(format!(
            "allow={},flags_empty={},rights={rights},principal={principal}",
            fields[0] == "A",
            fields[1].is_empty()
        ));
    }
    format!(
        "protected={},auto_inherited={},ace_count={ace_count},aces=[{}]",
        dacl_flags.contains('P'),
        dacl_flags.contains("AI"),
        summaries.join("|")
    )
}

#[cfg(any(windows, test))]
fn validate_windows_sid(value: &str) -> Result<(), TransportError> {
    if value.len() > 184
        || value.strip_prefix("S-1-").is_none_or(|suffix| {
            suffix.is_empty()
                || !suffix.split('-').all(|component| {
                    !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
                })
        })
    {
        return Err(identity_invalid("invalid authorized Windows SID"));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_cng_key(
    key: &NCryptKey,
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    authorized_user_sid: &str,
) -> Result<(), TransportError> {
    validate_cng_key_policy(key, authorized_user_sid)?;
    if !cng_public_key_matches(key, certificate)? {
        return Err(TransportError::new(
            "transport.identity_key_mismatch",
            "CNG key properties or public key do not match the client certificate",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn cng_u32_property(
    key: &NCryptKey,
    property: windows_sys::core::PCWSTR,
) -> Result<u32, TransportError> {
    let mut value = 0_u32;
    let mut size = 0_u32;
    let status = unsafe {
        NCryptGetProperty(
            key.inner(),
            property,
            (&mut value as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut size,
            0,
        )
    };
    if status != 0 || size != std::mem::size_of::<u32>() as u32 {
        return Err(identity_invalid("CNG key property is unavailable"));
    }
    Ok(value)
}

#[cfg(windows)]
fn cng_public_key_matches(
    key: &NCryptKey,
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<bool, TransportError> {
    let (exponent, modulus) = cng_rsa_parts(key)?;
    let parsed = certificate
        .public_key()
        .parsed()
        .map_err(|_| identity_invalid("client certificate public key is invalid"))?;
    let PublicKey::RSA(rsa) = parsed else {
        return Ok(false);
    };
    Ok(strip_leading_zero(rsa.exponent) == [0x01, 0x00, 0x01]
        && strip_leading_zero(rsa.exponent) == strip_leading_zero(&exponent)
        && strip_leading_zero(rsa.modulus) == strip_leading_zero(&modulus))
}

#[cfg(windows)]
fn cng_rsa_parts(key: &NCryptKey) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let blob = cng_rsa_public_blob(key)?;
    let header_size = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
    let header = unsafe { std::ptr::read_unaligned(blob.as_ptr().cast::<BCRYPT_RSAKEY_BLOB>()) };
    let exponent_end = header_size + header.cbPublicExp as usize;
    let modulus_end = exponent_end + header.cbModulus as usize;
    Ok((
        blob[header_size..exponent_end].to_vec(),
        blob[exponent_end..modulus_end].to_vec(),
    ))
}

#[cfg(windows)]
fn cng_rsa_public_blob(key: &NCryptKey) -> Result<Vec<u8>, TransportError> {
    let mut size = 0_u32;
    if unsafe {
        NCryptExportKey(
            key.inner(),
            0,
            BCRYPT_RSAPUBLIC_BLOB,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut size,
            0,
        )
    } != 0
    {
        return Err(identity_invalid("CNG public key export failed"));
    }
    let mut blob = vec![0_u8; size as usize];
    if unsafe {
        NCryptExportKey(
            key.inner(),
            0,
            BCRYPT_RSAPUBLIC_BLOB,
            std::ptr::null(),
            blob.as_mut_ptr(),
            size,
            &mut size,
            0,
        )
    } != 0
    {
        return Err(identity_invalid("CNG public key export failed"));
    }
    let header_size = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
    if blob.len() < header_size {
        return Err(identity_invalid("CNG public key blob is truncated"));
    }
    let header = unsafe { std::ptr::read_unaligned(blob.as_ptr().cast::<BCRYPT_RSAKEY_BLOB>()) };
    let exponent_end = header_size + header.cbPublicExp as usize;
    let modulus_end = exponent_end + header.cbModulus as usize;
    if header.Magic != BCRYPT_RSAPUBLIC_MAGIC
        || header.BitLength != 2048
        || modulus_end != blob.len()
    {
        return Err(identity_invalid("CNG public key blob is invalid"));
    }
    Ok(blob)
}

#[cfg(windows)]
fn strip_leading_zero(mut value: &[u8]) -> &[u8] {
    while value.first() == Some(&0) {
        value = &value[1..];
    }
    value
}

#[cfg(windows)]
fn validate_cng_key_name(key_name: &str) -> Result<(), TransportError> {
    let suffix = key_name.strip_prefix("FairyPam.Agent.").unwrap_or_default();
    if suffix.is_empty()
        || key_name.len() > 128
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return Err(identity_invalid("invalid CNG key name"));
    }
    Ok(())
}

#[cfg(windows)]
pub fn delete_cng_machine_key(key_name: &str) -> Result<(), TransportError> {
    validate_cng_key_name(key_name)?;
    let mut provider = 0;
    if unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) } != 0 {
        return Err(identity_invalid("Microsoft Software KSP is unavailable"));
    }
    let wide_name = key_name.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut handle = 0;
    let status = unsafe {
        NCryptOpenKey(
            provider,
            &mut handle,
            wide_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    let _ = unsafe { NCryptFreeObject(provider) };
    if matches!(status, NTE_BAD_KEYSET | NTE_NOT_FOUND) {
        return Ok(());
    }
    if status != 0 {
        return Err(identity_invalid("CNG machine key is unavailable"));
    }
    if unsafe { NCryptDeleteKey(handle, NCRYPT_SILENT_FLAG) } != 0 {
        let _ = unsafe { NCryptFreeObject(handle) };
        return Err(identity_invalid("CNG machine key deletion failed"));
    }
    Ok(())
}

#[cfg(windows)]
pub fn delete_local_machine_certificate(fingerprint: &[u8; 32]) -> Result<(), TransportError> {
    let store = CertStore::open(CertStoreType::LocalMachine, "MY")
        .map_err(|_| identity_invalid("LocalMachine certificate store is unavailable"))?;
    let certificates = store
        .find_by_sha256(fingerprint)
        .map_err(|_| identity_invalid("installed certificate lookup failed"))?;
    let Some(certificate) = certificates.first() else {
        return Ok(());
    };
    if certificates.len() != 1 {
        return Err(identity_invalid("installed certificate is ambiguous"));
    }
    let duplicate = unsafe { CertDuplicateCertificateContext(certificate.inner()) };
    if duplicate.is_null() || unsafe { CertDeleteCertificateFromStore(duplicate) } == 0 {
        return Err(identity_invalid("installed certificate deletion failed"));
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
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(5)))
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
            identity_key: IdentityKey::Pem("missing-key.pem".into()),
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
    fn windows_sid_validation_rejects_sddl_injection() {
        assert!(validate_windows_sid("S-1-5-21-1-2-3-1001").is_ok());
        for rejected in ["S-1-", "S-1-5--21", "S-1-5)(A;;GA;;;BU"] {
            assert_eq!(
                validate_windows_sid(rejected).unwrap_err().code(),
                "transport.identity_invalid"
            );
        }
    }

    #[test]
    fn sddl_diagnostic_never_contains_principal_values() {
        let summary = cng_security_sddl_summary(
            "D:P(A;;0xf01ff;;;S-1-0x28651FE848-12-72-9-110)(A;;GR;;;S-1-5-32-545)",
            "S-1-5-32-545",
        );
        assert_eq!(
            summary,
            "protected=true,auto_inherited=false,ace_count=2,aces=[allow=true,flags_empty=true,rights=HEX,principal=OTHER|allow=true,flags_empty=true,rights=OTHER,principal=USER]"
        );
        assert!(!summary.contains("S-1-"));
        assert!(!summary.contains("28651FE848"));
        for (flags, expected) in [
            ("AI", "protected=false,auto_inherited=true"),
            ("PAI", "protected=true,auto_inherited=true"),
            ("P", "protected=true,auto_inherited=false"),
        ] {
            let summary =
                cng_security_sddl_summary(&format!("D:{flags}(A;;GA;;;SY)"), "S-1-5-32-545");
            assert!(summary.starts_with(expected));
            let empty_summary = cng_security_sddl_summary(&format!("D:{flags}"), "S-1-5-32-545");
            assert!(empty_summary.starts_with(expected));
            assert!(empty_summary.contains("ace_count=0"));
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
            identity_key: IdentityKey::Pem(private_key),
            connect_timeout: Duration::from_secs(1),
        };

        validate_transport_config(&config).unwrap();
        fs::write(
            match &config.identity_key {
                IdentityKey::Pem(path) => path,
                #[cfg(windows)]
                IdentityKey::CngMachine { .. } => unreachable!(),
            },
            rcgen::KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        let mismatch = validate_transport_config(&config).unwrap_err();
        assert_eq!(mismatch.code(), "transport.identity_key_mismatch");
        let IdentityKey::Pem(key_path) = &config.identity_key else {
            unreachable!()
        };
        fs::write(key_path, "not a private key").unwrap();
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
            identity_key: IdentityKey::Pem(private_key),
            connect_timeout: Duration::from_secs(1),
        };

        let error = validate_transport_config(&config).unwrap_err();

        assert_eq!(error.code(), "transport.identity_invalid");
    }
}
