//! TLS configuration for XRPL peer connections.
//!
//! Each node generates a self-signed ECDSA-P256 certificate for the TLS layer.
//! The XRPL node identity key (secp256k1) is separate — after TLS is established,
//! each peer signs the TLS session's keying material with their identity key and
//! advertises it in the HTTP upgrade headers as `Session-Signature`.
//!
//! Peers verify identity via `Session-Signature` rather than the TLS certificate
//! chain, so `AcceptAnyCert` skips certificate validation while still preserving
//! encryption and session binding.

use anyhow::Result;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::Arc;

// ── TLS configuration ─────────────────────────────────────────────────────────

/// Rustls-based TLS configs. Peer connections use `OpenSslConfig` for
/// rippled-compatible session hash computation, while this remains available
/// for non-peer TLS uses such as WebSocket TLS.
pub struct TlsConfig {
    pub server: Arc<ServerConfig>,
    pub client: Arc<ClientConfig>,
}

impl TlsConfig {
    /// Generate a self-signed ECDSA-P256 certificate and build TLS configs.
    pub fn new_self_signed() -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Generate a self-signed certificate
        let cert_gen = rcgen::generate_simple_self_signed(vec!["xledgrs".to_string()])?;
        let cert_der = CertificateDer::from(cert_gen.serialize_der()?);
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert_gen.serialize_private_key_der(),
        ));

        // Server config — no client cert required
        let server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;

        // Client config does not verify certificate chains; identity is proven via Session-Signature.
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();

        Ok(Self {
            server: Arc::new(server),
            client: Arc::new(client),
        })
    }
}

// ── OpenSSL-based TLS configuration ──────────────────────────────────────────
//
// Used for peer-to-peer connections to compute the same session hash from TLS
// Finished messages that rippled uses.

/// OpenSSL TLS configs for peer connections (inbound + outbound).
pub struct OpenSslConfig {
    /// For accepting inbound peer connections.
    pub acceptor: SslAcceptor,
    /// For initiating outbound peer connections.
    pub connector_ctx: SslContext,
}

impl OpenSslConfig {
    /// Generate a self-signed ECDSA-P256 certificate and build OpenSSL configs.
    pub fn new_self_signed() -> Result<Self> {
        // Generate EC P-256 key
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        // Build self-signed X509 certificate
        let mut builder = X509::builder()?;
        builder.set_version(2)?; // X509 v3

        let serial = {
            let mut serial = openssl::bn::BigNum::new()?;
            serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        builder.set_serial_number(&serial)?;

        let mut name = openssl::x509::X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "xledgrs")?;
        let name = name.build();
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;

        builder.set_pubkey(&pkey)?;

        // Valid for 1 year
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
        let cert = builder.build();

        // Build SslAcceptor (for inbound peer connections)
        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        acceptor_builder.set_private_key(&pkey)?;
        acceptor_builder.set_certificate(&cert)?;
        acceptor_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        // Cap at TLS 1.2 — rippled's makeSharedValue uses TLS Finished messages
        // which behave differently in TLS 1.3. Must match the connector setting.
        acceptor_builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        let acceptor = acceptor_builder.build();

        // Build SslContext (for outbound peer connections)
        // Force TLS 1.2 max — rippled's makeSharedValue uses TLS Finished messages
        // which behave differently in TLS 1.3 vs 1.2. Both sides must agree on the
        // same Finished message content for the shared value to match.
        let mut connector_builder = SslContext::builder(SslMethod::tls_client())?;
        connector_builder.set_verify(SslVerifyMode::NONE);
        connector_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        connector_builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        connector_builder.set_certificate(&cert)?;
        connector_builder.set_private_key(&pkey)?;
        let connector_ctx = connector_builder.build();

        Ok(Self {
            acceptor,
            connector_ctx,
        })
    }
}

/// Compute the XRPL shared value from a completed TLS connection.
///
/// This mirrors rippled's `makeSharedValue()`: XOR the SHA-512 hashes of each
/// side's TLS Finished message, then hash the result and return the first 32
/// bytes.
pub fn make_shared_value(ssl: &openssl::ssl::SslRef) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha512};

    let mut buf1 = [0u8; 128];
    let len1 = ssl.finished(&mut buf1);
    if len1 < 12 {
        return None;
    }
    let cookie1: [u8; 64] = Sha512::digest(&buf1[..len1]).into();

    let mut buf2 = [0u8; 128];
    let len2 = ssl.peer_finished(&mut buf2);
    if len2 < 12 {
        return None;
    }
    let cookie2: [u8; 64] = Sha512::digest(&buf2[..len2]).into();

    let mut xored = [0u8; 64];
    for i in 0..64 {
        xored[i] = cookie1[i] ^ cookie2[i];
    }

    if xored.iter().all(|&b| b == 0) {
        return None;
    }

    let full = Sha512::digest(&xored);
    let mut result = [0u8; 32];
    result.copy_from_slice(&full[..32]);
    Some(result)
}

// ── Certificate verifier ──────────────────────────────────────────────────────
//
// XRPL uses ephemeral self-signed certs; CA-based PKI is not used.
// Identity verification happens at the application layer via Session-Signature.

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
