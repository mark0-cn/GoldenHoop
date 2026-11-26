//! Private signing material stays in trusted memory. Only the public CA is
//! exported to a workload; startup never silently creates a replacement CA.
use crate::{Secret, canonical_host, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaMaterial {
    pub certificate_pem: String,
    pub signing_key: Secret,
}

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
    expires: time::OffsetDateTime,
}

impl CertificateAuthority {
    /// Explicit provisioning operation; do not call as a missing-key fallback.
    pub fn generate() -> Result<CaMaterial, ApiError> {
        let key = KeyPair::generate()
            .map_err(|_| error(ErrorCode::Internal, "cannot generate private credential CA"))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|_| error(ErrorCode::Internal, "cannot initialize credential CA"))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
        params.not_after = params.not_before + time::Duration::days(366);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "GoldenHoop sandbox credential CA");
        let certificate = params
            .self_signed(&key)
            .map_err(|_| error(ErrorCode::Internal, "cannot sign credential CA"))?;
        Ok(CaMaterial {
            certificate_pem: certificate.pem(),
            signing_key: Secret(Zeroizing::new(key.serialize_pem())),
        })
    }

    pub fn open(material: CaMaterial) -> Result<Self, ApiError> {
        if material.certificate_pem.len() > 16 * 1024 {
            return Err(error(ErrorCode::Forbidden, "invalid credential CA"));
        }
        let (_, pem) = x509_parser::pem::parse_x509_pem(material.certificate_pem.as_bytes())
            .map_err(|_| error(ErrorCode::Forbidden, "invalid credential CA"))?;
        let (remaining, parsed) = X509Certificate::from_der(&pem.contents)
            .map_err(|_| error(ErrorCode::Forbidden, "invalid credential CA"))?;
        let ca = parsed
            .basic_constraints()
            .map_err(|_| error(ErrorCode::Forbidden, "invalid credential CA constraints"))?;
        let usage = parsed
            .key_usage()
            .map_err(|_| error(ErrorCode::Forbidden, "invalid credential CA key usage"))?;
        if !remaining.is_empty()
            || !parsed.validity().is_valid()
            || !ca.is_some_and(|v| v.value.ca)
            || !usage.is_some_and(|v| v.value.key_cert_sign())
        {
            return Err(error(
                ErrorCode::Forbidden,
                "credential CA is expired or cannot sign certificates",
            ));
        }
        let key = KeyPair::from_pem(&material.signing_key.0)
            .map_err(|_| error(ErrorCode::Forbidden, "invalid private credential CA key"))?;
        if key.subject_public_key_info() != parsed.public_key().raw {
            return Err(error(
                ErrorCode::Forbidden,
                "credential CA keypair mismatch",
            ));
        }
        let expires =
            time::OffsetDateTime::from_unix_timestamp(parsed.validity().not_after.timestamp())
                .map_err(|_| error(ErrorCode::Forbidden, "invalid credential CA validity"))?;
        let issuer = Issuer::from_ca_cert_pem(&material.certificate_pem, key)
            .map_err(|_| error(ErrorCode::Forbidden, "invalid credential CA issuer"))?;
        Ok(Self {
            issuer,
            certificate_pem: material.certificate_pem,
            certificate_der: CertificateDer::from(pem.contents),
            expires,
        })
    }

    pub fn public_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, ApiError> {
        let host = canonical_host(host)?;
        let now = time::OffsetDateTime::now_utc();
        if now >= self.expires {
            return Err(error(ErrorCode::Forbidden, "credential CA expired"));
        }
        let key = KeyPair::generate()
            .map_err(|_| error(ErrorCode::Internal, "cannot generate credential TLS leaf"))?;
        let mut params = CertificateParams::new(vec![host])
            .map_err(|_| error(ErrorCode::Forbidden, "invalid credential TLS identity"))?;
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = (now + time::Duration::days(1)).min(self.expires);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| error(ErrorCode::Internal, "cannot sign credential TLS leaf"))?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| error(ErrorCode::Internal, "credential TLS versions unavailable"))?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), self.certificate_der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .map_err(|_| {
                error(
                    ErrorCode::Internal,
                    "credential TLS configuration unavailable",
                )
            })?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}
