use crate::error;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use goldenhoop_protocol::{ApiError, ErrorCode};
use hmac::{Hmac, Mac};
use sha2_11::Sha256;
use std::{
    io::{Read, Write},
    path::Path,
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct VaultKey(Arc<Zeroizing<[u8; 32]>>);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn read_private_config(path: &Path) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let unavailable = || {
        error(
            ErrorCode::Forbidden,
            "private credential configuration is unavailable or unsafe",
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| unavailable())?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(unavailable());
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > 1024 * 1024 {
        return Err(unavailable());
    }
    Ok(bytes)
}

impl VaultKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(Zeroizing::new(bytes)))
    }

    /// Open an explicitly provisioned, private host key. Missing, symlinked,
    /// truncated and permissive files are refused; no silent replacement.
    pub fn open(path: &Path) -> Result<Self, ApiError> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(path)
            .map_err(|_| error(ErrorCode::Forbidden, "private vault key is unavailable"))?;
        let metadata = file.metadata().map_err(|_| {
            error(
                ErrorCode::Forbidden,
                "private vault key cannot be inspected",
            )
        })?;
        if !metadata.is_file() || metadata.len() != 32 {
            return Err(error(
                ErrorCode::Forbidden,
                "vault key must be a regular 32-byte file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(error(
                    ErrorCode::Forbidden,
                    "vault key must be private and owned by this service",
                ));
            }
        }
        let mut key = Zeroizing::new([0; 32]);
        file.read_exact(key.as_mut())
            .map_err(|_| error(ErrorCode::Forbidden, "private vault key cannot be read"))?;
        let mut extra = [0];
        if file
            .read(&mut extra)
            .map_err(|_| error(ErrorCode::Forbidden, "private vault key cannot be read"))?
            != 0
        {
            return Err(error(ErrorCode::Forbidden, "vault key changed during read"));
        }
        Ok(Self(Arc::new(key)))
    }

    pub fn create(path: &Path) -> Result<(), ApiError> {
        let mut key = Zeroizing::new([0; 32]);
        getrandom::fill(key.as_mut())
            .map_err(|_| error(ErrorCode::Internal, "system randomness is unavailable"))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(path).map_err(|_| {
            error(
                ErrorCode::Forbidden,
                "cannot create a new private vault key",
            )
        })?;
        file.write_all(key.as_ref())
            .and_then(|()| file.sync_all())
            .map_err(|_| error(ErrorCode::Internal, "vault key creation is incomplete"))
    }

    fn context(installation: Uuid, sandbox: Uuid, binding: Uuid, revision: u64) -> Vec<u8> {
        let mut value = b"GoldenHoop credential v1\0".to_vec();
        value.extend_from_slice(installation.as_bytes());
        value.extend_from_slice(sandbox.as_bytes());
        value.extend_from_slice(binding.as_bytes());
        value.extend_from_slice(&revision.to_be_bytes());
        value
    }

    pub fn seal(
        &self,
        installation: Uuid,
        sandbox: Uuid,
        binding: Uuid,
        revision: u64,
        plaintext: &[u8],
    ) -> Result<Sealed, ApiError> {
        if plaintext.len() > 64 * 1024 || revision == 0 {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid secret size or revision",
            ));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.0.as_ref().as_ref())
            .map_err(|_| error(ErrorCode::Internal, "vault encryption is unavailable"))?;
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce)
            .map_err(|_| error(ErrorCode::Internal, "system randomness is unavailable"))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &Self::context(installation, sandbox, binding, revision),
                },
            )
            .map_err(|_| error(ErrorCode::Internal, "vault encryption failed"))?;
        Ok(Sealed { nonce, ciphertext })
    }

    pub fn unseal(
        &self,
        installation: Uuid,
        sandbox: Uuid,
        binding: Uuid,
        revision: u64,
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        if sealed.ciphertext.len() > 64 * 1024 + 16 {
            return Err(error(ErrorCode::Forbidden, "invalid encrypted secret"));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.0.as_ref().as_ref())
            .map_err(|_| error(ErrorCode::Internal, "vault encryption is unavailable"))?;
        cipher
            .decrypt(
                &XNonce::from(sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &Self::context(installation, sandbox, binding, revision),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                error(
                    ErrorCode::Forbidden,
                    "credential identity or ciphertext authentication failed",
                )
            })
    }

    /// Keyed domain-separated fingerprints cannot be used as a public offline
    /// dictionary oracle for low-entropy values.
    pub fn fingerprint(&self, context: &[u8], value: &[u8]) -> Result<String, ApiError> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.0.as_ref().as_ref())
            .map_err(|_| error(ErrorCode::Internal, "vault fingerprint is unavailable"))?;
        mac.update(b"GoldenHoop credential fingerprint v1\0");
        mac.update(&(context.len() as u64).to_be_bytes());
        mac.update(context);
        mac.update(value);
        Ok(mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
}
