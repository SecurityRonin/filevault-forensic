//! `forensic-vfs` [`CryptoLayer`] adapter for FileVault / CoreStorage, behind the
//! `vfs` feature.
//!
//! Wraps an encrypted FileVault logical volume (a parent [`ImageSource`]) and,
//! given a password, presents the **decrypted** volume as a [`DynSource`] a
//! normal filesystem mounts unchanged. The decryption is filevault-core's own
//! (audited RustCrypto AES-XTS); this module only wires the contract.

use std::io::{Read, Seek};
use std::sync::{Arc, Mutex, PoisonError};

use forensic_vfs::adapters::SourceCursor;
use forensic_vfs::{
    Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource, ImageSource, VfsError,
    VfsResult,
};

use crate::{FileVaultError, FileVaultVolume};

/// A FileVault-encrypted logical volume presented as a [`CryptoLayer`].
pub struct FileVaultLayer {
    encrypted: DynSource,
    len: u64,
}

impl FileVaultLayer {
    /// Wrap an encrypted FileVault/CoreStorage volume (the ciphertext byte source).
    pub fn new(encrypted: DynSource) -> Self {
        let len = encrypted.len();
        Self { encrypted, len }
    }
}

impl CryptoLayer for FileVaultLayer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::FileVault
    }

    fn open(&self, creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        let cands = creds.credentials_for(CryptoScheme::FileVault, "");
        if cands.is_empty() {
            return Err(VfsError::NeedCredentials {
                scheme: "filevault",
                target: String::new(),
            });
        }
        // FileVault is unlocked by a volume password; try each offered one over a
        // fresh Read+Seek view of the ciphertext (unlock consumes the reader).
        let mut last_err = None;
        for cred in &cands {
            let Credential::Password(p) = cred else {
                continue; // only a password protector is wired here
            };
            let cursor = SourceCursor::new(Arc::clone(&self.encrypted), 0, self.len);
            match FileVaultVolume::unlock_with_password(cursor, p) {
                Ok(vol) => return Ok(Arc::new(FileVaultSource::new(vol))),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.as_ref().map_or(
            VfsError::NeedCredentials {
                scheme: "filevault",
                target: String::new(),
            },
            map_fvde_err,
        ))
    }
}

/// Translate a filevault-core error into the VFS error type (a bad password / bad
/// header is a loud [`VfsError::Decode`]).
fn map_fvde_err(e: &FileVaultError) -> VfsError {
    VfsError::Decode {
        layer: "filevault",
        offset: 0,
        detail: e.to_string(),
        bytes: forensic_vfs::SmallHex::new(&[]),
    }
}

/// A decrypted FileVault volume presented as a read-only [`ImageSource`]. Reads
/// serialize through a poison-recovering `Mutex` (the reader advances a cursor).
struct FileVaultSource<R: Read + Seek> {
    inner: Mutex<FileVaultVolume<R>>,
    len: u64,
}

impl<R: Read + Seek> FileVaultSource<R> {
    fn new(vol: FileVaultVolume<R>) -> Self {
        let len = vol.size();
        Self {
            inner: Mutex::new(vol),
            len,
        }
    }
}

impl<R: Read + Seek + Send> ImageSource for FileVaultSource<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let avail = self.len.saturating_sub(offset);
        if avail == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(avail) as usize;
        let Some(dst) = buf.get_mut(..want) else {
            return Ok(0); // cov:unreachable: want <= buf.len() by the min above
        };
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard.read_at(offset, dst).map_err(|e| map_fvde_err(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::FileVaultLayer;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    struct FixedCreds(Vec<Credential>);
    impl CredentialSource for FixedCreds {
        fn credentials_for(&self, _scheme: CryptoScheme, _target: &str) -> Vec<Credential> {
            self.0.clone()
        }
    }

    /// The real dfVFS `fvdetest` CoreStorage volume (password `fvde-TEST`), carved
    /// to /tmp (env `FVDE_ORACLE_IMAGE`, default path). Ground truth from pyfvde:
    /// LV size 167,772,160; decrypted sector at LV offset 1024 has the SHA-256
    /// below. Skips cleanly if the image is absent.
    fn encrypted() -> Option<DynSource> {
        let path = std::env::var("FVDE_ORACLE_IMAGE")
            .unwrap_or_else(|_| "/tmp/fvde-oracle/fvde_cs_p1.raw".to_string());
        let src = FileSource::open(&path).ok()?;
        Some(Arc::new(src))
    }

    fn sha256_hex(data: &[u8]) -> String {
        use std::fmt::Write;
        Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn filevault_cryptolayer_decrypts_fvdetest() {
        let Some(enc) = encrypted() else {
            eprintln!("skip: no FileVault image (set FVDE_ORACLE_IMAGE)");
            return;
        };
        let layer = FileVaultLayer::new(enc);
        assert_eq!(layer.scheme(), CryptoScheme::FileVault);

        let creds = FixedCreds(vec![Credential::Password("fvde-TEST".to_string())]);
        let dec: DynSource = layer.open(&creds).expect("unlock fvdetest");
        assert_eq!(dec.len(), 167_772_160, "LV size (pyfvde ground truth)");

        // Decrypted sector at LV offset 1024 — pyfvde-derived SHA-256, non-zero
        // content (proves the wiring reaches real AES-XTS plaintext).
        let mut sector = [0u8; 512];
        assert_eq!(dec.read_at(1024, &mut sector).expect("read decrypted"), 512);
        assert_eq!(
            sha256_hex(&sector),
            "ebedb80407fc8bfdd3cce9c68de94efece7ed748df1babf35deeaacf008990af"
        );

        // No credentials offered → NeedCredentials, never a guess or panic.
        assert!(layer.open(&FixedCreds(vec![])).is_err());
    }
}
