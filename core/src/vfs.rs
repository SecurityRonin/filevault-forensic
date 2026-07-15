//! `forensic-vfs` [`CryptoLayer`] adapter for FileVault / CoreStorage, behind the
//! `vfs` feature.
//!
//! Wraps an encrypted FileVault logical volume (a parent [`ImageSource`]) and,
//! given a password, presents the **decrypted** volume as a [`DynSource`] a
//! normal filesystem mounts unchanged. The decryption is filevault-core's own
//! (audited RustCrypto AES-XTS); this module only wires the contract.

use forensic_vfs::{CredentialSource, CryptoLayer, CryptoScheme, DynSource, VfsError, VfsResult};

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

    fn open(&self, _creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        // RED: decryption not wired yet.
        Err(VfsError::NeedCredentials {
            scheme: "filevault",
            target: String::new(),
        })
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
        Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
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
