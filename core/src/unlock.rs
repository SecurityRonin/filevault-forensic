//! The CoreStorage / FileVault key hierarchy (RustCrypto — never hand-rolled).
//!
//! ```text
//! passphrase_key = PBKDF2-HMAC-SHA256(password, salt, iterations, 16)
//! KEK            = AES-KW-unwrap(wrapped_kek, passphrase_key)   (RFC 3394, 24->16)
//! VMK            = AES-KW-unwrap(wrapped_vmk, KEK)              (24->16)
//! tweak_key      = SHA256(VMK || familyUUID_bytes)[0..16]
//! ```
//!
//! Every value here is checked against the dfvfs `fvdetest` ground truth in
//! `docs/RESEARCH.md` (VMK `d0d9c323…`, tweak_key `53a17ba3…`).

use aes_kw::KekAes128;
use hmac::Hmac;
use sha2::{Digest, Sha256};

use crate::context::EncryptionContext;
use crate::error::FileVaultError;

/// The volume master key and its XTS tweak key, derived from a password.
#[derive(Debug, Clone)]
pub struct VolumeKeys {
    /// AES-XTS key1 for LV sector decryption.
    pub vmk: [u8; 16],
    /// AES-XTS key2 (tweak key) for LV sector decryption.
    pub tweak_key: [u8; 16],
}

/// Derive the PBKDF2 passphrase key (16 bytes) from the password and context.
#[must_use]
pub fn passphrase_key(password: &str, salt: &[u8; 16], iterations: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    // pbkdf2 with an explicit round count; a zero count would be nonsensical but
    // is bounded here to at least 1 so the KDF always runs.
    let rounds = iterations.max(1);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, rounds, &mut out)
        .map_err(|_| ())
        .ok();
    out
}

/// Unwrap a 24-byte RFC 3394 wrapped key with `kek`, returning the 16-byte key.
///
/// # Errors
/// [`FileVaultError::KeyUnwrap`] if the integrity check fails (wrong key /
/// corrupt input) — the "wrong password" signal at the KEK step.
fn aes_kw_unwrap(
    kek_bytes: &[u8; 16],
    wrapped: &[u8; 24],
    what: &'static str,
) -> Result<[u8; 16], FileVaultError> {
    let kek = KekAes128::from(*kek_bytes);
    let mut out = [0u8; 16];
    kek.unwrap(wrapped, &mut out)
        .map_err(|_| FileVaultError::KeyUnwrap { what })?;
    Ok(out)
}

/// Run the full key hierarchy for a password against an encryption context and
/// family UUID, returning the LV keys.
///
/// # Errors
/// [`FileVaultError::KeyUnwrap`] if the password is wrong (KEK unwrap fails) or
/// the VMK unwrap fails.
pub fn derive_volume_keys(
    password: &str,
    context: &EncryptionContext,
    family_uuid_bytes: &[u8; 16],
) -> Result<VolumeKeys, FileVaultError> {
        let _ = (password, context, family_uuid_bytes); return Err(FileVaultError::KeyUnwrap { what: "RED" });
    }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::EncryptionContext;

    fn hexn<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    // Ground truth: RESEARCH.md Tier-2 table (dfvfs fvdetest, password fvde-TEST).
    #[test]
    fn pbkdf2_matches_ground_truth() {
        let salt: [u8; 16] = hexn("9bfcf480e4d9ad0eddd9ac6f47b85955");
        let pk = passphrase_key("fvde-TEST", &salt, 90506);
        assert_eq!(pk, hexn::<16>("0ec2849349f914e8bdbc189ac09c8bc7"));
    }

    #[test]
    fn aes_kw_unwrap_kek_matches_ground_truth() {
        let pk: [u8; 16] = hexn("0ec2849349f914e8bdbc189ac09c8bc7");
        let wrapped: [u8; 24] = hexn("ebbc1f64b9684eb4b26bfba3f85578677bab8cfafaf7b2c1");
        let kek = aes_kw_unwrap(&pk, &wrapped, "KEK").unwrap();
        assert_eq!(kek, hexn::<16>("a2543f0b8a6fc5cf2eaf7e76c95ef49c"));
    }

    #[test]
    fn aes_kw_unwrap_vmk_matches_ground_truth() {
        let kek: [u8; 16] = hexn("a2543f0b8a6fc5cf2eaf7e76c95ef49c");
        let wrapped: [u8; 24] = hexn("9a5b30e99f902ed8e2f03989e5f9c1543ed60512aa1dc9d1");
        let vmk = aes_kw_unwrap(&kek, &wrapped, "VMK").unwrap();
        assert_eq!(vmk, hexn::<16>("d0d9c323197c62401c6e6b48f1c0f9d7"));
    }

    #[test]
    fn wrong_key_fails_unwrap_loudly() {
        let bad: [u8; 16] = [0u8; 16];
        let wrapped: [u8; 24] = hexn("ebbc1f64b9684eb4b26bfba3f85578677bab8cfafaf7b2c1");
        assert!(matches!(
            aes_kw_unwrap(&bad, &wrapped, "KEK"),
            Err(FileVaultError::KeyUnwrap { what: "KEK" })
        ));
    }

    #[test]
    fn full_hierarchy_derives_vmk_and_tweak_key() {
        let ctx = EncryptionContext {
            salt: hexn("9bfcf480e4d9ad0eddd9ac6f47b85955"),
            iterations: 90506,
            wrapped_kek: hexn("ebbc1f64b9684eb4b26bfba3f85578677bab8cfafaf7b2c1"),
            wrapped_vmk: hexn("9a5b30e99f902ed8e2f03989e5f9c1543ed60512aa1dc9d1"),
            protectors: Vec::new(),
            conversion_status: None,
        };
        // familyUUID 1F01CA34-5F6C-4123-AC0C-B0A256889DB2 in canonical byte order.
        let family: [u8; 16] = hexn("1f01ca345f6c4123ac0cb0a256889db2");
        let keys = derive_volume_keys("fvde-TEST", &ctx, &family).unwrap();
        assert_eq!(keys.vmk, hexn::<16>("d0d9c323197c62401c6e6b48f1c0f9d7"));
        assert_eq!(
            keys.tweak_key,
            hexn::<16>("53a17ba3213ec213bedcc34fe4e239af")
        );
    }

    #[test]
    fn wrong_password_surfaces_key_unwrap_error() {
        let ctx = EncryptionContext {
            salt: hexn("9bfcf480e4d9ad0eddd9ac6f47b85955"),
            iterations: 90506,
            wrapped_kek: hexn("ebbc1f64b9684eb4b26bfba3f85578677bab8cfafaf7b2c1"),
            wrapped_vmk: hexn("9a5b30e99f902ed8e2f03989e5f9c1543ed60512aa1dc9d1"),
            protectors: Vec::new(),
            conversion_status: None,
        };
        let family: [u8; 16] = hexn("1f01ca345f6c4123ac0cb0a256889db2");
        assert!(matches!(
            derive_volume_keys("wrong-password", &ctx, &family),
            Err(FileVaultError::KeyUnwrap { .. })
        ));
    }
}
