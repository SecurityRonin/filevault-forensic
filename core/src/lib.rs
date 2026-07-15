//! # filevault — Apple CoreStorage / FileVault 2 (FVDE) reader & decryptor
//!
//! A panic-free, bounds-checked decryptor for CoreStorage / FileVault 2 volumes
//! (macOS 10.7–10.15, AES-XTS-128, password protector). Parses the physical
//! volume header, decrypts the CoreStorage metadata, derives the volume key
//! hierarchy from a password (PBKDF2-HMAC-SHA256 → RFC 3394 AES-KW → SHA-256
//! tweak key, all RustCrypto — never hand-rolled), and exposes the plaintext
//! logical volume as a `Read + Seek` stream.
//!
//! APFS-native encryption (10.13+) is a separate format and is out of scope.
//!
//! ```no_run
//! use std::fs::File;
//! use filevault::FileVaultVolume;
//!
//! let image = File::open("cs_partition.raw")?;
//! let mut volume = FileVaultVolume::unlock_with_password(image, "fvde-TEST")?;
//! let mut sector = [0u8; 512];
//! volume.read_at(0, &mut sector)?;
//! # Ok::<(), filevault::FileVaultError>(())
//! ```

#![forbid(unsafe_code)]
// `doc_markdown` false-positives on the domain proper nouns that pervade these
// docs (CoreStorage, FileVault, FVDE, PBKDF2, RustCrypto, UserType, …).
#![allow(clippy::doc_markdown)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{Read, Seek, SeekFrom};

pub mod context;
pub mod error;
pub mod metadata;
pub mod read;
pub mod unlock;
pub mod volume;
pub mod volume_header;
#[cfg(feature = "vfs")]
pub mod vfs;
pub mod xts;

pub use context::{EncryptionContext, LogicalVolumeInfo, Protector, ProtectorKind};
pub use error::FileVaultError;
pub use volume::DecryptedVolume;
pub use volume_header::VolumeHeader;

/// Physical volume header length.
const VOLUME_HEADER_LEN: usize = 512;

/// Password-independent metadata parsed from a CoreStorage volume.
///
/// Everything here is derivable WITHOUT the password, so `filevault-forensic`
/// can audit protector inventory, encryption state, and KDF strength on a locked
/// volume. Producing it never unwraps any key.
#[derive(Debug, Clone)]
pub struct FileVaultInfo {
    /// Physical volume identifier (UUID string).
    pub physical_volume_identifier: String,
    /// PBKDF2 iteration count of the password protector.
    pub pbkdf2_iterations: u32,
    /// PBKDF2 salt (16 bytes).
    pub pbkdf2_salt: [u8; 16],
    /// Logical volume family UUID (string).
    pub family_uuid: String,
    /// Logical volume identifier UUID (string), if present.
    pub lv_identifier: Option<String>,
    /// Logical volume name, if present.
    pub lv_name: Option<String>,
    /// Logical volume size in bytes.
    pub lv_size: u64,
    /// Encryption method label (always AES-XTS-128 for a supported volume).
    pub encryption_method: &'static str,
    /// LV conversion status (`Complete` / `Converting` / …), if present.
    pub conversion_status: Option<String>,
    /// Protectors (crypto users) present.
    pub protectors: Vec<Protector>,
}

/// An unlocked CoreStorage / FileVault volume presenting the decrypted logical
/// volume as a `Read + Seek` stream.
#[derive(Debug)]
pub struct FileVaultVolume<R: Read + Seek> {
    decrypted: DecryptedVolume<R>,
    info: FileVaultInfo,
}

impl<R: Read + Seek> FileVaultVolume<R> {
    /// Parse, decrypt the metadata, derive the key hierarchy from `password`,
    /// and return an unlocked volume.
    ///
    /// # Errors
    /// Any [`FileVaultError`] from parsing (not CoreStorage, unsupported method,
    /// missing metadata) or key derivation (wrong password → `KeyUnwrap`).
    pub fn unlock_with_password(mut reader: R, password: &str) -> Result<Self, FileVaultError> {
        let mut header_bytes = [0u8; VOLUME_HEADER_LEN];
        reader.seek(SeekFrom::Start(0))?;
        read_exact_or_err(&mut reader, &mut header_bytes)?;
        let header = VolumeHeader::parse(&header_bytes)?;

        let plaintext = decrypt_metadata_region(&mut reader, &header)?;
        let context = EncryptionContext::extract(&plaintext)?;
        let lv = LogicalVolumeInfo::extract(&plaintext)?;

        let family_uuid_bytes =
            parse_uuid_bytes(&lv.family_uuid).ok_or(FileVaultError::MetadataStructureMissing {
                what: "parseable family UUID",
            })?;
        let keys = unlock::derive_volume_keys(password, &context, &family_uuid_bytes)?;

        let (physical_base, size) = resolve_lv_extent(&plaintext, &header, &lv);

        let info = build_info(&header, &context, &lv, size);
        let decrypted = DecryptedVolume::new(reader, keys, physical_base, size);
        Ok(FileVaultVolume { decrypted, info })
    }

    /// Read and decrypt `buf.len()` bytes at logical `offset` (see
    /// [`DecryptedVolume::read_at`]).
    ///
    /// # Errors
    /// [`FileVaultError::Io`] if the underlying read fails.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, FileVaultError> {
        self.decrypted.read_at(offset, buf)
    }

    /// The logical volume size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.decrypted.size()
    }

    /// The password-independent parsed metadata.
    #[must_use]
    pub fn info(&self) -> &FileVaultInfo {
        &self.info
    }

    /// Consume the volume, returning the inner decrypted `Read + Seek` stream.
    #[must_use]
    pub fn into_decrypted(self) -> DecryptedVolume<R> {
        self.decrypted
    }
}

impl<R: Read + Seek> Read for FileVaultVolume<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decrypted.read(buf)
    }
}

impl<R: Read + Seek> Seek for FileVaultVolume<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.decrypted.seek(pos)
    }
}

/// Parse only the password-independent metadata from a reader, WITHOUT the
/// password — the entry point `filevault-forensic` uses to audit a locked volume.
///
/// # Errors
/// Any [`FileVaultError`] from header/metadata parsing.
pub fn parse_info<R: Read + Seek>(mut reader: R) -> Result<FileVaultInfo, FileVaultError> {
    let mut header_bytes = [0u8; VOLUME_HEADER_LEN];
    reader.seek(SeekFrom::Start(0))?;
    read_exact_or_err(&mut reader, &mut header_bytes)?;
    let header = VolumeHeader::parse(&header_bytes)?;

    let plaintext = decrypt_metadata_region(&mut reader, &header)?;
    let context = EncryptionContext::extract(&plaintext)?;
    let lv = LogicalVolumeInfo::extract(&plaintext)?;
    let (_, size) = resolve_lv_extent(&plaintext, &header, &lv);
    Ok(build_info(&header, &context, &lv, size))
}

/// Read the plaintext metadata region, then read and decrypt the encrypted
/// metadata region, returning the decrypted metadata bytes.
fn decrypt_metadata_region<R: Read + Seek>(
    reader: &mut R,
    header: &VolumeHeader,
) -> Result<Vec<u8>, FileVaultError> {
    let (region_offset, _) = metadata::plaintext_metadata_region(header);

    // Read the first plaintext block to learn the region size.
    let block_size = header.block_size as usize;
    if block_size == 0 {
        return Err(FileVaultError::OutOfRange {
            what: "block size is zero",
        });
    }
    let mut first_block = vec![0u8; block_size];
    reader.seek(SeekFrom::Start(region_offset))?;
    read_exact_or_err(reader, &mut first_block)?;

    let region_size = metadata::plaintext_metadata_size(header, &first_block)?;
    let mut region = vec![0u8; region_size as usize];
    reader.seek(SeekFrom::Start(region_offset))?;
    read_exact_or_err(reader, &mut region)?;

    let location = metadata::locate_encrypted_metadata(header, &region)?;
    let mut ciphertext = vec![0u8; location.length as usize];
    reader.seek(SeekFrom::Start(location.primary_offset))?;
    read_exact_or_err(reader, &mut ciphertext)?;

    metadata::decrypt_metadata(header, &mut ciphertext);
    Ok(ciphertext)
}

/// Derive the LV physical base and size. Prefer the parsed `0x0305` segment
/// descriptor (a single contiguous segment); fall back to the plist LV size for
/// the size when the segment map is absent.
fn resolve_lv_extent(
    metadata_bytes: &[u8],
    header: &VolumeHeader,
    lv: &LogicalVolumeInfo,
) -> (u64, u64) {
    let block_size = u64::from(header.block_size);
    let segments = metadata::parse_segments(metadata_bytes, header.block_size as usize);
    if let Some(first) = segments.first() {
        let base = first.physical_block.saturating_mul(block_size);
        let size = if lv.size != 0 {
            lv.size
        } else {
            u64::from(first.number_of_blocks).saturating_mul(block_size)
        };
        (base, size)
    } else {
        (0, lv.size)
    }
}

/// Assemble the password-independent [`FileVaultInfo`].
fn build_info(
    header: &VolumeHeader,
    context: &EncryptionContext,
    lv: &LogicalVolumeInfo,
    size: u64,
) -> FileVaultInfo {
    FileVaultInfo {
        physical_volume_identifier: format_uuid(&header.physical_volume_identifier),
        pbkdf2_iterations: context.iterations,
        pbkdf2_salt: context.salt,
        family_uuid: lv.family_uuid.clone(),
        lv_identifier: lv.lv_identifier.clone(),
        lv_name: lv.name.clone(),
        lv_size: size,
        encryption_method: "AES-XTS-128",
        conversion_status: context.conversion_status.clone(),
        protectors: context.protectors.clone(),
    }
}

/// Read exactly `buf.len()` bytes, erroring loudly on a short read (a truncated
/// image is a bootstrap failure, never a silent empty result).
fn read_exact_or_err<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), FileVaultError> {
    reader.read_exact(buf).map_err(FileVaultError::Io)
}

/// Format 16 on-disk UUID bytes as the canonical `8-4-4-4-12` string.
fn format_uuid(bytes: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*bytes).hyphenated().to_string()
}

/// Parse a UUID string to its 16 canonical bytes (as used for the tweak key).
fn parse_uuid_bytes(text: &str) -> Option<[u8; 16]> {
    uuid::Uuid::parse_str(text).ok().map(|u| *u.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_kw::KekAes128;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    const BLOCK: usize = 4096;
    const PASSWORD: &str = "synthetic-pass";
    const SALT: [u8; 16] = [0xAB; 16];
    const ITERS: u32 = 1000;
    const KEK: [u8; 16] = [0x10; 16];
    const VMK: [u8; 16] = [0x20; 16];
    const KEY1: [u8; 16] = [0x30; 16]; // metadata XTS key1
    const PV_ID: [u8; 16] = [0x40; 16]; // metadata XTS key2
    const FAMILY: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const LV_PHYS_BLOCK: u64 = 16; // LV base = 16 * 4096 = 0x10000
    const LV_BLOCKS: u32 = 4; // 4 * 4096 = 16384 bytes

    fn wrap(kek: &[u8; 16], key: &[u8; 16]) -> [u8; 24] {
        let k = KekAes128::from(*kek);
        let mut out = [0u8; 24];
        k.wrap(key, &mut out).unwrap();
        out
    }

    fn set_block_type(block: &mut [u8], t: u16) {
        block[10..12].copy_from_slice(&t.to_le_bytes());
    }

    /// Build a decrypted metadata region: block 0 = context plist (0x0013),
    /// block 1 = 0x001a familyUUID+size, block 2 = 0x0305 segment descriptor.
    fn build_decrypted_metadata() -> Vec<u8> {
        let passphrase_key = {
            let mut pk = [0u8; 16];
            pbkdf2::<Hmac<Sha256>>(PASSWORD.as_bytes(), &SALT, ITERS, &mut pk).unwrap();
            pk
        };
        let wrapped_kek = wrap(&passphrase_key, &KEK);
        let wrapped_vmk = wrap(&KEK, &VMK);

        // PassphraseWrappedKEKStruct (284 bytes): salt@8, wrappedKEK@32, iters@168.
        let mut pw = vec![0u8; 284];
        pw[8..24].copy_from_slice(&SALT);
        pw[32..56].copy_from_slice(&wrapped_kek);
        pw[168..172].copy_from_slice(&ITERS.to_le_bytes());
        // KEKWrappedVolumeKeyStruct (256): wrappedVMK@8.
        let mut kekw = vec![0u8; 256];
        kekw[8..32].copy_from_slice(&wrapped_vmk);

        let plist = format!(
            "<dict ID=\"0\"><key>CryptoUsers</key><array ID=\"2\"><dict ID=\"3\">\
             <key>PassphraseWrappedKEKStruct</key><data ID=\"4\">{}</data>\
             <key>UserType</key><integer size=\"32\" ID=\"5\">0x10000001</integer>\
             <key>BlockAlgorithm</key><string ID=\"6\">AES-XTS</string>\
             <key>KEKWrappedVolumeKeyStruct</key><data ID=\"7\">{}</data>\
             </dict></array>\
             <key>ConversionStatus</key><string ID=\"8\">Complete</string></dict>",
            B64.encode(&pw),
            B64.encode(&kekw),
        );

        let mut meta = vec![0u8; BLOCK * 3];
        // Block 0: context plist.
        set_block_type(&mut meta[0..BLOCK], 0x0013);
        let body = plist.as_bytes();
        meta[64..64 + body.len()].copy_from_slice(body);

        // Block 1: 0x001a familyUUID + name + uuid + size.
        set_block_type(&mut meta[BLOCK..2 * BLOCK], 0x001a);
        let fam_uuid = uuid::Uuid::from_bytes(FAMILY).hyphenated().to_string();
        let lv_plist = format!(
            "<dict ID=\"0\">\
             <key>com.apple.corestorage.lv.familyUUID</key><string ID=\"1\">{fam_uuid}</string>\
             <key>com.apple.corestorage.lv.name</key><string ID=\"2\">SynthLV</string>\
             <key>com.apple.corestorage.lv.uuid</key><string ID=\"3\">00000000-0000-0000-0000-000000000001</string>\
             <key>com.apple.corestorage.lv.size</key><integer size=\"64\" ID=\"4\">0x4000</integer></dict>"
        );
        let lb = lv_plist.as_bytes();
        meta[BLOCK + 64..BLOCK + 64 + lb.len()].copy_from_slice(lb);

        // Block 2: 0x0305 segment descriptor (1 entry).
        let base = 2 * BLOCK;
        set_block_type(&mut meta[base..base + BLOCK], 0x0305);
        let payload = base + 64;
        meta[payload..payload + 4].copy_from_slice(&1u32.to_le_bytes());
        let entry = payload + 8;
        meta[entry + 8..entry + 16].copy_from_slice(&0u64.to_le_bytes()); // logical block
        meta[entry + 16..entry + 20].copy_from_slice(&LV_BLOCKS.to_le_bytes());
        let phys = LV_PHYS_BLOCK | (0x99u64 << 48);
        meta[entry + 32..entry + 40].copy_from_slice(&phys.to_le_bytes());
        meta
    }

    /// Build a whole synthetic CoreStorage image (header + plaintext metadata +
    /// encrypted metadata + encrypted LV).
    fn build_image() -> Vec<u8> {
        // Layout (blocks): 0 header-block region, plaintext meta region at block 1,
        // encrypted meta at block 8, LV at block 16.
        let enc_meta_block: u64 = 8;
        let plaintext_meta_block: u64 = 1;

        // Decrypt-then-encrypt the metadata for the encrypted region.
        let plain_meta = build_decrypted_metadata();
        let mut enc_meta = plain_meta.clone();
        crate::xts::encrypt_units(&mut enc_meta, &KEY1, &PV_ID, 8192, 0);

        // Plaintext metadata region (one block): 0x0011 pointer.
        let meta_size = BLOCK as u32; // region = 1 block
        let mut region = vec![0u8; BLOCK];
        set_block_type(&mut region, 0x0011);
        region[64..68].copy_from_slice(&meta_size.to_le_bytes()); // metadata_size@payload 0
                                                                  // Descriptor offset (region-relative). Put descriptor at payload 200.
        let desc_off = 200u32;
        region[64 + 156..64 + 160].copy_from_slice(&desc_off.to_le_bytes());
        let d = desc_off as usize;
        region[d + 8..d + 16]
            .copy_from_slice(&(plain_meta.len() as u64 / BLOCK as u64).to_le_bytes()); // count
        region[d + 32..d + 40].copy_from_slice(&enc_meta_block.to_le_bytes()); // primary block

        // LV plaintext -> encrypt with VMK/tweak_key.
        let tweak_key = {
            let mut h = Sha256::new();
            h.update(VMK);
            h.update(FAMILY);
            let dg = h.finalize();
            let mut tk = [0u8; 16];
            tk.copy_from_slice(&dg[..16]);
            tk
        };
        let lv_len = (LV_BLOCKS as usize) * BLOCK;
        let lv_plain: Vec<u8> = (0..lv_len).map(|i| (i & 0xff) as u8).collect();
        let mut lv_cipher = lv_plain.clone();
        crate::xts::encrypt_units(&mut lv_cipher, &VMK, &tweak_key, 512, 0);

        // Assemble the image.
        let lv_block: u64 = LV_PHYS_BLOCK;
        let total = (lv_block as usize + LV_BLOCKS as usize) * BLOCK;
        let mut image = vec![0u8; total];

        // Header at block 0.
        image[88] = b'C';
        image[89] = b'S';
        image[48..52].copy_from_slice(&512u32.to_le_bytes());
        image[96..100].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        image[64..72].copy_from_slice(&(total as u64).to_le_bytes());
        image[172..176].copy_from_slice(&2u32.to_le_bytes());
        image[104..112].copy_from_slice(&plaintext_meta_block.to_le_bytes());
        image[176..192].copy_from_slice(&KEY1);
        image[304..320].copy_from_slice(&PV_ID);

        // Plaintext metadata region at block 1.
        let po = plaintext_meta_block as usize * BLOCK;
        image[po..po + region.len()].copy_from_slice(&region);
        // Encrypted metadata at block 8.
        let eo = enc_meta_block as usize * BLOCK;
        image[eo..eo + enc_meta.len()].copy_from_slice(&enc_meta);
        // LV at block 16.
        let lo = lv_block as usize * BLOCK;
        image[lo..lo + lv_cipher.len()].copy_from_slice(&lv_cipher);

        image
    }

    #[test]
    fn unlock_synthetic_volume_end_to_end() {
        let image = build_image();
        let mut vol = FileVaultVolume::unlock_with_password(Cursor::new(image), PASSWORD).unwrap();
        assert_eq!(vol.size(), 0x4000);
        assert_eq!(vol.info().pbkdf2_iterations, ITERS);
        assert_eq!(vol.info().lv_name.as_deref(), Some("SynthLV"));
        assert_eq!(vol.info().encryption_method, "AES-XTS-128");
        assert_eq!(vol.info().conversion_status.as_deref(), Some("Complete"));
        assert_eq!(vol.info().protectors.len(), 1);

        // Decrypt LV offset 0 -> known plaintext (0,1,2,...).
        let mut buf = [0u8; 512];
        assert_eq!(vol.read_at(0, &mut buf).unwrap(), 512);
        let expected: Vec<u8> = (0..512).map(|i| (i & 0xff) as u8).collect();
        assert_eq!(&buf[..], &expected[..]);

        // Read + Seek passthrough.
        assert_eq!(vol.seek(SeekFrom::Start(512)).unwrap(), 512);
        let mut b2 = [0u8; 16];
        assert!(std::io::Read::read(&mut vol, &mut b2).unwrap() > 0);

        // parse_info (no password) matches.
        let image2 = build_image();
        let info = parse_info(Cursor::new(image2)).unwrap();
        assert_eq!(info.family_uuid, vol.info().family_uuid);
        assert_eq!(info.lv_size, 0x4000);
        assert_eq!(
            info.physical_volume_identifier,
            uuid::Uuid::from_bytes(PV_ID).hyphenated().to_string()
        );

        // into_decrypted exposes the stream.
        let mut dec = vol.into_decrypted();
        assert_eq!(dec.size(), 0x4000);
        let mut b3 = [0u8; 16];
        assert_eq!(dec.read_at(0, &mut b3).unwrap(), 16);
    }

    #[test]
    fn unlock_wrong_password_fails() {
        let image = build_image();
        assert!(matches!(
            FileVaultVolume::unlock_with_password(Cursor::new(image), "nope"),
            Err(FileVaultError::KeyUnwrap { .. })
        ));
    }

    #[test]
    fn unlock_non_corestorage_fails() {
        let image = vec![0u8; 4096];
        assert!(matches!(
            FileVaultVolume::unlock_with_password(Cursor::new(image), PASSWORD),
            Err(FileVaultError::NotCoreStorage { .. })
        ));
    }

    #[test]
    fn truncated_image_errors_loudly() {
        // A header-only image: metadata read runs past EOF -> Io error, not empty.
        let mut image = vec![0u8; 600];
        image[88] = b'C';
        image[89] = b'S';
        image[96..100].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        image[172..176].copy_from_slice(&2u32.to_le_bytes());
        image[104..112].copy_from_slice(&1u64.to_le_bytes());
        let err = parse_info(Cursor::new(image)).unwrap_err();
        assert!(matches!(err, FileVaultError::Io(_)));
    }

    #[test]
    fn zero_block_size_header_errors() {
        // block_size 0 in the header -> decrypt_metadata_region OutOfRange.
        let mut image = vec![0u8; 4096];
        image[88] = b'C';
        image[89] = b'S';
        image[96..100].copy_from_slice(&0u32.to_le_bytes());
        image[172..176].copy_from_slice(&2u32.to_le_bytes());
        let err = parse_info(Cursor::new(image)).unwrap_err();
        assert!(matches!(err, FileVaultError::OutOfRange { .. }));
    }

    #[test]
    fn format_and_parse_uuid_roundtrip() {
        let s = format_uuid(&FAMILY);
        assert_eq!(parse_uuid_bytes(&s), Some(FAMILY));
        assert_eq!(parse_uuid_bytes("not-a-uuid"), None);
    }

    #[test]
    fn resolve_extent_uses_segment_blocks_when_lv_size_zero() {
        // Segment present, but lv.size == 0 -> size derived from segment blocks.
        let header = VolumeHeader {
            block_size: BLOCK as u32,
            bytes_per_sector: 512,
            physical_volume_size: 0,
            metadata_block_numbers: [1, 0, 0, 0],
            key_data: KEY1,
            physical_volume_identifier: PV_ID,
        };
        // Metadata with a single 0x0305 segment (16 blocks) and no lv.size key.
        let mut meta = vec![0u8; BLOCK];
        meta[10..12].copy_from_slice(&0x0305u16.to_le_bytes());
        let payload = 64;
        meta[payload..payload + 4].copy_from_slice(&1u32.to_le_bytes());
        let entry = payload + 8;
        meta[entry + 16..entry + 20].copy_from_slice(&2u32.to_le_bytes());
        meta[entry + 32..entry + 40].copy_from_slice(&5u64.to_le_bytes());
        let lv = LogicalVolumeInfo {
            size: 0,
            family_uuid: "x".to_string(),
            lv_identifier: None,
            name: None,
        };
        let (base, size) = resolve_lv_extent(&meta, &header, &lv);
        assert_eq!(base, 5 * BLOCK as u64);
        assert_eq!(size, 2 * BLOCK as u64);
    }

    #[test]
    fn resolve_extent_no_segment_falls_back_to_lv_size() {
        let header = VolumeHeader {
            block_size: BLOCK as u32,
            bytes_per_sector: 512,
            physical_volume_size: 0,
            metadata_block_numbers: [1, 0, 0, 0],
            key_data: KEY1,
            physical_volume_identifier: PV_ID,
        };
        let meta = vec![0u8; BLOCK]; // no 0x0305 block
        let lv = LogicalVolumeInfo {
            size: 12345,
            family_uuid: "x".to_string(),
            lv_identifier: None,
            name: None,
        };
        let (base, size) = resolve_lv_extent(&meta, &header, &lv);
        assert_eq!(base, 0);
        assert_eq!(size, 12345);
    }
}
