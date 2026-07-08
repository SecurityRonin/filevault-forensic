//! Cover the reader-based analyzer entry points (`audit`, `audit_path`,
//! `audit_findings`) and the `EncryptionState` / `WeakKdfIterations` finding
//! arms WITHOUT the env-gated oracle image, so the `--workspace` coverage gate
//! passes in CI (which runs without `FVDE_ORACLE_IMAGE`).
//!
//! These are real behavior tests: they build a minimal but structurally valid
//! synthetic CoreStorage image (a `0x0011` pointer block → an AES-XTS-encrypted
//! metadata region carrying the encryption-context plist) that `parse_info`
//! accepts, then assert the findings' codes, severities, and evidence. The
//! synthetic image is Tier-3 scaffolding under the Tier-1 oracle — it exercises
//! the analyzer plumbing, not the crypto (which the oracle test validates).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::Cursor;

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes128;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use xts_mode::{get_tweak_default, Xts128};

use forensicnomicon::report::Severity;

const BLOCK_SIZE: usize = 512;
const BLOCK_HEADER_SIZE: usize = 64;
// Metadata XTS keys (arbitrary — the fixture is self-consistent, not the oracle).
const KEY_DATA: [u8; 16] = [0x11; 16];
const PV_ID: [u8; 16] = [0x22; 16];
// Encrypted-metadata region: block 8 (offset 4096), one 8192-byte XTS unit.
const ENC_PRIMARY_BLOCK: u64 = 8;
const ENC_UNIT: usize = 8192;

/// A 284-byte `PassphraseWrappedKEKStruct` with salt@8, wrapped-KEK@32 and the
/// iteration count@168 (the real offset), here a deliberately weak 1000.
fn passphrase_struct(iterations: u32) -> Vec<u8> {
    let mut s = vec![0u8; 284];
    s[8..24].copy_from_slice(&[0xAB; 16]); // salt
    s[32..56].copy_from_slice(&[0xCD; 24]); // wrapped KEK
    s[168..172].copy_from_slice(&iterations.to_le_bytes());
    s
}

/// A 256-byte `KEKWrappedVolumeKeyStruct` with the wrapped VMK at offset 8.
fn kek_wrapped_struct() -> Vec<u8> {
    let mut s = vec![0u8; 256];
    s[8..32].copy_from_slice(&[0xEF; 24]);
    s
}

/// The decrypted-metadata plist: an encryption context (weak KDF, `Converting`
/// state, a password protector) plus the LV family UUID `parse_info` needs.
fn plist(iterations: u32, status: &str) -> Vec<u8> {
    let pw = BASE64.encode(passphrase_struct(iterations));
    let none_kek = BASE64.encode(kek_wrapped_struct());
    let xts_kek = BASE64.encode(kek_wrapped_struct());
    format!(
        "<dict ID=\"0\"><key>CryptoUsers</key><array ID=\"2\"><dict ID=\"3\">\
         <key>PassphraseWrappedKEKStruct</key><data ID=\"4\">{pw}</data>\
         <key>UserType</key><integer size=\"32\" ID=\"6\">0x10000001</integer>\
         <key>BlockAlgorithm</key><string ID=\"7\">None</string>\
         <key>KEKWrappedVolumeKeyStruct</key><data ID=\"8\">{none_kek}</data>\
         <key>BlockAlgorithm</key><string ID=\"9\">AES-XTS</string>\
         <key>KEKWrappedVolumeKeyStruct</key><data ID=\"10\">{xts_kek}</data>\
         </dict></array>\
         <key>ConversionStatus</key><string ID=\"20\">{status}</string></dict>\
         <dict ID=\"30\">\
         <key>com.apple.corestorage.lv.familyUUID</key><string ID=\"31\">1F01CA34-5F6C-4123-AC0C-B0A256889DB2</string>\
         <key>com.apple.corestorage.lv.name</key><string ID=\"32\">SynthLV</string>\
         <key>com.apple.corestorage.lv.size</key><integer size=\"64\" ID=\"33\">0xa000000</integer>\
         <key>com.apple.corestorage.lv.uuid</key><string ID=\"34\">420AF122-CF73-4A30-8B0A-A593A65FBEF5</string>\
         </dict>"
    )
    .into_bytes()
}

fn xts_encrypt(buffer: &mut [u8]) {
    let c1 = Aes128::new(GenericArray::from_slice(&KEY_DATA));
    let c2 = Aes128::new(GenericArray::from_slice(&PV_ID));
    Xts128::<Aes128>::new(c1, c2).encrypt_area(buffer, ENC_UNIT, 0, get_tweak_default);
}

/// Assemble a minimal CoreStorage image `parse_info` accepts: header → plaintext
/// `0x0011` pointer region → XTS-encrypted metadata unit holding the plist.
fn synthetic_image(iterations: u32, status: &str) -> Vec<u8> {
    let mut img = vec![0u8; (ENC_PRIMARY_BLOCK as usize) * BLOCK_SIZE + ENC_UNIT];

    // Volume header (block 0): CS sig, AES-XTS method, block size, mbn[0]=1, keys.
    img[88] = b'C';
    img[89] = b'S';
    img[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    img[96..100].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    img[172..176].copy_from_slice(&2u32.to_le_bytes()); // AES-XTS-128
    img[104..112].copy_from_slice(&1u64.to_le_bytes()); // mbn[0] = 1
    img[176..192].copy_from_slice(&KEY_DATA);
    img[304..320].copy_from_slice(&PV_ID);

    // Plaintext metadata region at block 1 (offset 512), 4 blocks (2048 bytes).
    let region = BLOCK_SIZE;
    let region_len = BLOCK_SIZE * 4;
    img[region + 10..region + 12].copy_from_slice(&0x0011u16.to_le_bytes());
    let payload = region + BLOCK_HEADER_SIZE;
    img[payload..payload + 4].copy_from_slice(&(region_len as u32).to_le_bytes()); // metadata_size
                                                                                   // Volume-groups descriptor offset (region-relative) at payload+156 → 1024.
    let desc_rel = 2 * BLOCK_SIZE;
    img[payload + 156..payload + 160].copy_from_slice(&(desc_rel as u32).to_le_bytes());
    let desc = region + desc_rel;
    // Encrypted region = one 8192-byte XTS unit = 16 × 512-byte blocks.
    let enc_blocks = (ENC_UNIT / BLOCK_SIZE) as u64;
    img[desc + 8..desc + 16].copy_from_slice(&enc_blocks.to_le_bytes());
    // Primary block number (48-bit) with a physical-volume index in the top bits.
    let primary_field = ENC_PRIMARY_BLOCK | (0x1234u64 << 48);
    img[desc + 32..desc + 40].copy_from_slice(&primary_field.to_le_bytes());

    // Encrypted metadata unit at block 8 (offset 4096): XTS-encrypt the plist.
    let enc = (ENC_PRIMARY_BLOCK as usize) * BLOCK_SIZE;
    let mut unit = vec![0u8; ENC_UNIT];
    let p = plist(iterations, status);
    unit[..p.len()].copy_from_slice(&p);
    xts_encrypt(&mut unit);
    img[enc..enc + ENC_UNIT].copy_from_slice(&unit);
    img
}

#[test]
fn audit_over_synthetic_image_yields_all_kinds() {
    let img = synthetic_image(1000, "Converting");
    let anomalies =
        filevault_forensic::audit(Cursor::new(img)).expect("audit parses synthetic image");
    let codes: Vec<&str> = anomalies.iter().map(|a| a.code).collect();
    assert!(codes.contains(&"FVDE-PROTECTOR-INVENTORY"));
    assert!(codes.contains(&"FVDE-ENCRYPTION-STATE"));
    assert!(codes.contains(&"FVDE-WEAK-KDF-ITERATIONS"));

    let state = anomalies
        .iter()
        .find(|a| a.code == "FVDE-ENCRYPTION-STATE")
        .unwrap();
    assert!(state.note.contains("Converting"));
    let weak = anomalies
        .iter()
        .find(|a| a.code == "FVDE-WEAK-KDF-ITERATIONS")
        .unwrap();
    assert_eq!(weak.severity, Severity::Medium);
    assert!(weak.note.contains("1000"));
}

#[test]
fn audit_findings_maps_every_kind_with_evidence() {
    // Exercises audit_findings() AND the per-kind evidence()/category() arms
    // (EncryptionState, WeakKdfIterations) via Observation::to_finding.
    let img = synthetic_image(1000, "Converting");
    let findings = filevault_forensic::audit_findings(Cursor::new(img), "synthetic.raw")
        .expect("audit_findings");
    assert_eq!(findings.len(), 3);
    for f in &findings {
        assert_eq!(f.source.analyzer, "filevault-forensic");
        assert_eq!(f.source.scope, "synthetic.raw");
        assert!(!f.evidence.is_empty(), "{} carries evidence", f.code);
    }
    let state = findings
        .iter()
        .find(|f| f.code == "FVDE-ENCRYPTION-STATE")
        .unwrap();
    assert!(state
        .evidence
        .iter()
        .any(|e| e.field == "conversion_status"));
    let weak = findings
        .iter()
        .find(|f| f.code == "FVDE-WEAK-KDF-ITERATIONS")
        .unwrap();
    assert!(weak.evidence.iter().any(|e| e.field == "pbkdf2_iterations"));
}

#[test]
fn audit_path_reads_a_file() {
    let img = synthetic_image(50_000, "Complete");
    let mut path = std::env::temp_dir();
    path.push(format!("fvde_synth_{}.raw", std::process::id()));
    std::fs::write(&path, &img).unwrap();

    let anomalies = filevault_forensic::audit_path(&path).expect("audit_path parses the file");
    // 50000 iterations is above the weak threshold → not flagged.
    assert!(anomalies
        .iter()
        .all(|a| a.code != "FVDE-WEAK-KDF-ITERATIONS"));
    assert!(anomalies
        .iter()
        .any(|a| a.code == "FVDE-PROTECTOR-INVENTORY"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn audit_path_missing_file_errors() {
    let err = filevault_forensic::audit_path(std::path::Path::new(
        "/nonexistent/fvde/definitely/missing.raw",
    ));
    assert!(err.is_err());
}
