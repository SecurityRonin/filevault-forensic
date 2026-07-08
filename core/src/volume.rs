//! Decrypted logical-volume reader: AES-XTS-128 over 512-byte sectors, tweak =
//! logical sector number, single contiguous segment at the LV physical base.

use std::io::{self, Read, Seek, SeekFrom};

use crate::error::FileVaultError;
use crate::unlock::VolumeKeys;
use crate::xts;

/// AES-XTS unit for LV sector decryption.
const SECTOR_SIZE: usize = 512;

/// A decrypted CoreStorage logical volume over a `Read + Seek` source.
///
/// Reads are decrypted on demand: for a logical offset `L`, the physical offset
/// is `segment_base + (L - segment_logical_base)`, the sector is `L / 512`, and
/// the tweak is that logical sector number.
#[derive(Debug)]
pub struct DecryptedVolume<R: Read + Seek> {
    reader: R,
    keys: VolumeKeys,
    /// Physical byte offset of the LV base (first segment).
    physical_base: u64,
    /// Logical volume size in bytes.
    size: u64,
    /// Current logical read position (for the `Read`/`Seek` impls).
    position: u64,
}

impl<R: Read + Seek> DecryptedVolume<R> {
    /// Construct a decrypted-volume view for a single contiguous segment.
    pub(crate) fn new(reader: R, keys: VolumeKeys, physical_base: u64, size: u64) -> Self {
        DecryptedVolume {
            reader,
            keys,
            physical_base,
            size,
            position: 0,
        }
    }

    /// The logical volume size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Read and decrypt `buf.len()` bytes at logical `offset`, returning the
    /// number of bytes read (0 at or past the end of the volume).
    ///
    /// Reads are sector-aligned internally: the enclosing 512-byte sectors are
    /// fetched, decrypted with their logical-sector tweaks, and the requested
    /// window is copied out.
    ///
    /// # Errors
    /// [`FileVaultError::Io`] if the underlying read/seek fails.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, FileVaultError> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let available = self.size - offset;
        let want = (buf.len() as u64).min(available) as usize;

        let first_sector = offset / SECTOR_SIZE as u64;
        let end = offset + want as u64;
        let last_sector = (end - 1) / SECTOR_SIZE as u64;
        let sector_count = (last_sector - first_sector + 1) as usize;

        let region_len =
            sector_count
                .checked_mul(SECTOR_SIZE)
                .ok_or(FileVaultError::OutOfRange {
                    what: "read region length",
                })?;
        let mut region = vec![0u8; region_len];

        let physical = self.physical_base + first_sector * SECTOR_SIZE as u64;
        self.reader.seek(SeekFrom::Start(physical))?;
        // A short read (past end of the backing image) leaves the tail zeroed;
        // decryption of zero ciphertext yields defined-but-meaningless bytes,
        // never a panic. We still surface the bytes we could read.
        read_full_or_eof(&mut self.reader, &mut region)?;

        xts::decrypt_units(
            &mut region,
            &self.keys.vmk,
            &self.keys.tweak_key,
            SECTOR_SIZE,
            u128::from(first_sector),
        );

        let inner = (offset - first_sector * SECTOR_SIZE as u64) as usize;
        let slice = region
            .get(inner..inner + want)
            .ok_or(FileVaultError::OutOfRange {
                what: "decrypted window",
            })?;
        buf.get_mut(..want)
            .ok_or(FileVaultError::OutOfRange {
                what: "output buffer window",
            })?
            .copy_from_slice(slice);
        Ok(want)
    }
}

/// Read exactly `buf.len()` bytes, or until EOF; a clean EOF short read leaves
/// the remaining bytes as-is (zero-filled) rather than erroring.
fn read_full_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl<R: Read + Seek> Read for DecryptedVolume<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.position, buf).map_err(io::Error::other)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for DecryptedVolume<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => add_signed(self.size, o)?,
            SeekFrom::Current(o) => add_signed(self.position, o)?,
        };
        self.position = new;
        Ok(new)
    }
}

/// Apply a signed offset to a base position, erroring on overflow/underflow.
fn add_signed(base: u64, offset: i64) -> io::Result<u64> {
    let result = if offset >= 0 {
        base.checked_add(offset as u64)
    } else {
        base.checked_sub(offset.unsigned_abs())
    };
    result.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn keys() -> VolumeKeys {
        VolumeKeys {
            vmk: [0x55u8; 16],
            tweak_key: [0x66u8; 16],
        }
    }

    /// Build a backing image: `physical_base` bytes of padding, then XTS-encrypted
    /// sectors whose plaintext is known. Logical sector N uses tweak N.
    fn build_backing(base: u64, plaintext: &[u8], keys: &VolumeKeys) -> Vec<u8> {
        let mut cipher = plaintext.to_vec();
        crate::xts::encrypt_units(&mut cipher, &keys.vmk, &keys.tweak_key, SECTOR_SIZE, 0);
        let mut image = vec![0u8; base as usize];
        image.extend_from_slice(&cipher);
        image
    }

    #[test]
    fn read_at_decrypts_aligned_sector() {
        let k = keys();
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
        let image = build_backing(4096, &plaintext, &k);
        let mut vol =
            DecryptedVolume::new(Cursor::new(image), keys(), 4096, plaintext.len() as u64);
        let mut buf = [0u8; 512];
        assert_eq!(vol.read_at(0, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &plaintext[..512]);
        assert_eq!(vol.read_at(512, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &plaintext[512..1024]);
    }

    #[test]
    fn read_at_handles_unaligned_window() {
        let k = keys();
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
        let image = build_backing(0, &plaintext, &k);
        let mut vol = DecryptedVolume::new(Cursor::new(image), keys(), 0, plaintext.len() as u64);
        let mut buf = [0u8; 300];
        // Offset 600 spans sector 1 and sector 2 boundary crossing.
        assert_eq!(vol.read_at(600, &mut buf).unwrap(), 300);
        assert_eq!(&buf[..], &plaintext[600..900]);
    }

    #[test]
    fn read_at_past_end_returns_zero() {
        let mut vol = DecryptedVolume::new(Cursor::new(vec![0u8; 4096]), keys(), 0, 512);
        let mut buf = [0u8; 16];
        assert_eq!(vol.read_at(512, &mut buf).unwrap(), 0);
        assert_eq!(vol.read_at(1000, &mut buf).unwrap(), 0);
    }

    #[test]
    fn read_at_truncates_to_volume_end() {
        let k = keys();
        let plaintext: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
        let image = build_backing(0, &plaintext, &k);
        let mut vol = DecryptedVolume::new(Cursor::new(image), keys(), 0, 512);
        let mut buf = [0u8; 512];
        // Ask for 512 from offset 256 → only 256 available.
        assert_eq!(vol.read_at(256, &mut buf).unwrap(), 256);
        assert_eq!(&buf[..256], &plaintext[256..512]);
    }

    #[test]
    fn empty_buffer_reads_nothing() {
        let mut vol = DecryptedVolume::new(Cursor::new(vec![0u8; 4096]), keys(), 0, 512);
        assert_eq!(vol.read_at(0, &mut []).unwrap(), 0);
    }

    #[test]
    fn size_accessor() {
        let vol = DecryptedVolume::new(Cursor::new(vec![0u8; 16]), keys(), 0, 167_772_160);
        assert_eq!(vol.size(), 167_772_160);
    }

    #[test]
    fn read_and_seek_impls() {
        let k = keys();
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
        let image = build_backing(0, &plaintext, &k);
        let mut vol = DecryptedVolume::new(Cursor::new(image), keys(), 0, plaintext.len() as u64);
        let mut buf = [0u8; 512];
        assert_eq!(std::io::Read::read(&mut vol, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &plaintext[..512]);
        // Seek to sector 1 and read.
        assert_eq!(vol.seek(SeekFrom::Start(512)).unwrap(), 512);
        assert_eq!(std::io::Read::read(&mut vol, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &plaintext[512..1024]);
        // SeekFrom::End / Current.
        assert_eq!(vol.seek(SeekFrom::End(0)).unwrap(), 1024);
        assert_eq!(vol.seek(SeekFrom::Current(-1024)).unwrap(), 0);
    }

    #[test]
    fn seek_out_of_range_errors() {
        let mut vol = DecryptedVolume::new(Cursor::new(vec![0u8; 16]), keys(), 0, 512);
        assert!(vol.seek(SeekFrom::Current(-1)).is_err());
        assert!(vol.seek(SeekFrom::End(1)).is_ok());
    }

    /// A reader that yields one `Interrupted`, then one hard error after N bytes.
    struct FlakyReader {
        data: Vec<u8>,
        pos: usize,
        interrupted_once: bool,
    }

    impl Read for FlakyReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted_once {
                self.interrupted_once = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.pos >= self.data.len() {
                return Err(io::Error::other("backing read failed"));
            }
            let n = (buf.len()).min(self.data.len() - self.pos).min(4);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn read_full_or_eof_retries_interrupt_and_propagates_error() {
        // Interrupted is retried; a subsequent hard error propagates.
        let mut r = FlakyReader {
            data: vec![1u8; 8],
            pos: 0,
            interrupted_once: false,
        };
        let mut buf = [0u8; 16];
        let err = read_full_or_eof(&mut r, &mut buf).unwrap_err();
        assert_eq!(err.to_string(), "backing read failed");
        // The 8 available bytes were read before the error (interrupt was retried).
        assert_eq!(&buf[..8], &[1u8; 8]);
    }

    /// A reader that returns clean EOF (Ok(0)) immediately.
    struct EofReader;
    impl Read for EofReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn read_full_or_eof_stops_at_clean_eof() {
        let mut r = EofReader;
        let mut buf = [0xffu8; 8];
        read_full_or_eof(&mut r, &mut buf).unwrap();
        // Untouched (zero bytes read, no error).
        assert_eq!(buf, [0xffu8; 8]);
    }
}
