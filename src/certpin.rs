//! certpin — Certificate pinning.
//!
//! Compute and validate SHA-256 certificate pins without external crypto
//! dependencies. Pins are computed over the Subject Public Key Info (SPKI)
//! of DER-encoded certificates, following RFC 7469.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::certpin::{Pin, PinSet};
//!
//! // Build a pin set from known-good base64 hashes
//! let mut pins = PinSet::new();
//! pins.add(Pin::from_base64("YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=").unwrap());
//!
//! // Validate a certificate's SPKI against the pin set
//! let cert_der = std::fs::read("/path/to/cert.der").unwrap();
//! assert!(pins.validate_der(&cert_der));
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;

// ── SHA-256 (minimal, no-dep implementation) ────────────────────────

const SHA256_DIGEST_LEN: usize = 32;

/// SHA-256 initial hash values.
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-256 hash of input bytes.
#[must_use]
fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut h = H_INIT;

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 64-byte block
    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut digest = [0u8; SHA256_DIGEST_LEN];
    for (i, val) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    digest
}

// ── Base64 encode/decode (minimal, no-dep) ──────────────────────────

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ── Public types ────────────────────────────────────────────────────

/// A SHA-256 certificate pin (32 bytes).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Pin {
    hash: [u8; SHA256_DIGEST_LEN],
}

impl Pin {
    /// Create a pin from raw SHA-256 bytes.
    #[inline]
    #[must_use]
    pub fn from_bytes(hash: [u8; SHA256_DIGEST_LEN]) -> Self {
        Self { hash }
    }

    /// Create a pin from a base64-encoded SHA-256 hash (RFC 7469 format).
    pub fn from_base64(b64: &str) -> Result<Self> {
        let bytes =
            base64_decode(b64).ok_or(SysError::InvalidArgument(Cow::Borrowed("invalid base64")))?;
        if bytes.len() != SHA256_DIGEST_LEN {
            return Err(SysError::InvalidArgument(Cow::Owned(format!(
                "expected {} bytes, got {}",
                SHA256_DIGEST_LEN,
                bytes.len()
            ))));
        }
        let mut hash = [0u8; SHA256_DIGEST_LEN];
        hash.copy_from_slice(&bytes);
        Ok(Self { hash })
    }

    /// Compute a pin from the raw SPKI (Subject Public Key Info) bytes.
    #[inline]
    #[must_use]
    pub fn from_spki(spki: &[u8]) -> Self {
        Self { hash: sha256(spki) }
    }

    /// The raw 32-byte SHA-256 hash.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHA256_DIGEST_LEN] {
        &self.hash
    }

    /// Base64-encoded representation (RFC 7469).
    #[must_use]
    pub fn to_base64(&self) -> String {
        base64_encode(&self.hash)
    }

    /// Hex-encoded representation.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(SHA256_DIGEST_LEN * 2);
        for b in &self.hash {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pin({})", self.to_base64())
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256/{}", self.to_base64())
    }
}

/// A set of trusted certificate pins.
#[derive(Debug, Clone, Default)]
pub struct PinSet {
    pins: Vec<Pin>,
}

impl PinSet {
    /// Create an empty pin set.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pin to the set.
    pub fn add(&mut self, pin: Pin) {
        if !self.pins.contains(&pin) {
            self.pins.push(pin);
        }
    }

    /// Number of pins in the set.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Whether the pin set is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Check if a pin is in the set.
    #[must_use]
    pub fn contains(&self, pin: &Pin) -> bool {
        self.pins.contains(pin)
    }

    /// Validate raw SPKI bytes against this pin set.
    #[must_use]
    pub fn validate_spki(&self, spki: &[u8]) -> bool {
        let pin = Pin::from_spki(spki);
        self.contains(&pin)
    }

    /// Validate a DER-encoded certificate by extracting its SPKI and checking the pin.
    ///
    /// This performs a best-effort SPKI extraction from the DER structure.
    /// For production use, consider using a proper ASN.1 parser.
    #[must_use]
    pub fn validate_der(&self, der: &[u8]) -> bool {
        if let Some(spki) = extract_spki_from_der(der) {
            self.validate_spki(spki)
        } else {
            false
        }
    }
}

// ── DER/ASN.1 SPKI extraction (minimal) ────────────────────────────

/// Best-effort extraction of the SubjectPublicKeyInfo from a DER certificate.
///
/// X.509 structure: SEQUENCE { tbsCertificate SEQUENCE { version, serial,
/// sigAlgo, issuer, validity, subject, subjectPublicKeyInfo SEQUENCE { ... } } }
///
/// We walk the outer SEQUENCE → tbsCertificate SEQUENCE → skip fields → SPKI.
fn extract_spki_from_der(der: &[u8]) -> Option<&[u8]> {
    let (_, cert_body) = parse_tlv(der)?;
    let (_, tbs_body) = parse_tlv(cert_body)?;

    let mut pos = tbs_body;

    // Skip version (explicit tag [0], optional — present if v2/v3)
    if pos.first().copied() == Some(0xA0) {
        let (rest, _) = parse_tlv(pos)?;
        pos = rest;
    }

    // Skip serialNumber (INTEGER)
    let (rest, _) = parse_tlv(pos)?;
    pos = rest;

    // Skip signature algorithm (SEQUENCE)
    let (rest, _) = parse_tlv(pos)?;
    pos = rest;

    // Skip issuer (SEQUENCE)
    let (rest, _) = parse_tlv(pos)?;
    pos = rest;

    // Skip validity (SEQUENCE)
    let (rest, _) = parse_tlv(pos)?;
    pos = rest;

    // Skip subject (SEQUENCE)
    let (rest, _) = parse_tlv(pos)?;
    let _ = rest;

    // Next is subjectPublicKeyInfo — return the full TLV (tag + length + value)
    let spki_start = pos.as_ptr() as usize - tbs_body.as_ptr() as usize;
    let full_tbs = tbs_body;
    let (_, spki_val) = parse_tlv(&full_tbs[spki_start..])?;
    let spki_total_len =
        spki_val.as_ptr() as usize + spki_val.len() - full_tbs[spki_start..].as_ptr() as usize;
    Some(&full_tbs[spki_start..spki_start + spki_total_len])
}

/// Parse a DER TLV: returns (remaining bytes after TLV, value bytes).
fn parse_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let _tag = data[0];
    let (len, header_size) = parse_der_length(&data[1..])?;
    let total_header = 1 + header_size;
    if data.len() < total_header + len {
        return None;
    }
    let value = &data[total_header..total_header + len];
    let rest = &data[total_header + len..];
    Some((rest, value))
}

/// Parse DER length encoding.
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pin>();
        assert_send_sync::<PinSet>();
    };

    // ── SHA-256 ─────────────────────────────────────────────────────

    #[test]
    fn sha256_empty() {
        let hash = sha256(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(Pin::from_bytes(hash).to_hex(), expected);
    }

    #[test]
    fn sha256_hello() {
        let hash = sha256(b"hello");
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(Pin::from_bytes(hash).to_hex(), expected);
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(Pin::from_bytes(hash).to_hex(), expected);
    }

    #[test]
    fn sha256_long_input() {
        // 64 bytes — exactly one block after padding
        let hash = sha256(&[0x61; 56]);
        assert_eq!(hash.len(), 32);
        // Just verify it doesn't panic and produces a deterministic output
        let hash2 = sha256(&[0x61; 56]);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn sha256_multi_block() {
        // > 64 bytes — multiple blocks
        let hash = sha256(&[0xFF; 200]);
        assert_eq!(hash.len(), 32);
    }

    // ── Base64 ──────────────────────────────────────────────────────

    #[test]
    fn base64_round_trip() {
        let data = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_decode_invalid() {
        assert!(base64_decode("!!!invalid!!!").is_none());
    }

    #[test]
    fn base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    // ── Pin ─────────────────────────────────────────────────────────

    #[test]
    fn pin_from_bytes() {
        let hash = sha256(b"test");
        let pin = Pin::from_bytes(hash);
        assert_eq!(pin.as_bytes(), &hash);
    }

    #[test]
    fn pin_from_base64_round_trip() {
        let pin = Pin::from_spki(b"some public key info");
        let b64 = pin.to_base64();
        let pin2 = Pin::from_base64(&b64).unwrap();
        assert_eq!(pin, pin2);
    }

    #[test]
    fn pin_from_base64_invalid() {
        assert!(Pin::from_base64("!!!").is_err());
    }

    #[test]
    fn pin_from_base64_wrong_length() {
        assert!(Pin::from_base64("AQID").is_err()); // only 3 bytes
    }

    #[test]
    fn pin_to_hex() {
        let pin = Pin::from_bytes([0xAB; 32]);
        let hex = pin.to_hex();
        assert_eq!(hex, "ab".repeat(32));
    }

    #[test]
    fn pin_display() {
        let pin = Pin::from_spki(b"test");
        let s = format!("{pin}");
        assert!(s.starts_with("sha256/"));
    }

    #[test]
    fn pin_debug() {
        let pin = Pin::from_spki(b"test");
        let d = format!("{pin:?}");
        assert!(d.starts_with("Pin("));
    }

    #[test]
    fn pin_eq() {
        let a = Pin::from_spki(b"same");
        let b = Pin::from_spki(b"same");
        let c = Pin::from_spki(b"different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn pin_clone() {
        let a = Pin::from_spki(b"test");
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── PinSet ──────────────────────────────────────────────────────

    #[test]
    fn pinset_new_empty() {
        let ps = PinSet::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn pinset_add_and_contains() {
        let mut ps = PinSet::new();
        let pin = Pin::from_spki(b"key1");
        ps.add(pin.clone());
        assert_eq!(ps.len(), 1);
        assert!(ps.contains(&pin));
    }

    #[test]
    fn pinset_dedup() {
        let mut ps = PinSet::new();
        let pin = Pin::from_spki(b"key1");
        ps.add(pin.clone());
        ps.add(pin.clone());
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn pinset_validate_spki() {
        let mut ps = PinSet::new();
        ps.add(Pin::from_spki(b"good_key"));
        assert!(ps.validate_spki(b"good_key"));
        assert!(!ps.validate_spki(b"bad_key"));
    }

    #[test]
    fn pinset_validate_der_empty() {
        let ps = PinSet::new();
        assert!(!ps.validate_der(b""));
    }

    #[test]
    fn pinset_clone() {
        let mut ps = PinSet::new();
        ps.add(Pin::from_spki(b"key"));
        let ps2 = ps.clone();
        assert_eq!(ps.len(), ps2.len());
    }

    #[test]
    fn pinset_debug() {
        let ps = PinSet::new();
        let d = format!("{ps:?}");
        assert!(d.contains("PinSet"));
    }

    // ── DER parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_tlv_simple() {
        // tag=0x30, length=3, value=[1,2,3]
        let data = [0x30, 0x03, 1, 2, 3];
        let (rest, val) = parse_tlv(&data).unwrap();
        assert_eq!(val, &[1, 2, 3]);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_tlv_empty() {
        assert!(parse_tlv(&[]).is_none());
    }

    #[test]
    fn parse_tlv_truncated() {
        // Claims 5 bytes but only 3 available
        assert!(parse_tlv(&[0x30, 0x05, 1, 2, 3]).is_none());
    }

    #[test]
    fn parse_der_length_short() {
        let (len, size) = parse_der_length(&[0x03]).unwrap();
        assert_eq!(len, 3);
        assert_eq!(size, 1);
    }

    #[test]
    fn parse_der_length_long() {
        // 0x82, 0x01, 0x00 = 256 bytes, 3 byte length encoding
        let (len, size) = parse_der_length(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(size, 3);
    }

    #[test]
    fn parse_der_length_empty() {
        assert!(parse_der_length(&[]).is_none());
    }
}
