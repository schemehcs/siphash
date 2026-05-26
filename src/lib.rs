use std::hash::Hasher;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    pub fn new(v0: u64, v1: u64, v2: u64, v3: u64) -> Self {
        State { v0, v1, v2, v3 }
    }

    pub fn round(&mut self, count: usize) {
        for _ in 0..count {
            self.v0 = self.v0.wrapping_add(self.v1);
            self.v2 = self.v2.wrapping_add(self.v3);
            self.v1 = self.v1.rotate_left(13);
            self.v3 = self.v3.rotate_left(16);
            self.v1 ^= self.v0;
            self.v3 ^= self.v2;
            self.v0 = self.v0.rotate_left(32);
            self.v2 = self.v2.wrapping_add(self.v1);
            self.v0 = self.v0.wrapping_add(self.v3);
            self.v1 = self.v1.rotate_left(17);
            self.v3 = self.v3.rotate_left(21);
            self.v1 ^= self.v2;
            self.v3 ^= self.v0;
            self.v2 = self.v2.rotate_left(32);
        }
    }

    pub fn update(&mut self, count: usize, n: u64) {
        self.v3 ^= n;
        self.round(count);
        self.v0 ^= n;
    }

    pub fn finish(&mut self, count: usize) -> u64 {
        self.v2 ^= 0xff;
        self.round(count);
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.v0.zeroize();
        self.v1.zeroize();
        self.v2.zeroize();
        self.v3.zeroize();
    }
}

#[derive(Default, Clone)]
struct Buf {
    buf: [u8; 8],
    cursor: usize,
    len: usize,
}

impl Buf {
    fn write(&mut self, bytes: &[u8]) -> Option<(u64, usize)> {
        let cap = 8 - self.cursor;
        if cap > bytes.len() {
            let cursor_n = self.cursor + bytes.len();
            self.buf[self.cursor..cursor_n].copy_from_slice(bytes);
            self.cursor = cursor_n;
            self.len += bytes.len();
            None
        } else {
            self.buf[self.cursor..].copy_from_slice(&bytes[..cap]);
            self.cursor = 0;
            self.len += cap;
            Some((self.as_u64_le(), cap))
        }
    }

    fn finish(&mut self) -> u64 {
        self.buf[self.cursor..7].fill(0);
        self.buf[7] = self.len as u8;
        self.cursor = 0;
        self.as_u64_le()
    }

    fn as_u64_le(&self) -> u64 {
        u64::from_le_bytes(self.buf)
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        self.len = 0;
        self.cursor = 0;
        self.buf.fill(0);
    }
}

pub struct SipHash {
    c: usize,
    d: usize,
    state: State,
    buf: Buf,
}

impl SipHash {
    pub fn new(c: usize, d: usize, key: &[u8; 16]) -> Self {
        let mut k0: u64 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let mut k1: u64 = u64::from_le_bytes(key[8..].try_into().unwrap());
        let sip_hash = SipHash {
            c,
            d,
            state: State::new(
                k0 ^ 0x736f6d6570736575,
                k1 ^ 0x646f72616e646f6d,
                k0 ^ 0x6c7967656e657261,
                k1 ^ 0x7465646279746573,
            ),
            buf: Buf::default(),
        };
        k0.zeroize();
        k1.zeroize();
        sip_hash
    }

    fn update(&mut self, n: u64) {
        self.state.update(self.c, n);
    }
}

impl Hasher for SipHash {
    fn write(&mut self, mut bytes: &[u8]) {
        while let Some((n, offset)) = self.buf.write(bytes) {
            self.update(n);
            if offset < bytes.len() {
                bytes = &bytes[offset..];
            } else {
                return;
            }
        }
    }

    fn finish(&self) -> u64 {
        let mut buf_cloned = self.buf.clone();
        let mut state_cloned = self.state.clone();
        state_cloned.update(self.c, buf_cloned.finish());
        state_cloned.finish(self.d)
    }
}

pub fn sip_hash(c: usize, d: usize, key: &[u8; 16], message: &[u8]) -> u64 {
    let mut siphash = SipHash::new(c, d, key);
    siphash.write(message);
    siphash.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    const VECTORS: [[u8; 8]; 64] = [
        [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72],
        [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74],
        [0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d],
        [0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85],
        [0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf],
        [0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18],
        [0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb],
        [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab],
        [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93],
        [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e],
        [0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a],
        [0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4],
        [0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75],
        [0x90, 0x3d, 0x84, 0xc0, 0x27, 0x56, 0xea, 0x14],
        [0xee, 0xf2, 0x7a, 0x8e, 0x90, 0xca, 0x23, 0xf7],
        [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1],
        [0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f],
        [0x94, 0x47, 0xbe, 0x2c, 0xf5, 0xe9, 0x9a, 0x69],
        [0x9c, 0xd3, 0x8d, 0x96, 0xf0, 0xb3, 0xc1, 0x4b],
        [0xbd, 0x61, 0x79, 0xa7, 0x1d, 0xc9, 0x6d, 0xbb],
        [0x98, 0xee, 0xa2, 0x1a, 0xf2, 0x5c, 0xd6, 0xbe],
        [0xc7, 0x67, 0x3b, 0x2e, 0xb0, 0xcb, 0xf2, 0xd0],
        [0x88, 0x3e, 0xa3, 0xe3, 0x95, 0x67, 0x53, 0x93],
        [0xc8, 0xce, 0x5c, 0xcd, 0x8c, 0x03, 0x0c, 0xa8],
        [0x94, 0xaf, 0x49, 0xf6, 0xc6, 0x50, 0xad, 0xb8],
        [0xea, 0xb8, 0x85, 0x8a, 0xde, 0x92, 0xe1, 0xbc],
        [0xf3, 0x15, 0xbb, 0x5b, 0xb8, 0x35, 0xd8, 0x17],
        [0xad, 0xcf, 0x6b, 0x07, 0x63, 0x61, 0x2e, 0x2f],
        [0xa5, 0xc9, 0x1d, 0xa7, 0xac, 0xaa, 0x4d, 0xde],
        [0x71, 0x65, 0x95, 0x87, 0x66, 0x50, 0xa2, 0xa6],
        [0x28, 0xef, 0x49, 0x5c, 0x53, 0xa3, 0x87, 0xad],
        [0x42, 0xc3, 0x41, 0xd8, 0xfa, 0x92, 0xd8, 0x32],
        [0xce, 0x7c, 0xf2, 0x72, 0x2f, 0x51, 0x27, 0x71],
        [0xe3, 0x78, 0x59, 0xf9, 0x46, 0x23, 0xf3, 0xa7],
        [0x38, 0x12, 0x05, 0xbb, 0x1a, 0xb0, 0xe0, 0x12],
        [0xae, 0x97, 0xa1, 0x0f, 0xd4, 0x34, 0xe0, 0x15],
        [0xb4, 0xa3, 0x15, 0x08, 0xbe, 0xff, 0x4d, 0x31],
        [0x81, 0x39, 0x62, 0x29, 0xf0, 0x90, 0x79, 0x02],
        [0x4d, 0x0c, 0xf4, 0x9e, 0xe5, 0xd4, 0xdc, 0xca],
        [0x5c, 0x73, 0x33, 0x6a, 0x76, 0xd8, 0xbf, 0x9a],
        [0xd0, 0xa7, 0x04, 0x53, 0x6b, 0xa9, 0x3e, 0x0e],
        [0x92, 0x59, 0x58, 0xfc, 0xd6, 0x42, 0x0c, 0xad],
        [0xa9, 0x15, 0xc2, 0x9b, 0xc8, 0x06, 0x73, 0x18],
        [0x95, 0x2b, 0x79, 0xf3, 0xbc, 0x0a, 0xa6, 0xd4],
        [0xf2, 0x1d, 0xf2, 0xe4, 0x1d, 0x45, 0x35, 0xf9],
        [0x87, 0x57, 0x75, 0x19, 0x04, 0x8f, 0x53, 0xa9],
        [0x10, 0xa5, 0x6c, 0xf5, 0xdf, 0xcd, 0x9a, 0xdb],
        [0xeb, 0x75, 0x09, 0x5c, 0xcd, 0x98, 0x6c, 0xd0],
        [0x51, 0xa9, 0xcb, 0x9e, 0xcb, 0xa3, 0x12, 0xe6],
        [0x96, 0xaf, 0xad, 0xfc, 0x2c, 0xe6, 0x66, 0xc7],
        [0x72, 0xfe, 0x52, 0x97, 0x5a, 0x43, 0x64, 0xee],
        [0x5a, 0x16, 0x45, 0xb2, 0x76, 0xd5, 0x92, 0xa1],
        [0xb2, 0x74, 0xcb, 0x8e, 0xbf, 0x87, 0x87, 0x0a],
        [0x6f, 0x9b, 0xb4, 0x20, 0x3d, 0xe7, 0xb3, 0x81],
        [0xea, 0xec, 0xb2, 0xa3, 0x0b, 0x22, 0xa8, 0x7f],
        [0x99, 0x24, 0xa4, 0x3c, 0xc1, 0x31, 0x57, 0x24],
        [0xbd, 0x83, 0x8d, 0x3a, 0xaf, 0xbf, 0x8d, 0xb7],
        [0x0b, 0x1a, 0x2a, 0x32, 0x65, 0xd5, 0x1a, 0xea],
        [0x13, 0x50, 0x79, 0xa3, 0x23, 0x1c, 0xe6, 0x60],
        [0x93, 0x2b, 0x28, 0x46, 0xe4, 0xd7, 0x06, 0x66],
        [0xe1, 0x91, 0x5f, 0x5c, 0xb1, 0xec, 0xa4, 0x6c],
        [0xf3, 0x25, 0x96, 0x5c, 0xa1, 0x6d, 0x62, 0x9f],
        [0x57, 0x5f, 0xf2, 0x8e, 0x60, 0x38, 0x1b, 0xe5],
        [0x72, 0x45, 0x06, 0xeb, 0x4c, 0x32, 0x8a, 0x95],
    ];

    // --- KAT: sip_hash() one-shot ---

    #[test]
    fn kat_oneshot() {
        for (len, expected_bytes) in VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = u64::from_le_bytes(*expected_bytes);
            let actual = sip_hash(2, 4, &KEY, &msg);
            assert_eq!(
                expected, actual,
                "sip_hash KAT failed for len={}: expected {:016x}, got {:016x}",
                len, expected, actual
            );
        }
    }

    // --- KAT: SipHash::write() + finish() ---

    #[test]
    fn kat_hasher_single_write() {
        for (len, expected_bytes) in VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = u64::from_le_bytes(*expected_bytes);
            let mut hasher = SipHash::new(2, 4, &KEY);
            hasher.write(&msg);
            let actual = hasher.finish();
            assert_eq!(
                expected, actual,
                "hasher KAT failed for len={}: expected {:016x}, got {:016x}",
                len, expected, actual
            );
        }
    }

    // --- Incremental write consistency ---
    // Feeding bytes one at a time must match a single write.
    // This exercises every buffer-straddling boundary.

    #[test]
    fn incremental_byte_by_byte_matches_single_write() {
        for (len, expected_bytes) in VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = u64::from_le_bytes(*expected_bytes);
            let mut hasher = SipHash::new(2, 4, &KEY);
            for byte in &msg {
                hasher.write(&[*byte]);
            }
            let actual = hasher.finish();
            assert_eq!(
                expected, actual,
                "byte-by-byte failed for len={}: expected {:016x}, got {:016x}",
                len, expected, actual
            );
        }
    }

    // Split at every possible position within each test vector message.
    // Covers all buffer-straddling cases systematically.
    #[test]
    fn incremental_all_split_points() {
        for (len, expected_bytes) in VECTORS.iter().enumerate() {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = u64::from_le_bytes(*expected_bytes);
            for split in 0..=len {
                let mut hasher = SipHash::new(2, 4, &KEY);
                hasher.write(&msg[..split]);
                hasher.write(&msg[split..]);
                let actual = hasher.finish();
                assert_eq!(
                    expected, actual,
                    "split at {} failed for len={}: expected {:016x}, got {:016x}",
                    split, len, expected, actual
                );
            }
        }
    }

    // --- finish() is non-destructive ---

    #[test]
    fn finish_is_idempotent() {
        let mut hasher = SipHash::new(2, 4, &KEY);
        hasher.write(&[0x00, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(hasher.finish(), hasher.finish());
    }

    // --- Different keys produce different hashes ---

    #[test]
    fn different_keys_differ() {
        let key2 = [0xff_u8; 16];
        let msg = b"hello";
        let h1 = sip_hash(2, 4, &KEY, msg);
        let h2 = sip_hash(2, 4, &key2, msg);
        assert_ne!(h1, h2);
    }

    // --- Different messages produce different hashes ---

    #[test]
    fn different_messages_differ() {
        let h1 = sip_hash(2, 4, &KEY, b"hello");
        let h2 = sip_hash(2, 4, &KEY, b"world");
        assert_ne!(h1, h2);
    }

    // --- SipHash-1-3 vs SipHash-2-4 differ ---

    #[test]
    fn different_rounds_differ() {
        let msg = b"test";
        let h24 = sip_hash(2, 4, &KEY, msg);
        let h13 = sip_hash(1, 3, &KEY, msg);
        assert_ne!(h24, h13);
    }

    // --- Large input (exercises multiple full block iterations) ---

    #[test]
    fn large_input_consistent() {
        let msg: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let h1 = sip_hash(2, 4, &KEY, &msg);

        let mut hasher = SipHash::new(2, 4, &KEY);
        hasher.write(&msg[..128]);
        hasher.write(&msg[128..]);
        let h2 = hasher.finish();

        assert_eq!(h1, h2);
    }

    // --- Zero key ---

    #[test]
    fn zero_key_does_not_panic() {
        let key = [0u8; 16];
        let _ = sip_hash(2, 4, &key, b"anything");
    }
}
