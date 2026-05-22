use std::{cell::RefCell, hash::Hasher, mem, ptr};

pub struct SipHash {
    inner: RefCell<Inner>,
}

struct Inner {
    c: usize,
    d: usize,
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    len: usize,
    buf: [u8; 8],
    cursor: usize,
}

impl Inner {
    fn round(&mut self, n: usize) {
        for _ in 0..n {
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

    fn cap(&self) -> usize {
        8 - self.cursor
    }

    fn feed(&mut self, bytes: &[u8]) {
        let cap = self.cap();
        if cap > bytes.len() {
            let cursor = self.cursor;
            let cursor_n = cursor + bytes.len();
            self.buf[cursor..cursor_n].copy_from_slice(bytes);
            self.cursor = cursor_n;
        } else {
            let cursor = self.cursor;
            self.buf[cursor..].copy_from_slice(&bytes[..cap]);
            let m = u64::from_le_bytes(self.buf);
            self.v3 ^= m;
            self.round(self.c);
            self.v0 ^= m;
            let mut chunks = bytes[cap..].chunks_exact(8);
            for chunk in chunks.by_ref() {
                let m = u64::from_le_bytes(chunk.try_into().unwrap());
                self.v3 ^= m;
                self.round(self.c);
                self.v0 ^= m;
            }
            let remainder = chunks.remainder();
            self.buf[..remainder.len()].copy_from_slice(remainder);
            self.cursor = remainder.len();
        }
        self.len += bytes.len();
    }

    fn finalize(&mut self) -> u64 {
        self.buf[self.cursor..7].fill(0);
        self.buf[7] = self.len as u8;
        let m = u64::from_le_bytes(self.buf);
        self.v3 ^= m;
        self.round(self.c);
        self.v0 ^= m;
        self.v2 ^= 0xff;
        self.round(self.d);
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

impl SipHash {
    pub fn new(c: usize, d: usize, key: &[u8; 16]) -> Self {
        let mut k0: u64 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let mut k1: u64 = u64::from_le_bytes(key[8..].try_into().unwrap());
        let inner = RefCell::new(Inner {
            c,
            d,
            len: 0,
            buf: [0; 8],
            cursor: 0,
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
        });
        unsafe {
            ptr::write_volatile(&mut k0, mem::zeroed());
            ptr::write_volatile(&mut k1, mem::zeroed());
        }
        // explicit zero k0 & k1 on stack
        SipHash { inner }
    }
}

impl Hasher for SipHash {
    fn write(&mut self, bytes: &[u8]) {
        self.inner.borrow_mut().feed(bytes);
    }

    fn finish(&self) -> u64 {
        self.inner.borrow_mut().finalize()
    }
}

pub fn sip_hash_oneoff(c: usize, d: usize, key: &[u8; 16], message: &[u8]) -> u64 {
    let k0: u64 = u64::from_le_bytes(key[..8].try_into().unwrap());
    let k1: u64 = u64::from_le_bytes(key[8..].try_into().unwrap());
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;
    let mut chunks = message.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let m: u64 = u64::from_le_bytes(chunk.try_into().unwrap());
        // FIX 3: Correct block injection per spec
        v3 ^= m;
        sip_round(c, &mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
    let remainder = chunks.remainder();
    let mut last_bytes: [u8; 8] = [0; 8];
    last_bytes[..remainder.len()].copy_from_slice(remainder);
    last_bytes[7] = message.len() as u8; // Length goes into the last byte (MSB)
    let last_block = u64::from_le_bytes(last_bytes);
    v3 ^= last_block;
    sip_round(c, &mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last_block;
    v2 ^= 0xff;
    sip_round(d, &mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^ v1 ^ v2 ^ v3
}

pub fn sip_round(c: usize, v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    for _ in 0..c {
        *v0 = v0.wrapping_add(*v1);
        *v2 = v2.wrapping_add(*v3);
        *v1 = v1.rotate_left(13);
        *v3 = v3.rotate_left(16);
        *v1 ^= *v0;
        *v3 ^= *v2;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v1);
        *v0 = v0.wrapping_add(*v3);
        *v1 = v1.rotate_left(17);
        *v3 = v3.rotate_left(21);
        *v1 ^= *v2;
        *v3 ^= *v0;
        *v2 = v2.rotate_left(32);
    }
}

#[cfg(test)]
mod official_tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn test_empty() {
        let actual = sip_hash_oneoff(2, 4, &KEY, &[]);
        let expected = u64::from_le_bytes([0x31_u8, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72]);
        assert_eq!(
            expected, actual,
            "expected: {:x}, actual {:x}",
            expected, actual
        );
    }

    #[test]
    fn test_empty_hasher() {
        let mut hasher = SipHash::new(2, 4, &KEY);
        hasher.write(&[]);
        let actual = hasher.finish();
        let expected = u64::from_le_bytes([0x31_u8, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72]);
        assert_eq!(
            expected, actual,
            "expected: {:x}, actual {:x}",
            expected, actual
        );
    }

    #[test]
    fn test_1() {
        let actual = sip_hash_oneoff(2, 4, &KEY, &[0x00]);
        let expected = u64::from_le_bytes([0xfd_u8, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74]);
        assert_eq!(
            expected, actual,
            "expected: {:x}, actual {:x}",
            expected, actual
        );
    }

    #[test]
    fn test_1_hasher() {
        let mut hasher = SipHash::new(2, 4, &KEY);
        hasher.write(&[0x00]);
        let actual = hasher.finish();
        let expected = u64::from_le_bytes([0xfd_u8, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74]);
        assert_eq!(
            expected, actual,
            "expected: {:x}, actual {:x}",
            expected, actual
        );
    }

    #[test]
    fn test_10() {
        let mut hasher = SipHash::new(2, 4, &KEY);
        hasher.write(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        let actual = hasher.finish();
        let expected = u64::from_le_bytes([0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a]);
        assert_eq!(
            expected, actual,
            "expected: {:x}, actual {:x}",
            expected, actual
        );
    }

    #[test]
    fn test_10_hasher() {
        let mut hasher = SipHash::new(2, 4, &KEY);
        hasher.write(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        let actual = hasher.finish();
        let expected = u64::from_le_bytes([0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a]);
        assert_eq!(
            expected, actual,
            "expected: {:x}, actual {:x}",
            expected, actual
        );
    }
}
