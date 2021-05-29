use crate::util::u8_slice;

#[repr(C)]
struct LexicalKey128 {
    key1: [u8; 8],
    key2: [u8; 8],
}

#[repr(C)]
struct LexicalKey64 {
    key: [u8; 8],
}

impl AsRef<[u8]> for LexicalKey128 {
    fn as_ref(&self) -> &[u8] {
        u8_slice(self)
    }
}

impl AsRef<[u8]> for LexicalKey64 {
    fn as_ref(&self) -> &[u8] {
        u8_slice(self)
    }
}

impl LexicalKey128 {
    pub fn new(key1: u64, key2: u64) -> LexicalKey128 {
        LexicalKey128 {
            key1: key1.to_be_bytes(),
            key2: key2.to_be_bytes(),
        }
    }
}

impl LexicalKey64 {
    pub fn new(key: u64) -> LexicalKey64 {
        LexicalKey64 {
            key: key.to_be_bytes(),
        }
    }
}
