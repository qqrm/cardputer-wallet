/// Build a nonce for the journal envelope domain.
pub(crate) fn build(domain: [u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&domain);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_big_endian_counter() {
        let nonce = build(*b"TEST", 0x0102_0304_0506_0708);
        assert_eq!(&nonce[..4], b"TEST");
        assert_eq!(&nonce[4..], &0x0102_0304_0506_0708u64.to_be_bytes());
    }
}
