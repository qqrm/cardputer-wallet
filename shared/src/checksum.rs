/// Accumulates a rolling checksum using an FNV-like algorithm.
///
/// The function multiplies the running seed with a fixed prime and
/// xors the next byte. This matches the behaviour previously used in
/// both the host CLI and firmware crates.
pub fn accumulate_checksum(mut seed: u32, payload: &[u8]) -> u32 {
    for byte in payload {
        seed = seed.wrapping_mul(16777619) ^ u32::from(*byte);
    }
    seed
}

#[cfg(test)]
mod tests {
    use super::accumulate_checksum;

    #[test]
    fn accumulates_consistently() {
        let data = b"cardputer";
        let seed = 0xA5A5_5A5A;
        let checksum = accumulate_checksum(seed, data);

        let mut manual = seed;
        for byte in data {
            manual = manual.wrapping_mul(16777619) ^ u32::from(*byte);
        }

        assert_eq!(checksum, manual);
    }
}
