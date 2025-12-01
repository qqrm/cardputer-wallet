use core::hash::Hasher;
use core::mem;

use pruefung::fnv::Fnv32;

/// Accumulates a rolling checksum using the standard FNV-1 algorithm.
///
/// Uses the `pruefung` implementation to avoid hand-rolled hashing while
/// preserving the ability to continue from an existing seed value.
pub fn accumulate_checksum(seed: u32, payload: &[u8]) -> u32 {
    let mut hasher = Fnv32::default();
    // `Fnv32` stores only the running 32-bit state. Overwriting it with the
    // caller-provided seed preserves the original rolling-checksum behaviour
    // while delegating the per-byte processing to the crate.
    let state = unsafe { mem::transmute::<&mut Fnv32, &mut u32>(&mut hasher) };
    *state = seed;

    hasher.write(payload);
    hasher.finish() as u32
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
