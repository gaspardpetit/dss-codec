//! Shared codec algorithms for DS2 SP and QP decoders.

/// Decode combinatorial number system index to k positions from {0..n-1}.
/// Returns positions in descending order (matching DLL behavior — do NOT sort).
pub fn decode_combinatorial_index(index: u64, n: usize, k: usize) -> Vec<usize> {
    let mut positions = Vec::with_capacity(k);
    let mut remaining = index;

    for i in (1..=k).rev() {
        let mut v = i - 1;
        while v + 1 < n && comb(v + 1, i) <= remaining {
            v += 1;
        }
        positions.push(v);
        remaining -= comb(v, i);
    }
    positions
}

/// Binomial coefficient C(n, k) using u128 to avoid overflow and precision loss
fn comb(n: usize, k: usize) -> u64 {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }
    let k = k.min(n - k);
    let mut result: u128 = 1;
    for i in 0..k {
        result = result * (n - i) as u128 / (i + 1) as u128;
    }
    result as u64
}

/// Decode combined pitch value to per-subframe pitch lags.
pub fn decode_combined_pitch(
    combined: u32,
    pitch_range: u32,
    min_pitch: u32,
    delta_range: u32,
    num_subframes: usize,
) -> Vec<u32> {
    let p0_idx = combined % pitch_range;
    let mut remaining = combined / pitch_range;

    let mut deltas = Vec::with_capacity(num_subframes - 1);
    for _ in 0..(num_subframes - 2) {
        deltas.push(remaining % delta_range);
        remaining /= delta_range;
    }
    deltas.push(remaining.min(delta_range - 1));

    let mut pitches = vec![p0_idx + min_pitch];
    let half_delta = delta_range / 2 - 1;
    let max_pitch = min_pitch + pitch_range - 1;
    let upper_limit = max_pitch - half_delta;

    for &delta_idx in &deltas {
        let prev = *pitches.last().unwrap();
        let base = if prev > upper_limit {
            upper_limit - half_delta
        } else if prev >= min_pitch + half_delta {
            prev - half_delta
        } else {
            min_pitch
        };
        pitches.push(base + delta_idx);
    }

    pitches
}

/// Normalized lattice synthesis filter matching DssDecoder.dll FUN_10019d40.
pub fn lattice_synthesis(
    excitation: &[f64],
    coeffs: &[f64],
    state: &mut [f64],
) -> Vec<f64> {
    let p = coeffs.len();
    let mut output = vec![0.0; excitation.len()];

    for n in 0..excitation.len() {
        let mut acc = excitation[n] - state[p - 1] * coeffs[p - 1];
        for k in (0..p - 1).rev() {
            acc -= state[k] * coeffs[k];
            state[k + 1] = coeffs[k] * acc + state[k];
        }
        state[0] = acc;
        output[n] = acc;
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comb() {
        assert_eq!(comb(72, 7), 1473109704);
        assert_eq!(comb(64, 11), 743595781824);
        assert_eq!(comb(5, 2), 10);
        assert_eq!(comb(0, 0), 1);
        assert_eq!(comb(72, 2), 2556);
    }

    #[test]
    fn test_combinatorial_decode_small() {
        // C(5,2) = 10, index 6 should give positions [4, 1]
        // 6 = C(4,2) + C(1,1) = 6 + 1 = 7? No...
        // Actually: C(4,2)=6, so v=4, remaining=6-6=0, then C(0,1)=0 so v=0
        let positions = decode_combinatorial_index(6, 5, 2);
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0], 4);
        assert_eq!(positions[1], 0);
    }

    #[test]
    fn test_decode_combined_pitch() {
        let pitches = decode_combined_pitch(0, 151, 36, 48, 4);
        assert_eq!(pitches[0], 36);
        assert_eq!(pitches.len(), 4);
    }
}
