use crate::error::{DecodeError, Result};

/// Resample mono f64 audio from one sample rate to another using rubato.
pub fn resample(
    samples: &[f64],
    from_rate: u32,
    to_rate: u32,
) -> Result<Vec<f64>> {
    if from_rate == to_rate {
        return Ok(samples.to_vec());
    }

    use rubato::{FftFixedInOut, Resampler};

    let chunk_size = 1024;
    let mut resampler = FftFixedInOut::<f64>::new(
        from_rate as usize,
        to_rate as usize,
        chunk_size,
        1, // mono
    )
    .map_err(|e| DecodeError::Resample(e.to_string()))?;

    let mut output = Vec::new();
    let input_frames_needed = resampler.input_frames_next();
    let mut pos = 0;

    while pos < samples.len() {
        let end = (pos + input_frames_needed).min(samples.len());
        let mut chunk: Vec<f64> = samples[pos..end].to_vec();

        // Pad with zeros if needed
        chunk.resize(input_frames_needed, 0.0);

        let result = resampler
            .process(&[chunk], None)
            .map_err(|e| DecodeError::Resample(e.to_string()))?;

        if !result.is_empty() {
            output.extend_from_slice(&result[0]);
        }

        pos += input_frames_needed;
    }

    // Trim to expected length
    let expected_len =
        (samples.len() as f64 * to_rate as f64 / from_rate as f64).round() as usize;
    output.truncate(expected_len);

    Ok(output)
}
