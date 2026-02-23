use crate::error::Result;
use hound::{SampleFormat, WavSpec, WavWriter};
use std::path::Path;

/// Write f64 samples to a WAV file with given parameters.
pub fn write_wav(
    path: &Path,
    samples: &[f64],
    sample_rate: u32,
    bit_depth: u16,
    channels: u16,
) -> Result<()> {
    let spec = WavSpec {
        channels,
        sample_rate,
        bits_per_sample: bit_depth,
        sample_format: if bit_depth == 32 {
            SampleFormat::Float
        } else {
            SampleFormat::Int
        },
    };

    let mut writer = WavWriter::create(path, spec)?;

    for &sample in samples {
        // Duplicate mono to stereo if needed
        for _ in 0..channels {
            match bit_depth {
                16 => {
                    let s = sample.clamp(-32768.0, 32767.0) as i16;
                    writer.write_sample(s)?;
                }
                24 => {
                    let s = sample.clamp(-8388608.0, 8388607.0) as i32;
                    writer.write_sample(s)?;
                }
                32 => {
                    let s = (sample / 32768.0) as f32;
                    writer.write_sample(s)?;
                }
                _ => {
                    let s = sample.clamp(-32768.0, 32767.0) as i16;
                    writer.write_sample(s)?;
                }
            }
        }
    }

    writer.finalize()?;
    Ok(())
}
