pub mod bitstream;
pub mod codec;
pub mod crypto;
pub mod demux;
pub mod error;
pub mod output;
pub mod streaming;
pub mod tables;

use crate::crypto::ds2_encrypted::{decrypt_encrypted_ds2, ENCRYPTED_MAGIC};
use crate::demux::{detect_format, AudioFormat};
use crate::error::{DecodeError, Result};
use crate::output::resample::resample;
use crate::output::wav::write_wav;
use crate::output::OutputConfig;
use crate::streaming::StreamingDecoder;

use std::borrow::Cow;
use std::path::Path;

/// Decoded audio buffer
pub struct AudioBuffer {
    /// Samples as f64 (mono)
    pub samples: Vec<f64>,
    /// Native sample rate before any resampling
    pub native_rate: u32,
    /// Detected format
    pub format: AudioFormat,
}

/// Decode a DSS/DS2 file to an AudioBuffer.
pub fn decode_file(path: &Path) -> Result<AudioBuffer> {
    decode_file_with_password(path, None)
}

/// Decode a DSS/DS2 file to an AudioBuffer, optionally decrypting encrypted DS2 input first.
pub fn decode_file_with_password(path: &Path, password: Option<&[u8]>) -> Result<AudioBuffer> {
    let data = std::fs::read(path)?;
    decode_to_buffer_with_password(&data, password)
}

/// Decode raw file bytes to an AudioBuffer.
pub fn decode_to_buffer(data: &[u8]) -> Result<AudioBuffer> {
    decode_to_buffer_with_password(data, None)
}

/// Decode raw file bytes to an AudioBuffer, optionally decrypting encrypted DS2 input first.
pub fn decode_to_buffer_with_password(data: &[u8], password: Option<&[u8]>) -> Result<AudioBuffer> {
    let prepared = prepare_decode_bytes(data, password)?;
    let mut decoder = StreamingDecoder::new();
    let mut samples = decoder.push(&prepared)?;
    samples.extend(decoder.finish_lenient()?);

    let format = decoder
        .format()
        .or_else(|| detect_format(&prepared))
        .ok_or_else(|| DecodeError::UnsupportedFormat(prepared.first().copied().unwrap_or(0)))?;

    Ok(AudioBuffer {
        samples,
        native_rate: format.native_sample_rate(),
        format,
    })
}

fn prepare_decode_bytes<'a>(data: &'a [u8], password: Option<&[u8]>) -> Result<Cow<'a, [u8]>> {
    if data.starts_with(&ENCRYPTED_MAGIC) {
        let password = password.ok_or_else(|| {
            DecodeError::EncryptedDs2("password required for encrypted DS2 input".to_string())
        })?;
        let decrypted = decrypt_encrypted_ds2(data, password)?;
        return Ok(Cow::Owned(decrypted));
    }
    Ok(Cow::Borrowed(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ds2_sp::Ds2SpDecoder;
    use crate::codec::dss_sp::DssSpDecoder;
    use crate::codec::ds2_qp::Ds2QpDecoder;
    use crate::demux::ds2::{demux_ds2, DemuxedDs2};
    use crate::demux::dss::demux_dss;
    fn make_truncated_ds2_qp_file(frame_count: u8) -> Vec<u8> {
        let mut data = vec![0u8; 0x600];
        data[..4].copy_from_slice(b"\x03ds2");

        let mut block = [0u8; 512];
        block[2] = frame_count;
        block[4] = 6;
        for (i, byte) in block[6..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }

        data.extend_from_slice(&block);
        data
    }

    fn make_truncated_ds2_sp_file(frame_count: u8) -> Vec<u8> {
        let mut data = vec![0u8; 0x600];
        data[..4].copy_from_slice(b"\x03ds2");

        let mut block = [0u8; 512];
        block[2] = frame_count;
        block[4] = 0;
        for (i, byte) in block[6..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(5).wrapping_add(7);
        }

        data.extend_from_slice(&block);
        data
    }

    fn make_truncated_dss_sp_file(frame_count: u8) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0] = 2;
        data[1..4].copy_from_slice(b"dss");

        let mut block = [0u8; 512];
        block[2] = frame_count;
        for (i, byte) in block[6..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
        }

        data.extend_from_slice(&block);
        data
    }

    #[test]
    fn test_decode_to_buffer_keeps_legacy_lenient_tail_handling_for_ds2_qp() {
        let data = make_truncated_ds2_qp_file(10);

        let expected = match demux_ds2(&data).unwrap() {
            DemuxedDs2::Qp {
                stream,
                total_frames,
            } => {
                let mut decoder = Ds2QpDecoder::new();
                decoder.decode_all_frames(&stream, total_frames)
            }
            _ => panic!("expected DS2 QP stream"),
        };

        let decoded = decode_to_buffer(&data).unwrap();
        let mut streaming = StreamingDecoder::new();
        let _ = streaming.push(&data).unwrap();

        assert!(matches!(streaming.finish(), Err(DecodeError::Truncated(_))));
        assert_eq!(decoded.format, AudioFormat::Ds2Qp);
        assert_eq!(decoded.native_rate, 16000);
        assert_eq!(decoded.samples, expected);
    }

    #[test]
    fn test_decode_to_buffer_keeps_legacy_lenient_tail_handling_for_ds2_sp() {
        let data = make_truncated_ds2_sp_file(13);

        let expected = match demux_ds2(&data).unwrap() {
            DemuxedDs2::Sp { packets, .. } => {
                let mut decoder = Ds2SpDecoder::new();
                let mut samples = Vec::new();
                for packet in &packets {
                    samples.extend_from_slice(&decoder.decode_frame(packet));
                }
                samples
            }
            _ => panic!("expected DS2 SP packets"),
        };

        let decoded = decode_to_buffer(&data).unwrap();
        let mut streaming = StreamingDecoder::new();
        let _ = streaming.push(&data).unwrap();

        assert!(matches!(streaming.finish(), Err(DecodeError::Truncated(_))));
        assert_eq!(decoded.format, AudioFormat::Ds2Sp);
        assert_eq!(decoded.native_rate, 12000);
        assert_eq!(decoded.samples, expected);
    }

    #[test]
    fn test_decode_to_buffer_keeps_legacy_lenient_tail_handling_for_dss_sp() {
        let data = make_truncated_dss_sp_file(13);

        let expected = {
            let (packets, _) = demux_dss(&data).unwrap();
            let mut decoder = DssSpDecoder::new();
            let mut samples = Vec::new();
            for packet in &packets {
                samples.extend(decoder.decode_frame(packet).into_iter().map(|sample| sample as f64));
            }
            samples
        };

        let decoded = decode_to_buffer(&data).unwrap();
        let mut streaming = StreamingDecoder::new();
        let _ = streaming.push(&data).unwrap();

        assert!(matches!(streaming.finish(), Err(DecodeError::Truncated(_))));
        assert_eq!(decoded.format, AudioFormat::DssSp);
        assert_eq!(decoded.native_rate, 11025);
        assert_eq!(decoded.samples, expected);
    }
}

/// Decode a file and write to WAV with given output configuration.
pub fn decode_and_write(input: &Path, output: &Path, config: &OutputConfig) -> Result<AudioBuffer> {
    decode_and_write_with_password(input, output, config, None)
}

pub fn decode_and_write_with_password(
    input: &Path,
    output: &Path,
    config: &OutputConfig,
    password: Option<&[u8]>,
) -> Result<AudioBuffer> {
    let mut buf = decode_file_with_password(input, password)?;

    let target_rate = config.sample_rate.unwrap_or(buf.native_rate);

    if target_rate != buf.native_rate {
        buf.samples = resample(&buf.samples, buf.native_rate, target_rate)?;
    }

    write_wav(
        output,
        &buf.samples,
        target_rate,
        config.bit_depth,
        config.channels,
    )?;

    Ok(buf)
}
