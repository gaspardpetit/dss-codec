use std::path::Path;

#[test]
fn test_detect_ds2_sp() {
    let path = Path::new("../test_files/sample_sp.DS2");
    if !path.exists() {
        eprintln!("Skipping: test file not found (place an SP-mode .DS2 file at test_files/sample_sp.DS2)");
        return;
    }
    let data = std::fs::read(path).unwrap();
    let fmt = dss_codec::demux::detect_format(&data).unwrap();
    assert_eq!(fmt, dss_codec::demux::AudioFormat::Ds2Sp);
}

#[test]
fn test_detect_ds2_qp() {
    let path = Path::new("../test_files/sample_qp.DS2");
    if !path.exists() {
        eprintln!("Skipping: test file not found (place a QP-mode .DS2 file at test_files/sample_qp.DS2)");
        return;
    }
    let data = std::fs::read(path).unwrap();
    let fmt = dss_codec::demux::detect_format(&data).unwrap();
    assert_eq!(fmt, dss_codec::demux::AudioFormat::Ds2Qp);
}

#[test]
fn test_decode_ds2_sp_basic() {
    let path = Path::new("../test_files/sample_sp.DS2");
    if !path.exists() {
        eprintln!("Skipping: test file not found");
        return;
    }
    let buf = dss_codec::decode_file(path).unwrap();
    assert_eq!(buf.native_rate, 12000);
    assert!(!buf.samples.is_empty());
    // SP mode: 288 samples per frame
    assert_eq!(buf.samples.len() % 288, 0);
}

#[test]
fn test_decode_ds2_qp_basic() {
    let path = Path::new("../test_files/sample_qp.DS2");
    if !path.exists() {
        eprintln!("Skipping: test file not found");
        return;
    }
    let buf = dss_codec::decode_file(path).unwrap();
    assert_eq!(buf.native_rate, 16000);
    assert!(!buf.samples.is_empty());
    // QP mode: 256 samples per frame
    assert_eq!(buf.samples.len() % 256, 0);
}

#[test]
fn test_decode_dss_sp_basic() {
    let path = Path::new("../test_files/sample.DSS");
    if !path.exists() {
        eprintln!("Skipping: test file not found (place a .DSS file at test_files/sample.DSS)");
        return;
    }
    let buf = dss_codec::decode_file(path).unwrap();
    assert_eq!(buf.native_rate, 11025);
    assert!(!buf.samples.is_empty());
}

#[test]
fn test_detect_grundig_sp() {
    let data = include_bytes!("fixtures/grundig_sample.dss");
    let fmt = dss_codec::demux::detect_format(data).unwrap();
    assert_eq!(fmt, dss_codec::demux::AudioFormat::GrundigSp);
    assert_eq!(fmt.native_sample_rate(), 16000);
}

#[test]
fn test_decode_grundig_sp_bit_exact() {
    use std::io::Write;

    // Decode the committed Grundig .dss sample to a 16 kHz WAV and compare it
    // byte-for-byte with the reference produced by the genuine Grundig decoder.
    let data = include_bytes!("fixtures/grundig_sample.dss");
    let reference = include_bytes!("fixtures/grundig_sample_16k.wav");

    let dir = std::env::temp_dir();
    let in_path = dir.join("dss_codec_grundig_in.dss");
    let out_path = dir.join("dss_codec_grundig_out.wav");
    {
        let mut f = std::fs::File::create(&in_path).unwrap();
        f.write_all(data).unwrap();
    }

    let buf = dss_codec::decode_and_write(
        &in_path,
        &out_path,
        &dss_codec::output::OutputConfig::default(),
    )
    .unwrap();

    assert_eq!(buf.format, dss_codec::demux::AudioFormat::GrundigSp);
    assert_eq!(buf.native_rate, 16000);
    assert!(!buf.samples.is_empty());
    // Grundig SP yields 384 samples per frame @ 16 kHz.
    assert_eq!(buf.samples.len() % 384, 0);

    let produced = std::fs::read(&out_path).unwrap();
    assert_eq!(
        produced.len(),
        reference.len(),
        "WAV length mismatch: {} vs reference {}",
        produced.len(),
        reference.len()
    );
    assert!(
        produced == reference,
        "decoded Grundig WAV is not byte-for-byte identical to the reference"
    );

    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&out_path);
}

fn assert_encrypted_ds2_matches_golden(input: &[u8], reference: &[u8], mode: &str) {
    let buf = dss_codec::decode_to_buffer_with_password(input, Some(b"1234")).unwrap();
    assert!(matches!(
        buf.format,
        dss_codec::demux::AudioFormat::Ds2Qp | dss_codec::demux::AudioFormat::Ds2Qp7
    ));
    assert_eq!(buf.native_rate, 16000);

    let out_path = std::env::temp_dir().join(format!(
        "dss_codec_encrypted_{mode}_{}_out.wav",
        std::process::id()
    ));
    dss_codec::output::wav::write_wav(&out_path, &buf.samples, buf.native_rate, 16, 1).unwrap();

    let produced = std::fs::read(&out_path).unwrap();
    assert_eq!(
        produced, reference,
        "encrypted DS2 {mode} output changed from the reviewed golden WAV"
    );

    let _ = std::fs::remove_file(out_path);
}

#[test]
fn test_decode_encrypted_ds2_aes128_matches_golden() {
    assert_encrypted_ds2_matches_golden(
        include_bytes!("fixtures/encrypted_aes128.ds2"),
        include_bytes!("fixtures/encrypted_aes128_reference.wav"),
        "aes128",
    );
}

#[test]
fn test_decode_encrypted_ds2_aes256_matches_golden() {
    assert_encrypted_ds2_matches_golden(
        include_bytes!("fixtures/encrypted_aes256.ds2"),
        include_bytes!("fixtures/encrypted_aes256_reference.wav"),
        "aes256",
    );
}
