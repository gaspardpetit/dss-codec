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
