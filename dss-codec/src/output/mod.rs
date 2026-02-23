pub mod wav;
pub mod resample;

/// Output configuration
#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub sample_rate: Option<u32>,
    pub bit_depth: u16,
    pub channels: u16,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            sample_rate: None, // native rate
            bit_depth: 16,
            channels: 1,
        }
    }
}
