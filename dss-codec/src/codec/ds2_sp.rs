//! DS2 SP decoder — f64 lattice synthesis, 12000 Hz output.
//!
//! 14 reflection coefficients, 72-sample subframes, 4 subframes/frame,
//! 7-pulse combinatorial codebook C(72,7), byte-swap demuxed packets.

use crate::bitstream::BitstreamReader;
use crate::codec::common::{decode_combinatorial_index, decode_combined_pitch, lattice_synthesis};
use crate::tables::ds2_sp::sp_codebook_lookup;
use crate::tables::ds2_quant::{SP_EXCITATION_GAIN, SP_PITCH_GAIN, SP_PULSE_AMP};

const NUM_COEFFS: usize = 14;
const NUM_SUBFRAMES: usize = 4;
const SUBFRAME_SIZE: usize = 72;
const SAMPLES_PER_FRAME: usize = NUM_SUBFRAMES * SUBFRAME_SIZE; // 288
const MIN_PITCH: u32 = 36;
const MAX_PITCH: u32 = 186;
const PITCH_RANGE: u32 = MAX_PITCH - MIN_PITCH + 1; // 151
const PITCH_DELTA_RANGE: u32 = 48;
const EXCITATION_PULSES: usize = 7;
const REFL_BIT_ALLOC: [u32; 14] = [5, 5, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3];
const PITCH_GAIN_BITS: u32 = 5;
const GAIN_BITS: u32 = 6;
const PULSE_BITS: u32 = 3;
const COMBINED_PITCH_BITS: u32 = 24;
// CB_BITS = ceil(log2(C(72,7))) = ceil(log2(1473109704)) = 31
const CB_BITS: u32 = 31;

pub struct Ds2SpDecoder {
    lattice_state: [f64; NUM_COEFFS],
    pitch_memory: Vec<f64>,
}

impl Default for Ds2SpDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ds2SpDecoder {
    pub fn new() -> Self {
        Self {
            lattice_state: [0.0; NUM_COEFFS],
            pitch_memory: vec![0.0; MAX_PITCH as usize + SUBFRAME_SIZE],
        }
    }

    /// Decode a single SP frame from a 42-byte packet. Returns 288 f64 samples.
    pub fn decode_frame(&mut self, pkt: &[u8]) -> Vec<f64> {
        let mut reader = BitstreamReader::new(pkt);

        // Read reflection coefficient indices
        let mut refl_indices = [0usize; NUM_COEFFS];
        for i in 0..NUM_COEFFS {
            refl_indices[i] = reader.read_bits(REFL_BIT_ALLOC[i]) as usize;
        }

        // Read per-subframe parameters
        let mut subframe_data = Vec::with_capacity(NUM_SUBFRAMES);
        for _ in 0..NUM_SUBFRAMES {
            let pg_idx = reader.read_bits(PITCH_GAIN_BITS) as usize;
            let cb_idx = reader.read_bits(CB_BITS) as u64;
            let gain_idx = reader.read_bits(GAIN_BITS) as usize;
            let mut pulses = [0usize; EXCITATION_PULSES];
            for p in &mut pulses {
                *p = reader.read_bits(PULSE_BITS) as usize;
            }
            subframe_data.push((pg_idx, cb_idx, gain_idx, pulses));
        }

        // Read combined pitch (at end of frame)
        let combined_pitch = reader.read_bits(COMBINED_PITCH_BITS);

        // Decode pitch lags
        let pitches = decode_combined_pitch(
            combined_pitch,
            PITCH_RANGE,
            MIN_PITCH,
            PITCH_DELTA_RANGE,
            NUM_SUBFRAMES,
        );

        // Dequantize reflection coefficients
        let mut coeffs = [0.0f64; NUM_COEFFS];
        for i in 0..NUM_COEFFS {
            coeffs[i] = sp_codebook_lookup(i, refl_indices[i]);
        }

        // Decode subframes
        let mut all_output = Vec::with_capacity(SAMPLES_PER_FRAME);

        for sf in 0..NUM_SUBFRAMES {
            let (pg_idx, cb_idx, gain_idx, pulses) = &subframe_data[sf];
            let pitch = pitches[sf] as usize;
            let gp = SP_PITCH_GAIN[*pg_idx];

            // Adaptive excitation from pitch memory
            let mut adaptive_exc = [0.0f64; SUBFRAME_SIZE];
            let mem_len = self.pitch_memory.len();
            for i in 0..SUBFRAME_SIZE {
                let mem_idx = if pitch < SUBFRAME_SIZE {
                    mem_len - pitch + (i % pitch)
                } else {
                    mem_len - pitch + i
                };
                if mem_idx < mem_len {
                    adaptive_exc[i] = self.pitch_memory[mem_idx];
                }
            }

            // Fixed codebook excitation
            let gc = SP_EXCITATION_GAIN[*gain_idx];
            let positions =
                decode_combinatorial_index(*cb_idx, SUBFRAME_SIZE, EXCITATION_PULSES);
            let mut fixed_exc = [0.0f64; SUBFRAME_SIZE];
            for (pi, &pos) in positions.iter().enumerate() {
                if pos < SUBFRAME_SIZE {
                    fixed_exc[pos] += SP_PULSE_AMP[pulses[pi]] * gc;
                }
            }

            // Total excitation
            let mut excitation = [0.0f64; SUBFRAME_SIZE];
            for i in 0..SUBFRAME_SIZE {
                excitation[i] = gp * adaptive_exc[i] + fixed_exc[i];
            }

            // Lattice synthesis
            let output = lattice_synthesis(&excitation, &coeffs, &mut self.lattice_state);

            // Update pitch memory
            let mem_len = self.pitch_memory.len();
            self.pitch_memory.copy_within(SUBFRAME_SIZE..mem_len, 0);
            let start = mem_len - SUBFRAME_SIZE;
            self.pitch_memory[start..].copy_from_slice(&excitation);

            all_output.extend_from_slice(&output);
        }

        all_output
    }
}
