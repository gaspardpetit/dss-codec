/// DS2 file demuxer.
///
/// SP mode (0-1): byte-swap demuxing, returns list of 42-byte packets.
/// QP mode (6-7): continuous bitstream, returns raw byte stream + frame count.
use crate::error::{DecodeError, Result};
const DS2_HEADER_SIZE: usize = 0x600;
const DS2_BLOCK_SIZE: usize = 512;
const DS2_BLOCK_HEADER_SIZE: usize = 6;
const DSS_SP_PACKET_SIZE: usize = 42;
const DS2_QP_FRAME_SIZE: usize = 56;

const DS2_BLOCK_PAYLOAD_SIZE: usize = DS2_BLOCK_SIZE - DS2_BLOCK_HEADER_SIZE; // 506
const MS_PER_FRAME: usize = 16;
const MAX_ANNOTATIONS: usize = 32;

/// Demux a DS2 file.
/// Returns (frame_data, total_frames, is_qp).
/// For SP: frame_data is a Vec<Vec<u8>> of packets.
/// For QP: frame_data is a list of QpSegment.
pub fn demux_ds2(data: &[u8]) -> Result<DemuxedDs2> {
    if data.len() < DS2_HEADER_SIZE + DS2_BLOCK_SIZE || &data[1..4] != b"ds2" {
        return Err(DecodeError::NotDs2(std::path::PathBuf::from("<bytes>")));
    }

    let num_blocks = (data.len() - DS2_HEADER_SIZE) / DS2_BLOCK_SIZE;
    if num_blocks == 0 {
        return Err(DecodeError::Truncated("no audio data".to_string()));
    }
    let format_type = data[DS2_HEADER_SIZE + 4];

    if format_type >= 6 {
        // QP mode
        let mut raw = Vec::with_capacity(num_blocks * DS2_BLOCK_PAYLOAD_SIZE);
        for bi in 0..num_blocks {
            let bstart = DS2_HEADER_SIZE + bi * DS2_BLOCK_SIZE;
            raw.extend_from_slice(&data[bstart + DS2_BLOCK_HEADER_SIZE..bstart + DS2_BLOCK_SIZE]);
        }

        // Identify physical segments based on block header continuation markers.
        #[derive(Copy, Clone)]
        struct PhysSeg {
            raw_start: usize,
            frame_start: usize,
            frame_count: usize,
        }
        let mut phys_segs = Vec::new();
        let mut raw_read_pos = 0;
        let mut current_seg = PhysSeg {
            raw_start: 0,
            frame_start: 0,
            frame_count: 0,
        };

        for bi in 0..num_blocks {
            let bstart = DS2_HEADER_SIZE + bi * DS2_BLOCK_SIZE;
            let cont_bytes = data[bstart + 1] as usize * 2;
            let frame_count = data[bstart + 2] as usize;
            let payload_off = cont_bytes.saturating_sub(DS2_BLOCK_HEADER_SIZE);
            let frames_raw_start = bi * DS2_BLOCK_PAYLOAD_SIZE + payload_off;

            if bi == 0 {
                raw_read_pos = frames_raw_start;
                current_seg.raw_start = frames_raw_start;
            } else if frames_raw_start != raw_read_pos {
                if current_seg.frame_count > 0 {
                    phys_segs.push(current_seg);
                }
                current_seg = PhysSeg {
                    raw_start: frames_raw_start,
                    frame_start: current_seg.frame_start + current_seg.frame_count,
                    frame_count: 0,
                };
                raw_read_pos = frames_raw_start;
            }
            current_seg.frame_count += frame_count;
            raw_read_pos += frame_count * DS2_QP_FRAME_SIZE;
        }
        if current_seg.frame_count > 0 {
            phys_segs.push(current_seg);
        }

        let annotations = read_annotations(data);
        let mut out_segments = Vec::new();
        let mut total_frames_out = 0;
        let mut is_first_segment = true;

        for phys in phys_segs {
            let mut run_start = 0;
            let mut run_is_ann = is_annotation(phys.frame_start, &annotations);
            for i in 1..=phys.frame_count {
                let cur_is_ann = if i < phys.frame_count {
                    is_annotation(phys.frame_start + i, &annotations)
                } else {
                    !run_is_ann
                };

                if cur_is_ann != run_is_ann {
                    let run_len = i - run_start;
                    if run_len > 0 {
                        let start = phys.raw_start + run_start * DS2_QP_FRAME_SIZE;
                        let end = start + run_len * DS2_QP_FRAME_SIZE;
                        out_segments.push(QpSegment {
                            stream: raw[start..end].to_vec(),
                            frame_count: run_len,
                            reset_before: !is_first_segment,
                        });
                        is_first_segment = false;
                        total_frames_out += run_len;
                    }
                    run_start = i;
                    run_is_ann = cur_is_ann;
                }
            }
        }

        Ok(DemuxedDs2::Qp {
            segments: out_segments,
            total_frames: total_frames_out,
        })
    } else {
        // SP mode: byte-swap demuxing
        let mut total_frames = 0;
        for bi in 0..num_blocks {
            total_frames += data[DS2_HEADER_SIZE + bi * DS2_BLOCK_SIZE + 2] as usize;
        }

        let mut stream = Vec::new();
        for bi in 0..num_blocks {
            let bstart = DS2_HEADER_SIZE + bi * DS2_BLOCK_SIZE;
            stream
                .extend_from_slice(&data[bstart + DS2_BLOCK_HEADER_SIZE..bstart + DS2_BLOCK_SIZE]);
        }

        let mut swap = ((data[DS2_HEADER_SIZE] >> 7) & 1) as usize;
        let mut swap_byte: u8 = 0;
        let mut pos: usize = 0;
        let mut frame_packets = Vec::with_capacity(total_frames);

        for _fi in 0..total_frames {
            let mut pkt = [0u8; DSS_SP_PACKET_SIZE + 1];
            if swap != 0 {
                let read_size = 40;
                let end = (pos + read_size).min(stream.len());
                let count = end - pos;
                pkt[3..3 + count].copy_from_slice(&stream[pos..end]);
                pos += read_size;
                for i in (0..DSS_SP_PACKET_SIZE - 2).step_by(2) {
                    pkt[i] = pkt[i + 4];
                }
                pkt[DSS_SP_PACKET_SIZE] = 0;
                pkt[1] = swap_byte;
            } else {
                let end = (pos + DSS_SP_PACKET_SIZE).min(stream.len());
                let count = end - pos;
                pkt[..count].copy_from_slice(&stream[pos..end]);
                pos += DSS_SP_PACKET_SIZE;
                swap_byte = pkt[DSS_SP_PACKET_SIZE - 2];
            }
            pkt[DSS_SP_PACKET_SIZE - 2] = 0;
            swap ^= 1;
            frame_packets.push(pkt[..DSS_SP_PACKET_SIZE].to_vec());
        }

        Ok(DemuxedDs2::Sp {
            packets: frame_packets,
            total_frames,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct AnnRange {
    first_frame: usize,
    last_frame: usize,
}

fn read_annotations(data: &[u8]) -> Vec<AnnRange> {
    let mut result = Vec::new();
    let mut off = 0x400usize;

    while off + 8 <= 0x500.min(data.len()) && result.len() < MAX_ANNOTATIONS {
        let start_ms = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        if start_ms == 0xFFFF_FFFF {
            break;
        }
        let end_ms = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]));

        result.push(AnnRange {
            first_frame: start_ms as usize / MS_PER_FRAME,
            last_frame: end_ms as usize / MS_PER_FRAME,
        });
        off += 8;
    }
    result
}

#[inline]
fn is_annotation(abs_frame: usize, annotations: &[AnnRange]) -> bool {
    annotations
        .iter()
        .any(|a| abs_frame >= a.first_frame && abs_frame < a.last_frame)
}

pub enum DemuxedDs2 {
    Sp {
        packets: Vec<Vec<u8>>,
        total_frames: usize,
    },
    Qp {
        segments: Vec<QpSegment>,
        total_frames: usize,
    },
}

/// One uninterrupted run of QP frames ready for the bitstream decoder.
pub struct QpSegment {
    pub stream: Vec<u8>,
    pub frame_count: usize,
    /// True -> decoder must call `reset()` before processing this segment.
    pub reset_before: bool,
}

pub(crate) struct Ds2SpStreamDemuxer {
    header_complete: bool,
    block_buf: Vec<u8>,
    stream_buf: Vec<u8>,
    pending_frames: usize,
    swap: usize,
    swap_byte: u8,
    have_initial_swap: bool,
}

impl Ds2SpStreamDemuxer {
    pub(crate) fn new() -> Self {
        Self {
            header_complete: false,
            block_buf: Vec::new(),
            stream_buf: Vec::new(),
            pending_frames: 0,
            swap: 0,
            swap_byte: 0,
            have_initial_swap: false,
        }
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        let mut offset = 0;

        if !self.header_complete {
            let needed = DS2_HEADER_SIZE.saturating_sub(self.block_buf.len());
            let take = needed.min(data.len());
            self.block_buf.extend_from_slice(&data[..take]);
            offset += take;
            if self.block_buf.len() < DS2_HEADER_SIZE {
                return Ok(frames);
            }
            self.header_complete = true;
            self.block_buf.clear();
        }

        self.block_buf.extend_from_slice(&data[offset..]);
        while self.block_buf.len() >= DS2_BLOCK_SIZE {
            let block: Vec<u8> = self.block_buf.drain(..DS2_BLOCK_SIZE).collect();
            self.process_block(&block, &mut frames);
        }

        Ok(frames)
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<Vec<u8>>> {
        if !self.header_complete {
            if self.block_buf.is_empty() {
                return Ok(Vec::new());
            }
            return Err(DecodeError::Truncated("DS2 header".to_string()));
        }
        if !self.block_buf.is_empty() {
            return Err(DecodeError::Truncated("DS2 block".to_string()));
        }
        if self.pending_frames > 0 {
            return Err(DecodeError::Truncated("DS2 SP frame".to_string()));
        }
        Ok(Vec::new())
    }

    pub(crate) fn finish_lenient(&mut self) -> Result<Vec<Vec<u8>>> {
        if !self.header_complete {
            if self.block_buf.is_empty() {
                return Ok(Vec::new());
            }
            return Err(DecodeError::Truncated("DS2 header".to_string()));
        }

        self.block_buf.clear();

        let mut frames = Vec::with_capacity(self.pending_frames);
        while self.pending_frames > 0 {
            let needed = if self.swap != 0 {
                40
            } else {
                DSS_SP_PACKET_SIZE
            };
            frames.push(self.extract_sp_packet_padded(needed));
            self.pending_frames -= 1;
        }

        Ok(frames)
    }

    fn process_block(&mut self, block: &[u8], frames: &mut Vec<Vec<u8>>) {
        if !self.have_initial_swap {
            self.swap = ((block[0] >> 7) & 1) as usize;
            self.have_initial_swap = true;
        }
        self.pending_frames += block[2] as usize;
        self.stream_buf
            .extend_from_slice(&block[DS2_BLOCK_HEADER_SIZE..DS2_BLOCK_SIZE]);

        while self.pending_frames > 0 {
            let needed = if self.swap != 0 {
                40
            } else {
                DSS_SP_PACKET_SIZE
            };
            if self.stream_buf.len() < needed {
                break;
            }
            frames.push(self.extract_sp_packet(needed));
            self.pending_frames -= 1;
        }
    }

    fn extract_sp_packet(&mut self, read_size: usize) -> Vec<u8> {
        let mut pkt = [0u8; DSS_SP_PACKET_SIZE + 1];
        let chunk: Vec<u8> = self.stream_buf.drain(..read_size).collect();
        self.fill_sp_packet(&mut pkt, &chunk);
        pkt[..DSS_SP_PACKET_SIZE].to_vec()
    }

    fn extract_sp_packet_padded(&mut self, read_size: usize) -> Vec<u8> {
        let take = read_size.min(self.stream_buf.len());
        let chunk: Vec<u8> = self.stream_buf.drain(..take).collect();
        let mut pkt = [0u8; DSS_SP_PACKET_SIZE + 1];
        self.fill_sp_packet(&mut pkt, &chunk);
        pkt[..DSS_SP_PACKET_SIZE].to_vec()
    }

    fn fill_sp_packet(&mut self, pkt: &mut [u8; DSS_SP_PACKET_SIZE + 1], chunk: &[u8]) {
        if self.swap != 0 {
            pkt[3..3 + chunk.len()].copy_from_slice(chunk);
            for i in (0..DSS_SP_PACKET_SIZE - 2).step_by(2) {
                pkt[i] = pkt[i + 4];
            }
            pkt[DSS_SP_PACKET_SIZE] = 0;
            pkt[1] = self.swap_byte;
        } else {
            pkt[..chunk.len()].copy_from_slice(chunk);
            self.swap_byte = pkt[DSS_SP_PACKET_SIZE - 2];
        }
        pkt[DSS_SP_PACKET_SIZE - 2] = 0;
        self.swap ^= 1;
    }
}

pub(crate) struct Ds2QpStreamDemuxer {
    header_complete: bool,
    block_buf: Vec<u8>,
    stream_buf: Vec<u8>,
    pending_frames: usize,
}

impl Ds2QpStreamDemuxer {
    pub(crate) fn new() -> Self {
        Self {
            header_complete: false,
            block_buf: Vec::new(),
            stream_buf: Vec::new(),
            pending_frames: 0,
        }
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        let mut offset = 0;

        if !self.header_complete {
            let needed = DS2_HEADER_SIZE.saturating_sub(self.block_buf.len());
            let take = needed.min(data.len());
            self.block_buf.extend_from_slice(&data[..take]);
            offset += take;
            if self.block_buf.len() < DS2_HEADER_SIZE {
                return Ok(frames);
            }
            self.header_complete = true;
            self.block_buf.clear();
        }

        self.block_buf.extend_from_slice(&data[offset..]);
        while self.block_buf.len() >= DS2_BLOCK_SIZE {
            let block: Vec<u8> = self.block_buf.drain(..DS2_BLOCK_SIZE).collect();
            self.process_block(&block, &mut frames);
        }

        Ok(frames)
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<Vec<u8>>> {
        if !self.header_complete {
            if self.block_buf.is_empty() {
                return Ok(Vec::new());
            }
            return Err(DecodeError::Truncated("DS2 header".to_string()));
        }
        if !self.block_buf.is_empty() {
            return Err(DecodeError::Truncated("DS2 block".to_string()));
        }
        if self.pending_frames > 0 {
            return Err(DecodeError::Truncated("DS2 QP frame".to_string()));
        }
        Ok(Vec::new())
    }

    pub(crate) fn finish_lenient(&mut self) -> Result<Vec<Vec<u8>>> {
        if !self.header_complete {
            if self.block_buf.is_empty() {
                return Ok(Vec::new());
            }
            return Err(DecodeError::Truncated("DS2 header".to_string()));
        }

        self.block_buf.clear();

        let mut frames = Vec::with_capacity(self.pending_frames);
        while self.pending_frames > 0 {
            let take = DS2_QP_FRAME_SIZE.min(self.stream_buf.len());
            let mut frame = vec![0u8; DS2_QP_FRAME_SIZE];
            let chunk: Vec<u8> = self.stream_buf.drain(..take).collect();
            frame[..chunk.len()].copy_from_slice(&chunk);
            frames.push(frame);
            self.pending_frames -= 1;
        }

        Ok(frames)
    }

    fn process_block(&mut self, block: &[u8], frames: &mut Vec<Vec<u8>>) {
        self.pending_frames += block[2] as usize;
        self.stream_buf
            .extend_from_slice(&block[DS2_BLOCK_HEADER_SIZE..DS2_BLOCK_SIZE]);

        while self.pending_frames > 0 && self.stream_buf.len() >= DS2_QP_FRAME_SIZE {
            let frame: Vec<u8> = self.stream_buf.drain(..DS2_QP_FRAME_SIZE).collect();
            frames.push(frame);
            self.pending_frames -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ds2_file(mode: u8, frame_count: u8, payload_pattern: u8) -> Vec<u8> {
        let mut data = vec![0u8; DS2_HEADER_SIZE];
        data[..4].copy_from_slice(b"\x03ds2");

        let mut block = [0u8; DS2_BLOCK_SIZE];
        block[2] = frame_count;
        block[4] = mode;
        for (i, byte) in block[DS2_BLOCK_HEADER_SIZE..].iter_mut().enumerate() {
            *byte = payload_pattern.wrapping_add(i as u8);
        }

        data.extend_from_slice(&block);
        data
    }

    #[test]
    fn test_ds2_sp_stream_demux_matches_batch() {
        let data = make_ds2_file(0, 4, 0x10);
        let expected = match demux_ds2(&data).unwrap() {
            DemuxedDs2::Sp { packets, .. } => packets,
            _ => panic!("expected DS2 SP packets"),
        };

        let mut demuxer = Ds2SpStreamDemuxer::new();
        let mut actual = Vec::new();
        for chunk in data.chunks(137) {
            actual.extend(demuxer.push(chunk).unwrap());
        }
        actual.extend(demuxer.finish().unwrap());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_ds2_qp_stream_demux_matches_batch() {
        let data = make_ds2_file(6, 3, 0x40);
        let expected = match demux_ds2(&data).unwrap() {
            DemuxedDs2::Qp {
                segments,
                total_frames: _,
            } => segments
                .iter()
                .flat_map(|s| s.stream.chunks(DS2_QP_FRAME_SIZE))
                .map(|chunk| chunk.to_vec())
                .collect::<Vec<_>>(),
            _ => panic!("expected DS2 QP stream"),
        };

        let mut demuxer = Ds2QpStreamDemuxer::new();
        let mut actual = Vec::new();
        for chunk in data.chunks(113) {
            actual.extend(demuxer.push(chunk).unwrap());
        }
        actual.extend(demuxer.finish().unwrap());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_ds2_qp_stream_demux_truncated_frame() {
        let data = make_ds2_file(6, 10, 0x55);
        let mut demuxer = Ds2QpStreamDemuxer::new();
        for chunk in data.chunks(97) {
            let _ = demuxer.push(chunk).unwrap();
        }

        let err = demuxer.finish().unwrap_err();
        assert!(matches!(err, DecodeError::Truncated(_)));
    }
}
