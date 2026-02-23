/// DSS block-aware demuxer with byte-swap frame extraction.
///
/// Handles empty blocks (frame_count=0) by only including continuation bytes
/// from empty block payloads, and resetting swap state at block group boundaries.
use crate::error::{DecodeError, Result};

const DSS_BLOCK_SIZE: usize = 512;
const DSS_BLOCK_HEADER_SIZE: usize = 6;
const DSS_SP_FRAME_SIZE: usize = 42;

struct BlockInfo {
    frame_count: usize,
    swap: usize,
    cont_size: usize,
    payload: Vec<u8>,
}

pub fn demux_dss(data: &[u8]) -> Result<(Vec<Vec<u8>>, usize)> {
    if data.len() < 4 || data[1..4] != *b"dss" || (data[0] != 2 && data[0] != 3) {
        return Err(DecodeError::NotDss(std::path::PathBuf::from("<bytes>")));
    }

    let version = data[0] as usize;
    let header_size = version * DSS_BLOCK_SIZE;
    let num_blocks = (data.len() - header_size) / DSS_BLOCK_SIZE;

    let mut blocks = Vec::with_capacity(num_blocks);
    let mut total_frames: usize = 0;

    for bi in 0..num_blocks {
        let bstart = header_size + bi * DSS_BLOCK_SIZE;
        let byte0 = data[bstart];
        let byte1 = data[bstart + 1] as usize;
        let frame_count = data[bstart + 2] as usize;
        let blk_swap = ((byte0 >> 7) & 1) as usize;
        let cont_size = (2 * byte1 + 2 * blk_swap).saturating_sub(DSS_BLOCK_HEADER_SIZE);
        let payload_end = bstart + DSS_BLOCK_SIZE;
        let payload = data[bstart + DSS_BLOCK_HEADER_SIZE..payload_end].to_vec();
        blocks.push(BlockInfo {
            frame_count,
            swap: blk_swap,
            cont_size,
            payload,
        });
        total_frames += frame_count;
    }

    // Build stream: for empty blocks, only include continuation bytes.
    // Track positions where swap state needs resetting.
    let mut stream = Vec::new();
    let mut swap_reset_positions = std::collections::HashMap::new();
    let mut pos: usize = 0;

    for bi in 0..blocks.len() {
        if blocks[bi].frame_count == 0 {
            let cs = blocks[bi].cont_size.min(blocks[bi].payload.len());
            stream.extend_from_slice(&blocks[bi].payload[..cs]);
            pos += cs;
            // Find next non-empty block and record its swap state
            for nbi in (bi + 1)..blocks.len() {
                if blocks[nbi].frame_count > 0 {
                    swap_reset_positions.insert(pos, blocks[nbi].swap);
                    break;
                }
            }
        } else {
            stream.extend_from_slice(&blocks[bi].payload);
            pos += blocks[bi].payload.len();
        }
    }

    // Byte-swap demuxing
    let mut swap = blocks[0].swap;
    let mut swap_byte: u8 = 0;
    let mut spos: usize = 0;
    let mut frame_packets = Vec::with_capacity(total_frames);

    for _fi in 0..total_frames {
        if let Some(&new_swap) = swap_reset_positions.get(&spos) {
            swap = new_swap;
            swap_byte = 0;
        }

        let mut pkt = [0u8; DSS_SP_FRAME_SIZE + 1];
        if swap != 0 {
            let read_size = 40;
            let end = (spos + read_size).min(stream.len());
            let count = end - spos;
            pkt[3..3 + count].copy_from_slice(&stream[spos..end]);
            spos += read_size;
            for i in (0..DSS_SP_FRAME_SIZE - 2).step_by(2) {
                pkt[i] = pkt[i + 4];
            }
            pkt[DSS_SP_FRAME_SIZE] = 0;
            pkt[1] = swap_byte;
        } else {
            let end = (spos + DSS_SP_FRAME_SIZE).min(stream.len());
            let count = end - spos;
            pkt[..count].copy_from_slice(&stream[spos..end]);
            spos += DSS_SP_FRAME_SIZE;
            swap_byte = pkt[DSS_SP_FRAME_SIZE - 2];
        }
        pkt[DSS_SP_FRAME_SIZE - 2] = 0;
        swap ^= 1;
        frame_packets.push(pkt[..DSS_SP_FRAME_SIZE].to_vec());
    }

    Ok((frame_packets, total_frames))
}
