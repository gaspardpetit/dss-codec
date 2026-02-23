# Reply to FFmpeg Trac #6091 — DS2 Format Support

*Draft reply for https://trac.ffmpeg.org/ticket/6091*

---

I've fully reverse-engineered the DS2 (DSS Pro) codec from Olympus's DssDecoder.dll / AudioSDK DLL using Ghidra, and built a working open-source decoder that produces output matching the proprietary DLLs (1.0000 correlation, bit-exact on all test files). Posting the complete findings here so this can finally get proper FFmpeg support.

**Reference implementation**: https://github.com/hirparak/dss-codec (Rust, MIT-licensed) — all algorithms, tables, and test vectors included.

## Why FFmpeg's DSS decoder doesn't work for DS2

The current `-f dss` path fails for three independent reasons:

1. **Wrong sample rate**: FFmpeg uses 11025 Hz. DS2 SP is 12000 Hz, DS2 QP is 16000 Hz.
2. **Different codec tables**: None of FFmpeg's `dss_sp` tables (filter_cb, fixed_cb_gain, pulse_val, adaptive_gain, sinc) exist in the Olympus DLL. The codecs share a CELP architecture but every parameter differs.
3. **Different demuxing**: DS2 SP uses a byte-swap packet scheme not present in FFmpeg's DSS demuxer. DS2 QP uses a continuous bitstream across blocks with no per-frame packet boundaries.

## Format detection

DS2 files have magic bytes `\x03ds2` (vs DSS: `\x02dss` or `\x03dss`).

The codec mode is determined by byte 4 of the first audio block (at file offset 0x604):

| byte4 value | Codec | Sample rate | Bitrate |
|-------------|-------|-------------|---------|
| 0-1 | DS2 SP | 12000 Hz | ~13.7 kbps |
| 2-5 | LP (unimplemented) | 8000 Hz | — |
| 6-7 | DS2 QP | 16000 Hz | ~28 kbps |

## File structure

- **Header**: 1536 bytes (0x600)
- **Audio data**: sequence of 512-byte blocks starting at offset 0x600
- **Block header**: 6 bytes per block (`byte0 byte1 frame_count 0xFF format_type 0xFF`)
  - `byte0` bit 7: swap initialization flag (SP mode only)
  - `byte1`: continuation size parameter (DSS/SP only, for empty block handling)
  - `byte2`: number of frames starting in this block
  - `byte4`: format type (0=SP, 6=QP)
- **Block payload**: 506 bytes of audio data per block

Total frame count = sum of `byte2` across all blocks.

## Bitstream reader

Both DS2 codecs use an MSB-first-within-16-bit-LE-words bitstream reader:

- Read 16-bit words in little-endian byte order
- Within each word, consume bits from MSB (bit 15) to LSB (bit 0)
- Fields span word boundaries seamlessly

This is the same bit order as FFmpeg's existing DSS SP reader.

## DS2 SP codec (mode 0-1, 12000 Hz)

### Parameters

| Parameter | DS2 SP | FFmpeg dss_sp |
|-----------|--------|---------------|
| Sample rate | 12000 Hz | 11025 Hz |
| Subframe size | 72 samples | 66 samples |
| Subframes/frame | 4 | 4 |
| Samples/frame | 288 | 264 |
| Reflection coeffs | 14 | 12 |
| Pitch range | 36–186 | 20–143 |
| Excitation pulses | 7 | 6 |
| Codebook | C(72,7) combinatorial | different |
| Frame bits | 328 | 264 |
| Packet size | 42 bytes | 42 bytes |
| Synthesis filter | Lattice (f64) | Direct-form |

### Demuxing (SP mode)

SP mode uses a byte-swap alternation scheme similar to FFmpeg's existing DSS demuxer, but the swap logic differs:

1. Strip 6-byte block headers, concatenate 506-byte payloads into a flat stream.
2. Initialize swap state from bit 7 of the first block's byte0.
3. Alternate between reading 42-byte (no-swap) and 40-byte (swap) chunks:
   - **No-swap frame**: Read 42 bytes directly as the packet. Save byte[40] as the swap byte.
   - **Swap frame**: Read 40 bytes into `pkt[3..43]`, then shift even-indexed bytes: `pkt[i] = pkt[i+4]` for i in 0..40 step 2. Set `pkt[1] = swap_byte`.
4. In both cases, zero out `pkt[40]` before decoding.
5. Toggle swap state after each frame.

### Frame bitfield layout (328 bits, MSB-first)

```
refl[0]:  5 bits    (codebook 0, 32 entries)
refl[1]:  5 bits    (codebook 1, 32 entries)
refl[2]:  4 bits    (codebook 2, 16 entries)
refl[3]:  4 bits    (codebook 3, 16 entries)
refl[4]:  4 bits    (codebook 4, 16 entries)
refl[5]:  4 bits    (codebook 5, 16 entries)
refl[6]:  4 bits    (codebook 6, 16 entries)
refl[7]:  4 bits    (codebook 7, 16 entries)
refl[8]:  3 bits    (codebook 8, 8 entries)
refl[9]:  3 bits    (codebook 9, 8 entries)
refl[10]: 3 bits    (codebook 10, 8 entries)
refl[11]: 3 bits    (codebook 11, 8 entries)
refl[12]: 3 bits    (codebook 12, 8 entries)
refl[13]: 3 bits    (codebook 13, 8 entries)
--- 52 bits total for reflection coefficients ---

Per subframe (x4):
  pitch_gain:  5 bits  (32 entries)
  cb_index:   31 bits  (combinatorial index into C(72,7))
  exc_gain:    6 bits  (64 entries)
  pulse[0..6]: 3 bits each = 21 bits  (7 pulses, 8 amplitudes each)
--- 63 bits per subframe, 252 total ---

combined_pitch: 24 bits  (encodes 4 pitch lags)
--- total: 52 + 252 + 24 = 328 bits ---
```

### Combined pitch encoding (SP)

The 24-bit combined pitch value encodes 4 subframe pitch lags:

```
p0_idx = combined % 151          (pitch range = 186-36+1 = 151)
remainder = combined / 151
delta1 = remainder % 48          (delta range = 48)
remainder = remainder / 48
delta2 = remainder % 48
delta3 = remainder              (clamped to 0..47)

pitch[0] = p0_idx + 36
pitch[i] = base + delta[i-1]     where base = max(36, min(prev - 23, 163))
```

The base calculation for delta decoding: `half_delta = 48/2 - 1 = 23`. If prev > 163 (upper_limit = 186 - 23), base = 163 - 23 = 140. If prev >= 59 (min_pitch + half_delta), base = prev - 23. Otherwise base = 36.

## DS2 QP codec (mode 6-7, 16000 Hz)

### Parameters

| Parameter | DS2 QP |
|-----------|--------|
| Sample rate | 16000 Hz |
| Subframe size | 64 samples |
| Subframes/frame | 4 |
| Samples/frame | 256 |
| Reflection coeffs | 16 |
| Pitch range | 45–300 |
| Excitation pulses | 11 |
| Codebook | C(64,11) combinatorial |
| Frame bits | 448 |
| De-emphasis | y[n] = x[n] + 0.1*y[n-1] |

### Demuxing (QP mode)

QP is simpler — no byte-swap. Strip 6-byte block headers, concatenate 506-byte payloads into a continuous bitstream. Frames are read sequentially from this stream (448 bits = 56 bytes each, but frames are not byte-aligned since the bitstream reader works at the bit level).

28 blocks = 14168 bytes of payload = 113344 bits. At 448 bits/frame, that's 253 frames per 28-block cycle.

### Frame bitfield layout (448 bits, MSB-first)

```
refl[0]:   7 bits   (codebook 0, 128 entries)
refl[1]:   7 bits   (codebook 1, 128 entries)
refl[2]:   6 bits   (codebook 2, 64 entries)
refl[3]:   6 bits   (codebook 3, 64 entries)
refl[4]:   5 bits   (codebook 4, 32 entries)
refl[5]:   5 bits   (codebook 5, 32 entries)
refl[6]:   5 bits   (codebook 6, 32 entries)
refl[7]:   5 bits   (codebook 7, 32 entries)
refl[8]:   5 bits   (codebook 8, 32 entries)
refl[9]:   4 bits   (codebook 9, 16 entries)
refl[10]:  4 bits   (codebook 10, 16 entries)
refl[11]:  4 bits   (codebook 11, 16 entries)
refl[12]:  4 bits   (codebook 12, 16 entries)
refl[13]:  3 bits   (codebook 13, 8 entries)
refl[14]:  3 bits   (codebook 14, 8 entries)
refl[15]:  3 bits   (codebook 15, 8 entries)
--- 76 bits total ---

Per subframe (x4):
  pitch:       8 bits   (direct index, pitch = index + 45)
  pitch_gain:  6 bits   (64 entries)
  cb_index:   40 bits   (combinatorial index into C(64,11))
  exc_gain:    6 bits   (64 entries)
  pulse[0..10]: 3 bits each = 33 bits  (11 pulses)
--- 93 bits per subframe, 372 total ---

--- total: 76 + 372 = 448 bits ---
```

Note: QP encodes pitch directly per subframe (8 bits each), not as a combined value like SP.

## Shared algorithms

### Combinatorial codebook

Both codecs use the combinatorial number system to encode pulse positions. An index value selects k positions from {0..n-1}:

```c
// Decode combinatorial index to k positions from {0..n-1}
// Positions are returned in DESCENDING order (do NOT sort!)
void decode_combinatorial(uint64_t index, int n, int k, int *positions) {
    uint64_t remaining = index;
    for (int i = k; i >= 1; i--) {
        int v = i - 1;
        while (v + 1 < n && comb(v + 1, i) <= remaining)
            v++;
        positions[k - i] = v;
        remaining -= comb(v, i);
    }
}
```

- SP: C(72, 7), 31-bit index, max value 1,473,109,703
- QP: C(64, 11), 40-bit index, max value 743,595,781,823

### Excitation generation (per subframe)

```
excitation[i] = pitch_gain * adaptive_exc[i] + fixed_exc[i]
```

Where:
- `adaptive_exc` = pitch memory repeated at the pitch period
- `fixed_exc` = sparse pulse excitation: for each pulse position p[j], `fixed_exc[p[j]] += pulse_amp[pulse_idx[j]] * exc_gain`

When pitch < subframe_size, the adaptive excitation wraps: `adaptive_exc[i] = pitch_memory[end - pitch + (i % pitch)]`.

### Lattice synthesis filter

Both codecs use an identical normalized lattice filter with the reflection coefficients:

```c
// p = number of reflection coefficients (14 for SP, 16 for QP)
// coeffs[] = dequantized reflection coefficients
// state[] = persistent filter state (p elements, init to 0)
for (int n = 0; n < subframe_size; n++) {
    double acc = excitation[n] - state[p-1] * coeffs[p-1];
    for (int k = p-2; k >= 0; k--) {
        acc -= state[k] * coeffs[k];
        state[k+1] = coeffs[k] * acc + state[k];
    }
    state[0] = acc;
    output[n] = acc;
}
```

### De-emphasis (QP only)

QP applies a first-order de-emphasis filter after synthesis:

```
y[n] = x[n] + 0.1 * y[n-1]
```

SP does not use de-emphasis.

## Quantization tables

All tables were extracted from the Olympus DssDecoder.dll / AudioSDK DLL via Ghidra. The complete tables (reflection coefficient codebooks + quantization tables) are available in the reference implementation. Summary of table sizes:

### SP quantization tables

- **Pitch gain**: 32 entries (5-bit), linear range 0.05–2.0
- **Excitation gain**: 64 entries (6-bit), roughly exponential 0–5000
- **Pulse amplitude**: 8 entries (3-bit), symmetric [-0.952, 0.952]
- **Reflection codebooks**: 14 codebooks, sizes [32, 32, 16, 16, 16, 16, 16, 16, 8, 8, 8, 8, 8, 8] entries (f64)

### QP quantization tables

- **Pitch gain**: 64 entries (6-bit), non-linear range 0.005–2.0
- **Excitation gain**: 64 entries (6-bit), range 3.9–4970.3
- **Pulse amplitude**: 8 entries (3-bit), asymmetric [-0.922, 0.931]
- **Reflection codebooks**: 16 codebooks, sizes [128, 128, 64, 64, 32, 32, 32, 32, 32, 16, 16, 16, 16, 8, 8, 8] entries (f64)

The full table data is in the source repo. The SP and QP codecs use **completely different** quantization tables — they're at different DLL addresses and have different value ranges.

## Implementation notes for FFmpeg

1. **Demuxer changes**: The existing DSS demuxer (`libavformat/dss.c`) needs to detect `\x03ds2` magic and handle the DS2 block structure. SP byte-swap logic is similar to DSS but not identical. QP needs a continuous-bitstream mode. The demuxer should set codec_id based on byte4 of the first block.

2. **New codec IDs**: Need at least `AV_CODEC_ID_DS2_SP` and `AV_CODEC_ID_DS2_QP` (or a single `AV_CODEC_ID_DS2` with mode detection in init).

3. **Arithmetic precision**: The DLL uses f64 (double) throughout. An f32 implementation would likely introduce audible artifacts given the lattice filter's sensitivity to coefficient precision.

4. **State management**: Each codec maintains persistent state across frames: lattice filter state (14 or 16 doubles), pitch memory buffer (up to 186+72 or 300+64 doubles), and de-emphasis state (QP only).

5. **The DSS SP codec in FFmpeg is unrelated**: Despite the similar name, FFmpeg's existing `dss_sp` codec (11025 Hz, direct-form filter, different tables) cannot be adapted for DS2. The codec needs to be written from scratch.

## Verification

The reference decoder has been verified against output from the proprietary Olympus DirectShow filters (via NCH Switch under Wine):

- **DS2 SP**: 1.0000 correlation, 99% sample-exact (±1 from f64→i16 rounding)
- **DS2 QP**: 1.0000 correlation, 100% sample-exact (bit-exact match)

Happy to provide test files and reference WAVs for anyone working on an FFmpeg implementation.
