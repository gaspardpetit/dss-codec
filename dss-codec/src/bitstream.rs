/// MSB-first bitstream reader within 16-bit little-endian words.
///
/// Matches DssDecoder.dll FUN_10017460: reads bits from MSB to LSB within
/// each 16-bit word, words stored in little-endian byte order.
pub struct BitstreamReader<'a> {
    data: &'a [u8],
    word_index: usize,
    mask: u16,
    current_word: u16,
}

impl<'a> BitstreamReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            word_index: 0,
            mask: 0,
            current_word: 0,
        }
    }

    fn load_next_word(&mut self) {
        let offset = self.word_index * 2;
        if offset + 1 < self.data.len() {
            self.current_word =
                self.data[offset] as u16 | ((self.data[offset + 1] as u16) << 8);
        } else {
            self.current_word = 0;
        }
        self.word_index += 1;
    }

    pub fn read_bits(&mut self, n: u32) -> u32 {
        debug_assert!(n <= 32, "read_bits: n={} exceeds u32", n);
        self.read_bits_u64(n) as u32
    }

    /// Read up to 64 bits — needed for QP CB index (40 bits)
    pub fn read_bits_u64(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut result: u64 = 0;
        let mut result_mask: u64 = 1 << (n - 1);

        for _ in 0..n {
            if self.mask == 0 {
                self.mask = 0x8000;
                self.load_next_word();
            } else {
                self.mask >>= 1;
                if self.mask == 0 {
                    self.mask = 0x8000;
                    self.load_next_word();
                }
            }
            if self.current_word & self.mask != 0 {
                result |= result_mask;
            }
            result_mask >>= 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bits_basic() {
        // Two 16-bit LE words: 0xABCD, 0x1234
        // LE bytes: [0xCD, 0xAB, 0x34, 0x12]
        // Word 0 = 0xABCD, bits MSB first: 1010_1011_1100_1101
        // Word 1 = 0x1234, bits MSB first: 0001_0010_0011_0100
        let data = [0xCD, 0xAB, 0x34, 0x12];
        let mut reader = BitstreamReader::new(&data);

        // Read 4 bits from word 0: 1010 = 10
        assert_eq!(reader.read_bits(4), 0b1010);
        // Read 8 bits: 1011_1100 = 0xBC
        assert_eq!(reader.read_bits(8), 0b1011_1100);
        // Read 4 bits: 1101 = 13
        assert_eq!(reader.read_bits(4), 0b1101);
        // Now on word 1: read 8 bits: 0001_0010 = 0x12
        assert_eq!(reader.read_bits(8), 0b0001_0010);
    }

    #[test]
    fn test_read_bits_cross_word() {
        let data = [0xFF, 0xFF, 0x00, 0x00];
        let mut reader = BitstreamReader::new(&data);

        // Read 12 bits from word 0: all 1s
        assert_eq!(reader.read_bits(12), 0xFFF);
        // Read 8 bits crossing word boundary: 1111_0000
        assert_eq!(reader.read_bits(8), 0xF0);
    }

    #[test]
    fn test_read_zero_bits() {
        let data = [0xFF, 0xFF];
        let mut reader = BitstreamReader::new(&data);
        assert_eq!(reader.read_bits(0), 0);
    }
}
