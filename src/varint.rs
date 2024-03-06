use std::io::{self, Cursor, Read};

/// We create a `VarInt` struct to hold methods for calculating
/// the number of bytes in the `VarInt``
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct VarInt;

impl VarInt {
    /// This converts our VarInt byte into the number of bytes that we need to parse
    pub const fn parse(byte: u8) -> usize {
        match byte {
            // 0 to 252 is treated as a Rust u8 which is 1 byte long
            0..=252 => 1,
            // 253 is treated as a Rust u16 which is 2 bytes long
            253 => 2,
            // 253 is treated as a Rust u32 which is 4 bytes long
            254 => 4,
            // 253 is treated as a Rust u64 which is 8 bytes long
            255 => 8,
        }
    }

    /// Given a Cursor of bytes, we read the current or next number of bytes
    /// then convert them into an integer
    pub fn integer(byte_len: usize, bytes: &mut Cursor<&[u8]>) -> io::Result<usize> {
        let outcome = match byte_len {
            1 => {
                // NOTE - Since we are reading one value and the Cursor always advances
                // by the number of bytes read, we reset the cursor to the last position
                // in order to parse that one byte. First we get the current cursor
                // position using `bytes.position()` and then subtract 1
                bytes.set_position(bytes.position() - 1);

                // A u8 has array length of 1
                let mut buffer = [0u8; 1];
                // Read exactly one byte
                bytes.read_exact(&mut buffer)?;

                buffer[0] as usize
            }
            2 => {
                // A u16 has array length of 2
                let mut buffer = [0u8; 2];
                // Read exactly two bytes
                bytes.read_exact(&mut buffer)?;

                u16::from_le_bytes(buffer) as usize
            }
            4 => {
                // A u32 has array length of 4
                let mut buffer = [0u8; 4];
                // Read exactly four bytes
                bytes.read_exact(&mut buffer)?;

                u32::from_le_bytes(buffer) as usize
            }
            8 => {
                // A u32 has array length of 8
                let mut buffer = [0u8; 8];
                // Read exactly eight bytes
                bytes.read_exact(&mut buffer)?;

                u64::from_le_bytes(buffer) as usize
            }
            _ => {
                // All other values are not supported and we return an error to
                // indicate this
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "The byte length specified is not supported",
                ));
            }
        };

        Ok(outcome)
    }
}
