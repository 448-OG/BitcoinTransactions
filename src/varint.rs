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

#[cfg(test)]
mod varint_sanity_checks {
    use crate::VarInt;
    use std::io::{Cursor, Read};

    #[test]
    fn varint_zero_to_252() {
        let bytes = [0u8, 0, 0, 0, 1];
        let mut bytes = Cursor::new(bytes.as_slice());

        // Simulate version bytes by skipping 4 bytes
        bytes.set_position(4);

        let mut varint_byte = [0u8; 1];
        bytes.read_exact(&mut varint_byte).unwrap();
        let varint_byte_len = VarInt::parse(varint_byte[0]);
        let varint_len = VarInt::integer(varint_byte_len, &mut bytes);
        assert!(varint_len.is_ok());
        assert_eq!(1usize, varint_len.unwrap());
    }

    #[test]
    fn varint_253() {
        let mut bytes = vec![0u8, 0, 0, 0, 253];
        let placeholder_bytes = [1u8; 257];
        bytes.extend_from_slice(&placeholder_bytes);
        let mut bytes = Cursor::new(bytes.as_slice());

        // Simulate version bytes by skipping 4 bytes
        bytes.set_position(4);

        let mut varint_byte = [0u8; 1];
        bytes.read_exact(&mut varint_byte).unwrap();
        let varint_byte_len = VarInt::parse(varint_byte[0]);
        let varint_len = VarInt::integer(varint_byte_len, &mut bytes);
        assert!(varint_len.is_ok());
        assert_eq!(257usize, varint_len.unwrap());
    }

    #[test]
    fn varint_254() {
        let mut bytes = vec![0u8, 0, 0, 0, 254];
        let placeholder_bytes = [1u8; 40];
        bytes.extend_from_slice(&placeholder_bytes);
        let mut bytes = Cursor::new(bytes.as_slice());

        // Simulate version bytes by skipping 4 bytes
        bytes.set_position(4);

        let mut varint_byte = [0u8; 1];
        bytes.read_exact(&mut varint_byte).unwrap();
        let varint_byte_len = VarInt::parse(varint_byte[0]);
        let varint_len = VarInt::integer(varint_byte_len, &mut bytes);
        assert!(varint_len.is_ok());
        assert_eq!(16843009usize, varint_len.unwrap());
    }

    #[test]
    fn varint_255() {
        let mut bytes = vec![0u8, 0, 0, 0, 255];
        let placeholder_bytes = [1u8; 40];
        bytes.extend_from_slice(&placeholder_bytes);
        let mut bytes = Cursor::new(bytes.as_slice());

        // Simulate version bytes by skipping 4 bytes
        bytes.set_position(4);

        let mut varint_byte = [0u8; 1];
        bytes.read_exact(&mut varint_byte).unwrap();
        let varint_byte_len = VarInt::parse(varint_byte[0]);
        let varint_len = VarInt::integer(varint_byte_len, &mut bytes);
        assert!(varint_len.is_ok());
        assert_eq!(72340172838076673usize, varint_len.unwrap());
    }
}
