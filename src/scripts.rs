use std::{
    io::{self, Cursor, Error, ErrorKind, Read},
    ops::Add,
};

#[derive(Debug, Clone, Copy)]
pub struct StandardScripts;

impl StandardScripts {
    pub fn parse(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut opcode_buffer = [0u8; 1];
        bytes.read_exact(&mut opcode_buffer)?;
        let first_opcode = Opcode::from_byte(opcode_buffer[0]);

        match first_opcode {
            Opcode::PushBytes(65) => Self::parse_p2pk(bytes),
            Opcode::OP_DUP => Self::parse_p2pkh(bytes),
            Opcode::OP_HASH160 => Self::parse_p2sh(bytes),
            Opcode::OP_RETURN => Self::parse_data(bytes),
            Opcode::OP_0 => {
                bytes.read_exact(&mut opcode_buffer)?;
                let second_opcode = Opcode::from_byte(opcode_buffer[0]);
                if second_opcode.eq(&Opcode::PushBytes(20)) {
                    Self::parse_p2wpkh(bytes)
                } else if second_opcode.eq(&Opcode::PushBytes(32)) {
                    Self::parse_p2wsh(bytes)
                } else {
                    return Self::to_io_error(
                        "Invalid Script. Expected OP_PUSHBYTES_20 or OP_PUSHBYTES_32 after OP_0",
                    );
                }
            }
            _ => {
                bytes.read_exact(&mut opcode_buffer)?;
                let second_opcode = Opcode::from_byte(opcode_buffer[0]);

                if first_opcode.eq(&Opcode::OP_1) && second_opcode.eq(&Opcode::PushBytes(32)) {
                    Self::parse_p2tr(bytes)
                } else {
                    bytes.set_position(bytes.position() - 2);
                    Self::parse_p2ms(bytes)
                }
            }
        }
    }

    pub fn to_io_error(message: &str) -> io::Result<String> {
        Err(io::Error::new(ErrorKind::InvalidData, message))
    }

    pub fn parse_p2pk(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut public_key_bytes = [0u8; 65];
        bytes.read_exact(&mut public_key_bytes)?;

        let mut op_checksig_byte = [0u8; 1];
        bytes.read_exact(&mut op_checksig_byte)?;
        let op_checksig = Opcode::from_byte(op_checksig_byte[0]);

        if op_checksig.ne(&Opcode::OP_CHECKSIG) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_CHECKSIG as last byte of the script.",
            ));
        }

        let mut script_builder = ScriptBuilder::new();
        script_builder
            .push_opcode(Opcode::PushBytes(65))?
            .push_bytes(&public_key_bytes)?
            .push_opcode(Opcode::OP_CHECKSIG)?;

        Ok(script_builder.build())
    }

    pub fn parse_p2pkh(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut opcode_buffer = [0u8; 1];

        bytes.read_exact(&mut opcode_buffer)?;
        let should_be_ophash160 = Opcode::from_byte(opcode_buffer[0]);
        if should_be_ophash160.ne(&Opcode::OP_HASH160) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_HASH160 as second byte of the script.",
            ));
        }

        bytes.read_exact(&mut opcode_buffer)?;
        let should_be_op_pushbytes20 = Opcode::from_byte(opcode_buffer[0]);
        if should_be_op_pushbytes20.ne(&Opcode::PushBytes(20)) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_PUSHBYTES_20 as third byte of the script.",
            ));
        }

        let mut hash160_bytes = [0u8; 20];
        bytes.read_exact(&mut hash160_bytes)?;

        bytes.read_exact(&mut opcode_buffer)?;
        let should_be_opequalverify = Opcode::from_byte(opcode_buffer[0]);
        if should_be_opequalverify.ne(&Opcode::OP_EQUALVERIFY) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_EQUALVERIFY after reading 20 bytes after third byte of the script.",
            ));
        }

        bytes.read_exact(&mut opcode_buffer)?;
        let should_be_opchecksing = Opcode::from_byte(opcode_buffer[0]);
        if should_be_opchecksing.ne(&Opcode::OP_CHECKSIG) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_CHECKSIG after reading OP_EQUALVERIFY byte in the script.",
            ));
        }
        let mut script_builder = ScriptBuilder::new();
        script_builder
            .push_opcode(Opcode::OP_DUP)?
            .push_opcode(Opcode::OP_HASH160)?
            .push_opcode(Opcode::PushBytes(20))?
            .push_bytes(&hash160_bytes)?
            .push_opcode(Opcode::OP_EQUALVERIFY)?
            .push_opcode(Opcode::OP_CHECKSIG)?;

        Ok(script_builder.build())
    }

    pub fn parse_p2sh(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut script_buffer = [0u8; 1];

        bytes.read_exact(&mut script_buffer)?;
        let second_opcode = Opcode::from_byte(script_buffer[0]);
        if second_opcode.ne(&Opcode::PushBytes(20)) {
            return Self::to_io_error(
                "Invalid Data. Expected an OP_PUSHBYTES_20 opcode after OP_HASH160",
            );
        }

        let mut bytes_20_buffer = [0u8; 20];
        bytes.read_exact(&mut bytes_20_buffer)?;

        bytes.read_exact(&mut script_buffer)?;
        let last_opcode = Opcode::from_byte(script_buffer[0]);
        if last_opcode.ne(&Opcode::OP_EQUAL) {
            return Self::to_io_error(
                "Invalid Data. Expected an OP_EQUAL opcode after reading 20 bytes",
            );
        }

        let mut script_builder = ScriptBuilder::new();
        script_builder
            .push_opcode(Opcode::OP_HASH160)?
            .push_opcode(Opcode::PushBytes(20))?
            .push_bytes(&bytes_20_buffer)?
            .push_opcode(Opcode::OP_EQUAL)?;

        Ok(script_builder.build())
    }

    pub fn parse_data(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut script_buffer = [0u8; 1];

        bytes.read_exact(&mut script_buffer)?;
        let second_opcode = Opcode::from_byte(script_buffer[0]);
        let data_bytes = second_opcode.read_bytes(bytes)?;

        let mut script_builder = ScriptBuilder::new();
        script_builder
            .push_opcode(Opcode::OP_RETURN)?
            .push_opcode(second_opcode)?
            .push_bytes(&data_bytes)?;

        Ok(script_builder.build())
    }

    pub fn parse_p2wpkh(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut pubkey_hash_bytes = [0u8; 20];
        bytes.read_exact(&mut pubkey_hash_bytes)?;

        let mut scripts = ScriptBuilder::new();
        scripts
            .push_opcode(Opcode::OP_0)?
            .push_opcode(Opcode::PushBytes(20))?
            .push_bytes(&pubkey_hash_bytes)?;

        Ok(scripts.build())
    }

    pub fn parse_p2wsh(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut hash_bytes = [0u8; 32];
        bytes.read_exact(&mut hash_bytes)?;

        let mut scripts = ScriptBuilder::new();
        scripts
            .push_opcode(Opcode::OP_0)?
            .push_opcode(Opcode::PushBytes(32))?
            .push_bytes(&hash_bytes)?;

        Ok(scripts.build())
    }

    pub fn parse_p2tr(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut hash_bytes = [0u8; 32];
        bytes.read_exact(&mut hash_bytes)?;

        let mut scripts = ScriptBuilder::new();
        scripts
            .push_opcode(Opcode::Num(1))?
            .push_opcode(Opcode::PushBytes(32))?
            .push_bytes(&hash_bytes)?;

        Ok(scripts.build())
    }

    pub fn parse_p2ms(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut opcode_buffer = [0u8; 1];
        bytes.read_exact(&mut opcode_buffer)?;
        let threshold_opcode = Opcode::from_byte(opcode_buffer[0]);

        match threshold_opcode {
            Opcode::Num(_) | Opcode::OP_1 => {
                let mut script_builder = ScriptBuilder::new();
                script_builder.push_opcode(threshold_opcode)?;

                let mut pubkey_count = 0u8;
                let parsed_pubkey_count: u8;
                let mut pushbytes_buffer = Vec::<u8>::new();

                loop {
                    bytes.read_exact(&mut opcode_buffer)?;
                    let current_opcode = Opcode::from_byte(opcode_buffer[0]);

                    match current_opcode {
                        Opcode::Num(value) => {
                            parsed_pubkey_count = value;
                            script_builder.push_opcode(current_opcode)?;
                            break;
                        }
                        Opcode::PushBytes(value) => {
                            let new_position = bytes.position() as usize + value as usize;
                            let read_bytes =
                                &bytes.get_ref()[bytes.position() as usize..new_position];
                            pushbytes_buffer.extend_from_slice(read_bytes);

                            script_builder
                                .push_opcode(current_opcode)?
                                .push_bytes(&pushbytes_buffer)?;

                            pushbytes_buffer.clear();
                            bytes.set_position(new_position as u64);
                            pubkey_count = pubkey_count.add(1);
                        }
                        _ => {
                            return Self::to_io_error(
                                "Invalid Script. Expected a PUSH_BYTES_* or OP_1..16",
                            )
                        }
                    }
                }

                if pubkey_count.ne(&parsed_pubkey_count) {
                    return Self::to_io_error(
                                "Invalid Script. The number of public keys for multisignature is less than or greater than the script requirements.",
                            );
                }

                Ok(script_builder.build())
            }
            _ => Self::to_io_error("Invalid Script."),
        }
    }
}

#[derive(Debug, Default)]
pub struct ScriptBuilder(Vec<String>);

impl ScriptBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_opcode(&mut self, opcode: Opcode) -> io::Result<&mut Self> {
        let opcode_string: String = opcode.try_into()?;
        self.0.push(opcode_string);

        Ok(self)
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> io::Result<&mut Self> {
        self.0.push(hex::encode(bytes));

        Ok(self)
    }

    pub fn build(self) -> String {
        self.0
            .into_iter()
            .map(|mut part| {
                part.push(' ');
                part
            })
            .collect::<String>()
            .trim()
            .into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    OP_HASH160,
    OP_CHECKSIG,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_DUP,
    OP_RETURN,
    OP_0,
    OP_1,
    Num(u8),
    PushBytes(u8),
    UnsupportedOpcode,
}

impl Opcode {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            169 => Self::OP_HASH160,
            1..=75 => Self::PushBytes(byte),
            172 => Self::OP_CHECKSIG,
            135 => Self::OP_EQUAL,
            136 => Self::OP_EQUALVERIFY,
            118 => Self::OP_DUP,
            106 => Self::OP_RETURN,
            0 => Self::OP_0,
            81 => Self::OP_1,
            82..=96 => {
                let to_num = match byte {
                    82 => 2u8,
                    83 => 3,
                    84 => 4,
                    85 => 5,
                    86 => 6,
                    87 => 7,
                    88 => 8,
                    89 => 9,
                    90 => 10,
                    91 => 11,
                    92 => 12,
                    93 => 13,
                    94 => 14,
                    95 => 15,
                    96 => 16,
                    _ => return Self::UnsupportedOpcode,
                };
                Self::Num(to_num)
            }
            _ => Self::UnsupportedOpcode,
        }
    }

    pub fn read_bytes(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::new();

        match self {
            Self::PushBytes(byte_len) => {
                let new_position = (bytes.position() as usize).add(*byte_len as usize);
                buffer.extend_from_slice(&bytes.get_ref()[bytes.position() as usize..new_position]);
                bytes.set_position(new_position as u64);

                Ok(buffer)
            }
            _ => Err(io::Error::new(
                ErrorKind::Unsupported,
                "This operation is not supported",
            )),
        }
    }
}

impl TryFrom<Opcode> for String {
    type Error = io::Error;

    fn try_from(value: Opcode) -> Result<Self, Self::Error> {
        let opcode = match value {
            Opcode::OP_HASH160 => "OP_HASH160",
            Opcode::PushBytes(bytes_len) => {
                return Ok(String::from("OP_PUSHBYTES_").add(bytes_len.to_string().as_str()))
            }
            Opcode::OP_CHECKSIG => "OP_CHECKSIG",
            Opcode::OP_EQUAL => "OP_EQUAL",
            Opcode::OP_EQUALVERIFY => "OP_EQUALVERIFY",
            Opcode::OP_DUP => "OP_DUP",
            Opcode::OP_RETURN => "OP_RETURN",
            Opcode::OP_0 => "OP_0",
            Opcode::OP_1 => "OP_1",
            Opcode::Num(value) => return Ok(String::from("OP_").add(value.to_string().as_str())),
            Opcode::UnsupportedOpcode => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Unsupported Opcode. Opcode not part of Bitcoin Core standard scripts",
                ))
            }
        };

        Ok(opcode.into())
    }
}
