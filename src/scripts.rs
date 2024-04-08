use std::{
    io::{self, Cursor, Error, ErrorKind, Read},
    ops::Add,
};

#[derive(Debug, Clone, Copy)]
pub enum StandardScripts {
    P2PK,
    P2PKH,
    P2MS,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    Data,
    UnsupportedScript,
}

impl StandardScripts {
    pub fn parse(bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
        let mut opcode_buffer = [0u8; 1];
        bytes.read_exact(&mut opcode_buffer)?;
        let first_opcode = Opcode::from_byte(opcode_buffer[0]);

        match first_opcode {
            Opcode::PushBytes(65) => Self::P2PK.parse_p2pk(bytes),
            Opcode::OP_DUP => Self::P2PKH.parse_p2pkh(bytes),
            Opcode::OP_HASH160 => Self::P2SH.parse_p2sh(bytes),
            Opcode::OP_RETURN => Self::Data.parse_data(bytes),
            _ => todo!(),
            // Opcode::OP_0 => {
            //     bytes.read_exact(&mut opcode_buffer)?;
            //     let second_opcode = Opcode::from_byte(opcode_buffer[0]);
            //     if second_opcode.eq(&Opcode::OP_PUSHBYTES_20) {
            //         Self::P2WPKH.parse_p2wpkh(bytes)
            //     } else if second_opcode.eq(&Opcode::OP_PUSHBYTES_32) {
            //         Self::P2WSH.parse_p2wsh(bytes)
            //     } else {
            //         return  Self::to_io_error("Invalid data. Expected second opcode after OP_0 to be either OP_PUSHBYTES_20 or OP_PUSHBYTES_32");
            //     }
            // }
            // Opcode::OP_RETURN => Self::Data.parse_data(bytes),
            // _ => {
            //     if P2MS_OPCODES.contains(&first_opcode) {
            //         let mut second_opcode_buffer = [0u8; 1];
            //         bytes.read_exact(&mut second_opcode_buffer)?;
            //         let second_opcode = Opcode::from_byte(second_opcode_buffer[0]);
            //         // Reset to two positions
            //         bytes.set_position(bytes.position() - 2);
            //         if second_opcode.eq(&Opcode::OP_PUSHBYTES_65) {
            //             ///////////////HERE
            //             Self::P2MS.parse_p2ms(bytes)
            //         } else if second_opcode.eq(&Opcode::OP_PUSHBYTES_32) {
            //             Self::P2TR.parse_p2tr(bytes)
            //         } else {
            //             return Self::to_io_error(
            //                 "Invalid data. Expected second opcode after OP_1 to be either OP_PUSHBYTES_33 or OP_PUSHBYTES_32",
            //             );
            //         }
            //     } else {
            //         return Self::to_io_error(
            //             "Invalid data. This is not a standard Bitcoin core script",
            //         );
            //     }
            //}
        }
    }

    pub fn to_io_error(message: &str) -> io::Result<String> {
        Err(io::Error::new(ErrorKind::InvalidData, message))
    }

    pub fn parse_p2pk(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
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

    pub fn parse_p2pkh(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
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

    pub fn parse_p2sh(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
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

    pub fn parse_data(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
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

    // pub fn parse_p2ms(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
    //     let mut opcode_buffer = [0u8; 1];
    //     bytes.read_exact(&mut opcode_buffer)?;
    //     let threshold_opcode = Opcode::from_byte(opcode_buffer[0]);

    //     let mut script_builder = ScriptBuilder::new();
    //     script_builder.push_opcode(threshold_opcode)?;

    //     let mut public_key_buffer = [0u8; 65];

    //     let mut public_key_count = 0usize;

    //     loop {
    //         bytes.read_exact(&mut opcode_buffer)?;
    //         let opcode = Opcode::from_byte(opcode_buffer[0]);

    //         if opcode.eq(&Opcode::OP_PUSHBYTES_65) {
    //             bytes.read_exact(&mut public_key_buffer)?;

    //             script_builder.push_opcode(opcode)?;
    //             script_builder.push_bytes(&public_key_buffer)?;
    //             public_key_count = public_key_count.add(1);
    //         } else if P2MS_OPCODES.contains(&opcode) {
    //             script_builder.push_opcode(opcode)?;

    //             if let Some((index, _)) = P2MS_OPCODES
    //                 .iter()
    //                 .enumerate()
    //                 .find(|(_, inner_opcode)| *inner_opcode == &opcode)
    //             {
    //                 dbg!(public_key_count);
    //                 dbg!(index);
    //                 dbg!(opcode);
    //                 dbg!(&script_builder);
    //                 if (index + 1) != public_key_count {
    //                     return Self::to_io_error("Invalid number of public keys");
    //                 }
    //             }
    //             break;
    //         } else {
    //             return Self::to_io_error("Invalid multisignature script");
    //         }
    //     }

    //     Ok(script_builder.build())
    // }

    // pub fn parse_p2wpkh(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
    //     todo!()
    // }

    // pub fn parse_p2wsh(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
    //     todo!()
    // }

    // pub fn parse_p2tr(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<String> {
    //     todo!()
    // }
}

pub const P2MS_OPCODES: &[Opcode] = &[
    Opcode::OP_1,
    Opcode::OP_2,
    Opcode::OP_3,
    Opcode::OP_4,
    Opcode::OP_5,
    Opcode::OP_6,
    Opcode::OP_7,
    Opcode::OP_8,
    Opcode::OP_9,
    Opcode::OP_10,
    Opcode::OP_11,
    Opcode::OP_12,
    Opcode::OP_13,
    Opcode::OP_14,
    Opcode::OP_15,
];

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
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,
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
            82 => Self::OP_2,
            83 => Self::OP_3,
            84 => Self::OP_4,
            85 => Self::OP_5,
            86 => Self::OP_6,
            87 => Self::OP_7,
            88 => Self::OP_8,
            89 => Self::OP_9,
            90 => Self::OP_10,
            91 => Self::OP_11,
            92 => Self::OP_12,
            93 => Self::OP_13,
            94 => Self::OP_14,
            95 => Self::OP_15,
            96 => Self::OP_16,
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
            Opcode::OP_2 => "OP_2",
            Opcode::OP_3 => "OP_3",
            Opcode::OP_4 => "OP_4",
            Opcode::OP_5 => "OP_5",
            Opcode::OP_6 => "OP_6",
            Opcode::OP_7 => "OP_7",
            Opcode::OP_8 => "OP_8",
            Opcode::OP_9 => "OP_9",
            Opcode::OP_10 => "OP_10",
            Opcode::OP_11 => "OP_11",
            Opcode::OP_12 => "OP_12",
            Opcode::OP_13 => "OP_13",
            Opcode::OP_14 => "OP_14",
            Opcode::OP_15 => "OP_15",
            Opcode::OP_16 => "OP_16",
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
