use std::{
    borrow::Cow,
    io::{self, Cursor, Error, ErrorKind, Read},
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
    pub fn parse<'a>(bytes: &mut Cursor<&[u8]>) -> io::Result<Cow<'a, str>> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    OP_HASH160,
    OP_PUSHBYTES_11,
    OP_PUSHBYTES_20,
    OP_PUSHBYTES_32,
    OP_PUSHBYTES_33,
    OP_PUSHBYTES_65,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
    OP_DUP,
    OP_RETURN,
    OP_0,
    OP_1,
    OP_2,
    UnsupportedOpcode,
}

impl Opcode {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            169 => Self::OP_HASH160,
            11 => Self::OP_PUSHBYTES_11,
            20 => Self::OP_PUSHBYTES_20,
            32 => Self::OP_PUSHBYTES_32,
            33 => Self::OP_PUSHBYTES_33,
            65 => Self::OP_PUSHBYTES_65,
            172 => Self::OP_CHECKSIG,
            136 => Self::OP_EQUALVERIFY,
            118 => Self::OP_DUP,
            106 => Self::OP_RETURN,
            0 => Self::OP_0,
            81 => Self::OP_1,
            82 => Self::OP_2,
            _ => Self::UnsupportedOpcode,
        }
    }
}

impl TryFrom<Opcode> for &str {
    type Error = io::Error;

    fn try_from(value: Opcode) -> Result<Self, Self::Error> {
        let opcode = match value {
            Opcode::OP_HASH160 => "OP_HASH160",
            Opcode::OP_PUSHBYTES_11 => "OP_PUSHBYTES_11",
            Opcode::OP_PUSHBYTES_20 => "OP_PUSHBYTES_20",
            Opcode::OP_PUSHBYTES_32 => "OP_PUSHBYTES_32",
            Opcode::OP_PUSHBYTES_33 => "OP_PUSHBYTES_33",
            Opcode::OP_PUSHBYTES_65 => "OP_PUSHBYTES_65",
            Opcode::OP_CHECKSIG => "OP_CHECKSIG",
            Opcode::OP_EQUALVERIFY => "OP_EQUALVERIFY",
            Opcode::OP_DUP => "OP_DUP",
            Opcode::OP_RETURN => "OP_RETURN",
            Opcode::OP_0 => "OP_0",
            Opcode::OP_1 => "OP_1",
            Opcode::OP_2 => "OP_2",
            Opcode::UnsupportedOpcode => todo!(),
        };

        Ok(opcode)
    }
}
