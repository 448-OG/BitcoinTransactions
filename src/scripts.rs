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
        let mut first_byte = [0u8; 1];
        bytes.read_exact(&mut first_byte)?;
        let first_opcode = Opcode::from_byte(first_byte[0]);

        match first_opcode {
            Opcode::OP_PUSHBYTES_65 => Self::P2PK.parse_p2pk(bytes),
            Opcode::OP_DUP => Self::P2PKH.parse_p2pkh(bytes),
            _ => todo!(),
        }
    }

    pub fn parse_p2pk<'a>(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<Cow<'a, str>> {
        let mut public_key_bytes = [0u8; 65];
        bytes.read_exact(&mut public_key_bytes)?;

        let hex_public_key = hex::encode(&public_key_bytes);
        let mut op_checksig_byte = [0u8; 1];
        bytes.read_exact(&mut op_checksig_byte)?;
        let op_checksig = Opcode::from_byte(op_checksig_byte[0]);

        if op_checksig.ne(&Opcode::OP_CHECKSIG) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_CHECKSIG as last byte of the script.",
            ));
        }

        Ok(Cow::Borrowed(Opcode::OP_PUSHBYTES_65.try_into()?)
            + " "
            + Cow::Owned(hex_public_key.as_str().to_owned())
            + " "
            + Cow::Borrowed(Opcode::OP_CHECKSIG.try_into()?))
    }

    pub fn parse_p2pkh<'a>(&self, bytes: &mut Cursor<&[u8]>) -> io::Result<Cow<'a, str>> {
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
        if should_be_op_pushbytes20.ne(&Opcode::OP_PUSHBYTES_20) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid Data. Expected OP_PUSHBYTES_20 as third byte of the script.",
            ));
        }

        let mut hash160_bytes = [0u8; 20];
        bytes.read_exact(&mut hash160_bytes)?;
        let hex_hash160 = hex::encode(&hash160_bytes);

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

        Ok(Cow::Borrowed(Opcode::OP_DUP.try_into()?)
            + " "
            + Cow::Borrowed(Opcode::OP_HASH160.try_into()?)
            + " "
            + Cow::Borrowed(Opcode::OP_PUSHBYTES_20.try_into()?)
            + " "
            + Cow::Owned(hex_hash160)
            + " "
            + Cow::Borrowed(Opcode::OP_EQUALVERIFY.try_into()?)
            + " "
            + Cow::Borrowed(Opcode::OP_CHECKSIG.try_into()?))
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
