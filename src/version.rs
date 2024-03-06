/// Bitcoin transactions version one and two are supported
/// by Bitcoin core. A node must pre-configure a transaction
/// version higher than version 2 and this transaction is
/// not guaranteed to be propagated by all Bitcoin core.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TxVersion {
    /// This will be treated as the default version
    /// when calling TxVersion::default()
    #[default]
    One,
    /// The Bitcoin transaction version two which allows
    /// using the OPCODE `OP_CHECKSEQUENCEVERIFY` which allows
    /// setting relative locktime for spending outputs.
    Two,
    /// Custom transaction version which is considered non-standard,
    /// must be set by the Bitcoin node operator and is not guaranteed
    /// to be accepted by other nodes running Bitcoin core software
    Custom(u32),
}

impl TxVersion {
    /// This converts our version to bytes.
    /// Since version number is four bytes little-endian we use `u32::to_le_bytes()`
    pub fn to_bytes(&self) -> [u8; 4] {
        match self {
            Self::One => 1u32.to_le_bytes(),
            Self::Two => 2u32.to_le_bytes(),
            Self::Custom(version) => version.to_le_bytes(),
        }
    }

    /// This converts from bytes to `Self`
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        let parsed = u32::from_le_bytes(bytes);

        match parsed {
            1u32 => Self::One,
            2u32 => Self::Two,
            _ => Self::Custom(parsed),
        }
    }
}

#[cfg(test)]
mod tx_sanity_checks {
    use crate::TxVersion;

    #[test]
    fn tx_version() {
        assert_eq!([1u8, 0, 0, 0], TxVersion::One.to_bytes());
        assert_eq!([2u8, 0, 0, 0], TxVersion::Two.to_bytes());
        assert_eq!([30u8, 0, 0, 0], TxVersion::Custom(30).to_bytes());

        assert_eq!(TxVersion::One, TxVersion::from_bytes([1u8, 0, 0, 0]));
        assert_eq!(TxVersion::Two, TxVersion::from_bytes([2u8, 0, 0, 0]));
        assert_eq!(
            TxVersion::Custom(30),
            TxVersion::from_bytes([30u8, 0, 0, 0])
        );
    }
}
