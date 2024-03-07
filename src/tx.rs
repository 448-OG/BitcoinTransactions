use crate::{TxVersion, VarInt};
use std::io::{self, Cursor, Read};

/// The structure of the Bitcoin transaction
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BtcTx {
    // The version of the Bitcoin transaction
    version: TxVersion,
    // A transaction can have multiple inputs
    inputs: Vec<TxInput>,
    // A transaction can have multiple outputs
    outputs: Vec<TxOutput>,
    // The locktime for the transaction parsed
    // from 4 bytes into a u32
    locktime: u32,
}

impl BtcTx {
    pub fn from_hex_bytes(bytes: impl AsRef<[u8]>) -> io::Result<Self> {
        let mut bytes = Cursor::new(bytes.as_ref());

        let mut version_bytes = [0u8; 4];
        bytes.read_exact(&mut version_bytes)?;
        let version = TxVersion::from_bytes(version_bytes);

        let inputs = BtcTx::get_inputs(&mut bytes)?;
        let outputs = BtcTx::outputs_decoder(&mut bytes)?;
        let locktime = BtcTx::locktime(&mut bytes)?;

        Ok(BtcTx {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    fn get_inputs(bytes: &mut Cursor<&[u8]>) -> io::Result<Vec<TxInput>> {
        let mut varint_len = [0u8];
        bytes.read_exact(&mut varint_len)?;

        let varint_byte_len = VarInt::parse(varint_len[0]);
        let no_of_inputs = VarInt::integer(varint_byte_len, bytes)?;

        let mut inputs = Vec::<TxInput>::new();

        (0..no_of_inputs).into_iter().for_each(|_| {
            inputs.push(BtcTx::input_decoder(bytes).unwrap());
        });

        Ok(inputs)
    }

    fn input_decoder(bytes: &mut Cursor<&[u8]>) -> io::Result<TxInput> {
        let mut previous_tx_id = [0u8; 32];
        bytes.read_exact(&mut previous_tx_id)?;
        previous_tx_id.reverse();

        let mut previous_tx_index_bytes = [0u8; 4];

        bytes.read_exact(&mut previous_tx_index_bytes)?;
        let previous_output_index = u32::from_le_bytes(previous_tx_index_bytes);

        let mut signature_script_size = [0u8];
        bytes.read_exact(&mut signature_script_size)?;

        let varint_byte_len = VarInt::parse(signature_script_size[0]);
        let integer_from_varint = VarInt::integer(varint_byte_len, bytes)?;

        let mut signature_script = Vec::<u8>::new();
        let mut sig_buf = [0u8; 1];
        (0..integer_from_varint).for_each(|_| {
            bytes.read_exact(&mut sig_buf).unwrap();

            signature_script.extend_from_slice(&sig_buf);
        });

        let mut sequence_num_bytes = [0u8; 4];
        bytes.read_exact(&mut sequence_num_bytes)?;
        let sequence_number = u32::from_le_bytes(sequence_num_bytes);

        let tx_input = TxInput {
            previous_tx_id,
            previous_output_index,
            signature_script,
            sequence_number,
        };

        Ok(tx_input)
    }

    fn outputs_decoder(bytes: &mut Cursor<&[u8]>) -> io::Result<Vec<TxOutput>> {
        let mut num_of_output_bytes = [0u8; 1];
        bytes.read_exact(&mut num_of_output_bytes)?;
        let var_int_byte_length = VarInt::parse(num_of_output_bytes[0]);
        let num_of_outputs = VarInt::integer(var_int_byte_length, bytes)?;

        let mut outputs = Vec::<TxOutput>::new();

        (0..num_of_outputs).into_iter().for_each(|_| {
            let mut satoshis_as_bytes = [0u8; 8];
            bytes.read_exact(&mut satoshis_as_bytes).unwrap();
            let satoshis = u64::from_le_bytes(satoshis_as_bytes);

            let mut locking_script_len = [0u8; 1];
            bytes.read_exact(&mut locking_script_len).unwrap();

            let script_byte_len = VarInt::parse(locking_script_len[0]);
            let script_len = VarInt::integer(script_byte_len, bytes).unwrap();
            let mut script = Vec::<u8>::new();

            (0..script_len).for_each(|_| {
                let mut current_byte = [0u8; 1];

                bytes.read_exact(&mut current_byte).unwrap();
                script.extend_from_slice(&current_byte);
            });

            outputs.push(TxOutput {
                amount: satoshis,
                locking_script: script,
            });
        });

        Ok(outputs)
    }

    fn locktime(bytes: &mut Cursor<&[u8]>) -> io::Result<u32> {
        let mut locktime_bytes = [0u8; 4];
        bytes.read_exact(&mut locktime_bytes)?;

        Ok(u32::from_le_bytes(locktime_bytes))
    }
}

/// Our transaction inputs
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TxInput {
    // The SHA256 bytes of the previous transaction ID
    // of the unspent UTXO
    previous_tx_id: [u8; 32],
    // Previous index of the previous transaction output
    previous_output_index: u32,
    // The scriptSig
    signature_script: Vec<u8>,
    // The sequence number
    sequence_number: u32,
}

/// Transaction outputs
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TxOutput {
    // Amount in satoshis
    amount: u64,
    // The locking script which gives conditions for spending the bitcoins
    locking_script: Vec<u8>,
}
