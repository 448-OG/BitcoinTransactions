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
    /// Convert hex bytes into a Transaction struct. This calls all other
    /// methods to parse the version, inputs, outputs and locktime.
    pub fn from_hex_bytes(bytes: impl AsRef<[u8]>) -> io::Result<Self> {
        // Instantiate a new cursor to hold the bytes.
        // The cursor's position advances whenever we read
        // bytes allowing us to simplify the logic
        // instead of using a counter to keep track of bytes read
        let mut bytes = Cursor::new(bytes.as_ref());

        // The version number is always a 4 byte array
        let mut version_bytes = [0u8; 4];
        // Read exactly 4 bytes and advance the cursor to the 4th byte
        bytes.read_exact(&mut version_bytes)?;
        // Get the transaction version from the bytes
        let version = TxVersion::from_bytes(version_bytes);

        // Get a vector of inputs by calling the `Self::get_inputs()` method
        let inputs = BtcTx::get_inputs(&mut bytes)?;
        // Get a vector of outputs by calling the `Self::get_outputs()` method
        let outputs = BtcTx::get_outputs(&mut bytes)?;
        // Get a vector of inputs by calling the `Self::locktime()` method
        let locktime = BtcTx::locktime(&mut bytes)?;

        Ok(BtcTx {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    /// Get all inputs from the current position of the `Cursor`.
    /// This method decodes the number of inputs by first decoding the
    /// `varint` and then looping number of inputs calling
    /// `Self::input_decoder()` on each iteration.
    fn get_inputs(bytes: &mut Cursor<&[u8]>) -> io::Result<Vec<TxInput>> {
        let mut varint_len = [0u8];
        bytes.read_exact(&mut varint_len)?;

        let varint_byte_len = VarInt::parse(varint_len[0]);
        let no_of_inputs = VarInt::integer(varint_byte_len, bytes)?;

        let mut inputs = Vec::<TxInput>::new();

        (0..no_of_inputs).for_each(|_| {
            inputs.push(BtcTx::input_decoder(bytes).unwrap());
        });

        Ok(inputs)
    }

    // Decodes an input from current `Cursor` position.
    fn input_decoder(bytes: &mut Cursor<&[u8]>) -> io::Result<TxInput> {
        // The previous transaction ID is always a SHA256 hash converted to a 32 byte array
        let mut previous_tx_id = [0u8; 32];
        // Read exactly 32 bytes and advance the cursor to the end of the 32 byte array
        bytes.read_exact(&mut previous_tx_id)?;
        // The transaction ID in hex format is in network byte order so we reverse
        // it to little endian
        previous_tx_id.reverse();

        //Previous transaction index is 4 bytes long which is a Rust u32
        let mut previous_tx_index_bytes = [0u8; 4];
        bytes.read_exact(&mut previous_tx_index_bytes)?;
        // Convert the read 4 bytes to a u32
        let previous_output_index = u32::from_le_bytes(previous_tx_index_bytes);

        // Get the length of the scriptSig
        let mut signature_script_size = [0u8];
        bytes.read_exact(&mut signature_script_size)?;
        // Parse the length VarInt
        let varint_byte_len = VarInt::parse(signature_script_size[0]);
        // Get the length by converting VarInt into an integer by calling `integer`
        let integer_from_varint = VarInt::integer(varint_byte_len, bytes)?;

        // Buffer to hold the signature script
        let mut signature_script = Vec::<u8>::new();
        let mut sig_buf = [0u8; 1];
        // Since we are using a cursor, we iterate in order to advance
        // the cursor in each iteration
        (0..integer_from_varint).for_each(|_| {
            bytes.read_exact(&mut sig_buf).unwrap();

            signature_script.extend_from_slice(&sig_buf);
        });

        // The sequence number is a u32 (4 bytes long)
        let mut sequence_num_bytes = [0u8; 4];
        bytes.read_exact(&mut sequence_num_bytes)?;
        // Convert the sequence number to a integer
        let sequence_number = u32::from_le_bytes(sequence_num_bytes);

        Ok(TxInput {
            previous_tx_id,
            previous_output_index,
            signature_script,
            sequence_number,
        })
    }

    /// Get the outputs after all inputs have been parsed.
    fn get_outputs(bytes: &mut Cursor<&[u8]>) -> io::Result<Vec<TxOutput>> {
        // Get the number of outputs by reading our VarInt
        let mut num_of_output_bytes = [0u8; 1];
        bytes.read_exact(&mut num_of_output_bytes)?;
        let var_int_byte_length = VarInt::parse(num_of_output_bytes[0]);
        // Convert our VarInt to an integer
        let num_of_outputs = VarInt::integer(var_int_byte_length, bytes)?;

        let mut outputs = Vec::<TxOutput>::new();

        // Iterate over number of outputs
        (0..num_of_outputs).for_each(|_| {
            // The first value of the output is the amount in satoshis
            // which is 8 bytes long (Rust u64)
            let mut satoshis_as_bytes = [0u8; 8];
            bytes.read_exact(&mut satoshis_as_bytes).unwrap();
            // Get the number of satoshis in decimal
            let satoshis = u64::from_le_bytes(satoshis_as_bytes);

            // Get the exact size of the locking script
            let mut locking_script_len = [0u8; 1];
            bytes.read_exact(&mut locking_script_len).unwrap();
            // Parse the length into a varint
            let script_byte_len = VarInt::parse(locking_script_len[0]);
            // Convert our VarInt to an integer
            let script_len = VarInt::integer(script_byte_len, bytes).unwrap();
            let mut script = Vec::<u8>::new();

            // For the length of the script, read each byte and advance the cursor in each iteration
            (0..script_len).for_each(|_| {
                let mut current_byte = [0u8; 1];

                bytes.read_exact(&mut current_byte).unwrap();
                script.extend_from_slice(&current_byte);
            });

            // Construct our Transaction Output struct and then push it to the outputs vec
            outputs.push(TxOutput {
                amount: satoshis,
                locking_script: script,
            });
        });

        Ok(outputs)
    }

    // Lastly, after parsing our version, inputs and outputs we parse the locktime
    fn locktime(bytes: &mut Cursor<&[u8]>) -> io::Result<u32> {
        // The locktime is 4 bytes long
        let mut locktime_bytes = [0u8; 4];
        bytes.read_exact(&mut locktime_bytes)?;

        // Convert the locktime into an integer
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
