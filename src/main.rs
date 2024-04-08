mod version;
use std::io::Cursor;

use hex_literal::hex;
pub use version::*;

mod varint;
pub use varint::*;

mod tx;
pub use tx::*;

mod scripts;
pub use scripts::*;

fn main() {
    // TODO - After parsing standard script, also add this transaction
    /*let raw_tx = hex!("010000000269adb42422fb021f38da0ebe12a8d2a14c0fe484bcb0b7cb365841871f2d5e24000000006a4730440220199a6aa56306cebcdacd1eba26b55eaf6f92eb46eb90d1b7e7724bacbe1d19140220101c0d46e033361c60536b6989efdd6fa692265fcda164676e2f49885871038a0121039ac8bac8f6d916b8a85b458e087e0cd07e6a76a6bfdde9bb766b17086d9a5c8affffffff69adb42422fb021f38da0ebe12a8d2a14c0fe484bcb0b7cb365841871f2d5e24010000006b48304502210084ec4323ed07da4af6462091b4676250c377527330191a3ff3f559a88beae2e2022077251392ec2f52327cb7296be89cc001516e4039badd2ad7bbc950c4c1b6d7cc012103b9b554e25022c2ae549b0c30c18df0a8e0495223f627ae38df0992efb4779475ffffffff0118730100000000001976a9140ce17649c1306c291ca9e587f8793b5b06563cea88ac00000000");
    let tx_decode = BtcTx::from_hex_bytes(raw_tx);

    dbg!(tx_decode.unwrap());*/

    // opcode!(OP, 4, 5, 6);
    // println!("{:?}", OP);

    //dbg!(hex!("4f"));

    let p2pk = hex!("410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac");
    let mut p2pk = Cursor::new(p2pk.as_ref());
    dbg!(StandardScripts::parse(&mut p2pk).unwrap());

    let p2pkh = hex!("76a914000000000000000000000000000000000000000088ac");
    let mut p2pkh = Cursor::new(p2pkh.as_ref());
    dbg!(StandardScripts::parse(&mut p2pkh).unwrap());
}
