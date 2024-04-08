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

    let p2pk_bytes = hex!("410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac");
    let mut p2pk = Cursor::new(p2pk_bytes.as_ref());
    dbg!(StandardScripts::parse(&mut p2pk).unwrap());

    let p2pkh_bytes = hex!("76a914000000000000000000000000000000000000000088ac");
    let mut p2pkh = Cursor::new(p2pkh_bytes.as_ref());
    dbg!(StandardScripts::parse(&mut p2pkh).unwrap());

    let p2ms_3_bytes = hex!("524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae");
    let mut p2ms_3 = Cursor::new(p2ms_3_bytes.as_ref());
    dbg!(StandardScripts::parse(&mut p2ms_3).unwrap());

    let p2ms_2_bytes = hex!("51210000000000000000000000000000000000000000000000000000000000000000002100000000000000000000000000000000000000000000000000000000000000000052ae");
    let mut p2ms_2 = Cursor::new(p2ms_2_bytes.as_ref());
    dbg!(StandardScripts::parse(&mut p2ms_2).unwrap());
}
