pub mod types;

use bitcoin::{
    blockdata::script::Builder,
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    Address, AddressType, Network, OutPoint, PublicKey, PrivateKey, Script, SigHashType, Transaction, TxIn,
    TxOut, Txid,
};
use ic_btc_types::Utxo;
use ic_cdk::{
    call,
    export::{
        candid::{CandidType},
        serde::{Deserialize, Serialize as SerializeNew},
        Principal
    },
    print
};
use std::str::FromStr;

// The signature hash type that is always used.
const SIG_HASH_TYPE: SigHashType = SigHashType::All;

#[derive(CandidType, SerializeNew, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[derive(CandidType, SerializeNew, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, SerializeNew, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

type CanisterId = Principal;

pub async fn get_ecdsa_public_key() -> Result<Vec<u8>, String> {
    print(&format!("TESTTTTTT 123: {:?}", "dau xanh"));

    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "".to_string(),
    };
    let thecdsa_canister_id = std::env!("CANISTER_ID_ic00");
    let thecdsa = CanisterId::from_str(&thecdsa_canister_id).unwrap();

    ic_cdk::println!("thecdsa_canister_id = {:?}", thecdsa_canister_id);
    ic_cdk::println!("thecdsa = {:?}", thecdsa);

    let publickey: Vec<u8> = {
        let request = ECDSAPublicKey {
            canister_id: None,
            derivation_path: vec![vec![2, 3]],
            key_id: key_id.clone(),
        };
        ic_cdk::println!("Sending signature request = {:?}", request);
        let (res,): (ECDSAPublicKeyReply,) = call(thecdsa, "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("Failed to call ecdsa_public_key {}", e.1))?;
        ic_cdk::println!("Got response = {:?}", res);
        res.public_key
    };

    print(&format!("publickey: {:?}", publickey));

    Ok(publickey)
}

pub fn get_p2pkh_address(private_key: &PrivateKey, network: Network) -> Address {
    let public_key = private_key.public_key(&Secp256k1::new());
    Address::p2pkh(&public_key, network)
}

// Builds a transaction that sends the given `amount` of satoshis to the `destination` address.
pub fn build_transaction(
    utxos: Vec<Utxo>,
    source: Address,
    destination: Address,
    amount: u64,
    fees: u64,
) -> Result<Transaction, String> {
    // Assume that any amount below this threshold is dust.
    const DUST_THRESHOLD: u64 = 10_000;

    // Select which UTXOs to spend. For now, we naively spend the first available UTXOs,
    // even if they were previously spent in a transaction.
    let mut utxos_to_spend = vec![];
    let mut total_spent = 0;
    for utxo in utxos.into_iter() {
        total_spent += utxo.value;
        utxos_to_spend.push(utxo);
        if total_spent >= amount + fees {
            // We have enough inputs to cover the amount we want to spend.
            break;
        }
    }

    print(&format!("UTXOs to spend: {:?}", utxos_to_spend));

    if total_spent < amount {
        return Err("Insufficient balance".to_string());
    }

    let inputs: Vec<TxIn> = utxos_to_spend
        .into_iter()
        .map(|utxo| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_hash(Hash::from_slice(&utxo.outpoint.txid).unwrap()),
                vout: utxo.outpoint.vout,
            },
            sequence: 0xffffffff,
            witness: Vec::new(),
            script_sig: Script::new(),
        })
        .collect();

    let mut outputs = vec![TxOut {
        script_pubkey: destination.script_pubkey(),
        value: amount,
    }];

    let remaining_amount = total_spent - amount - fees;

    if remaining_amount >= DUST_THRESHOLD {
        outputs.push(TxOut {
            script_pubkey: source.script_pubkey(),
            value: remaining_amount,
        });
    }

    Ok(Transaction {
        input: inputs,
        output: outputs,
        lock_time: 0,
        version: 2,
    })
}

/// Sign a bitcoin transaction given the private key and the source address of the funds.
///
/// Constraints:
/// * All the inputs are referencing outpoints that are owned by `src_address`.
/// * `src_address` is a P2PKH address.
pub fn sign_transaction(
    mut transaction: Transaction,
    private_key: PrivateKey,
    src_address: Address,
) -> Transaction {
    // Verify that the address is P2PKH. The signature algorithm below is specific to P2PKH.
    match src_address.address_type() {
        Some(AddressType::P2pkh) => {}
        _ => panic!("This demo supports signing p2pkh addresses only."),
    };

    let secp = Secp256k1::new();
    let txclone = transaction.clone();
    let public_key = private_key.public_key(&Secp256k1::new());

    for (index, input) in transaction.input.iter_mut().enumerate() {
        let sighash =
            txclone.signature_hash(index, &src_address.script_pubkey(), SIG_HASH_TYPE.as_u32());

        let signature = secp
            .sign(
                &Message::from_slice(&sighash[..]).unwrap(),
                &private_key.key,
            )
            .serialize_der();

        let mut sig_with_hashtype = signature.to_vec();
        sig_with_hashtype.push(SIG_HASH_TYPE.as_u32() as u8);
        input.script_sig = Builder::new()
            .push_slice(sig_with_hashtype.as_slice())
            .push_slice(public_key.to_bytes().as_slice())
            .into_script();
        input.witness.clear();
    }

    transaction
}
