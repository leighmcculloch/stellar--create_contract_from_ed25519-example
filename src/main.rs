use clap::Parser;
use ed25519_dalek::{Keypair, Signer};
use sha2::{Digest, Sha256};
use soroban_env_common::xdr::{
    HostFunction, LedgerEntry, LedgerKey, ScHostStorageErrorCode, ScObject, ScStatus, ScVal,
};
use soroban_env_host::{
    budget::Budget,
    storage::{SnapshotSource, Storage},
    xdr::{AccountId, PublicKey::PublicKeyTypeEd25519, Uint256},
    Host, HostError, LedgerInfo,
};
use std::rc::Rc;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    fail: bool,
}

fn main() {
    let args = Args::parse();

    let rf = Rc::new(EmptySnapshotSource());
    let storage = Storage::with_recording_footprint(rf);
    let h = Host::with_storage_and_budget(storage, Budget::default());

    h.set_source_account(AccountId(PublicKeyTypeEd25519(Uint256([0u8; 32]))));

    h.set_ledger_info(LedgerInfo {
        protocol_version: 0,
        sequence_number: 0,
        timestamp: 0,
        network_passphrase: vec![0u8],
        base_reserve: 0,
    });

    let separator =
        "create_contract_from_ed25519(contract: Vec<u8>, salt: u256, key: u256, sig: Vec<u8>)";
    eprintln!("Separator: {}", separator);
    let separator = separator.as_bytes();

    let contract_file = b"test_contract";
    eprintln!("Contract File Contents: {}", hex::encode(contract_file));

    let salt = Sha256::digest(b"a1");
    let salt = salt.as_slice();
    eprintln!("Salt Hash: {}", hex::encode(salt));
    let payload = [separator, salt, contract_file].concat();
    let hash = Sha256::digest(payload);
    eprintln!("Hash to Sign: {}", hex::encode(hash));
    eprintln!();

    let kp = Keypair::generate(&mut rand::thread_rng());
    eprintln!("Secret Key: {}", hex::encode(kp.secret.as_bytes()));
    eprintln!("Public Key: {}", hex::encode(kp.public.as_bytes()));
    let pk = kp.public.as_bytes();
    let sig = kp.sign(&hash);
    let sig = sig.to_bytes();
    let sig = if args.fail {
        &[0u8; 64]
    } else {
        sig.as_slice()
    };
    eprintln!("Signature of Hash: {}", hex::encode(sig));
    eprintln!();

    let args = vec![
        ScVal::Object(Some(ScObject::Bytes(contract_file.try_into().unwrap()))),
        ScVal::Object(Some(ScObject::Bytes(salt.try_into().unwrap()))),
        ScVal::Object(Some(ScObject::Bytes(pk.try_into().unwrap()))),
        ScVal::Object(Some(ScObject::Bytes(sig.try_into().unwrap()))),
    ]
    .try_into()
    .unwrap();
    eprintln!("Args to Submit: {:?}", args);
    eprintln!();

    eprintln!("Submitting...");
    let res = h.invoke_function(HostFunction::CreateContractWithEd25519, args);
    eprintln!("Result: {res:?}");
    if let Ok(ScVal::Object(Some(ScObject::Bytes(contract_id)))) = res {
        eprintln!("Result Contract ID: {}", hex::encode(contract_id));
    }
    eprintln!();

    let (storage, _, events) = h.try_finish().unwrap();

    eprintln!("Footprint:");
    for (ledger_key, access_type) in storage.footprint.0 {
        eprintln!(" • {access_type:?} of {ledger_key:?}");
    }
    eprintln!();

    eprintln!("Events:");
    for event in events.0 {
        eprintln!(" • {event:?}");
    }
    eprintln!();
}

struct EmptySnapshotSource();

impl SnapshotSource for EmptySnapshotSource {
    fn get(&self, _key: &LedgerKey) -> Result<LedgerEntry, HostError> {
        Err(ScStatus::HostStorageError(ScHostStorageErrorCode::UnknownError).into())
    }

    fn has(&self, _key: &LedgerKey) -> Result<bool, HostError> {
        Ok(false)
    }
}
