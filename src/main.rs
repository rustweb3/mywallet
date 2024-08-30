use {
    ansi_term::Color::Green,
    base58::ToBase58,
    bip32::{DerivationPath, PublicKey, XPrv},
    bip39::{Language, Mnemonic},
    blake2b_simd::{Hash, Params},
    dotenv,
    ed25519_dalek::VerifyingKey as Ed25519VerifyingKey,
    hex,
    sha3::Digest,
    std::{env, io::Write, str::FromStr},
};

mod slip_10_ed25519;
mod tui;

// this is used to generate sui address
pub fn msg_hash(msg: &Vec<u8>) -> Hash {
    let mut state = Params::new().hash_length(32).to_state();
    state.update(&msg).finalize()
}

fn main() {
    println!("");
    dotenv::dotenv().ok();
    let words = {
        let words = env::var("words");
        if words.is_err() {
            let mut rng = rand::thread_rng();
            println!("{}", Green.paint("words is empty,generate new words "));
            let words: Mnemonic =
                Mnemonic::generate_in_with(&mut rng, Language::English, 12).unwrap();
            println!("words: {}", words);
            // write words to .env file
            let mut file = std::fs::File::create(".env").unwrap();
            file.write_all(format!("words=\"{}\"", words).as_bytes())
                .unwrap();
            file.flush().unwrap();
            words
        } else {
            let words = words.unwrap();
            println!("{}", Green.paint(format!("words: {}", words)));
            Mnemonic::from_str(&words).unwrap()
        }
    };

    let seeds = words.to_seed("");

    println!(
        "\n{}",
        Green.paint("==========  EVM Address Generate  ==========")
    );
    // generate evm address
    let evm_derive_path: DerivationPath = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
    let evm_xprv = XPrv::derive_from_path(seeds, &evm_derive_path).unwrap();
    println!(
        "evm private key: 0x{}",
        hex::encode(evm_xprv.private_key().to_bytes())
    );
    let evm_public_key = evm_xprv.private_key().verifying_key();
    println!(
        "evm public key: 0x{}",
        hex::encode(evm_public_key.to_bytes())
    );
    let mut kh = sha3::Keccak256::new();
    kh.update(&evm_public_key.to_encoded_point(false).as_bytes()[1..]);
    let hash = kh.finalize().to_vec();
    let evm_address = &hash[12..];
    println!("evm address: 0x{}", hex::encode(evm_address));

    println!(
        "\n{}",
        Green.paint("========== Generate an Aptos address by SLIP-0010 ==========")
    );
    // Generate an Aptos address by SLIP-0010
    let aptos_derive_path = "m/44'/637'/0'/0'/0'";
    let aptos_derive_path = DerivationPath::from_str(aptos_derive_path).unwrap();
    let indexes = aptos_derive_path
        .into_iter()
        .map(|i: bip32::ChildNumber| i.into())
        .collect::<Vec<_>>();

    let derived = slip_10_ed25519::derive_ed25519_private_key(&seeds, &indexes);
    let apt_key = ed25519_dalek::SigningKey::from_bytes(&derived);

    let verify_key = apt_key.verifying_key();
    println!(
        "aptos secret key: 0x{}",
        hex::encode(&verify_key.to_bytes())
    );

    let apt_pub = Ed25519VerifyingKey::from_bytes(&verify_key.to_bytes()).unwrap();
    let mut apt_pub_bytes = apt_pub.to_bytes().to_vec();
    println!("aptos public key: 0x{}", hex::encode(&apt_pub_bytes));
    apt_pub_bytes.push(0 as u8);
    let mut apt_hasher = sha3::Sha3_256::new();
    apt_hasher.update(&apt_pub_bytes);
    let h = apt_hasher.finalize();
    println!("aptos address: 0x{}", hex::encode(h));

    println!(
        "\n{}",
        Green.paint("========== Generate  SUI address by SLIP-0010 ==========")
    );

    let mypath = DerivationPath::from_str("m/44'/784'/0'/0'/0").unwrap();
    let indexes = mypath
        .into_iter()
        .map(|i: bip32::ChildNumber| i.into())
        .collect::<Vec<_>>();
    let derived = slip_10_ed25519::derive_ed25519_private_key(&seeds, &indexes);
    let sui_key = ed25519_dalek::SigningKey::from_bytes(&derived);
    println!("sui secret key: 0x{}", hex::encode(sui_key.to_bytes()));
    let sui_pub = sui_key.verifying_key();
    println!("sui public key: 0x{}", hex::encode(sui_pub.to_bytes()));
    let sui_pub_bytes = sui_pub.to_bytes().to_vec();

    let mut payload: Vec<u8> = vec![0];
    payload.extend_from_slice(&sui_pub_bytes);
    let h = msg_hash(&payload);
    println!("sui address: 0x{}", h.to_hex());

    println!(
        "\n{}",
        Green.paint("============ Generarte solana address ============")
    );

    // pubkey: 852mPVXMXNKMuBr4bM2fbRyRfaQk2ZUwY9uyDL8X7BPA
    // carpet detect differ kite atom account cry onion chase provide general olive

    let sol_path = DerivationPath::from_str("m/44'/501'/0'/0'").unwrap();
    // let evm_xprv = XPrv::derive_from_path(seeds, &sol_path).unwrap();
    // println!("evm xprv: {:?}", evm_xprv.to_bytes());
    let indexes = sol_path
        .into_iter()
        .map(|i: bip32::ChildNumber| i.into())
        .collect::<Vec<_>>();
    let derived = slip_10_ed25519::derive_ed25519_private_key(&seeds, &indexes);
    // println!("derived: {:?}", derived);

    let sol_key = ed25519_dalek::SigningKey::from_bytes(&derived);
    println!("solana secret key: {}", sol_key.to_bytes().to_base58());
    let sol_pub = sol_key.verifying_key();
    println!("solana public key: 0x{}", hex::encode(sol_pub.to_bytes()));
    println!("solana address: {}", sol_pub.to_bytes().to_base58());

    println!("\nAlso solana cli use seed slice 0,32 directly");
    let sol_key = ed25519_dalek::SigningKey::from_bytes(
        &seeds[0..32]
            .try_into()
            .expect("slice with incorrect length"),
    );
    println!("solana secret key: {}", sol_key.to_bytes().to_base58());
    let sol_pub = sol_key.verifying_key();
    println!("solana public key: {}", hex::encode(sol_pub.to_bytes()));
    println!("solana address: {}", sol_pub.to_bytes().to_base58());
}
