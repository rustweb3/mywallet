use bip32::DerivationPath;
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub fn derive_ed25519_private_key_by_path(seed: &[u8], path: DerivationPath) -> [u8; 32] {
    let indexes = path
        .into_iter()
        .map(|i: bip32::ChildNumber| i.into())
        .collect::<Vec<_>>();
    derive_ed25519_private_key(seed, &indexes)
}

#[allow(non_snake_case)]
fn derive_ed25519_private_key(seed: &[u8], indexes: &[u32]) -> [u8; 32] {
    let mut I = hmac_sha512(b"ed25519 seed", &seed);
    let mut data = [0u8; 37];

    for i in indexes {
        let hardened_index = 0x80000000 | *i;
        let Il = &I[0..32];
        let Ir = &I[32..64];

        data[1..33].copy_from_slice(Il);
        data[33..37].copy_from_slice(&hardened_index.to_be_bytes());

        //I = HMAC-SHA512(Key = Ir, Data = 0x00 || Il || ser32(i'))
        I = hmac_sha512(&Ir, &data);
    }

    I[0..32].try_into().unwrap()
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;
    let mut hmac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(data);
    let result = hmac.finalize();
    result.into_bytes().try_into().unwrap()
}
