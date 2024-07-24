use core::ecdsa::check_ecdsa_signature;
use starknet::ContractAddress;

#[derive(Copy, Debug, Default, Drop, Serde)]
pub struct Signature {
    pub r: felt252,
    pub s: felt252,
}

pub mod Err {
    pub fn INVALID_SIGNATURE_LENGTH(length: usize) {
        panic!("Signature length is not 64 nor 65 bytes. Length: {}", length);
    }
    pub fn INVALID_SIGNATURE(signer: super::ContractAddress, digest: felt252) {
        panic!("Invalid signature. Signer: {:?}, Digest: {:?}", signer, digest);
    }
}
