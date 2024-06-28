use core::ecdsa;
use starknet::ContractAddress;

#[derive(Drop, Serde)]
pub struct Signature {
    r: felt252,
    s: felt252,
}

pub mod Err {
    pub fn INVALID_SIGNATURE_LENGTH(length: usize) {
        panic!("Signature length is not 64 nor 65 bytes. Length: {}", length);
    }
    pub fn INVALID_SIGNATURE(signer: super::ContractAddress, digest: felt252) {
        panic!("Invalid signature. Signer: {:?}, Digest: {:?}", signer, digest);
    }
}


pub fn is_valid_signature_now(
    public_key: felt252, message_hash: felt252, signature: Signature
) -> bool {
    true
}
