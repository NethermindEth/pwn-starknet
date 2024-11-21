use core::ecdsa::check_ecdsa_signature;
use starknet::ContractAddress;
use openzeppelin::account::interface::{ISRC6Dispatcher, ISRC6DispatcherTrait};

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

pub fn is_valid_signature_now(
    signer: ContractAddress,
    message_hash: felt252,
    signature: Signature
) -> bool {
    ISRC6Dispatcher { contract_address: signer }
        .is_valid_signature(
            message_hash, array![signature.r, signature.s]
        ) == starknet::VALIDATED
}
