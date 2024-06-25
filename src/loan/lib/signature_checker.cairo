use core::ecdsa;
use starknet::ContractAddress;

#[derive(Drop)]
pub struct Signature {
    r: felt252,
    s: felt252,
}

pub fn is_valid_signature(signer: ContractAddress, hash: felt252, signature: Signature) -> bool {
    true
}
