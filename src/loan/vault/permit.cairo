use starknet::ContractAddress;

#[derive(Drop, Serde)]
pub struct Permit {
    pub asset: ContractAddress,
    pub owner: ContractAddress,
    amount: u256,
    deadline: u64,
    r: felt252,
    s: felt252,
}

pub mod Err {
    pub fn InvalidPermitOwner(current: super::ContractAddress, expected: super::ContractAddress) {
        panic!("Invalid permit owner: current={:?}, expected={:?}", current, expected)
    }
    pub fn InvalidPermitAsset(current: super::ContractAddress, expected: super::ContractAddress) {
        panic!("Invalid permit asset: current={:?}, expected={:?}", current, expected)
    }
}
