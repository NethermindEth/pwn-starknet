use starknet::ContractAddress;

#[derive(Drop, Serde)]
pub struct Permit {
    asset: ContractAddress,
    owner: ContractAddress,
    amount: u256,
    deadline: u64,
    r: felt252,
    s: felt252,
}

mod Err {
    fn InvalidPermitOwner(current: super::ContractAddress, expected: super::ContractAddress) {
        panic!("Invalid permit owner: current={:?}, expected={:?}", current, expected)
    }
    fn InvalidPermitAsset(current: super::ContractAddress, expected: super::ContractAddress) {
        panic!("Invalid permit asset: current={:?}, expected={:?}", current, expected)
    }
}
