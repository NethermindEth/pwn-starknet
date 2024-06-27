use starknet::ContractAddress;

#[starknet::interface]
pub trait IPoolAdapter<TState> {
    fn withdraw(
        ref self: TState,
        pool: ContractAddress,
        owner: ContractAddress,
        asset: ContractAddress,
        amount: u256
    );
    fn supply(
        ref self: TState,
        pool: ContractAddress,
        owner: ContractAddress,
        asset: ContractAddress,
        amount: u256
    );
}
