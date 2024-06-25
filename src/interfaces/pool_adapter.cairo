use starknet::ContractAddress;

#[starknet::interface]
pub trait IPoolAdapter<TState> {
    fn withdraw(
        ref self: TState,
        pool: ContractAddress,
        owner: ContractAddress,
        asset: ContractAddress,
        amount: u128
    );
    fn supply(
        ref self: TState,
        pool: ContractAddress,
        owner: ContractAddress,
        asset: ContractAddress,
        amount: u128
    );
}
