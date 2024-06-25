use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnConfig<TState> {
    fn initialize(
        ref self: TState, owner: ContractAddress, fee: u16, fee_collector: ContractAddress
    );
    fn set_fee(ref self: TState, fee: u16);
    fn set_fee_collector(ref self: TState, fee_collector: ContractAddress);
    fn set_loan_metadata_uri(
        ref self: TState, loan_contract: ContractAddress, metadata_uri: felt252
    );
    fn set_default_loan_metadata_uri(ref self: TState, metadata_uri: felt252);
    fn register_state_fingerprint_computer(
        ref self: TState, asset: ContractAddress, computer: ContractAddress
    );
    fn register_pool_adapter(ref self: TState, pool: ContractAddress, adapter: ContractAddress);
    fn get_state_fingerprint_computer(ref self: TState, asset: ContractAddress) -> ContractAddress;
    fn get_pool_adapter(self: @TState, pool: ContractAddress) -> ContractAddress;
    fn loan_metadata_uri(self: @TState, loan_contract: ContractAddress) -> felt252;
}
