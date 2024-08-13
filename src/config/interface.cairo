use pwn::interfaces::{
    pool_adapter::IPoolAdapterDispatcher, fingerprint_computer::IStateFingerpringComputerDispatcher
};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnConfig<TState> {
    fn initialize(
        ref self: TState, owner: ContractAddress, fee: u16, fee_collector: ContractAddress
    );
    fn set_fee(ref self: TState, fee: u16);
    fn get_fee(self: @TState) -> u16;
    fn set_fee_collector(ref self: TState, fee_collector: ContractAddress);
    fn get_fee_collector(self: @TState) -> ContractAddress;
    fn set_loan_metadata_uri(
        ref self: TState, loan_contract: ContractAddress, metadata_uri: ByteArray
    );
    fn set_default_loan_metadata_uri(ref self: TState, metadata_uri: ByteArray);
    fn register_state_fingerprint_computer(
        ref self: TState, asset: ContractAddress, computer: ContractAddress
    );
    fn register_pool_adapter(ref self: TState, pool: ContractAddress, adapter: ContractAddress);
    fn get_max_fee(self: @TState) -> u16;
    fn get_state_fingerprint_computer(
        self: @TState, asset: ContractAddress
    ) -> IStateFingerpringComputerDispatcher;
    fn get_pool_adapter(self: @TState, pool: ContractAddress) -> IPoolAdapterDispatcher;
    fn loan_metadata_uri(self: @TState, loan_contract: ContractAddress) -> ByteArray;
}
