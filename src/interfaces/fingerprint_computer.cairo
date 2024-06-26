use starknet::ContractAddress;

#[starknet::interface]
pub trait IStateFingerpringComputer<TState> {
    fn compute_state_fingerprint(
        self: @TState, token: ContractAddress, token_id: felt252
    ) -> felt252;
    fn supports_token(self: @TState, token: ContractAddress) -> bool;
}
