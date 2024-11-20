pub const IERC5646_ID: felt252 = 0x012ee61ceedb7b8ff3da67d4e5d24d13d2a1ef35fdcd3a10b9138823f62342ba;

#[starknet::interface]
pub trait IERC5646<TState> {
    fn get_state_fingerprint(self: @TState, token_id: felt252) -> felt252;
}
