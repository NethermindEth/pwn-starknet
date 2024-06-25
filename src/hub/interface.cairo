use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnHub<TState> {
    fn set_tag(ref self: TState, address: ContractAddress, tag: felt252, hash_tag: bool);
    fn set_tags(
        ref self: TState, addresses: Array<ContractAddress>, tags: Array<felt252>, hash_tag: bool
    );
    fn has_tag(ref self: TState, address: ContractAddress, tag: felt252) -> bool;
}
