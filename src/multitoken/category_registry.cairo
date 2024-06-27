use starknet::ContractAddress;

#[starknet::interface]
pub trait IMultitokenCategoryRegistry<TState> {
    fn register_category_value(ref self: TState, category: u8);
    fn unregister_category_value(ref self: TState, asset_address: ContractAddress);
    fn registered_category_value(self: @TState, asset_address: ContractAddress) -> u8;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
}
