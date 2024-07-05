use pwn::multitoken::category_registry::MultitokenCategoryRegistry;
use starknet::ContractAddress;
use pwn::mocks::erc20_mock::ERC20Mock;
use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};

use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address_global,
};

#[starknet::interface]
trait IMultitokenCategoryRegistry<TState> {
    fn register_category_value(ref self: TState, asset_address: ContractAddress, category: u8);
    fn unregister_category_value(ref self: TState, asset_address: ContractAddress);
    fn registered_category_value(self: @TState, asset_address: ContractAddress) -> u8;
    fn owner(self: @TState) -> ContractAddress;
}

#[starknet::interface]
trait IERC20Mock<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, amount: u256);
}

fn ERC20_MOCK() -> ContractAddress {
    deploy_erc20_mock()
}
fn SOURCE() -> ContractAddress {
    starknet::contract_address_const::<'ACCOUNT2'>()
}
fn RECIPIENT() -> ContractAddress {
    starknet::contract_address_const::<'ACCOUNT3'>()
}

fn deploy_category_registry() -> IMultitokenCategoryRegistryDispatcher {
    let contract = declare("MultitokenCategoryRegistry").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();

    IMultitokenCategoryRegistryDispatcher { contract_address }
}

fn deploy_erc20_mock() -> ContractAddress {    
    let contract = declare("ERC20Mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();

    contract_address
}

fn mint_erc20(contract_address: ContractAddress, recipient: ContractAddress, amount: u256) {
    IERC20MockDispatcher { contract_address }.mint(recipient, amount);
}

mod factory_functions {
    use pwn::multitoken::library::MultiToken;

    #[test]
    fn test_fuzz_should_return_erc20(asset_address: u128, amount: u256) {
        let asset_address : felt252 = asset_address.try_into().unwrap();

        let asset : MultiToken::Asset = MultiToken::ERC20(asset_address.try_into().unwrap(), amount);

        assert_eq!(asset.category, MultiToken::Category::ERC20);
        assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
        assert_eq!(asset.id, 0);
        assert_eq!(asset.amount, amount);
    }

    #[test]
    fn test_fuzz_should_return_erc721(asset_address: u128, id: felt252) {
        let asset_address : felt252 = asset_address.try_into().unwrap();

        let asset : MultiToken::Asset = MultiToken::ERC721(asset_address.try_into().unwrap(), id);

        assert_eq!(asset.category, MultiToken::Category::ERC721);
        assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
        assert_eq!(asset.id, id);
        assert_eq!(asset.amount, 0);
    }

    #[test]
    fn test_fuzz_should_return_erc1155(asset_address: u128, id:felt252, amount: u256) {
        let asset_address : felt252 = asset_address.try_into().unwrap();

        let asset : MultiToken::Asset = MultiToken::ERC1155(asset_address.try_into().unwrap(), id, Option::Some(amount));

        assert_eq!(asset.category, MultiToken::Category::ERC1155);
        assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
        assert_eq!(asset.id, id);
        assert_eq!(asset.amount, amount);
    }

    #[test]
    fn test_fuzz_should_return_erc1155_with_no_amount(asset_address: u128, id:felt252) {
        let asset_address : felt252 = asset_address.try_into().unwrap();

        let asset : MultiToken::Asset = MultiToken::ERC1155(asset_address.try_into().unwrap(), id, Option::None);

        assert_eq!(asset.category, MultiToken::Category::ERC1155);
        assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
        assert_eq!(asset.id, id);
        assert_eq!(asset.amount, 0);
    }
}

mod transfer_asset_from {
    use pwn::multitoken::library::MultiToken;
    use pwn::multitoken::library::MultiToken::AssetTrait;
    use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use snforge_std::mock_call;
    use super::{RECIPIENT, deploy_erc20_mock, mint_erc20};

    #[test]
    fn test_should_call_transfer_when_erc20_when_source_is_this() {
        let token_address = deploy_erc20_mock();
        let address_this = starknet::get_contract_address();
        mint_erc20(token_address, address_this, 1000);

        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(address_this), 1000);

        let asset = MultiToken::ERC20(token_address, 1000);
        asset.transfer_asset_from(address_this, RECIPIENT(), true);

        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(address_this), 0);
    }

}
