use pwn::multitoken::category_registry::MultitokenCategoryRegistry;
use starknet::ContractAddress;
use pwn::mocks::{erc20_mock::ERC20Mock, erc721_mock::ERC721Mock, erc1155_mock::ERC1155Mock};
use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
use openzeppelin::token::erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait};

use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address, CheatSpan
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

#[starknet::interface]
trait IERC7210Mock<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, tokenId: u256);
}

#[starknet::interface]
trait IERC1155Mock<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, tokenId: u256, value: u256);
}

fn ALICE() -> ContractAddress {
    starknet::contract_address_const::<'ACCOUNT2'>()
}
fn BOB() -> ContractAddress {
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

fn deploy_erc721_mock() -> ContractAddress {    
    let contract = declare("ERC721Mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();

    contract_address
}

fn deploy_erc1155_mock() -> ContractAddress {    
    let contract = declare("ERC1155Mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();

    contract_address
}

fn mint_erc20(contract_address: ContractAddress, recipient: ContractAddress, amount: u256) {
    IERC20MockDispatcher { contract_address }.mint(recipient, amount);
}

fn mint_erc721(contract_address: ContractAddress, recipient: ContractAddress, tokenId: u256) {
    IERC7210MockDispatcher { contract_address }.mint(recipient, tokenId);
}

fn mint_erc1155(contract_address: ContractAddress, recipient: ContractAddress, tokenId: u256, value: u256) {
    IERC1155MockDispatcher { contract_address }.mint(recipient, tokenId, value);
}

fn give_allowance_erc20(token_address: ContractAddress, owner: ContractAddress, spender: ContractAddress, amount: u256) {
    cheat_caller_address(token_address, owner, CheatSpan::TargetCalls(1));
    ERC20ABIDispatcher { contract_address: token_address }.approve(spender, amount);
}

fn give_allowance_erc721(token_address: ContractAddress, owner: ContractAddress, spender: ContractAddress, tokenId: u256) {
    cheat_caller_address(token_address, owner, CheatSpan::TargetCalls(1));
    ERC721ABIDispatcher { contract_address: token_address }.approve(spender, tokenId);
}

fn give_allowance_erc1155(token_address: ContractAddress, owner: ContractAddress, spender: ContractAddress, tokenId: u256, value: u256) {
    cheat_caller_address(token_address, owner, CheatSpan::TargetCalls(1));
    ERC1155ABIDispatcher { contract_address: token_address }.set_approval_for_all(spender, true);
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
    use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
    use openzeppelin::token::erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait};
    use snforge_std::{mock_call, start_mock_call, stop_mock_call};
    use super::{ALICE, BOB, deploy_erc20_mock, mint_erc20, give_allowance_erc20, deploy_erc721_mock, mint_erc721, give_allowance_erc721, deploy_erc1155_mock, mint_erc1155, mint_batch_erc1155, give_allowance_erc1155};

    #[test]
    fn test_should_call_transfer_when_erc20_when_source_is_this() {
        let token_address = deploy_erc20_mock();
        let this_address = starknet::get_contract_address();
        mint_erc20(token_address, this_address, 1000);

        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(this_address), 1000);

        let asset = MultiToken::ERC20(token_address, 1000);
        asset.transfer_asset_from(this_address, BOB(), false);

        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(this_address), 0);
    }

    #[test]
    fn test_should_fail_when_erc20_when_source_is_this_when_transfer_returns_fale() {
        // Q - how to make the transfer fail?
        assert_eq!(0, 1);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_erc20_when_source_is_this_when_call_to_non_contract_address() {
        let non_contract_address = BOB();
        let this_address = starknet::get_contract_address();

        let asset = MultiToken::ERC20(non_contract_address, 1000);
        asset.transfer_asset_from(this_address, BOB(), false);
    }

    #[test]
    fn test_should_call_transfer_when_erc20_when_source_is_not_this() {
        let token_address = deploy_erc20_mock();
        let this_address = starknet::get_contract_address();
        mint_erc20(token_address, ALICE(), 1000);

        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(ALICE()), 1000);
        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(BOB()), 0);

        give_allowance_erc20(token_address, ALICE(), this_address, 1000);

        let asset = MultiToken::ERC20(token_address, 1000);
        asset.transfer_asset_from(ALICE(), BOB(), false);

        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(ALICE()), 0);
        assert_eq!(ERC20ABIDispatcher{ contract_address: token_address }.balance_of(BOB()), 1000);
    }

    #[test]
    fn test_should_fail_when_erc20_when_source_is_not_this_when_transfer_returns_fale() {
        // Q - how to make the transfer fail?
        assert_eq!(0, 1);
    }


    #[test]
    #[should_panic]
    fn test_should_fail_when_erc20_when_source_is_not_this_when_call_to_non_contract_address() {
        let non_contract_address = BOB();

        // Set up a non-contract address as the token address
        let asset = MultiToken::ERC20(non_contract_address, 1000);

        // Attempt to transfer from ALICE to BOB using the non-contract address
        // This should panic because the token address is not a valid contract
        asset.transfer_asset_from(ALICE(), BOB(), false);
    }

    // ERC721

    #[test]
    fn test_should_call_safe_transfer_from_when_erc721() {
        let token_address = deploy_erc721_mock();
        let this_address = starknet::get_contract_address();
        mint_erc721(token_address, ALICE(), 1);

        assert_eq!(ERC721ABIDispatcher{ contract_address: token_address }.owner_of(1), ALICE());

        let asset = MultiToken::ERC721(token_address, 1);

        give_allowance_erc721(token_address, ALICE(), this_address, 1);
        asset.transfer_asset_from(ALICE(), BOB(), false);

        assert_eq!(ERC721ABIDispatcher{ contract_address: token_address }.owner_of(1), BOB());
    }

    // ERC1155

    #[test]
    fn test_should_call_safe_transfer_from_when_erc1155() {
        // Set up the ERC1155 token
        let token_address = deploy_erc1155_mock();
        let this_address = starknet::get_contract_address();
        mint_erc1155(token_address, ALICE(), 1, 10);

        // assert_eq!(ERC1155ABIDispatcher{ contract_address: token_address }.balance_of(ALICE(), 1), 10);
        // assert_eq!(ERC1155ABIDispatcher{ contract_address: token_address }.balance_of(BOB(), 1), 0);

        // let asset = MultiToken::ERC1155(token_address, 1, Option::Some(5));

        // give_allowance_erc1155(token_address, ALICE(), this_address, 1, 5);
        // asset.transfer_asset_from(ALICE(), BOB(), false);

        // assert_eq!(ERC1155ABIDispatcher{ contract_address: token_address }.balance_of(ALICE(), 1), 5);
        // assert_eq!(ERC1155ABIDispatcher{ contract_address: token_address }.balance_of(BOB(), 1), 5);
    }
}
