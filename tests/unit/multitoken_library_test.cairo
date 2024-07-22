use openzeppelin::token::erc1155::interface::{
    ERC1155ABI, ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait
};
use openzeppelin::token::erc20::interface::{ERC20ABI, ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
use openzeppelin::token::erc721::interface::{
    ERC721ABI, ERC721ABIDispatcher, ERC721ABIDispatcherTrait
};
use pwn::mocks::{
    erc20_mock::ERC20Mock, erc721_mock::ERC721Mock, erc1155_mock::ERC1155Mock,
    account_mock::AccountMock
};
use pwn::multitoken::{
    category_registry::MultiTokenCategoryRegistry, library::{MultiToken, MultiToken::AssetTrait}
};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address, CheatSpan, mock_call, start_mock_call, stop_mock_call
};
use starknet::ContractAddress;

fn ALICE() -> ContractAddress {
    starknet::contract_address_const::<'alice'>()
}
fn BOB() -> ContractAddress {
    starknet::contract_address_const::<'bob'>()
}

#[derive(Drop)]
struct Tokens {
    erc20: ERC20ABIDispatcher,
    erc721: ERC721ABIDispatcher,
    erc1155: ERC1155ABIDispatcher,
}

fn deploy() -> Tokens {
    let contract = declare("ERC20Mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();
    let erc20 = ERC20ABIDispatcher { contract_address };

    let contract = declare("ERC721Mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();
    let erc721 = ERC721ABIDispatcher { contract_address };

    let contract = declare("ERC1155Mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();
    let erc1155 = ERC1155ABIDispatcher { contract_address };

    Tokens { erc20, erc721, erc1155 }
}

fn deploy_accounts() -> (ContractAddress, ContractAddress) {
    let contract = declare("AccountMock").unwrap();
    let (alice, _) = contract.deploy(@array!['PUBKEY1']).unwrap();
    let (bob, _) = contract.deploy(@array!['PUBKEY2']).unwrap();

    (alice, bob)
}

#[test]
fn test_fuzz_should_return_erc20(asset_address: u128, amount: u256) {
    let asset_address: felt252 = asset_address.try_into().unwrap();

    let asset: MultiToken::Asset = MultiToken::ERC20(asset_address.try_into().unwrap(), amount);

    assert_eq!(asset.category, MultiToken::Category::ERC20);
    assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
    assert_eq!(asset.id, 0);
    assert_eq!(asset.amount, amount);
}

#[test]
fn test_fuzz_should_return_erc721(asset_address: u128, id: felt252) {
    let asset_address: felt252 = asset_address.try_into().unwrap();

    let asset: MultiToken::Asset = MultiToken::ERC721(asset_address.try_into().unwrap(), id);

    assert_eq!(asset.category, MultiToken::Category::ERC721);
    assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
    assert_eq!(asset.id, id);
    assert_eq!(asset.amount, 0);
}

#[test]
fn test_fuzz_should_return_erc1155(asset_address: u128, id: felt252, amount: u256) {
    let asset_address: felt252 = asset_address.try_into().unwrap();

    let asset: MultiToken::Asset = MultiToken::ERC1155(
        asset_address.try_into().unwrap(), id, Option::Some(amount)
    );

    assert_eq!(asset.category, MultiToken::Category::ERC1155);
    assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
    assert_eq!(asset.id, id);
    assert_eq!(asset.amount, amount);
}

#[test]
fn test_fuzz_should_return_erc1155_with_no_amount(asset_address: u128, id: felt252) {
    let asset_address: felt252 = asset_address.try_into().unwrap();

    let asset: MultiToken::Asset = MultiToken::ERC1155(
        asset_address.try_into().unwrap(), id, Option::None
    );

    assert_eq!(asset.category, MultiToken::Category::ERC1155);
    assert_eq!(asset.asset_address, asset_address.try_into().unwrap());
    assert_eq!(asset.id, id);
    assert_eq!(asset.amount, 0);
}


#[test]
fn test_should_call_transfer_when_erc20_when_source_is_this() {
    let tokens = deploy();
    let this_address = starknet::get_contract_address();
    store(
        tokens.erc20.contract_address,
        map_entry_address(selector!("ERC20_balances"), array![this_address.into()].span()),
        array![1000].span()
    );

    assert_eq!(tokens.erc20.balance_of(this_address), 1000);

    let asset = MultiToken::ERC20(tokens.erc20.contract_address, 1000);
    asset.transfer_asset_from(this_address, BOB(), false);

    assert_eq!(tokens.erc20.balance_of(this_address), 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_erc20_when_source_is_this_when_transfer_returns_fale() {
    let tokens = deploy();
    let this_address = starknet::get_contract_address();

    let asset = MultiToken::ERC20(tokens.erc20.contract_address, 1000);
    asset.transfer_asset_from(this_address, BOB(), false);
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
    let tokens = deploy();
    let this_address = starknet::get_contract_address();

    store(
        tokens.erc20.contract_address,
        map_entry_address(selector!("ERC20_balances"), array![ALICE().into()].span()),
        array![1000].span()
    );

    assert_eq!(tokens.erc20.balance_of(ALICE()), 1000);
    assert_eq!(tokens.erc20.balance_of(BOB()), 0);

    store(
        tokens.erc20.contract_address,
        map_entry_address(selector!("ERC20_allowances"), array![ALICE().into(), this_address.into()].span()),
        array![1000].span()
    );

    let asset = MultiToken::ERC20(tokens.erc20.contract_address, 1000);
    asset.transfer_asset_from(ALICE(), BOB(), false);

    assert_eq!(tokens.erc20.balance_of(ALICE()), 0);
    assert_eq!(tokens.erc20.balance_of(BOB()), 1000);
}

#[test]
#[should_panic]
fn test_should_fail_when_erc20_when_source_is_not_this_when_transfer_returns_false() {
    let tokens = deploy();

    let asset = MultiToken::ERC20(tokens.erc20.contract_address, 1000);
    asset.transfer_asset_from(ALICE(), BOB(), false);
}


#[test]
#[should_panic]
fn test_should_fail_when_erc20_when_source_is_not_this_when_call_to_non_contract_address() {
    let non_contract_address = BOB();

    let asset = MultiToken::ERC20(non_contract_address, 1000);

    asset.transfer_asset_from(ALICE(), BOB(), false);
}

// ERC721

#[test]
#[ignore]
fn test_should_call_transfer_from_when_erc721() {
    let tokens = deploy();
    // let this_address = starknet::get_contract_address();
    let token_id : u256 = 1;
    // Mint ERC721 token
    store(
        tokens.erc721.contract_address,
        map_entry_address(selector!("ERC721_owners"), array![1].span()),
        array![ALICE().into()].span()
    );

    assert_eq!(tokens.erc721.owner_of(token_id), ALICE());
    
    // let asset = MultiToken::ERC721(tokens.erc721.contract_address, 1);

    // store(
    //     tokens.erc721.contract_address,
    //     map_entry_address(selector!("ERC721_token_approvals"), array![1].span()),
    //     array![this_address.into()].span()
    // );
    // asset.transfer_asset_from(ALICE(), BOB(), false);

    // assert_eq!(tokens.erc721.owner_of(1), BOB());
}

// #[test]
// fn test_should_call_safe_transfer_from_when_erc721() {
//     let (alice, bob) = deploy_accounts();
//     let token_address = deploy_erc721_mock();
//     let this_address = starknet::get_contract_address();
//     mint_erc721(token_address, alice, 1);

//     assert_eq!(ERC721ABIDispatcher { contract_address: token_address }.owner_of(1), alice);

//     let asset = MultiToken::ERC721(token_address, 1);

//     give_allowance_erc721(token_address, alice, this_address, 1);
//     asset.transfer_asset_from(alice, bob, true);

//     assert_eq!(ERC721ABIDispatcher { contract_address: token_address }.owner_of(1), bob);
// }

// // ERC1155

// #[test]
// fn test_should_call_safe_transfer_from_when_erc1155() {
//     let (alice, bob) = deploy_accounts();
//     let token_address = deploy_erc1155_mock();
//     let this_address = starknet::get_contract_address();
//     mint_erc1155(token_address, alice, 1, 10);
//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(alice, 1), 10);
//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(bob, 1), 0);

//     let asset = MultiToken::ERC1155(token_address, 1, Option::Some(5));

//     give_allowance_erc1155(token_address, alice, this_address, 1, 5);
//     asset.transfer_asset_from(alice, bob, false);

//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(alice, 1), 5);
//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(bob, 1), 5);
// }

// #[test]
// fn test_should_set_amount_to_one_when_erc1155_with_zero_amount() {
//     let (alice, bob) = deploy_accounts();
//     let token_address = deploy_erc1155_mock();
//     let this_address = starknet::get_contract_address();

//     mint_erc1155(token_address, alice, 1, 10);
//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(alice, 1), 10);
//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(bob, 1), 0);

//     let asset = MultiToken::ERC1155(token_address, 1, Option::None);

//     give_allowance_erc1155(token_address, alice, this_address, 1, 5);
//     asset.transfer_asset_from(alice, bob, false);

//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(alice, 1), 9);
//     assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(bob, 1), 1);
// }


// mod balance_of {
//     use pwn::multitoken::library::MultiToken::AssetTrait;
//     use pwn::multitoken::library::MultiToken;
//     use super::{
//         deploy_erc20_mock, mint_erc20, deploy_erc721_mock, mint_erc721, deploy_erc1155_mock,
//         mint_erc1155, deploy_accounts
//     };

//     #[test]
//     fn test_should_return_balance_of_erc20() {
//         let token_address = deploy_erc20_mock();
//         let this_address = starknet::get_contract_address();
//         mint_erc20(token_address, this_address, 1000);

//         let asset = MultiToken::ERC20(token_address, 1000);
//         assert_eq!(asset.balance_of(this_address), 1000);
//     }

//     #[test]
//     fn test_should_return_balance_of_erc721() {
//         let token_address = deploy_erc721_mock();
//         let this_address = starknet::get_contract_address();
//         mint_erc721(token_address, this_address, 1);

//         let asset = MultiToken::ERC721(token_address, 1);
//         assert_eq!(asset.balance_of(this_address), 1);
//     }

//     #[test]
//     fn test_should_return_balance_of_erc1155() {
//         let (alice, _) = deploy_accounts();
//         let token_address = deploy_erc1155_mock();
//         mint_erc1155(token_address, alice, 1, 10);

//         let asset = MultiToken::ERC1155(token_address, 1, Option::Some(10));
//         assert_eq!(asset.balance_of(alice), 10);
//     }
// }

// mod approve_asset {
//     use openzeppelin::token::erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait};
//     use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
//     use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
//     use pwn::multitoken::library::MultiToken::AssetTrait;
//     use pwn::multitoken::library::MultiToken;
//     use snforge_std::{cheat_caller_address_global, stop_cheat_caller_address_global};
//     use super::{
//         ALICE, BOB, deploy_erc20_mock, mint_erc20, deploy_erc721_mock, mint_erc721,
//         deploy_erc1155_mock, mint_erc1155, deploy_accounts
//     };

//     #[test]
//     #[should_panic]
//     fn test_erc20_transfer_asset_from_should_fail_when_not_approved() {
//         let token_address = deploy_erc20_mock();
//         mint_erc20(token_address, ALICE(), 1000);

//         let asset = MultiToken::ERC20(token_address, 1000);
//         asset.transfer_asset_from(ALICE(), BOB(), false);
//     }

//     #[test]
//     fn test_erc20_transfer_asset_from_should_succeed_when_approved() {
//         let token_address = deploy_erc20_mock();
//         let this_address = starknet::get_contract_address();
//         mint_erc20(token_address, ALICE(), 1000);

//         assert_eq!(
//             ERC20ABIDispatcher { contract_address: token_address }.balance_of(ALICE()), 1000
//         );
//         assert_eq!(ERC20ABIDispatcher { contract_address: token_address }.balance_of(BOB()), 0);

//         let asset = MultiToken::ERC20(token_address, 1000);

//         cheat_caller_address_global(ALICE());
//         asset.approve_asset(this_address);
//         stop_cheat_caller_address_global();

//         asset.transfer_asset_from(ALICE(), BOB(), false);
//         assert_eq!(ERC20ABIDispatcher { contract_address: token_address }.balance_of(ALICE()), 0);
//         assert_eq!(ERC20ABIDispatcher { contract_address: token_address }.balance_of(BOB()), 1000);
//     }

//     #[test]
//     #[should_panic]
//     fn test_erc721_transfer_asset_from_should_fail_when_not_approved() {
//         let token_address = deploy_erc721_mock();
//         mint_erc721(token_address, ALICE(), 1);

//         let asset = MultiToken::ERC721(token_address, 1);
//         asset.transfer_asset_from(ALICE(), BOB(), false);
//     }

//     #[test]
//     fn test_erc721_transfer_asset_from_should_succeed_when_approved() {
//         let (alice, bob) = deploy_accounts();
//         let token_address = deploy_erc721_mock();
//         let this_address = starknet::get_contract_address();
//         mint_erc721(token_address, alice, 1);

//         assert_eq!(ERC721ABIDispatcher { contract_address: token_address }.owner_of(1), alice);

//         let asset = MultiToken::ERC721(token_address, 1);

//         cheat_caller_address_global(alice);
//         asset.approve_asset(this_address);
//         stop_cheat_caller_address_global();

//         asset.transfer_asset_from(alice, bob, false);
//         assert_eq!(ERC721ABIDispatcher { contract_address: token_address }.owner_of(1), bob);
//     }

//     #[test]
//     #[should_panic]
//     fn test_erc1155_transfer_asset_from_should_fail_when_not_approved() {
//         let (alice, bob) = deploy_accounts();
//         let token_address = deploy_erc1155_mock();
//         mint_erc1155(token_address, alice, 1, 10);

//         let asset = MultiToken::ERC1155(token_address, 1, Option::Some(10));
//         asset.transfer_asset_from(alice, bob, false);
//     }

//     #[test]
//     fn test_erc1155_transfer_asset_from_should_succeed_when_approved() {
//         let (alice, bob) = deploy_accounts();
//         let token_address = deploy_erc1155_mock();
//         let this_address = starknet::get_contract_address();
//         mint_erc1155(token_address, alice, 1, 10);

//         assert_eq!(
//             ERC1155ABIDispatcher { contract_address: token_address }.balance_of(alice, 1), 10
//         );
//         assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(bob, 1), 0);

//         let asset = MultiToken::ERC1155(token_address, 1, Option::Some(5));

//         cheat_caller_address_global(alice);
//         asset.approve_asset(this_address);
//         stop_cheat_caller_address_global();

//         asset.transfer_asset_from(alice, bob, false);
//         assert_eq!(
//             ERC1155ABIDispatcher { contract_address: token_address }.balance_of(alice, 1), 5
//         );
//         assert_eq!(ERC1155ABIDispatcher { contract_address: token_address }.balance_of(bob, 1), 5);
//     }
// }

mod is_valid_with_registry {
    use pwn::multitoken::library::MultiToken::AssetTrait;
    use pwn::multitoken::library::MultiToken;
    use snforge_std::mock_call;

    #[test]
    fn test_should_return_true_when_category_and_format_check_return_true() {
        let registry = starknet::contract_address_const::<'MULTITOKEN_CATEGORY_REGISTRY'>();
        let token = starknet::contract_address_const::<'TOKEN'>();

        // category check returns false
        mock_call(registry, selector!("registered_category_value"), 0, 1);
        let asset = MultiToken::ERC721(token, 1);
        assert_eq!(asset.is_valid(Option::Some(registry)), false);

        // format check returns false
        mock_call(registry, selector!("registered_category_value"), 1, 1);
        let mut asset = MultiToken::ERC721(token, 1);
        asset.amount = 1;
        assert_eq!(asset.is_valid(Option::Some(registry)), false);

        // both category and format check return true
        mock_call(registry, selector!("registered_category_value"), 1, 1);
        let asset = MultiToken::ERC721(token, 1);
        assert_eq!(asset.is_valid(Option::Some(registry)), true);
    }
}

mod is_valid_without_registry {
    use pwn::multitoken::library::MultiToken::AssetTrait;
    use pwn::multitoken::library::MultiToken;
    use snforge_std::mock_call;

    #[test]
    fn test_should_return_true_when_category_and_format_check_return_true() {
        let token = starknet::contract_address_const::<'TOKEN'>();

        // category check returns false
        mock_call(token, selector!("supports_interface"), false, 1);
        let asset = MultiToken::ERC721(token, 1);
        assert_eq!(asset.is_valid(Option::None), false);

        // format check returns false
        mock_call(token, selector!("supports_interface"), true, 1);
        let mut asset = MultiToken::ERC721(token, 1);
        asset.amount = 1;
        assert_eq!(asset.is_valid(Option::None), false);

        // both category and format check return true
        mock_call(token, selector!("supports_interface"), true, 1);
        let mut asset = MultiToken::ERC721(token, 1);
        assert_eq!(asset.is_valid(Option::None), true);
    }
}

mod is_same_as {
    use pwn::multitoken::library::MultiToken::AssetTrait;
    use pwn::multitoken::library::MultiToken;
    use snforge_std::mock_call;

    #[test]
    fn test_should_fail_when_different_category() {
        let token = starknet::contract_address_const::<'TOKEN'>();
        let asset_a = MultiToken::ERC721(token, 1);
        let asset_b = MultiToken::ERC1155(token, 1, Option::Some(5));

        assert_eq!(asset_a.is_same_as(asset_b), false);
    }

    #[test]
    fn test_should_fail_when_different_address() {
        let token_a = starknet::contract_address_const::<'TOKEN_A'>();
        let token_b = starknet::contract_address_const::<'TOKEN_B'>();
        let asset_a = MultiToken::ERC721(token_a, 1);
        let asset_b = MultiToken::ERC721(token_b, 1);

        assert_eq!(asset_a.is_same_as(asset_b), false);
    }

    #[test]
    fn test_should_fail_when_different_id() {
        let token = starknet::contract_address_const::<'TOKEN'>();
        let asset_a = MultiToken::ERC721(token, 1);
        let asset_b = MultiToken::ERC721(token, 2);

        assert_eq!(asset_a.is_same_as(asset_b), false);
    }

    #[test]
    fn test_should_pass_when_different_amount() {
        let token = starknet::contract_address_const::<'TOKEN'>();
        let asset_a = MultiToken::ERC1155(token, 1, Option::Some(10));
        let asset_b = MultiToken::ERC1155(token, 1, Option::Some(5));

        assert_eq!(asset_a.is_same_as(asset_b), true);
    }
}
