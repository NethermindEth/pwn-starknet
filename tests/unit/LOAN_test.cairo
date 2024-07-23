use core::clone::Clone;
use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::starknet::SyscallResultTrait;
use core::traits::Into;
use pwn::config::pwn_config::PwnConfig;
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::terms::simple::loan::{
    interface::{IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait},
    pwn_simple_loan::PwnSimpleLoan
};
use pwn::loan::token::pwn_loan::PwnLoan;
use pwn::multitoken::category_registry::MultiTokenCategoryRegistry;
use pwn::nonce::revoked_nonce::{RevokedNonce, IRevokedNonceDispatcher};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    stop_cheat_caller_address, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    cheat_block_timestamp_global, start_mock_call
};
use starknet::{ContractAddress, testing};

#[starknet::interface]
pub trait IPwnLoan<TState> {
    fn mint(ref self: TState, owner: ContractAddress) -> felt252;
    fn burn(ref self: TState, loan_id: felt252);
    fn name(self: @TState) -> ByteArray;
    fn symbol(self: @TState) -> ByteArray;
    fn token_uri(self: @TState, loan_id: felt252) -> ByteArray;
    fn tokenUri(self: @TState, loan_id: felt252) -> ByteArray;
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
    fn owner_of(self: @TState, token_id: u256) -> ContractAddress;
    fn safe_transfer_from(
        ref self: TState,
        from: ContractAddress,
        to: ContractAddress,
        token_id: u256,
        data: Span<felt252>
    );
    fn transfer_from(ref self: TState, from: ContractAddress, to: ContractAddress, token_id: u256);
    fn approve(ref self: TState, to: ContractAddress, token_id: u256);
    fn set_approval_for_all(ref self: TState, operator: ContractAddress, approved: bool);
    fn get_approved(self: @TState, token_id: u256) -> ContractAddress;
    fn is_approved_for_all(
        self: @TState, owner: ContractAddress, operator: ContractAddress
    ) -> bool;
}


fn hub() -> ContractAddress {
    starknet::contract_address_const::<'pwn_hub'>()
}
fn alice() -> ContractAddress {
    starknet::contract_address_const::<'alice'>()
}
fn active_loan_contract() -> ContractAddress {
    starknet::contract_address_const::<'active_loan_contract'>()
}
fn deploy() -> IPwnLoanDispatcher {
    let contract = declare("PwnLoan").unwrap();
    let (contract_address, _) = contract.deploy(@array![hub().into()]).unwrap();

    start_mock_call(hub(), selector!("has_tag"), true);

    IPwnLoanDispatcher { contract_address }
}

#[test]
fn test_should_have_correct_name_and_symbol() {
    let loan = deploy();

    let expected_name: ByteArray = "PWN LOAN";
    let expected_symbol: ByteArray = "LOAN";

    assert_eq!(loan.name(), expected_name);
    assert_eq!(loan.symbol(), expected_symbol);
}


#[test]
#[should_panic]
fn test_should_fail_when_caller_is_not_active_loan_contract() {
    let loan = deploy();
    start_mock_call(hub(), selector!("has_tag"), false);

    start_cheat_caller_address(loan.contract_address, alice());
    loan.mint(alice());
}

#[test]
fn test_should_increase_last_loan_id() {
    let loan = deploy();
    let last_loan_id = 3123;
    store(
        loan.contract_address,
        map_entry_address(selector!("last_loan_id"), array![].span(),),
        array![last_loan_id].span()
    );

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    loan.mint(alice());

    let last_loan_id_value = load(
        loan.contract_address, map_entry_address(selector!("last_loan_id"), array![].span(),), 1,
    );
    assert_eq!(*last_loan_id_value.at(0), last_loan_id + 1);
}

#[test]
fn test_should_store_loan_contract_under_loan_id() {
    let loan = deploy();

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    let loan_id = loan.mint(alice());

    let loan_contract_value = load(
        loan.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id.into()].span(),),
        1,
    );
    assert_eq!(*loan_contract_value.at(0), active_loan_contract().into());
}

#[test]
fn test_should_mint_loan_token() {
    let loan = deploy();

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    let loan_id = loan.mint(alice());

    assert_eq!(loan.owner_of(loan_id.into()), alice());
}

#[test]
fn test_should_return_loan_id() {
    let loan = deploy();
    let last_loan_id = 3123;
    store(
        loan.contract_address,
        map_entry_address(selector!("last_loan_id"), array![].span(),),
        array![last_loan_id].span()
    );

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    let loan_id = loan.mint(alice());

    assert_eq!(loan_id, last_loan_id + 1);
}

#[test]
fn test_should_emit_event_loan_minted() {
    let loan = deploy();
    let last_loan_id = 3123;
    store(
        loan.contract_address,
        map_entry_address(selector!("last_loan_id"), array![].span(),),
        array![last_loan_id].span()
    );

    let mut spy = spy_events();

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    loan.mint(alice());

    spy
        .assert_emitted(
            @array![
                (
                    loan.contract_address,
                    PwnLoan::Event::LoanMinted(
                        PwnLoan::LoanMinted {
                            loan_id: last_loan_id + 1,
                            loan_contract: active_loan_contract(),
                            owner: alice(),
                        }
                    )
                )
            ]
        );
}


fn setup_burn() -> (IPwnLoanDispatcher, felt252) {
    let loan = deploy();
    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    let loan_id = loan.mint(alice());

    (loan, loan_id)
}

#[test]
#[should_panic]
fn test_should_fail_when_caller_is_not_stored_loan_contract_for_given_loan_id() {
    let (loan, loan_id) = setup_burn();

    start_cheat_caller_address(loan.contract_address, alice());
    loan.burn(loan_id);
}

#[test]
fn test_should_delete_stored_loan_contract() {
    let (loan, loan_id) = setup_burn();

    loan.burn(loan_id);

    let loan_contract_value = load(
        loan.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    );

    assert_eq!(*loan_contract_value.at(0), 0);
}

#[test]
#[should_panic]
fn test_should_burn_loan_token() {
    let (loan, loan_id) = setup_burn();
    loan.burn(loan_id);

    loan.owner_of(loan_id.into());
}

#[test]
fn test_should_emit_event_loan_burned() {
    let (loan, loan_id) = setup_burn();

    let mut spy = spy_events();

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    loan.burn(loan_id);

    spy
        .assert_emitted(
            @array![
                (
                    loan.contract_address,
                    PwnLoan::Event::LoanBurned(PwnLoan::LoanBurned { loan_id: loan_id, })
                )
            ]
        );
}

fn setup_uri() -> (IPwnLoanDispatcher, felt252, ByteArray) {
    let loan = deploy();

    let token_uri: ByteArray = "test.uri.xyz";

    start_mock_call(loan.contract_address, selector!("token_uri"), token_uri.clone());

    start_cheat_caller_address(loan.contract_address, active_loan_contract());
    let loan_id = loan.mint(alice());

    (loan, loan_id, token_uri)
}

#[test]
fn test_should_call_loan_contract_and_return_correct_value() {
    let (loan, loan_id, uri) = setup_uri();

    let token_uri = loan.token_uri(loan_id);
    assert_eq!(token_uri, uri);
}
// #[test]
// fn test_should_return_zero_if_loan_does_not_exist() {
//     assert(true, '');
// }

// #[test]
// fn test_should_call_loan_contract_fingeprint() {
//     assert(true, '');
// }

// #[test]
// fn test_should_support_erc5646() {
//     assert(true, '');
// }


