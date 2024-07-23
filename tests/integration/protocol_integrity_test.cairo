use openzeppelin::token::{
    erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait}
};
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::terms::simple::loan::interface::IPwnSimpleLoanDispatcherTrait;
use pwn::loan::terms::simple::proposal::simple_loan_simple_proposal::{
    ISimpleLoanSimpleProposalDispatcher, ISimpleLoanSimpleProposalDispatcherTrait
};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address_global, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    cheat_block_timestamp_global, stop_cheat_caller_address, stop_cheat_caller_address_global
};
use super::base_integration_test::{
    E18, setup, protocol_timelock, _repay_loan, _create_erc1155_loan_failing, _create_erc1155_loan
};

#[test]
#[should_panic]
fn test_should_fail_to_create_loan_when_loan_contract_not_active() {
    let dsp = setup();

    cheat_caller_address_global(protocol_timelock());
    dsp.hub.set_tag(dsp.loan.contract_address, pwn_hub_tags::ACTIVE_LOAN, false);

    _create_erc1155_loan_failing(dsp, 'fail');
}

#[test]
fn test_should_repay_loan_when_loan_contract_not_active_when_original_lender_is_loan_owner() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    dsp.hub.set_tag(dsp.loan.contract_address, pwn_hub_tags::ACTIVE_LOAN, false);

    _repay_loan(dsp, loan_id);

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 110 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 10 * E18);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 0);
}

#[test]
fn test_should_repay_loan_when_loan_contract_not_active_when_original_lender_is_not_loan_owner() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    cheat_caller_address_global(dsp.lender.contract_address);
    let loan_token_erc721 = ERC721ABIDispatcher {
        contract_address: dsp.loan_token.contract_address
    };
    loan_token_erc721
        .transfer_from(dsp.lender.contract_address, dsp.lender2.contract_address, loan_id.into());
    stop_cheat_caller_address_global();

    dsp.hub.set_tag(dsp.loan.contract_address, pwn_hub_tags::ACTIVE_LOAN, false);
    // mock_call(dsp.nonce.contract_address, , true);

    _repay_loan(dsp, loan_id);

    assert_eq!(loan_token_erc721.owner_of(loan_id.into()), dsp.lender2.contract_address);

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.lender2.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 110 * E18);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.lender2.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 10 * E18);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 0);
}

#[test]
fn test_should_claim_repaid_loan_when_loan_contract_not_active() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    cheat_caller_address_global(dsp.lender.contract_address);
    let loan_token_erc721 = ERC721ABIDispatcher {
        contract_address: dsp.loan_token.contract_address
    };
    loan_token_erc721
        .transfer_from(dsp.lender.contract_address, dsp.lender2.contract_address, loan_id.into());
    stop_cheat_caller_address_global();

    _repay_loan(dsp, loan_id);

    dsp.hub.set_tag(dsp.loan.contract_address, pwn_hub_tags::ACTIVE_LOAN, false);

    start_cheat_caller_address(dsp.loan.contract_address, dsp.lender2.contract_address);
    dsp.loan.claim_loan(loan_id.into());
    stop_cheat_caller_address_global();

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.lender2.contract_address), 110 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.lender2.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 10 * E18);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 0);
}

#[test]
#[should_panic]
fn test_should_fail_to_create_loan_terms_when_caller_is_not_active_loan() {
    let dsp = setup();

    dsp.hub.set_tag(dsp.loan.contract_address, pwn_hub_tags::ACTIVE_LOAN, false);

    let proposal_data = dsp.proposal_simple.encode_proposal_data(dsp.simple_proposal);

    cheat_caller_address_global(dsp.loan.contract_address);
    dsp
        .proposal_simple
        .accept_proposal(
            dsp.borrower.contract_address, 0, proposal_data, array![], Default::default()
        );
}

#[test]
#[should_panic]
fn test_should_fail_to_create_loan_when_passing_invalid_terms_factory_contract() {
    let dsp = setup();

    dsp.hub.set_tag(dsp.loan.contract_address, pwn_hub_tags::LOAN_PROPOSAL, false);
    _create_erc1155_loan_failing(dsp, 'fail');
}
