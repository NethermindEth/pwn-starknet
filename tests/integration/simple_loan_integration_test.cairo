use core::poseidon::poseidon_hash_span;
use openzeppelin_token::{
    erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait}
};
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::terms::simple::loan::{
    interface::{IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait},
    types::{LenderSpec, ProposalSpec, CallerSpec}
};
use pwn::loan::terms::simple::proposal::simple_loan_dutch_auction_proposal::{
    SimpleLoanDutchAuctionProposal, ISimpleLoanDutchAuctionProposalDispatcher,
    ISimpleLoanDutchAuctionProposalDispatcherTrait
};
use pwn::loan::terms::simple::proposal::simple_loan_fungible_proposal::{
    SimpleLoanFungibleProposal, ISimpleLoanFungibleProposalDispatcher,
    ISimpleLoanFungibleProposalDispatcherTrait
};
use pwn::loan::terms::simple::proposal::simple_loan_simple_proposal::{
    SimpleLoanSimpleProposal, ISimpleLoanSimpleProposalDispatcher,
    ISimpleLoanSimpleProposalDispatcherTrait
};
use pwn::multitoken::library::MultiToken;
use pwn::nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    start_cheat_caller_address_global, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    start_cheat_block_timestamp_global, stop_cheat_caller_address, stop_cheat_caller_address_global,
};
use starknet::ContractAddress;
use super::base_integration_test::{
    _1_DAY, _7_DAYS, _30_HOURS, _4_HOURS, E18, setup, _repay_loan, _repay_loan_failing,
    _create_erc1155_loan_failing, _create_erc1155_loan, erc1155_mint, _sign, erc20_mint,
    _create_erc20_loan, _create_erc721_loan
};

#[test]
fn test_should_create_loan_from_simple_proposal() {
    let dsp = setup();

    let mut proposal: SimpleLoanSimpleProposal::Proposal = Default::default();
    proposal.collateral_category = MultiToken::Category::ERC1155;
    proposal.collateral_address = dsp.t1155.contract_address;
    proposal.collateral_id = 42;
    proposal.collateral_amount = 10 * E18;
    proposal.credit_address = dsp.credit.contract_address;
    proposal.credit_amount = 100 * E18;
    proposal.fixed_interest_amount = 10 * E18;
    proposal.duration = _7_DAYS;
    proposal.expiration = starknet::get_block_timestamp() + _1_DAY;
    proposal.allowed_acceptor = dsp.borrower.contract_address;
    proposal.proposer = dsp.lender.contract_address;
    proposal
        .proposer_spec_hash = dsp
        .loan
        .get_lender_spec_hash(LenderSpec { source_of_funds: dsp.lender.contract_address });
    proposal.is_offer = true;
    proposal.loan_contract = dsp.loan.contract_address;

    erc1155_mint(dsp.t1155.contract_address, dsp.borrower.contract_address, 42, 10 * E18);

    start_cheat_caller_address(dsp.t1155.contract_address, dsp.borrower.contract_address);
    dsp.t1155.set_approval_for_all(dsp.loan.contract_address, true);
    stop_cheat_caller_address(dsp.t1155.contract_address);

    let signature = _sign(dsp.proposal_simple.get_proposal_hash(proposal), dsp.lender_key_pair);

    erc20_mint(dsp.credit.contract_address, dsp.lender.contract_address, 100 * E18);

    start_cheat_caller_address(dsp.credit.contract_address, dsp.lender.contract_address);
    dsp.credit.approve(dsp.loan.contract_address, 100 * E18);
    stop_cheat_caller_address(dsp.credit.contract_address);

    let proposal_data = dsp.proposal_simple.encode_proposal_data(proposal);
    let proposal_spec = ProposalSpec {
        proposal_contract: dsp.proposal_simple.contract_address,
        proposal_data,
        proposal_inclusion_proof: array![],
        signature
    };
    let lender_spec = LenderSpec { source_of_funds: dsp.lender.contract_address };
    let caller_spec: CallerSpec = Default::default();

    start_cheat_caller_address(dsp.loan.contract_address, dsp.borrower.contract_address);
    let loan_id = dsp.loan.create_loan(proposal_spec, lender_spec, caller_spec, Option::None);

    assert_eq!(
        ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
            .owner_of(loan_id.into()),
        dsp.lender.contract_address
    );

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 100 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 10 * E18);

    assert_eq!(
        dsp
            .nonce
            .is_nonce_revoked(dsp.lender.contract_address, proposal.nonce_space, proposal.nonce),
        true
    );
    let stored_loan_contract: ContractAddress = (*load(
        dsp.loan_token.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_loan_contract, dsp.loan.contract_address);
}

#[test]
fn test_should_create_loan_from_list_proposal() {
    // NOTE: to be completed once merkle_proof is merged.
    assert(true, '');
}

#[test]
fn test_should_create_loan_from_fungible_proposal() {
    let dsp = setup();

    let mut proposal: SimpleLoanFungibleProposal::Proposal = Default::default();
    proposal.collateral_category = MultiToken::Category::ERC1155;
    proposal.collateral_address = dsp.t1155.contract_address;
    proposal.collateral_id = 42;
    proposal.min_collateral_amount = 1;
    proposal.credit_address = dsp.credit.contract_address;
    proposal.credit_per_collateral_unit = 10
        * E18
        * SimpleLoanFungibleProposal::CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR;
    proposal.available_credit_limit = 100 * E18;
    proposal.fixed_interest_amount = 10 * E18;
    proposal.duration = _7_DAYS;
    proposal.expiration = starknet::get_block_timestamp() + _1_DAY;
    proposal.allowed_acceptor = dsp.borrower.contract_address;
    proposal.proposer = dsp.lender.contract_address;
    proposal
        .proposer_spec_hash = dsp
        .loan
        .get_lender_spec_hash(LenderSpec { source_of_funds: dsp.lender.contract_address });
    proposal.is_offer = true;
    proposal.loan_contract = dsp.loan.contract_address;

    let proposal_values = SimpleLoanFungibleProposal::ProposalValues { collateral_amount: 7, };

    erc1155_mint(dsp.t1155.contract_address, dsp.borrower.contract_address, 42, 10);

    start_cheat_caller_address(dsp.t1155.contract_address, dsp.borrower.contract_address);
    dsp.t1155.set_approval_for_all(dsp.loan.contract_address, true);
    stop_cheat_caller_address(dsp.t1155.contract_address);

    let proposal_hash = dsp.proposal_fungible.get_proposal_hash(proposal);
    let signature = _sign(proposal_hash, dsp.lender_key_pair);

    erc20_mint(dsp.credit.contract_address, dsp.lender.contract_address, 100 * E18);

    start_cheat_caller_address(dsp.credit.contract_address, dsp.lender.contract_address);
    dsp.credit.approve(dsp.loan.contract_address, 100 * E18);
    stop_cheat_caller_address(dsp.credit.contract_address);

    let proposal_data = dsp.proposal_fungible.encode_proposal_data(proposal, proposal_values);

    let proposal_spec = ProposalSpec {
        proposal_contract: dsp.proposal_fungible.contract_address,
        proposal_data,
        proposal_inclusion_proof: array![],
        signature
    };
    let lender_spec = LenderSpec { source_of_funds: dsp.lender.contract_address };
    let caller_spec: CallerSpec = Default::default();

    start_cheat_caller_address(dsp.loan.contract_address, dsp.borrower.contract_address);
    let loan_id = dsp.loan.create_loan(proposal_spec, lender_spec, caller_spec, Option::None);

    assert_eq!(
        ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
            .owner_of(loan_id.into()),
        dsp.lender.contract_address
    );

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 30 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 70 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 3);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 7);

    assert_eq!(
        dsp
            .nonce
            .is_nonce_revoked(dsp.lender.contract_address, proposal.nonce_space, proposal.nonce),
        false
    );
    let stored_credit_used = (*load(
        dsp.proposal_fungible.contract_address,
        map_entry_address(selector!("credit_used"), array![proposal_hash].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_credit_used, 70 * E18);

    let stored_loan_contract: ContractAddress = (*load(
        dsp.loan_token.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_loan_contract, dsp.loan.contract_address);
}

#[test]
fn test_should_create_loan_from_dutch_auction_proposal() {
    let dsp = setup();

    let mut proposal: SimpleLoanDutchAuctionProposal::Proposal = Default::default();
    proposal.collateral_category = MultiToken::Category::ERC1155;
    proposal.collateral_address = dsp.t1155.contract_address;
    proposal.collateral_id = 42;
    proposal.collateral_amount = 10;
    proposal.credit_address = dsp.credit.contract_address;
    proposal.min_credit_amount = 10 * E18;
    proposal.max_credit_amount = 100 * E18;
    proposal.fixed_interest_amount = 10 * E18;
    proposal.duration = _7_DAYS;
    proposal.auction_start = starknet::get_block_timestamp();
    proposal.auction_duration = _30_HOURS;
    proposal.allowed_acceptor = dsp.lender.contract_address;
    proposal.proposer = dsp.borrower.contract_address;
    proposal.loan_contract = dsp.loan.contract_address;

    let proposal_values = SimpleLoanDutchAuctionProposal::ProposalValues {
        intended_credit_amount: 90 * E18, slippage: 10 * E18,
    };

    erc1155_mint(dsp.t1155.contract_address, dsp.borrower.contract_address, 42, 10);

    start_cheat_caller_address(dsp.t1155.contract_address, dsp.borrower.contract_address);
    dsp.t1155.set_approval_for_all(dsp.loan.contract_address, true);
    stop_cheat_caller_address(dsp.t1155.contract_address);

    let proposal_hash = dsp.proposal_dutch.get_proposal_hash(proposal);
    let signature = _sign(proposal_hash, dsp.borrower_key_pair);

    erc20_mint(dsp.credit.contract_address, dsp.lender.contract_address, 100 * E18);

    start_cheat_caller_address(dsp.credit.contract_address, dsp.lender.contract_address);
    dsp.credit.approve(dsp.loan.contract_address, 100 * E18);
    stop_cheat_caller_address(dsp.credit.contract_address);

    let proposal_data = dsp.proposal_dutch.encode_proposal_data(proposal, proposal_values);

    start_cheat_block_timestamp_global(starknet::get_block_timestamp() + _4_HOURS);

    let credit_amount = dsp
        .proposal_dutch
        .get_credit_amount(proposal, starknet::get_block_timestamp());

    let proposal_spec = ProposalSpec {
        proposal_contract: dsp.proposal_dutch.contract_address,
        proposal_data,
        proposal_inclusion_proof: array![],
        signature
    };
    let lender_spec = LenderSpec { source_of_funds: dsp.lender.contract_address };
    let caller_spec: CallerSpec = Default::default();

    start_cheat_caller_address(dsp.loan.contract_address, dsp.lender.contract_address);
    let loan_id = dsp.loan.create_loan(proposal_spec, lender_spec, caller_spec, Option::None);

    assert_eq!(
        ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
            .owner_of(loan_id.into()),
        dsp.lender.contract_address
    );

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 100 * E18 - credit_amount);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), credit_amount);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 10);

    assert_eq!(
        dsp
            .nonce
            .is_nonce_revoked(dsp.borrower.contract_address, proposal.nonce_space, proposal.nonce),
        true
    );
    let stored_loan_contract: ContractAddress = (*load(
        dsp.loan_token.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_loan_contract, dsp.loan.contract_address);
}

#[test]
fn test_should_create_loan_with_erc20_collateral() {
    let dsp = setup();

    let loan_id = _create_erc20_loan(dsp);

    assert_eq!(
        ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
            .owner_of(loan_id.into()),
        dsp.lender.contract_address
    );

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 100 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t20.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.t20.balance_of(dsp.borrower.contract_address), 0);
    assert_eq!(dsp.t20.balance_of(dsp.loan.contract_address), 10 * E18);

    assert_eq!(
        dsp
            .nonce
            .is_nonce_revoked(
                dsp.lender.contract_address,
                dsp.simple_proposal.nonce_space,
                dsp.simple_proposal.nonce
            ),
        true
    );
    let stored_loan_contract: ContractAddress = (*load(
        dsp.loan_token.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_loan_contract, dsp.loan.contract_address);
}

#[test]
fn test_should_create_loan_with_erc721_collateral() {
    let dsp = setup();

    let loan_id = _create_erc721_loan(dsp);

    assert_eq!(
        ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
            .owner_of(loan_id.into()),
        dsp.lender.contract_address
    );
    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 100 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t721.owner_of(42), dsp.loan.contract_address);

    assert_eq!(
        dsp
            .nonce
            .is_nonce_revoked(
                dsp.lender.contract_address,
                dsp.simple_proposal.nonce_space,
                dsp.simple_proposal.nonce
            ),
        true
    );
    let stored_loan_contract: ContractAddress = (*load(
        dsp.loan_token.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_loan_contract, dsp.loan.contract_address);
}

#[test]
fn test_should_create_loan_with_erc1155_collateral() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    assert_eq!(
        ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
            .owner_of(loan_id.into()),
        dsp.lender.contract_address
    );

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 100 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 10 * E18);

    assert_eq!(
        dsp
            .nonce
            .is_nonce_revoked(
                dsp.lender.contract_address,
                dsp.simple_proposal.nonce_space,
                dsp.simple_proposal.nonce
            ),
        true
    );
    let stored_loan_contract: ContractAddress = (*load(
        dsp.loan_token.contract_address,
        map_entry_address(selector!("loan_contract"), array![loan_id].span(),),
        1,
    )
        .at(0))
        .try_into()
        .unwrap();
    assert_eq!(stored_loan_contract, dsp.loan.contract_address);
}

#[test]
fn test_should_repay_loan_when_not_expired_when_original_lender_is_loan_owner() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    _repay_loan(dsp, loan_id);

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 110 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 10 * E18);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 0);
}

#[test]
#[should_panic]
fn test_should_fail_to_repay_loan_when_loan_expired() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    let expiration = starknet::get_block_timestamp() + dsp.simple_proposal.duration;
    start_cheat_block_timestamp_global(expiration);

    _repay_loan_failing(dsp, loan_id, 'LOAN_EXPIRED');
}

#[test]
fn test_should_claim_repaid_loan_when_original_lender_is_not_loan_owner() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    start_cheat_caller_address(dsp.loan_token.contract_address, dsp.lender.contract_address);
    ERC721ABIDispatcher { contract_address: dsp.loan_token.contract_address }
        .transfer_from(dsp.lender.contract_address, dsp.lender2.contract_address, loan_id.into());
    stop_cheat_caller_address(dsp.loan_token.contract_address);

    _repay_loan(dsp, loan_id);

    start_cheat_caller_address(dsp.loan.contract_address, dsp.lender2.contract_address);
    dsp.loan.claim_loan(loan_id);
    stop_cheat_caller_address(dsp.loan.contract_address);

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
fn test_should_claim_defaulted_loan() {
    let dsp = setup();

    let loan_id = _create_erc1155_loan(dsp);

    start_cheat_block_timestamp_global(
        starknet::get_block_timestamp() + dsp.simple_proposal.duration
    );

    start_cheat_caller_address(dsp.loan.contract_address, dsp.lender.contract_address);
    dsp.loan.claim_loan(loan_id);

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 0);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 100 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 0);

    assert_eq!(dsp.t1155.balance_of(dsp.lender.contract_address, 42), 10 * E18);
    assert_eq!(dsp.t1155.balance_of(dsp.borrower.contract_address, 42), 0);
    assert_eq!(dsp.t1155.balance_of(dsp.loan.contract_address, 42), 0);
}

