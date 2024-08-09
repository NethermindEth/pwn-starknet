use openzeppelin_token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
use openzeppelin_token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
use pwn::loan::terms::simple::loan::{
    interface::{IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait},
    types::{LenderSpec, ProposalSpec, CallerSpec}
};
use pwn::loan::terms::simple::proposal::simple_loan_simple_proposal::{
    ISimpleLoanSimpleProposalDispatcherTrait, SimpleLoanSimpleProposal::Proposal
};
use pwn::multitoken::category_registry::IMultiTokenCategoryRegistryDispatcherTrait;
use pwn::multitoken::library::MultiToken;
use snforge_std::{
    start_cheat_caller_address, stop_cheat_caller_address, start_cheat_block_timestamp_global
};
use starknet::ContractAddress;
use super::super::integration::base_integration_test::{
    setup as super_setup, erc20_mint, E18, Setup, _1_DAY, _7_DAYS, erc721_mint
};

fn STRK() -> ContractAddress {
    starknet::contract_address_const::<
        0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
    >()
}
fn WBTC() -> ContractAddress {
    starknet::contract_address_const::<
        0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac
    >()
}
fn USDC() -> ContractAddress {
    starknet::contract_address_const::<
        0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8
    >()
}
fn TETHER() -> ContractAddress {
    starknet::contract_address_const::<
        0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8
    >()
}
fn ETH() -> ContractAddress {
    starknet::contract_address_const::<
        0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7
    >()
}
fn UNI() -> ContractAddress {
    starknet::contract_address_const::<
        0x04fe90c0c4594b4a5ce3031a4bbdfbc7c046b4b9d7cf31b79647540c85b8ec79
    >()
}
fn ARGENT_NFT() -> ContractAddress {
    starknet::contract_address_const::<
        0x01b22f7a9d18754c994ae0ee9adb4628d414232e3ebd748c386ac286f86c3066
    >()
}

fn setup() -> (Setup, Proposal) {
    let dsp = super_setup();

    dsp.registry.register_category_value(USDC(), MultiToken::Category::ERC20.into());
    dsp.registry.register_category_value(WBTC(), MultiToken::Category::ERC20.into());
    dsp.registry.register_category_value(ETH(), MultiToken::Category::ERC20.into());
    dsp.registry.register_category_value(UNI(), MultiToken::Category::ERC20.into());
    dsp.registry.register_category_value(STRK(), MultiToken::Category::ERC20.into());

    erc20_mint(dsp.credit.contract_address, dsp.lender.contract_address, 100 * E18);
    erc20_mint(dsp.credit.contract_address, dsp.borrower.contract_address, 100 * E18);

    start_cheat_caller_address(dsp.credit.contract_address, dsp.lender.contract_address);
    dsp.credit.approve(dsp.loan.contract_address, 100 * E18);

    start_cheat_caller_address(dsp.credit.contract_address, dsp.borrower.contract_address);
    dsp.credit.approve(dsp.loan.contract_address, 100 * E18);
    stop_cheat_caller_address(dsp.credit.contract_address);

    let mut proposal: Proposal = Default::default();
    proposal.collateral_category = MultiToken::Category::ERC20;
    proposal.collateral_address = dsp.credit.contract_address;
    proposal.collateral_amount = 10 * E18;
    proposal.credit_address = dsp.credit.contract_address;
    proposal.credit_amount = E18;
    proposal.duration = _1_DAY;
    proposal.expiration = starknet::get_block_timestamp() + _7_DAYS;
    proposal.proposer = dsp.lender.contract_address;
    proposal
        .proposer_spec_hash = dsp
        .loan
        .get_lender_spec_hash(LenderSpec { source_of_funds: dsp.lender.contract_address });
    proposal.is_offer = true;
    proposal.loan_contract = dsp.loan.contract_address;

    (dsp, proposal)
}

fn _create_loan(dsp: Setup, proposal: Proposal) -> felt252 {
    start_cheat_caller_address(dsp.proposal_simple.contract_address, dsp.lender.contract_address);
    dsp.proposal_simple.make_proposal(proposal);
    stop_cheat_caller_address(dsp.proposal_simple.contract_address);

    let proposal_data = dsp.proposal_simple.encode_proposal_data(proposal);

    let proposal_spec = ProposalSpec {
        proposal_contract: dsp.proposal_simple.contract_address,
        proposal_data,
        proposal_inclusion_proof: array![],
        signature: Default::default()
    };
    let lender_spec = LenderSpec { source_of_funds: dsp.lender.contract_address };
    let caller_spec: CallerSpec = Default::default();

    start_cheat_caller_address(dsp.loan.contract_address, dsp.borrower.contract_address);
    let loan_id = dsp.loan.create_loan(proposal_spec, lender_spec, caller_spec, Option::None);
    stop_cheat_caller_address(dsp.loan.contract_address);

    loan_id
}

#[test]
#[should_panic]
#[fork("mainnet")]
#[ignore]
fn test_use_case_should_fail_when_20_collateral_passed_with_721_category() {
    let (dsp, mut proposal) = setup();

    proposal.collateral_category = MultiToken::Category::ERC721;
    proposal.collateral_address = USDC();
    proposal.collateral_id = (10 * E18).try_into().unwrap();
    proposal.collateral_amount = 0;

    _create_loan(dsp, proposal);
}

#[test]
#[should_panic]
#[fork("mainnet")]
#[ignore]
fn test_use_case_should_fail_when_20_collateral_passed_with_1155_category() {
    let (dsp, mut proposal) = setup();

    proposal.collateral_category = MultiToken::Category::ERC1155;
    proposal.collateral_address = STRK();
    proposal.collateral_id = 0;
    proposal.collateral_amount = 10 * E18;

    _create_loan(dsp, proposal);
}

#[test]
#[should_panic]
#[fork("mainnet")]
#[ignore]
fn test_use_case_should_fail_when_using_erc721_as_credit() {
    let (dsp, mut proposal) = setup();

    erc721_mint(dsp.t721.contract_address, dsp.lender.contract_address, 42);

    start_cheat_caller_address(dsp.t721.contract_address, dsp.lender.contract_address);
    dsp.t721.approve(dsp.loan.contract_address, 42);

    proposal.credit_address = dsp.t721.contract_address;
    proposal.credit_amount = 42;

    _create_loan(dsp, proposal);
}

#[test]
#[fork("mainnet")]
#[ignore]
fn test_should_pass_when_invalid_src5_support() {
    let (dsp, mut proposal) = setup();

    dsp.registry.register_category_value(ARGENT_NFT(), MultiToken::Category::ERC721.into());

    let coll_id = 2;
    let argent_nft = ERC721ABIDispatcher { contract_address: ARGENT_NFT() };
    let original_owner = argent_nft.owner_of(coll_id);

    start_cheat_caller_address(ARGENT_NFT(), original_owner);
    argent_nft.transfer_from(original_owner, dsp.borrower.contract_address, coll_id);
    stop_cheat_caller_address(ARGENT_NFT());

    start_cheat_caller_address(ARGENT_NFT(), dsp.borrower.contract_address);
    argent_nft.set_approval_for_all(dsp.loan.contract_address, true);
    stop_cheat_caller_address(ARGENT_NFT());

    proposal.collateral_category = MultiToken::Category::ERC721;
    proposal.collateral_address = ARGENT_NFT();
    proposal.collateral_id = coll_id.try_into().unwrap();
    proposal.collateral_amount = 0;

    _create_loan(dsp, proposal);

    assert_eq!(argent_nft.owner_of(coll_id), dsp.loan.contract_address);
}

#[test]
#[fork("mainnet")]
#[ignore]
fn test_use_case_should_refinance_running_loan() {
    let (dsp, mut proposal) = setup();

    proposal.credit_amount = 10 * E18;
    proposal.fixed_interest_amount = 1 * E18;
    proposal.available_credit_limit = 20 * E18;
    proposal.duration = _1_DAY * 5;

    start_cheat_caller_address(dsp.proposal_simple.contract_address, dsp.lender.contract_address);
    dsp.proposal_simple.make_proposal(proposal);
    stop_cheat_caller_address(dsp.proposal_simple.contract_address);

    let proposal_data = dsp.proposal_simple.encode_proposal_data(proposal);

    let proposal_spec = ProposalSpec {
        proposal_contract: dsp.proposal_simple.contract_address,
        proposal_data,
        proposal_inclusion_proof: array![],
        signature: Default::default()
    };
    let lender_spec = LenderSpec { source_of_funds: dsp.lender.contract_address };
    let caller_spec: CallerSpec = Default::default();

    start_cheat_caller_address(dsp.loan.contract_address, dsp.borrower.contract_address);
    let loan_id = dsp
        .loan
        .create_loan(proposal_spec.clone(), lender_spec, caller_spec, Option::None);
    stop_cheat_caller_address(dsp.loan.contract_address);

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 90 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 100 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 10 * E18);

    start_cheat_block_timestamp_global(starknet::get_block_timestamp() + _1_DAY * 4);

    let caller_spec = CallerSpec {
        refinancing_loan_id: loan_id, revoke_nonce: false, nonce: 0, permit_data: 0
    };

    start_cheat_caller_address(dsp.loan.contract_address, dsp.borrower.contract_address);
    dsp.loan.create_loan(proposal_spec, lender_spec, caller_spec, Option::None);

    assert_eq!(dsp.credit.balance_of(dsp.lender.contract_address), 91 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.borrower.contract_address), 99 * E18);
    assert_eq!(dsp.credit.balance_of(dsp.loan.contract_address), 10 * E18);
}
