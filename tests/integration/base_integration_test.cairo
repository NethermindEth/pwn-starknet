use core::result::ResultTrait;
use core::traits::Into;
use openzeppelin::account::interface::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
use openzeppelin::token::{
    erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait}
};
use pwn::config::interface::IPwnConfigDispatcher;
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::{
    interface::{IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait},
    types::{LenderSpec, ProposalSpec, CallerSpec}
};
use pwn::loan::terms::simple::proposal::simple_loan_simple_proposal::{
    SimpleLoanSimpleProposal::Proposal, ISimpleLoanSimpleProposalDispatcher,
    ISimpleLoanSimpleProposalDispatcherTrait
};
use pwn::loan::token::pwn_loan::IPwnLoanDispatcher;
use pwn::mocks::{erc20::ERC20Mock, erc721::ERC721Mock, erc1155::ERC1155Mock};
use pwn::multitoken::{
    library::MultiToken,
    category_registry::{
        IMultitokenCategoryRegistryDispatcher, IMultitokenCategoryRegistryDispatcherTrait
    }
};
use pwn::nonce::revoked_nonce::IRevokedNonceDispatcher;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl
};
use snforge_std::signature::{KeyPairTrait, KeyPair};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address_global, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    cheat_block_timestamp_global, stop_cheat_caller_address
};
use starknet::ContractAddress;

pub const E18: u256 = 1_000_000_000_000_000_000;
pub const _7_DAYS: u64 = 60 * 60 * 24 * 7;

pub fn lender() -> ContractAddress {
    starknet::contract_address_const::<'lenderPK'>()
}
// pub fn borrower() -> ContractAddress {
//     starknet::contract_address_const::<'borrowerPK'>()
// }
pub fn protocol_timelock() -> ContractAddress {
    starknet::contract_address_const::<'protocolTimeLock'>()
}

#[derive(Copy, Drop)]
pub struct Setup {
    pub hub: IPwnHubDispatcher,
    pub config: IPwnConfigDispatcher,
    pub nonce: IRevokedNonceDispatcher,
    pub registry: IMultitokenCategoryRegistryDispatcher,
    pub proposal: ISimpleLoanSimpleProposalDispatcher,
    pub loan_token: IPwnLoanDispatcher,
    pub loan: IPwnSimpleLoanDispatcher,
    pub t20: ERC20ABIDispatcher,
    pub t721: ERC721ABIDispatcher,
    pub t1155: ERC1155ABIDispatcher,
    pub credit: ERC20ABIDispatcher,
    pub simple_proposal: Proposal,
    pub borrower: IPublicKeyDispatcher,
    pub key_pair: KeyPair<felt252, felt252>
}

pub fn setup() -> Setup {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();
    let hub = IPwnHubDispatcher { contract_address: hub_address };
    println!("hub_address: {:?}", hub_address);

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();
    let config = IPwnConfigDispatcher { contract_address: config_address };
    println!("config_address: {:?}", config_address);

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();
    let nonce = IRevokedNonceDispatcher { contract_address: nonce_address };
    println!("nonce_address: {:?}", nonce_address);

    let contract = declare("SimpleLoanSimpleProposal").unwrap();
    let (proposal_address, _) = contract
        .deploy(
            @array![
                hub_address.into(), nonce_address.into(), config_address.into(), 'name', 'version'
            ]
        )
        .unwrap();
    let proposal = ISimpleLoanSimpleProposalDispatcher { contract_address: proposal_address };
    println!("proposal_address: {:?}", proposal_address);

    let contract = declare("PwnLoan").unwrap();
    let (loan_token_address, _) = contract.deploy(@array![hub_address.into()]).unwrap();
    let loan_token = IPwnLoanDispatcher { contract_address: loan_token_address };
    println!("loan_token_address: {:?}", loan_token_address);

    let contract = declare("MultiTokenCategoryRegistry").unwrap();
    let (registry_address, _) = contract.deploy(@array![]).unwrap();
    let registry = IMultitokenCategoryRegistryDispatcher { contract_address: registry_address };
    println!("registry_address: {:?}", registry_address);

    let contract = declare("PwnSimpleLoan").unwrap();
    let (loan_address, _) = contract
        .deploy(
            @array![
                hub_address.into(),
                loan_token_address.into(),
                config_address.into(),
                nonce_address.into(),
                registry_address.into()
            ]
        )
        .unwrap();
    let loan = IPwnSimpleLoanDispatcher { contract_address: loan_address };
    println!("loan_address: {:?}", loan_address);

    let erc20_contract = declare("ERC20Mock").unwrap();
    let (t20_address, _) = erc20_contract.deploy(@array![]).unwrap();
    let t20 = ERC20ABIDispatcher { contract_address: t20_address };
    registry.register_category_value(t20_address, MultiToken::Category::ERC20.into());
    println!("t20_address: {:?}", t20_address);

    let erc721_contract = declare("ERC721Mock").unwrap();
    let (t721_address, _) = erc721_contract.deploy(@array![]).unwrap();
    let t721 = ERC721ABIDispatcher { contract_address: t721_address };
    registry.register_category_value(t721_address, MultiToken::Category::ERC721.into());
    println!("t721_address: {:?}", t721_address);

    let erc1155_contract = declare("ERC1155Mock").unwrap();
    let (t1155_address, _) = erc1155_contract.deploy(@array![]).unwrap();
    let t1155 = ERC1155ABIDispatcher { contract_address: t1155_address };
    registry.register_category_value(t1155_address, MultiToken::Category::ERC1155.into());
    println!("t1155_address: {:?}", t1155_address);

    let (credit_address, _) = erc20_contract.deploy(@array![]).unwrap();
    let credit = ERC20ABIDispatcher { contract_address: credit_address };
    registry.register_category_value(credit_address, MultiToken::Category::ERC20.into());
    println!("credit_address: {:?}", credit_address);

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();

    let contract = declare("AccountUpgradeable").unwrap();
    let (account_address, _) = contract.deploy(@array![key_pair.public_key]).unwrap();
    let borrower = IPublicKeyDispatcher { contract_address: account_address };

    hub.set_tag(proposal_address, pwn_hub_tags::LOAN_PROPOSAL, true);
    hub.set_tag(proposal_address, pwn_hub_tags::ACTIVE_LOAN, true);
    hub.set_tag(loan_address, pwn_hub_tags::ACTIVE_LOAN, true);

    let simple_proposal = Proposal {
        collateral_category: MultiToken::Category::ERC1155,
        collateral_address: t1155_address,
        collateral_id: 42,
        collateral_amount: 10 * E18,
        check_collateral_state_fingerprint: false,
        collateral_state_fingerprint: 0,
        credit_address: credit_address,
        credit_amount: 100 * E18,
        available_credit_limit: 0,
        fixed_interest_amount: 10 * E18,
        accruing_interest_APR: 0,
        duration: 3000,
        expiration: starknet::get_block_timestamp() + _7_DAYS,
        allowed_acceptor: borrower.contract_address,
        proposer: lender(),
        proposer_spec_hash: loan.get_lender_spec_hash(LenderSpec { source_of_funds: lender() }),
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 0,
        nonce: 0,
        loan_contract: loan_address,
    };

    Setup {
        hub,
        config,
        nonce,
        registry,
        proposal,
        loan_token,
        loan,
        t20,
        t721,
        t1155,
        credit,
        simple_proposal,
        borrower,
        key_pair
    }
}

pub(crate) fn _sign(digest: felt252, key_pair: KeyPair<felt252, felt252>) -> Signature {
    let (r, s): (felt252, felt252) = key_pair.sign(digest).unwrap();
    Signature { r, s }
}

pub(crate) fn _create_erc20_loan(setup: Setup) -> felt252 {
    let mut simple_proposal = setup.simple_proposal;
    simple_proposal.collateral_category = MultiToken::Category::ERC20;
    simple_proposal.collateral_address = setup.t20.contract_address;
    simple_proposal.collateral_id = 0;
    simple_proposal.collateral_amount = 10 * E18;

    erc20_mint(setup.t20.contract_address, setup.borrower.contract_address, 10 * E18);

    start_cheat_caller_address(setup.t20.contract_address, setup.borrower.contract_address);
    setup.t20.approve(setup.loan.contract_address, E18);
    stop_cheat_caller_address(setup.t20.contract_address);

    _create_loan(setup, simple_proposal, '')
}

pub(crate) fn _create_erc721_loan(setup: Setup) -> felt252 {
    let mut simple_proposal = setup.simple_proposal;
    simple_proposal.collateral_category = MultiToken::Category::ERC721;
    simple_proposal.collateral_address = setup.t721.contract_address;
    simple_proposal.collateral_id = 42;
    simple_proposal.collateral_amount = 0;

    erc721_mint(setup.t721.contract_address, setup.borrower.contract_address, 42);

    start_cheat_caller_address(setup.t721.contract_address, setup.borrower.contract_address);
    setup.t721.approve(setup.loan.contract_address, 42);
    stop_cheat_caller_address(setup.t721.contract_address);

    _create_loan(setup, simple_proposal, '')
}

pub(crate) fn _create_erc1155_loan(setup: Setup) -> felt252 {
    _create_erc1155_loan_failing(setup, '')
}

pub(crate) fn _create_erc1155_loan_failing(setup: Setup, revert_data: felt252) -> felt252 {
    let mut simple_proposal = setup.simple_proposal;
    simple_proposal.collateral_category = MultiToken::Category::ERC1155;
    simple_proposal.collateral_address = setup.t1155.contract_address;
    simple_proposal.collateral_id = 42;
    simple_proposal.collateral_amount = 10 * E18;

    erc1155_mint(setup.t1155.contract_address, setup.borrower.contract_address, 42, 10 * E18);

    start_cheat_caller_address(setup.t1155.contract_address, setup.borrower.contract_address);
    setup.t1155.set_approval_for_all(setup.loan.contract_address, true);
    stop_cheat_caller_address(setup.t1155.contract_address);

    _create_loan(setup, simple_proposal, revert_data)
}

pub(crate) fn _create_loan(setup: Setup, _proposal: Proposal, revert_data: felt252) -> felt252 {
    let signature = _sign(setup.proposal.get_proposal_hash(_proposal), setup.key_pair);

    erc20_mint(setup.credit.contract_address, lender(), 100 * E18);

    start_cheat_caller_address(setup.credit.contract_address, lender());
    setup.credit.approve(setup.loan_token.contract_address, 100 * E18);
    stop_cheat_caller_address(setup.credit.contract_address);

    if revert_data != '' {
        panic!("{}", revert_data);
    }

    let proposal_data = setup.proposal.encode_proposal_data(_proposal);
    let proposal_spec = ProposalSpec {
        proposal_contract: setup.proposal.contract_address,
        proposal_data,
        proposal_inclusion_proof: array![],
        signature
    };
    let lender_spec = LenderSpec { source_of_funds: lender() };
    let caller_spec = CallerSpec {
        refinancing_loan_id: 0, revoke_nonce: false, nonce: 0, permit_data: 0
    };

    start_cheat_caller_address(setup.loan.contract_address, setup.borrower.contract_address);
    let loan_id = setup.loan.create_loan(proposal_spec, lender_spec, caller_spec, Option::None);
    stop_cheat_caller_address(setup.loan.contract_address);

    loan_id
}

pub(crate) fn _repay_loan(setup: Setup, loan_id: felt252,) {
    _repay_loan_failing(setup, loan_id, '')
}

pub(crate) fn _repay_loan_failing(setup: Setup, loan_id: felt252, revert_data: felt252) {
    erc20_mint(setup.credit.contract_address, setup.borrower.contract_address, 10 * E18);

    start_cheat_caller_address(setup.credit.contract_address, setup.borrower.contract_address);
    setup.credit.approve(setup.loan_token.contract_address, 10 * E18);
    stop_cheat_caller_address(setup.credit.contract_address);

    if revert_data != '' {
        panic!("{}", revert_data);
    }

    start_cheat_caller_address(setup.loan.contract_address, setup.borrower.contract_address);
    setup.loan.repay_loan(loan_id, '');
    stop_cheat_caller_address(setup.loan.contract_address);
}

fn erc20_mint(erc20: ContractAddress, receiver: ContractAddress, amount: u256) {
    store(
        erc20,
        map_entry_address(selector!("ERC20_total_supply"), array![].span(),),
        array![amount.try_into().unwrap()].span()
    );
    store(
        erc20,
        map_entry_address(selector!("ERC20_balances"), array![receiver.into()].span(),),
        array![amount.try_into().unwrap()].span()
    );
}

fn erc721_mint(erc721: ContractAddress, receiver: ContractAddress, id: u256) {
    store(
        erc721,
        map_entry_address(selector!("ERC721_owners"), array![id.try_into().unwrap()].span(),),
        array![receiver.into()].span()
    );
    store(
        erc721,
        map_entry_address(selector!("ERC721_balances"), array![receiver.into()].span(),),
        array![1.try_into().unwrap()].span()
    );
}


fn erc1155_mint(erc1155: ContractAddress, receiver: ContractAddress, id: u256, amount: u256) {
    let mut serialized: Array<felt252> = array![];
    id.serialize(ref serialized);
    receiver.serialize(ref serialized);

    store(
        erc1155,
        map_entry_address(selector!("ERC1155_balances"), serialized.span(),),
        array![amount.try_into().unwrap()].span()
    );
}
