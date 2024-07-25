use core::hash::LegacyHash;
use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::result::ResultTrait;
use core::serde::Serde;
use core::traits::Into;
use openzeppelin::token::{
    erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait},
};
use pwn::loan::terms::simple::loan::{
    interface::{
        IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait, IPwnSimpleLoanSafeDispatcher,
        IPwnSimpleLoanSafeDispatcherTrait
    },
    pwn_simple_loan::PwnSimpleLoan::{
        MIN_LOAN_DURATION, MAX_ACCRUING_INTEREST_APR, MAX_EXTENSION_DURATION, MIN_EXTENSION_DURATION
    },
    types,
};

use pwn::loan::{
    lib::{signature_checker, math,}, vault::permit,
    token::pwn_loan::{IPwnLoanDispatcher, IPwnLoanDispatcherTrait},
};
use pwn::{
    nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait},
    multitoken::{
        library::MultiToken,
        category_registry::{
            IMultiTokenCategoryRegistryDispatcher, IMultiTokenCategoryRegistryDispatcherTrait
        }
    },
    hub::pwn_hub_tags,
    interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait},
    hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait}
};
use snforge_std::{
    declare, store, load, map_entry_address, cheat_caller_address, cheat_block_timestamp_global,
    mock_call, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    signature::{
        KeyPairTrait, SignerTrait,
        stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
    },
    ContractClassTrait, CheatSpan
};
use starknet::ContractAddress;

impl U8IntoCategory of Into<u8, MultiToken::Category> {
    fn into(self: u8) -> MultiToken::Category {
        match self {
            0 => MultiToken::Category::ERC20,
            1 => MultiToken::Category::ERC721,
            2 => MultiToken::Category::ERC1155,
            _ => panic!("Invalid Category {}", self)
        }
    }
}
pub fn HUB() -> ContractAddress {
    starknet::contract_address_const::<'hub'>()
}

pub fn CONFIG() -> ContractAddress {
    starknet::contract_address_const::<'config'>()
}

pub fn LOAN_TOKEN() -> ContractAddress {
    starknet::contract_address_const::<'loanToken'>()
}

pub fn REVOKED_NONCE() -> ContractAddress {
    starknet::contract_address_const::<'revokedNonce'>()
}

pub fn CATEGORY_REGISTRY() -> ContractAddress {
    starknet::contract_address_const::<'categoryRegistry'>()
}

pub fn FEE_COLLECTOR() -> ContractAddress {
    starknet::contract_address_const::<'feeCollector'>()
}

pub fn ALICE() -> ContractAddress {
    starknet::contract_address_const::<'alice'>()
}

pub fn PROPOSAL_CONTRACT() -> ContractAddress {
    starknet::contract_address_const::<'proposalContract'>()
}

pub fn LENDER() -> ContractAddress {
    starknet::contract_address_const::<'lender'>()
}

pub fn BORROWER() -> ContractAddress {
    starknet::contract_address_const::<'borrower'>()
}

pub fn SOURCE_OF_FUNDS() -> ContractAddress {
    starknet::contract_address_const::<'sourceOfFunds'>()
}

pub fn SIMPLE_LOAN_ADDRESS() -> ContractAddress {
    starknet::contract_address_const::<'simpleLoanAddress'>()
}

pub fn ERC20_MOCK_ADDRESS() -> ContractAddress {
    starknet::contract_address_const::<'erc20Mock'>()
}

pub fn ERC721_MOCK_ADDRESS() -> ContractAddress {
    starknet::contract_address_const::<'erc721Mock'>()
}

pub fn ERC1155_MOCK_ADDRESS() -> ContractAddress {
    starknet::contract_address_const::<'erc1155Mock'>()
}

pub fn POOL_ADAPTER_MOCK_ADDRESS() -> ContractAddress {
    starknet::contract_address_const::<'poolAdapterMock'>()
}

pub fn LOAN_ID() -> felt252 {
    42
}

pub fn LOAN_DURATION_DAYS() -> u64 {
    101
}

pub const E30: u256 = 1_000_000_000_000_000_000_000_000_000_000;
pub const E20: u256 = 100_000_000_000_000_000_000;
pub const E18: u256 = 1_000_000_000_000_000_000;
pub const DAY: u64 = 86400;

pub fn SIMPLE_LOAN() -> types::Loan {
    types::Loan {
        status: 2_u8,
        credit_address: ERC20_MOCK_ADDRESS(),
        original_source_of_funds: LENDER(),
        start_timestamp: starknet::get_block_timestamp(),
        default_timestamp: starknet::get_block_timestamp() + LOAN_DURATION_DAYS() * DAY,
        borrower: BORROWER(),
        original_lender: LENDER(),
        accruing_interest_APR: 0,
        fixed_interest_amount: 6631,
        principal_amount: 100,
        collateral: MultiToken::Asset {
            category: MultiToken::Category::ERC721,
            asset_address: ERC721_MOCK_ADDRESS(),
            id: 2,
            amount: 0
        },
    }
}

pub fn SIMPLE_LOAN_TERMS() -> types::Terms {
    types::Terms {
        lender: LENDER(),
        borrower: BORROWER(),
        duration: LOAN_DURATION_DAYS() * DAY,
        collateral: MultiToken::Asset {
            category: MultiToken::Category::ERC721,
            asset_address: ERC721_MOCK_ADDRESS(),
            id: 2,
            amount: 0
        },
        credit: MultiToken::Asset {
            category: MultiToken::Category::ERC20,
            asset_address: ERC20_MOCK_ADDRESS(),
            id: 0,
            amount: 100
        },
        fixed_interest_amount: 6631,
        accruing_interest_APR: 0,
        lender_spec_hash: poseidon_hash_span(
            array![Into::<ContractAddress, felt252>::into(LENDER())].span()
        ),
        borrower_spec_hash: 0
    }
}

pub fn PROPOSAL_SPEC() -> types::ProposalSpec {
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s) = key_pair.sign(poseidon_hash_span(array!['proposalHash'].span())).unwrap();
    types::ProposalSpec {
        proposal_contract: PROPOSAL_CONTRACT(),
        proposal_data: array!['proposalData'],
        proposal_inclusion_proof: array![],
        signature: signature_checker::Signature { r, s }
    }
}

pub fn PROPOSAL_HASH() -> felt252 {
    'porposalHash'
}

pub fn LENDER_SPEC() -> types::LenderSpec {
    types::LenderSpec { source_of_funds: LENDER() }
}

pub fn NON_EXISTING_LOAN() -> types::Loan {
    types::Loan {
        status: 0,
        credit_address: starknet::contract_address_const::<0>(),
        original_source_of_funds: starknet::contract_address_const::<0>(),
        start_timestamp: 0,
        default_timestamp: 0,
        borrower: starknet::contract_address_const::<0>(),
        original_lender: starknet::contract_address_const::<0>(),
        accruing_interest_APR: 0,
        fixed_interest_amount: 0,
        principal_amount: 0,
        collateral: MultiToken::Asset {
            category: MultiToken::Category::ERC20,
            asset_address: starknet::contract_address_const::<0>(),
            id: 0,
            amount: 0
        },
    }
}

pub fn EXTENSION() -> types::ExtensionProposal {
    types::ExtensionProposal {
        loan_id: LOAN_ID(),
        compensation_address: ERC20_MOCK_ADDRESS(),
        compensation_amount: 100,
        duration: 2 * DAY,
        expiration: SIMPLE_LOAN().default_timestamp,
        proposer: BORROWER(),
        nonce_space: 1,
        nonce: 1,
    }
}

pub fn mint_erc20(token: ContractAddress, receiver: ContractAddress, amount: u256) {
    let mut serialized_u256: Array<felt252> = array![];
    amount.serialize(ref serialized_u256);
    store(
        token,
        map_entry_address(selector!("ERC20_balances"), array![receiver.into()].span()),
        serialized_u256.span()
    );
}

pub fn mint_erc721(token: ContractAddress, receiver: ContractAddress, id: u256, balance: u256) {
    let mut serialized_balance: Array<felt252> = array![];
    balance.serialize(ref serialized_balance);
    store(
        token,
        map_entry_address(selector!("ERC721_balances"), array![receiver.into()].span()),
        serialized_balance.span()
    );

    let mut serialized_id: Array<felt252> = array![];
    id.serialize(ref serialized_id);
    store(
        token,
        map_entry_address(selector!("ERC721_owners"), serialized_id.span()),
        array![receiver.into()].span()
    );
}

pub fn deploy() -> (
    IPwnSimpleLoanDispatcher,
    ERC20ABIDispatcher,
    ERC721ABIDispatcher,
    ERC1155ABIDispatcher,
    IPoolAdapterDispatcher,
    IRevokedNonceDispatcher,
    IPwnHubDispatcher,
    IPwnLoanDispatcher
) {
    let contract = declare("PwnLoan").unwrap();
    let (loan_token_address, _) = contract.deploy_at(@array![HUB().into()], LOAN_TOKEN()).unwrap();

    let contract = declare("PwnSimpleLoan").unwrap();
    let (loan_address, _) = contract
        .deploy_at(
            @array![
                HUB().into(),
                loan_token_address.into(),
                CONFIG().into(),
                REVOKED_NONCE().into(),
                CATEGORY_REGISTRY().into()
            ],
            SIMPLE_LOAN_ADDRESS()
        )
        .unwrap();

    let contract = declare("ERC20Mock").unwrap();
    let (erc20_mock_address, _) = contract.deploy_at(@array![], ERC20_MOCK_ADDRESS()).unwrap();

    let contract = declare("ERC721Mock").unwrap();
    let (erc721_mock_address, _) = contract.deploy_at(@array![], ERC721_MOCK_ADDRESS()).unwrap();

    let contract = declare("ERC1155Mock").unwrap();
    let (erc1155_mock_address, _) = contract.deploy_at(@array![], ERC1155_MOCK_ADDRESS()).unwrap();

    let contract = declare("MockPoolAdapter").unwrap();
    let (pool_adapter_mock_address, _) = contract
        .deploy_at(@array![], POOL_ADAPTER_MOCK_ADDRESS())
        .unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy_at(@array![HUB().into(), pwn_hub_tags::ACTIVE_LOAN], REVOKED_NONCE())
        .unwrap();

    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy_at(@array![], HUB()).unwrap();

    let contract = declare("MultiTokenCategoryRegistry").unwrap();
    let (category_registry_address, _) = contract
        .deploy_at(@array![], CATEGORY_REGISTRY())
        .unwrap();

    let erc20_mock = ERC20ABIDispatcher { contract_address: erc20_mock_address };
    let erc721_mock = ERC721ABIDispatcher { contract_address: erc721_mock_address };
    let erc1155_mock = ERC1155ABIDispatcher { contract_address: erc1155_mock_address };
    let pool_adapter = IPoolAdapterDispatcher { contract_address: pool_adapter_mock_address };
    let nonces = IRevokedNonceDispatcher { contract_address: nonce_address };
    let mut hub = IPwnHubDispatcher { contract_address: hub_address };
    let mut category_registry = IMultiTokenCategoryRegistryDispatcher {
        contract_address: category_registry_address
    };
    category_registry
        .register_category_value(erc20_mock_address, MultiToken::Category::ERC20.into());
    category_registry
        .register_category_value(erc721_mock_address, MultiToken::Category::ERC721.into());
    category_registry
        .register_category_value(erc1155_mock_address, MultiToken::Category::ERC1155.into());

    hub.set_tag(PROPOSAL_CONTRACT(), pwn_hub_tags::LOAN_PROPOSAL, true);
    hub.set_tag(loan_address, pwn_hub_tags::ACTIVE_LOAN, true);

    mint_erc20(erc20_mock_address, LENDER(), 6831);
    mint_erc20(erc20_mock_address, BORROWER(), 6831);
    mint_erc20(erc20_mock_address, starknet::get_contract_address(), 6831);
    mint_erc20(erc20_mock_address, SIMPLE_LOAN_ADDRESS(), 6831);
    mint_erc20(erc20_mock_address, SOURCE_OF_FUNDS(), E30);

    mint_erc721(erc721_mock_address, BORROWER(), 2, 1);

    cheat_caller_address(erc20_mock_address, LENDER(), CheatSpan::TargetCalls(1));
    erc20_mock.approve(loan_address, BoundedInt::max());

    cheat_caller_address(erc20_mock_address, BORROWER(), CheatSpan::TargetCalls(1));
    erc20_mock.approve(loan_address, BoundedInt::max());

    cheat_caller_address(erc20_mock_address, SOURCE_OF_FUNDS(), CheatSpan::TargetCalls(1));
    erc20_mock.approve(pool_adapter_mock_address, BoundedInt::max());

    erc20_mock.approve(loan_address, BoundedInt::max());

    cheat_caller_address(erc721_mock_address, BORROWER(), CheatSpan::TargetCalls(1));
    erc721_mock.approve(loan_address, 2);

    mock_call(erc20_mock_address, selector!("permit"), (), BoundedInt::<u32>::max());

    mock_call(CONFIG(), selector!("get_fee"), 0, BoundedInt::<u32>::max());
    mock_call(CONFIG(), selector!("get_fee_collector"), FEE_COLLECTOR(), BoundedInt::<u32>::max());
    mock_call(CONFIG(), selector!("get_pool_adapter"), pool_adapter, BoundedInt::<u32>::max());

    mock_call(
        PROPOSAL_CONTRACT(),
        selector!("accept_proposal"),
        (PROPOSAL_HASH(), SIMPLE_LOAN_TERMS()),
        BoundedInt::<u32>::max()
    );

    (
        IPwnSimpleLoanDispatcher { contract_address: loan_address },
        erc20_mock,
        erc721_mock,
        erc1155_mock,
        pool_adapter,
        nonces,
        hub,
        IPwnLoanDispatcher { contract_address: loan_token_address }
    )
}

pub fn print_all_addresses() {
    println!("Proposal contract: {:?}", PROPOSAL_CONTRACT());
    println!("Loan token contract: {:?}", LOAN_TOKEN());
    println!("SimpleLoan contract: {:?}", SIMPLE_LOAN_ADDRESS());
    println!("ERC20 contract: {:?}", ERC20_MOCK_ADDRESS());
    println!("ERC721 contract: {:?}", ERC721_MOCK_ADDRESS());
    println!("ERC1155 contract: {:?}", ERC1155_MOCK_ADDRESS());
    println!("HUB contract: {:?}", HUB());
    println!("CONFIG contract: {:?}", CONFIG());
    println!("CategoryRegistry contract: {:?}", CATEGORY_REGISTRY());
    println!("POOL_ADAPTER_MOCK_ADDRESS contract: {:?}", POOL_ADAPTER_MOCK_ADDRESS());
    println!("Nonce contract: {:?}", REVOKED_NONCE());
    println!("BORROWER {:?}", BORROWER());
    println!("LENDER {:?}", LENDER());
    println!("SOURCE_OF_FUNDS {:?}", SOURCE_OF_FUNDS());
    println!("ALICE {:?}", ALICE());
    println!("FEE_COLLECTOR {:?}", FEE_COLLECTOR());
}

pub fn store_loan(address: ContractAddress, loan_id: felt252, loan: types::Loan) {
    let mut serialized_loan: Array<felt252> = array![];
    loan.serialize(ref serialized_loan);
    store(
        address,
        map_entry_address(selector!("loans"), array![loan_id].span()),
        serialized_loan.span()
    );
}

fn assert_loan_eq(address: ContractAddress, loan_id: felt252, loan: types::Loan) {
    let stored_loan_raw = load(
        address, map_entry_address(selector!("loans"), array![loan_id].span()), 17
    );

    assert_eq!(TryInto::<felt252, u8>::try_into(*stored_loan_raw.at(0)).unwrap(), loan.status);
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(1)).unwrap(),
        loan.credit_address
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(2)).unwrap(),
        loan.original_source_of_funds
    );
    assert_eq!(
        TryInto::<felt252, u64>::try_into(*stored_loan_raw.at(3)).unwrap(), loan.start_timestamp
    );
    assert_eq!(
        TryInto::<felt252, u64>::try_into(*stored_loan_raw.at(4)).unwrap(), loan.default_timestamp
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(5)).unwrap(),
        loan.borrower
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(6)).unwrap(),
        loan.original_lender
    );
    assert_eq!(
        TryInto::<felt252, u32>::try_into(*stored_loan_raw.at(7)).unwrap(),
        loan.accruing_interest_APR
    );
    assert_eq!(
        u256 {
            low: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(8)).unwrap(),
            high: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(9)).unwrap()
        },
        loan.fixed_interest_amount
    );
    assert_eq!(
        u256 {
            low: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(10)).unwrap(),
            high: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(11)).unwrap()
        },
        loan.principal_amount
    );
    assert_eq!(
        TryInto::<felt252, u8>::try_into(*stored_loan_raw.at(12)).unwrap(),
        loan.collateral.category.into()
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(13)).unwrap(),
        loan.collateral.asset_address
    );
    assert_eq!(*stored_loan_raw.at(14), loan.collateral.id);
    assert_eq!(
        u256 {
            low: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(15)).unwrap(),
            high: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(16)).unwrap()
        },
        loan.collateral.amount
    );
}

mod get_lender_spec_hash {
    use core::traits::Into;
    use pwn::loan::terms::simple::loan::interface::IPwnSimpleLoanDispatcherTrait;
    use super::{poseidon_hash_span, deploy, LENDER_SPEC, ContractAddress};

    #[test]
    fn test_should_return_lender_spec_hash() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        let expected = poseidon_hash_span(
            array![Into::<ContractAddress, felt252>::into(LENDER_SPEC().source_of_funds)].span()
        );
        let actual = loan.get_lender_spec_hash(LENDER_SPEC());
        assert_eq!(expected, actual, "LENDER_SPEC_HASH does not match");
    }
}

mod create_loan {
    use core::array::ArrayTrait;
    use core::clone::Clone;
    use core::num::traits::zero::Zero;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use core::traits::Into;
    use core::traits::TryInto;
    use pwn::loan::lib::fee_calculator;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use pwn::loan::vault::permit::{Permit};
    use snforge_std::trace::get_call_trace;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        deploy, IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait, IRevokedNonceDispatcher,
        IRevokedNonceDispatcherTrait, IPwnHubDispatcherTrait, ERC721ABIDispatcher,
        ERC721ABIDispatcherTrait, ERC20ABIDispatcher, ERC20ABIDispatcherTrait, SIMPLE_LOAN_ADDRESS,
        PROPOSAL_CONTRACT, PROPOSAL_SPEC, LENDER_SPEC, ContractAddress, MultiToken,
        types::{CallerSpec, LenderSpec, ProposalSpec}, cheat_caller_address, CheatSpan,
        pwn_hub_tags, print_all_addresses, SIMPLE_LOAN_TERMS, mock_call, PROPOSAL_HASH, LENDER,
        CATEGORY_REGISTRY, MIN_LOAN_DURATION, MAX_ACCRUING_INTEREST_APR, load, store,
        map_entry_address, types, SIMPLE_LOAN, BORROWER, ERC20_MOCK_ADDRESS, SOURCE_OF_FUNDS,
        CONFIG, FEE_COLLECTOR, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
        mint_erc20, assert_loan_eq
    };

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_proposal_contract_not_tagged_loan_proposal(
        _proposal_contract: u128
    ) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        let mut proposal_contract: ContractAddress = Into::<u128, felt252>::into(_proposal_contract)
            .try_into()
            .unwrap();
        if proposal_contract == PROPOSAL_CONTRACT() {
            proposal_contract = Into::<u128, felt252>::into(_proposal_contract + 1)
                .try_into()
                .unwrap();
        }
        let mut proposal_spec = PROPOSAL_SPEC();
        proposal_spec.proposal_contract = proposal_contract;
        loan.create_loan(proposal_spec, LENDER_SPEC(), Default::default(), Option::Some(array![]));
    }

    #[test]
    fn test_fuzz_should_revoke_callers_nonce_when_flag_is_true(_caller: u128, nonce: felt252) {
        let (mut loan, _, _, _, _, nonces, _, _) = deploy();
        let caller: ContractAddress = Into::<u128, felt252>::into(_caller).try_into().unwrap();
        let mut caller_spec: CallerSpec = Default::default();
        caller_spec.revoke_nonce = true;
        caller_spec.nonce = nonce;

        assert!(nonces.is_nonce_usable(caller, 0, nonce), "Nonce {} is not usable", nonce);
        cheat_caller_address(loan.contract_address, caller, CheatSpan::TargetCalls(1));
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), caller_spec, Option::Some(array![]));
        assert!(!nonces.is_nonce_usable(caller, 0, nonce), "Nonce {} is usable", nonce);
    }


    #[test]
    fn test_fuzz_should_not_revoke_callers_nonce_when_flag_is_false(_caller: u128, nonce: felt252) {
        let (mut loan, _, _, _, _, nonces, _, _) = deploy();
        let caller: ContractAddress = Into::<u128, felt252>::into(_caller).try_into().unwrap();
        let mut caller_spec: CallerSpec = Default::default();
        caller_spec.nonce = nonce;

        assert!(nonces.is_nonce_usable(caller, 0, nonce), "Nonce {} is not usable", nonce);
        cheat_caller_address(loan.contract_address, caller, CheatSpan::TargetCalls(1));
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), caller_spec, Option::Some(array![]));
        assert!(nonces.is_nonce_usable(caller, 0, nonce), "Nonce {} is not usable", nonce);
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_call_proposal_contract() {
        assert(true, '');
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_caller_not_lender_when_lender_spec_hash_mismatch(
        mut _lender_spec_hash: felt252
    ) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        if _lender_spec_hash == loan.get_lender_spec_hash(LENDER_SPEC()) {
            _lender_spec_hash += 1;
        }
        let mut terms = SIMPLE_LOAN_TERMS();
        terms.lender_spec_hash = _lender_spec_hash;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
    }

    #[test]
    fn test_should_not_fail_when_caller_lender_when_lender_spec_hash_mismatch() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        let mut terms = SIMPLE_LOAN_TERMS();
        terms.lender_spec_hash = 0;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        cheat_caller_address(loan.contract_address, LENDER(), CheatSpan::TargetCalls(1));
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_loan_terms_duration_less_than_min(mut duration: u64) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        if duration >= MIN_LOAN_DURATION {
            duration %= duration % MIN_LOAN_DURATION;
        }

        let mut terms = SIMPLE_LOAN_TERMS();
        terms.duration = duration;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        cheat_caller_address(loan.contract_address, LENDER(), CheatSpan::TargetCalls(1));
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_loan_terms_interest_apr_out_of_bounds(
        mut accruing_interest_APR: u32
    ) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        if accruing_interest_APR < MAX_ACCRUING_INTEREST_APR {
            accruing_interest_APR += MAX_ACCRUING_INTEREST_APR + 1;
        }

        let mut terms = SIMPLE_LOAN_TERMS();
        terms.accruing_interest_APR = accruing_interest_APR;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        cheat_caller_address(loan.contract_address, LENDER(), CheatSpan::TargetCalls(1));
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_invalid_credit_asset() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        mock_call(
            PROPOSAL_CONTRACT(),
            selector!("accept_proposal"),
            (PROPOSAL_HASH(), SIMPLE_LOAN_TERMS()),
            1
        );

        mock_call(
            CATEGORY_REGISTRY(),
            selector!("registered_category_value"),
            Into::<MultiToken::Category, u8>::into(MultiToken::Category::ERC721),
            1
        );

        cheat_caller_address(loan.contract_address, LENDER(), CheatSpan::TargetCalls(1));
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_invalid_collateral_asset() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        mock_call(
            PROPOSAL_CONTRACT(),
            selector!("accept_proposal"),
            (PROPOSAL_HASH(), SIMPLE_LOAN_TERMS()),
            1
        );
        mock_call(
            CATEGORY_REGISTRY(),
            selector!("registered_category_value"),
            Into::<MultiToken::Category, u8>::into(MultiToken::Category::ERC20),
            2
        );
        cheat_caller_address(loan.contract_address, LENDER(), CheatSpan::TargetCalls(1));
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
    }

    #[test]
    fn test_should_mint_loan_token() {
        let (mut loan, _, _, _, _, _, _, loan_token) = deploy();
        let loan_token = ERC721ABIDispatcher { contract_address: loan_token.contract_address };
        let lender = LENDER();
        let prev_bal = loan_token.balance_of(lender);
        cheat_caller_address(loan.contract_address, lender, CheatSpan::TargetCalls(1));
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
        let curr_bal = loan_token.balance_of(LENDER());
        assert_lt!(prev_bal, curr_bal, "Loan token not minted!");
    }

    #[test]
    fn test_should_store_loan_data() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        let loan_id = loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
        assert_loan_eq(loan.contract_address, loan_id, SIMPLE_LOAN());
    }

    // #[test]
    // #[ignore]
    // fn test_fuzz_should_fail_when_invalid_permit_data_permit_owner(mut _permit_owner: felt252) {
    //     let (mut loan, _, _, _, _, _, _, _) = deploy();
    //     let mut permit_owner: ContractAddress = _permit_owner.try_into().unwrap();
    //     while permit_owner == BORROWER()
    //         || permit_owner == starknet::contract_address_const::<
    //             0
    //         >() {
    //             _permit_owner += 1;
    //             permit_owner = _permit_owner.try_into().unwrap();
    //         };
    // 
    //     let simple_loan = SIMPLE_LOAN();
    // 
    //     let permit = Permit {
    //         asset: simple_loan.credit_address,
    //         owner: permit_owner,
    //         amount: 0_u256,
    //         deadline: 0,
    //         r: 0,
    //         s: 0
    //     };
    // 
    //     let mut caller_spec: CallerSpec = Default::default();
    //     permit.serialize(ref caller_spec.permit_data);
    // 
    //     cheat_caller_address(loan.contract_address, BORROWER(), CheatSpan::TargetCalls(1));
    //     loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), caller_spec, Option::Some(array![]));
    // }

    //#[test]
    //#[should_panic]
    //fn test_fuzz_should_fail_when_invalid_permit_data_permit_asset(mut _permit_asset: u128) {
    //    let (mut loan, _, _, _, _, _, _, _) = deploy();
    //    let simple_loan = SIMPLE_LOAN();
    //    let mut _permit_asset: felt252 = _permit_asset.into();
    //    let mut permit_asset: ContractAddress = _permit_asset.try_into().unwrap();
    //    while permit_asset == simple_loan.credit_address
    //        || permit_asset == starknet::contract_address_const::<
    //            0
    //        >() {
    //            _permit_asset += 1;
    //            permit_asset = _permit_asset.try_into().unwrap();
    //        };
    //
    //    let permit = Permit {
    //        asset: permit_asset, owner: BORROWER(), amount: 0_u256, deadline: 0, r: 0, s: 0
    //    };
    //
    //    let mut caller_spec: CallerSpec = Default::default();
    //    permit.serialize(ref caller_spec.permit_data);
    //
    //    cheat_caller_address(loan.contract_address, BORROWER(), CheatSpan::TargetCalls(1));
    //    loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), caller_spec, Option::Some(array![]));
    //}

    #[test]
    #[ignore]
    fn test_should_call_permit_when_provided() {
        assert(true, '');
    }

    #[test]
    fn test_should_transfer_collateral_from_borrower_to_vault() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        let mut terms = SIMPLE_LOAN_TERMS();
        terms
            .collateral =
                MultiToken::Asset {
                    category: MultiToken::Category::ERC20,
                    asset_address: ERC20_MOCK_ADDRESS(),
                    id: 0,
                    amount: 50
                };

        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        let collateral = ERC20ABIDispatcher { contract_address: ERC20_MOCK_ADDRESS() };
        let borrower = BORROWER();
        let prev_bal_loan = collateral.balance_of(loan.contract_address);
        let prev_bal = collateral.balance_of(borrower);

        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );

        let curr_bal = collateral.balance_of(borrower);
        let curr_bal_loan = collateral.balance_of(loan.contract_address);
        assert_eq!(
            prev_bal_loan,
            curr_bal_loan - terms.collateral.amount,
            "Didn't transferred tokens to loan contract"
        );
        assert_eq!(
            prev_bal + terms.credit.amount - terms.collateral.amount,
            curr_bal,
            "Didn't transferred tokens from borrower"
        );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_pool_adapter_not_registered_when_pool_source_of_funds() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();

        let mut lender_spec = LENDER_SPEC();
        lender_spec.source_of_funds = SOURCE_OF_FUNDS();

        let mut terms = SIMPLE_LOAN_TERMS();
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(
            CONFIG(), selector!("get_pool_adapter"), starknet::contract_address_const::<0>(), 1
        );
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, Default::default(), Option::Some(array![]));
    }

    #[test]
    fn test_fuzz_should_call_withdraw_when_pool_source_of_funds(mut loan_amount: u256) {
        loan_amount %= E40;
        if loan_amount == 0 {
            loan_amount = 1;
        }

        let (mut loan, erc20, _, _, _, _, _, _) = deploy();

        let mut lender_spec = LENDER_SPEC();
        lender_spec.source_of_funds = SOURCE_OF_FUNDS();

        let mut terms = SIMPLE_LOAN_TERMS();
        terms.credit.amount = loan_amount;
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        let mut loan_amount_serialized: Array<felt252> = array![];
        loan_amount.serialize(ref loan_amount_serialized);
        store(
            erc20.contract_address,
            map_entry_address(selector!("ERC20_balances"), array![SOURCE_OF_FUNDS().into()].span()),
            loan_amount_serialized.span()
        );

        let prev_bal = erc20.balance_of(SOURCE_OF_FUNDS());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, Default::default(), Option::Some(array![]));
        let curr_bal = erc20.balance_of(SOURCE_OF_FUNDS());
        assert_eq!(
            prev_bal - loan_amount,
            curr_bal,
            "Pool havent called and transferred funds from source_of_funds"
        );
    }

    #[test]
    fn test_fuzz_should_transfer_credit_to_borrower_and_fee_collector(
        mut fee: u16, mut loan_amount: u256
    ) {
        fee %= 9999;
        loan_amount %= E40;
        if loan_amount == 0 {
            loan_amount += 1;
        }
        let (mut loan, erc20, _, _, _, _, _, _) = deploy();
        let mut terms = SIMPLE_LOAN_TERMS();
        terms.credit.amount = loan_amount;

        mint_erc20(erc20.contract_address, LENDER(), loan_amount);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(CONFIG(), selector!("get_fee"), fee, 1);
        let (fee_amount, loan_amount) = fee_calculator::calculate_fee_amount(fee, loan_amount);
        let prev_bal_borrower = erc20.balance_of(BORROWER());
        let prev_bal_lender = erc20.balance_of(LENDER());
        let prev_bal_fee_collector = erc20.balance_of(FEE_COLLECTOR());
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
        let curr_bal_borrower = erc20.balance_of(BORROWER());
        let curr_bal_lender = erc20.balance_of(LENDER());
        let curr_bal_fee_collector = erc20.balance_of(FEE_COLLECTOR());
        assert_eq!(prev_bal_borrower + loan_amount - terms.collateral.amount, curr_bal_borrower);
        assert_eq!(
            prev_bal_lender - loan_amount - fee_amount + terms.collateral.amount, curr_bal_lender
        );
        assert_eq!(prev_bal_fee_collector + fee_amount, curr_bal_fee_collector);
    }

    #[test]
    fn test_should_emit_loan_created() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        let caller_spec: CallerSpec = Default::default();
        let refinancing_loan_id = caller_spec.refinancing_loan_id;
        let lender_spec = LENDER_SPEC();
        let proposal_spec = PROPOSAL_SPEC();
        let proposal_contract = proposal_spec.proposal_contract;
        let mut spy = spy_events();
        let loan_id = loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        spy
            .assert_emitted(
                @array![
                    (
                        loan.contract_address,
                        PwnSimpleLoan::Event::LoanCreated(
                            PwnSimpleLoan::LoanCreated {
                                loan_id: loan_id,
                                proposal_hash: PROPOSAL_HASH(),
                                proposal_contract: proposal_contract,
                                refinancing_loan_id: refinancing_loan_id,
                                terms: SIMPLE_LOAN_TERMS(),
                                lender_spec: lender_spec,
                                extra: Option::Some(array!['lil extra']),
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_fuzz_should_return_new_loan_id(_loan_id: felt252) {
        let (mut loan, _, _, _, _, _, _, loan_token) = deploy();
        mock_call(loan_token.contract_address, selector!("mint"), _loan_id, 1);
        let loan_id = loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), Default::default(), Option::Some(array![])
            );
        assert_eq!(_loan_id, loan_id, "Loan ID mismatch!");
    }
}

mod refinance_loan {
    use core::traits::TryInto;
use core::traits::Into;
    use pwn::loan::lib::fee_calculator;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use super::{
        types, ERC20_MOCK_ADDRESS, ERC721_MOCK_ADDRESS, SIMPLE_LOAN_ADDRESS, LOAN_TOKEN,
        PROPOSAL_CONTRACT, PROPOSAL_HASH, PROPOSAL_SPEC, LENDER, LENDER_SPEC, BORROWER, MultiToken,
        mint_erc20, deploy, mint_erc721, poseidon_hash_span, cheat_caller_address, mock_call,
        CheatSpan, ERC20ABIDispatcher, ERC20ABIDispatcherTrait, ERC721ABIDispatcher,
        ERC721ABIDispatcherTrait, store_loan, cheat_block_timestamp_global, ERC1155ABIDispatcher,
        ERC1155ABIDispatcherTrait, IPwnSimpleLoanDispatcherTrait, IPwnLoanDispatcherTrait,
        ContractAddress, BoundedInt, SIMPLE_LOAN, SIMPLE_LOAN_TERMS, U8IntoCategory, spy_events,
        EventSpy, EventSpyTrait, EventSpyAssertionsTrait, map_entry_address, store,
        assert_loan_eq, SOURCE_OF_FUNDS, CONFIG, FEE_COLLECTOR, E20
    };


    pub fn REFINANCED_LOAN() -> types::Loan {
        types::Loan {
            status: 2,
            credit_address: ERC20_MOCK_ADDRESS(),
            original_source_of_funds: LENDER(),
            start_timestamp: starknet::get_block_timestamp(),
            default_timestamp: starknet::get_block_timestamp() + 40039,
            borrower: BORROWER(),
            original_lender: LENDER(),
            accruing_interest_APR: 0,
            fixed_interest_amount: 6631,
            principal_amount: E20,
            collateral: MultiToken::Asset {
                category: MultiToken::Category::ERC721,
                asset_address: ERC721_MOCK_ADDRESS(),
                id: 2,
                amount: 0
            },
        }
    }

    pub fn REFINANCED_LOAN_TERMS() -> types::Terms {
        types::Terms {
            lender: LENDER(),
            borrower: BORROWER(),
            duration: 40039,
            collateral: MultiToken::Asset {
                category: MultiToken::Category::ERC721,
                asset_address: ERC721_MOCK_ADDRESS(),
                id: 2,
                amount: 0
            },
            credit: MultiToken::Asset {
                category: MultiToken::Category::ERC20,
                asset_address: ERC20_MOCK_ADDRESS(),
                id: 0,
                amount: E20
            },
            fixed_interest_amount: 6631,
            accruing_interest_APR: 0,
            lender_spec_hash: poseidon_hash_span(array![LENDER().into()].span()),
            borrower_spec_hash: 0,
        }
    }

    pub fn NEW_LENDER() -> ContractAddress {
        starknet::contract_address_const::<'newLender'>()
    }

    pub fn CALLER_SPEC() -> types::CallerSpec {
        let mut spec: types::CallerSpec = Default::default();
        spec.refinancing_loan_id = REFINANCING_LOAN_ID;
        spec
    }

    fn setup() {
        let mut t721 = ERC721ABIDispatcher { contract_address: ERC721_MOCK_ADDRESS() };

        cheat_caller_address(t721.contract_address, BORROWER(), CheatSpan::TargetCalls(1));
        t721.transfer_from(BORROWER(), SIMPLE_LOAN_ADDRESS(), 2);

        let mut t20 = ERC20ABIDispatcher { contract_address: ERC20_MOCK_ADDRESS() };

        cheat_caller_address(t20.contract_address, NEW_LENDER(), CheatSpan::TargetCalls(1));
        t20.approve(SIMPLE_LOAN_ADDRESS(), BoundedInt::max());

        mock_call(
            PROPOSAL_CONTRACT(),
            selector!("accept_proposal"),
            (PROPOSAL_HASH(), REFINANCED_LOAN_TERMS()),
            1
        );
        mock_call(LOAN_TOKEN(), selector!("owner_of"), LENDER(), 1);

        mint_erc20(ERC20_MOCK_ADDRESS(), NEW_LENDER(), E20);
        mint_erc20(ERC20_MOCK_ADDRESS(), LENDER(), E20);
        mint_erc20(ERC20_MOCK_ADDRESS(), SIMPLE_LOAN_ADDRESS(), E20);
        store_loan(SIMPLE_LOAN_ADDRESS(), REFINANCING_LOAN_ID, SIMPLE_LOAN());

        mint_erc721(
            LOAN_TOKEN(),
            LENDER(),
            REFINANCING_LOAN_ID.into(),
            ERC721ABIDispatcher { contract_address: LOAN_TOKEN() }.balance_of(LENDER()) + 1
        );

        store(
            LOAN_TOKEN(),
            map_entry_address(
                selector!("loan_contract"), array![REFINANCING_LOAN_ID.into()].span()
            ),
            array![SIMPLE_LOAN_ADDRESS().into()].span()
        );
    }

    pub const REFINANCING_LOAN_ID: felt252 = 44;

    #[test]
    #[should_panic(expected: "Loan does not exist")]
    fn test_should_fail_when_loan_does_not_exist() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.status = 0;
        store_loan(loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Loan is not running")]
    fn test_should_fail_when_loan_is_not_running() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.status = 3;
        store_loan(loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_loan_is_defaulted() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        //mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), SIMPLE_LOAN_TERMS()), 1);
        cheat_block_timestamp_global(SIMPLE_LOAN().default_timestamp);
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Credit is not the same")]
    fn test_fuzz_should_fail_when_credit_asset_mismatch(_asset_address: u128) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let simple_loan = SIMPLE_LOAN();
        let mut _asset_address: felt252 = _asset_address.into();
        let mut asset_address: ContractAddress = _asset_address.try_into().unwrap();
        while asset_address == simple_loan
            .credit_address {
                _asset_address += 1;
                asset_address = _asset_address.try_into().unwrap();
            };

        let mut terms = REFINANCED_LOAN_TERMS();
        terms.credit.asset_address = asset_address;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Credit is not the same")]
    fn test_should_fail_when_credit_asset_amount_zero() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.credit.amount = 0;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_category_mismatch(mut category: u8) {
        category %= 3;
        let simple_loan = SIMPLE_LOAN();
        if category == simple_loan.collateral.category.into() {
            category = (category + 1) % 3;
        }
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.collateral.category = category.into();
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_address_mismatch(_asset_address: u128) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let simple_loan = SIMPLE_LOAN();
        let mut _asset_address: felt252 = _asset_address.into();
        let mut asset_address: ContractAddress = _asset_address.try_into().unwrap();
        while asset_address == simple_loan
            .collateral
            .asset_address {
                _asset_address += 1;
                asset_address = _asset_address.try_into().unwrap();
            };

        let mut terms = REFINANCED_LOAN_TERMS();
        terms.collateral.asset_address = asset_address;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_id_mismatch(mut id: felt252) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let simple_loan = SIMPLE_LOAN();
        if id == simple_loan.collateral.id {
            id += 1;
        };

        let mut terms = REFINANCED_LOAN_TERMS();
        terms.collateral.id = id;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_amount_mismatch(mut amount: u256) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let simple_loan = SIMPLE_LOAN();
        if amount == simple_loan.collateral.amount {
            amount += 1;
        };

        let mut terms = REFINANCED_LOAN_TERMS();
        terms.collateral.amount = amount;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_borrower_mismatch(_borrower: u128) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let simple_loan = SIMPLE_LOAN();
        let mut _borrower: felt252 = _borrower.into();
        let mut borrower: ContractAddress = _borrower.try_into().unwrap();
        if borrower == simple_loan.borrower {
            borrower = (_borrower + 1).try_into().unwrap();
        };

        let mut terms = REFINANCED_LOAN_TERMS();
        terms.borrower = borrower;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
    }

    #[test] // check whats wrong with the setup needed to mint loan token. Ensure setup matches with the solidity one
    fn test_should_emit_loan_paid_back() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();

        let mut spy = spy_events();
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array!['lil extra'])
            );
        spy
            .assert_emitted(
                @array![
                    (
                        loan.contract_address,
                        PwnSimpleLoan::Event::LoanPaidBack(
                            PwnSimpleLoan::LoanPaidBack { loan_id: REFINANCING_LOAN_ID }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_should_emit_loan_created() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();

        let mut spy = spy_events();
        let loan_id = loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array!['lil extra'])
            );

        spy
            .assert_emitted(
                @array![
                    (
                        loan.contract_address,
                        PwnSimpleLoan::Event::LoanCreated(
                            PwnSimpleLoan::LoanCreated {
                                loan_id: loan_id,
                                proposal_hash: PROPOSAL_HASH(),
                                proposal_contract: PROPOSAL_CONTRACT(),
                                refinancing_loan_id: REFINANCING_LOAN_ID,
                                terms: REFINANCED_LOAN_TERMS(),
                                lender_spec: LENDER_SPEC(),
                                extra: Option::Some(array!['lil extra']),
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_when_loan_owner_is_original_lender() {
        let (mut loan, _, _, _, _, _, _, loan_token) = deploy();
        setup();

        let loan_token = ERC721ABIDispatcher { contract_address: loan_token.contract_address };
        let prev_owner = loan_token.owner_of(REFINANCING_LOAN_ID.into());
        assert_eq!(prev_owner, LENDER());
        loan
            .create_loan(
                PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array!['lil extra'])
            );
        let curr_owner = loan_token.owner_of(REFINANCING_LOAN_ID.into());
        assert_eq!(curr_owner, starknet::contract_address_const::<0>());
    }

    #[test]
    fn test_should_emit_loan_claimed_when_loan_owner_is_original_lender() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();

        let mut spy = spy_events();
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));

        spy
            .assert_emitted(
                @array![
                    (
                        loan.contract_address,
                        PwnSimpleLoan::Event::LoanClaimed(
                            PwnSimpleLoan::LoanClaimed {
                                loan_id: REFINANCING_LOAN_ID, defaulted: false
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_should_update_loan_data_when_loan_owner_is_not_original_lender() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let not_original_sender = starknet::contract_address_const::<'notOriginalSender'>();
        mock_call(LOAN_TOKEN(), selector!("owner_of"), not_original_sender, 1);

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));

        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.status = 3;
        simple_loan.fixed_interest_amount = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID)
            - simple_loan.principal_amount;
        simple_loan.accruing_interest_APR = 0;
        assert_loan_eq(loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    }

    #[test]
    #[ignore] // when call fails reverts the whole tx
    fn test_should_update_loan_data_when_loan_owner_is_original_lender_when_direct_repayment_fails() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.credit.amount = SIMPLE_LOAN().principal_amount - 1;
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);

        mint_erc20(ERC20_MOCK_ADDRESS(), LENDER(), BoundedInt::max());

        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));

        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.status = 3;
        simple_loan.fixed_interest_amount = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID)
            - simple_loan.principal_amount;
        simple_loan.accruing_interest_APR = 0;
        assert_loan_eq(loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_pool_adapter_not_registered_when_pool_source_of_funds() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let lender_spec = types::LenderSpec { source_of_funds: SOURCE_OF_FUNDS() };
        let mut terms = SIMPLE_LOAN_TERMS();
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(
            CONFIG(), selector!("get_pool_adapter"), starknet::contract_address_const::<0>(), 1
        );
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
    }

    #[test]
    fn test_should_withdraw_full_credit_amount_when_should_transfer_common_when_pool_source_of_funds() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let lender_spec = types::LenderSpec { source_of_funds: SOURCE_OF_FUNDS() };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(SOURCE_OF_FUNDS());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(SOURCE_OF_FUNDS());
        assert_eq!(prev_bal - terms.credit.amount, curr_bal, "Source of funds balance mismatch!");
    }

    #[test]
    fn test_should_withdraw_credit_without_common_when_should_not_transfer_common_when_pool_source_of_funds() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let lender_spec = types::LenderSpec { source_of_funds: SOURCE_OF_FUNDS() };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender = NEW_LENDER();
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(LOAN_TOKEN(), selector!("owner_of"), NEW_LENDER(), 1);
        let repayment = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let common = if terms.credit.amount < repayment {
            terms.credit.amount
        } else {
            repayment
        };
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(SOURCE_OF_FUNDS());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(SOURCE_OF_FUNDS());
        assert_eq!(
            prev_bal - terms.credit.amount + common, curr_bal, "Source of funds balance mismatch!"
        );
    }

    #[test]
    fn test_should_not_withdraw_credit_when_should_not_transfer_common_when_no_surplus_when_no_fee_when_pool_source_of_funds() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let lender_spec = types::LenderSpec { source_of_funds: SOURCE_OF_FUNDS() };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender = NEW_LENDER();
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        terms.credit.amount = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(LOAN_TOKEN(), selector!("owner_of"), NEW_LENDER(), 1);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(SOURCE_OF_FUNDS());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(SOURCE_OF_FUNDS());
        assert_eq!(prev_bal, curr_bal, "Source of funds balance mismatch!");
    }

    #[test]
    fn test_fuzz_should_transfer_fee_to_collector(mut fee: u16) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        fee %= 9999;
        if fee == 0 {
            fee += 1;
        }

        let terms = REFINANCED_LOAN_TERMS();
        let (fee_amount, _) = fee_calculator::calculate_fee_amount(fee, terms.credit.amount);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(FEE_COLLECTOR());
        mock_call(CONFIG(), selector!("get_fee"), fee, 1);
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(FEE_COLLECTOR());
        assert_eq!(prev_bal + fee_amount, curr_bal, "Fee collector balance mismatch!");
    }

    #[test]
    fn test_should_transfer_common_to_vault_when_lender_not_loan_owner() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let new_lender = NEW_LENDER();
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender = new_lender;
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(
            LOAN_TOKEN(),
            selector!("owner_of"),
            starknet::contract_address_const::<'loanOwner'>(),
            1
        );
        let repayment = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let common = if terms.credit.amount < repayment {
            terms.credit.amount
        } else {
            repayment
        };
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(SIMPLE_LOAN_ADDRESS());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(SIMPLE_LOAN_ADDRESS());
        assert_eq!(prev_bal + common, curr_bal, "SimpleLoan balance mismatch!");
    }

    #[test] // this has no fuzzing parameter in original test what to do with this
    #[ignore]
    fn test_fuzz_should_transfer_common_to_vault_when_lender_original_lender_when_different_source_of_funds() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let new_lender = NEW_LENDER();
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender = new_lender;
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.original_lender = new_lender;
        simple_loan.original_source_of_funds = SOURCE_OF_FUNDS();
        store_loan(loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        mock_call(LOAN_TOKEN(), selector!("owner_of"), new_lender, 1);
        let repayment = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let common = if terms.credit.amount < repayment {
            terms.credit.amount
        } else {
            repayment
        };
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(NEW_LENDER());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(NEW_LENDER());
        assert_eq!(prev_bal - common, curr_bal, "SimpleLoan balance mismatch!");
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_not_transfer_common_to_vault_when_lender_loan_owner_when_lender_original_lender_when_same_source_of_funds(
        source_of_funds_flag: bool
    ) {
        assert(true, '');
    }

    #[test]
    fn test_should_transfer_surplus_to_borrower() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let new_lender = NEW_LENDER();
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender = new_lender;
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        let surplus = terms.credit.amount - loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(BORROWER());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(BORROWER());
        assert_eq!(prev_bal + surplus, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_should_not_transfer_surplus_to_borrower_when_no_surplus() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let new_lender = NEW_LENDER();
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.lender = new_lender;
        terms.lender_spec_hash = loan.get_lender_spec_hash(lender_spec);
        terms.credit.amount = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(BORROWER());
        loan.create_loan(PROPOSAL_SPEC(), lender_spec, CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(BORROWER());
        assert_eq!(prev_bal, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_should_transfer_shortage_from_borrower_to_vault() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut simple_loan = SIMPLE_LOAN();
        let terms = REFINANCED_LOAN_TERMS();
        simple_loan.principal_amount = terms.credit.amount + 1;
        store_loan(loan.contract_address, REFINANCING_LOAN_ID, simple_loan);

        let shortage = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID) - terms.credit.amount;
        let credit_asset = ERC20ABIDispatcher { contract_address: simple_loan.credit_address };
        let prev_bal = credit_asset.balance_of(BORROWER());
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(BORROWER());
        assert_eq!(prev_bal - shortage, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_should_not_transfer_shortage_from_borrower_to_vault_when_no_shortage() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        setup();
        let mut terms = REFINANCED_LOAN_TERMS();
        terms.credit.amount = loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        mock_call(PROPOSAL_CONTRACT(), selector!("accept_proposal"), (PROPOSAL_HASH(), terms), 1);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(BORROWER());
        loan.create_loan(PROPOSAL_SPEC(), LENDER_SPEC(), CALLER_SPEC(), Option::Some(array![]));
        let curr_bal = credit_asset.balance_of(BORROWER());
        assert_eq!(prev_bal, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_fuzz_should_try_claim_repaid_loan_full_amount_when_should_transfer_common(mut _loan_owner: u128) {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_try_claim_repaid_loan_shortage_amount_when_should_not_transfer_common() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_fail_when_try_claim_repaid_loan_fails() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_repay_original_loan() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_collect_protocol_fee() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_surplus_to_borrower() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_shortage_from_borrower() {
        assert(true, '');
    }
}

mod repay_loan {
    #[test]
    #[ignore]
    fn test_should_fail_when_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_loan_is_not_running() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_is_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_owner_when_permit_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_asset_when_permit_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_call_permit_when_permit_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_update_loan_data_when_loan_owner_is_not_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_data_when_loan_owner_is_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_burn_loan_token_when_loan_owner_is_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_repaid_amount_to_vault() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_collateral_to_borrower() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_paid_back() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_call_try_claim_repaid_loan() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_fail_when_try_claim_repaid_loan_fails() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed_when_loan_owner_is_original_lender() {
        assert(true, '');
    }
}

mod loan_repayment_amount {
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use pwn::loan::lib::math;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        deploy, store_loan, cheat_block_timestamp_global, IPwnSimpleLoanDispatcher,
        IPwnSimpleLoanDispatcherTrait, LOAN_ID, SIMPLE_LOAN, LOAN_DURATION_DAYS, DAY, E18
    };

    #[test]
    fn test_should_return_zero_when_loan_does_not_exist() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        assert_eq!(loan.get_loan_repayment_amount(LOAN_ID()), 0);
    }

    #[test]
    fn test_fuzz_should_return_fixed_interest_when_zero_accrued_interest(
        mut days: u64, mut principal: u256, mut fixed_interest: u256
    ) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        days %= 2 * LOAN_DURATION_DAYS();
        principal %= E40;
        if principal == 0 {
            principal = 1;
        }
        fixed_interest %= E40;
        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.default_timestamp = simple_loan.start_timestamp + 101 * DAY;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = 0;
        store_loan(loan.contract_address, LOAN_ID(), simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp + days + DAY);
        assert_eq!(
            loan.get_loan_repayment_amount(LOAN_ID()),
            principal + fixed_interest,
            "Loan repayment mismatch!"
        );
    }

    #[test]
    fn test_fuzz_should_return_accrued_interest_when_non_zero_accrued_interest(
        mut minutes: u64, mut principal: u256, mut fixed_interest: u256, mut interest_APR: u256
    ) {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        minutes %= 2 * LOAN_DURATION_DAYS() * 24 * 60;
        principal %= E40;
        if principal == 0 {
            principal = 1;
        }
        fixed_interest %= E40;
        interest_APR %= 16_000_000;
        if interest_APR == 0 {
            principal = 1;
        }
        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.default_timestamp = simple_loan.start_timestamp + 101 * DAY;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR.try_into().unwrap();
        store_loan(loan.contract_address, LOAN_ID(), simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp + minutes * 60 + 1);

        let expected_interest = fixed_interest
            +  math::mul_div(principal, (interest_APR * minutes.into()), PwnSimpleLoan::ACCRUING_INTEREST_APR_DENOMINATOR);
        let expected_loan_repayment = principal + expected_interest;
        assert_eq!(
            loan.get_loan_repayment_amount(LOAN_ID()),
            expected_loan_repayment,
            "Loan repayment mismatch!"
        );
    }

    #[test]
    fn test_should_return_accrued_interest() {
        let (mut loan, _, _, _, _, _, _, _) = deploy();
        let mut simple_loan = SIMPLE_LOAN();
        simple_loan.default_timestamp = simple_loan.start_timestamp + 101 * DAY;
        simple_loan.principal_amount = 100 * E18;
        simple_loan.fixed_interest_amount = 10 * E18;
        simple_loan.accruing_interest_APR = 36500;
        store_loan(loan.contract_address, LOAN_ID(), simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp);
        assert_eq!(
            loan.get_loan_repayment_amount(LOAN_ID()),
            simple_loan.principal_amount + simple_loan.fixed_interest_amount,
            "Loan repayment mismatch!"
        );

        cheat_block_timestamp_global(simple_loan.start_timestamp + DAY);
        assert_eq!(
            loan.get_loan_repayment_amount(LOAN_ID()),
            simple_loan.principal_amount + simple_loan.fixed_interest_amount + E18,
            "Loan repayment mismatch!"
        );
        
        simple_loan.accruing_interest_APR = 10_000;
        store_loan(loan.contract_address, LOAN_ID(), simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp + 365 * DAY);
        assert_eq!(
            loan.get_loan_repayment_amount(LOAN_ID()),
            2 * simple_loan.principal_amount + simple_loan.fixed_interest_amount,
            "Loan repayment mismatch!"
        );
    }
}

mod claim_loan {
    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_not_loan_token_holder() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_is_not_repaid_nor_expired() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_loan_is_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_loan_is_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_data() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_burn_loan_token() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_repaid_amount_to_lender_when_loan_is_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_collateral_to_lender_when_loan_is_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed_when_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed_when_defaulted() {
        assert(true, '');
    }
}

mod try_claim_repaid_loan {
    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_not_vault() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_not_proceed_when_loan_not_in_repaid_state() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_not_proceed_when_original_lender_not_equal_to_loan_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_burn_loan_token() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_data() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_call_transfer_when_credit_amount_is_zero() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_to_original_lender_when_source_of_funds_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_pool_adapter_not_registered_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_amount_to_pool_adapter_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_call_supply_on_pool_adapter_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_transfer_fails_when_source_of_funds_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_transfer_fails_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed() {
        assert(true, '');
    }
}

mod make_extension_proposal {
    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_not_proposer() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_store_made_flag() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_extension_proposal_made() {
        assert(true, '');
    }
}

mod extend_loan {
    #[test]
    #[ignore]
    fn test_should_fail_when_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_is_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_signature_when_eoa() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_offer_expirated() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_offer_nonce_not_usable() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_not_borrower_nor_loan_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_borrower_and_proposer_is_not_loan_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_loan_owner_and_proposer_is_not_borrower() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_extension_duration_less_than_min() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_extension_duration_more_than_max() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_revoke_extension_nonce() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_update_loan_data() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_emit_loan_extended() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_transfer_credit_when_amount_zero() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_transfer_credit_when_address_zero() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_invalid_compensation_asset() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_data_permit_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_data_permit_asset() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_call_permit_when_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_compensation_when_defined() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_borrower_signature_when_lender_accepts() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_lender_signature_when_borrower_accepts() {
        assert(true, '');
    }
}

mod get_extension_hash {
    #[test]
    #[ignore]
    fn test_should_return_extension_hash() {
        assert(true, '');
    }
}

mod get_loan {
    #[test]
    #[ignore]
    fn test_fuzz_should_return_static_loan_data_first_part() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_static_loan_data_second_part() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_return_correct_status() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_loan_token_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_repayment_amount() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_return_empty_loan_data_for_non_existing_loan() {
        assert(true, '');
    }
}

mod loan_metadata_uri {
    #[test]
    #[ignore]
    fn test_should_call_config() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_return_correct_value() {
        assert(true, '');
    }
}

mod get_state_fingerprint {
    #[test]
    #[ignore]
    fn test_should_return_zero_if_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_update_state_fingerprint_when_loan_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_correct_state_fingerprint() {
        assert(true, '');
    }
}
