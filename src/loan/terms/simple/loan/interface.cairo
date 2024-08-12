use pwn::loan::lib::{fee_calculator, math, signature_checker};
use pwn::loan::terms::simple::loan::types;
use pwn::loan::vault::permit::{Permit};
use pwn::multitoken::library::MultiToken::Asset;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnSimpleLoan<TState> {
    fn claim_loan(ref self: TState, loan_id: felt252);
    fn create_loan(
        ref self: TState,
        proposal_spec: types::ProposalSpec,
        lender_spec: types::LenderSpec,
        caller_spec: types::CallerSpec,
        extra: Option<Array<felt252>>
    ) -> felt252;
    fn extend_loan(
        ref self: TState,
        extension: types::ExtensionProposal,
        signature: signature_checker::Signature
    );
    fn make_extension_proposal(ref self: TState, extension: types::ExtensionProposal);
    fn repay_loan(ref self: TState, loan_id: felt252, permit_data: felt252);

    fn ACCRUING_INTEREST_APR_DECIMALS(self: @TState) -> u16;
    fn ACCRUING_INTEREST_APR_DENOMINATOR(self: @TState) -> u64;
    fn DOMAIN_SEPARATOR(self: @TState) -> felt252;
    fn EXTENSION_PROPOSAL_TYPEHASH(self: @TState) -> felt252;
    fn MAX_ACCRUING_INTEREST_APR(self: @TState) -> u32;
    fn MAX_EXTENSION_DURATION(self: @TState) -> u64;
    fn MINUTE_IN_YEAR(self: @TState) -> u64;
    fn MIN_EXTENSION_DURATION(self: @TState) -> u64;
    fn MIN_LOAN_DURATION(self: @TState) -> u64;
    fn VERSION(self: @TState) -> felt252;
    fn get_lender_spec_hash(self: @TState, calladata: types::LenderSpec) -> felt252;
    fn get_loan_repayment_amount(self: @TState, loan_id: felt252) -> u256;
    fn get_extension_hash(self: @TState, extension: types::ExtensionProposal) -> felt252;
    fn get_loan(self: @TState, loan_id: felt252) -> types::GetLoanReturnValue;
    fn get_is_valid_asset(self: @TState, asset: Asset) -> bool;
    fn get_loan_metadata_uri(self: @TState) -> ByteArray;
    fn get_state_fingerprint(self: @TState, token_id: felt252) -> felt252;
}
