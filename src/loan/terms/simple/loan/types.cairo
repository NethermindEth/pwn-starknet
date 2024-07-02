use pwn::ContractAddressDefault;
use pwn::multitoken::library::MultiToken::Asset;
use starknet::ContractAddress;


#[derive(Clone, Default, Drop, Serde)]
pub struct Terms {
    pub lender: ContractAddress,
    pub borrower: ContractAddress,
    pub duration: u64,
    pub collateral: Asset,
    pub credit: Asset,
    pub fixed_interest_amount: u256,
    pub accruing_interest_APR: u32,
    pub lender_spec_hash: felt252,
    pub borrower_spec_hash: felt252
}

#[derive(Drop, Serde)]
pub struct ProposalSpec {
    pub proposal_contract: ContractAddress,
    pub proposal_data: Span<felt252>,
    pub proposal_inclusion_proof: Span<felt252>,
    pub signature: felt252
}

#[derive(Clone, Drop, Serde)]
pub struct LenderSpec {
    pub source_of_funds: ContractAddress
}

#[derive(Drop, Serde)]
pub struct CallerSpec {
    pub refinancing_loan_id: felt252,
    pub revoke_nonce: bool,
    pub nonce: felt252,
    pub permit_data: felt252,
}

#[derive(Clone, Drop, Serde, Default, starknet::Store)]
pub struct Loan {
    pub status: u8,
    pub credit_address: ContractAddress,
    pub original_source_of_funds: ContractAddress,
    pub start_timestamp: u64,
    pub default_timestamp: u64,
    pub borrower: ContractAddress,
    pub original_lender: ContractAddress,
    pub accruing_interest_APR: u32,
    pub fixed_interest_amount: u256,
    pub principal_amount: u256,
    pub collateral: Asset,
}

#[derive(Drop, Serde)]
pub struct ExtensionProposal {
    pub loanId: felt252,
    pub compensationAddress: ContractAddress,
    pub compensationAmount: u256,
    pub duration: u64,
    pub expiration: u64,
    pub proposer: ContractAddress,
    pub nonceSpace: u256,
    pub nonce: felt252,
}

#[derive(Default, Drop, Serde)]
pub struct GetLoanReturnValue {
    status: u8,
    start_timestamp: u64,
    default_timestamp: u64,
    borrower: ContractAddress,
    original_lender: ContractAddress,
    loan_owner: ContractAddress,
    accruing_interest_APR: u32,
    fixed_interest_amount: u256,
    credit: Asset,
    collateral: Asset,
    original_source_of_funds: ContractAddress,
    repayment_amount: u256,
}
