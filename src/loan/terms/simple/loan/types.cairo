use pwn::ContractAddressDefault;
use pwn::multitoken::library::MultiToken::Asset;
use starknet::ContractAddress;


#[derive(Default, Drop, Serde)]
pub struct Terms {
    pub lender: ContractAddress,
    pub borrower: ContractAddress,
    pub duration: u64,
    pub collateral: Asset,
    pub credit: Asset,
    pub fixed_interest_amount: u256,
    pub accruing_interest_apr: u32,
    pub lender_spec_hash: felt252,
    pub borrower_spec_hash: felt252
}

#[derive(Drop, Serde)]
pub struct ProposalSpec {
    proposal_contract: ContractAddress,
    proposal_data: felt252,
    proposal_inclusion_proof: Span<felt252>,
    signature: felt252
}

#[derive(Drop, Serde)]
pub struct LenderSpec {
    source_of_funds: ContractAddress
}

#[derive(Drop, Serde)]
pub struct CallerSpec {
    refinancing_loan_id: u256,
    revoke_nonce: bool,
    nonce: felt252,
    permit_data: felt252,
}

#[derive(Drop, Serde, starknet::Store)]
pub struct Loan {
    status: u8,
    credit_address: ContractAddress,
    original_source_of_funds: ContractAddress,
    start_timestamp: u64,
    default_timestamp: u64,
    borrower: ContractAddress,
    original_lender: ContractAddress,
    accruing_interest_APR: u32,
    fixed_interest_amount: u256,
    principal_amount: u256,
    collateral: Asset,
}

#[derive(Drop, Serde)]
pub struct ExtensionProposal {
    loanId: felt252,
    compensationAddress: ContractAddress,
    compensationAmount: u256,
    duration: u64,
    expiration: u64,
    proposer: ContractAddress,
    nonceSpace: u256,
    nonce: felt252,
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
