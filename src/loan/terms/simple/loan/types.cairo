use pwn::ContractAddressDefault;
use pwn::loan::lib::signature_checker::Signature;
use pwn::multitoken::library::MultiToken::Asset;
use starknet::ContractAddress;

/// Represents the terms of a loan.
#[derive(Copy, Default, Drop, Serde)]
pub struct Terms {
    /// The address of the lender.
    pub lender: ContractAddress,
    /// The address of the borrower.
    pub borrower: ContractAddress,
    /// The duration of the loan in seconds.
    pub duration: u64,
    /// The collateral asset.
    pub collateral: Asset,
    /// The credit asset.
    pub credit: Asset,
    /// The fixed interest amount.
    pub fixed_interest_amount: u256,
    /// The annual percentage rate for accruing interest.
    pub accruing_interest_APR: u32,
    /// The hash of the lender's specifications.
    pub lender_spec_hash: felt252,
    /// The hash of the borrower's specifications.
    pub borrower_spec_hash: felt252
}

/// Represents the specifications of a loan proposal.
#[derive(Clone, Drop, Serde)]
pub struct ProposalSpec {
    /// The address of the proposal contract.
    pub proposal_contract: ContractAddress,
    /// The data associated with the proposal.
    pub proposal_data: Array<felt252>,
    /// The inclusion proof for the proposal.
    pub proposal_inclusion_proof: Array<u256>,
    /// The signature for the proposal.
    pub signature: Signature
}

/// Represents the specifications provided by a lender.
#[derive(Copy, Drop, Serde)]
pub struct LenderSpec {
    /// The address of the source of funds.
    pub source_of_funds: ContractAddress
}

/// Represents the specifications related to the caller of a function.
#[derive(Copy, Default, Drop, Serde)]
pub struct CallerSpec {
    /// The ID of the loan being refinanced.
    pub refinancing_loan_id: felt252,
    /// A flag indicating whether to revoke the nonce.
    pub revoke_nonce: bool,
    /// The nonce for the operation.
    pub nonce: felt252,
}

/// Represents a loan with its status and terms.
#[derive(Copy, Drop, Serde, Default, starknet::Store)]
pub struct Loan {
    /// The status of the loan.
    pub status: u8,
    /// The address of the credit asset.
    pub credit_address: ContractAddress,
    /// The original source of funds for the loan.
    pub original_source_of_funds: ContractAddress,
    /// The start timestamp of the loan.
    pub start_timestamp: u64,
    /// The default timestamp of the loan.
    pub default_timestamp: u64,
    /// The address of the borrower.
    pub borrower: ContractAddress,
    /// The address of the original lender.
    pub original_lender: ContractAddress,
    /// The annual percentage rate for accruing interest.
    pub accruing_interest_APR: u32,
    /// The fixed interest amount.
    pub fixed_interest_amount: u256,
    /// The principal amount of the loan.
    pub principal_amount: u256,
    /// The collateral asset.
    pub collateral: Asset,
}

/// Represents a proposal to extend a loan.
#[derive(Copy, Default, Drop, Serde)]
pub struct ExtensionProposal {
    /// The ID of the loan to be extended.
    pub loan_id: felt252,
    /// The address for compensation.
    pub compensation_address: ContractAddress,
    /// The amount of compensation.
    pub compensation_amount: u256,
    /// The duration of the extension in seconds.
    pub duration: u64,
    /// The expiration timestamp of the proposal.
    pub expiration: u64,
    /// The address of the proposer.
    pub proposer: ContractAddress,
    /// The space for the nonce.
    pub nonce_space: felt252,
    /// The nonce for the operation.
    pub nonce: felt252,
}

/// Represents the return value of a loan query.
#[derive(Default, Drop, Serde)]
pub struct GetLoanReturnValue {
    /// The status of the loan.
    pub status: u8,
    /// The start timestamp of the loan.
    pub start_timestamp: u64,
    /// The default timestamp of the loan.
    pub default_timestamp: u64,
    /// The address of the borrower.
    pub borrower: ContractAddress,
    /// The address of the original lender.
    pub original_lender: ContractAddress,
    /// The address of the loan owner.
    pub loan_owner: ContractAddress,
    /// The annual percentage rate for accruing interest.
    pub accruing_interest_APR: u32,
    /// The fixed interest amount.
    pub fixed_interest_amount: u256,
    /// The credit asset.
    pub credit: Asset,
    /// The collateral asset.
    pub collateral: Asset,
    /// The original source of funds for the loan.
    pub original_source_of_funds: ContractAddress,
    /// The amount required to repay the loan.
    pub repayment_amount: u256,
}
