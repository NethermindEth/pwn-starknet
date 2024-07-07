pub mod Err {
    use starknet::ContractAddress;
    pub fn LOAN_NOT_RUNNING() {
        panic!("Loan is not running");
    }
    pub fn CALLER_NOT_VAULT() {
        panic!("Caller is not vault");
    }
    pub fn LOAN_RUNNING() {
        panic!("Loan is running");
    }
    pub fn LOAN_REPAID() {
        panic!("Loan is repaid");
    }
    pub fn LOAN_DEFAULTED(default_timestamp: u64) {
        panic!("Loan is defaulted at time {}", default_timestamp);
    }
    pub fn NON_EXISTING_LOAN() {
        panic!("Loan does not exist");
    }
    pub fn CALLER_NOT_LOAN_TOKEN_HOLDER() {
        panic!("Caller is not the loan token holder");
    }
    pub fn REFINANCE_BORROWER_MISMATCH(
        currrent_borrower: ContractAddress, new_borrower: ContractAddress
    ) {
        panic!(
            "Current borrower is {:?} and new borrower is {:?}", currrent_borrower, new_borrower
        );
    }
    pub fn REFINANCE_CREDIT_MISMATCH() {
        panic!("Credit is not the same");
    }
    pub fn REFINANCE_COLLATERAL_MISMATCH() {
        panic!("Collateral is not the same");
    }
    pub fn INVALID_LENDER_SPEC_HASH(current: felt252, expected: felt252) {
        panic!("Invalid lender spec hash. Current: {}, Expected: {}", current, expected);
    }
    pub fn INVALID_DURATION(current: u64, limit: u64) {
        panic!("Invalid duration. Current: {}, Limit: {}", current, limit);
    }
    pub fn INTEREST_APR_OUT_OF_BOUNDS(current: u32, limit: u32) {
        panic!("Interest APR is out of bounds. Current: {}, Limit: {}", current, limit);
    }
    pub fn INVALID_SOURCE_OF_FUNDS(source_of_funds: ContractAddress) {
        panic!("Invalid source of funds. Source of fungs: {:?}", source_of_funds);
    }
    pub fn INVALID_EXTENSION_CALLER() {
        panic!("Invalid extension caller");
    }
    pub fn INVALID_EXTENSION_SINGNER(allowed: ContractAddress, current: ContractAddress) {
        panic!("Invalid extension signer. Allowed: {:?}, Current: {:?}", allowed, current);
    }
    pub fn INVALID_EXTENSION_DURATION(duration: u64, limit: u64) {
        panic!("Invalid extension duration. Current: {}, Limit: {}", duration, limit);
    }
    pub fn INVALID_MULTITOKEN_ASSET(
        category: u8, address: ContractAddress, id: felt252, amount: u256
    ) {
        panic!(
            "Invalid multi token asset. Category: {}, Address: {:?}, ID: {}, Amount: {}",
            category,
            address,
            id,
            amount
        );
    }
}
