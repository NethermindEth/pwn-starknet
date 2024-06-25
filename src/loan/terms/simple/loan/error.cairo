pub mod Err {
    fn LOAN_NOT_RUNNING() {
        panic!("Loan is not running");
    }
    fn LOAN_RUNNING() {
        panic!("Loan is running");
    }
    fn LOAN_REPAID() {
        panic!("Loan is repaid");
    }
    fn LOAN_DEFAULTED(default_time: u64) {
        panic!("Loan is defaulted at time {}", default_time);
    }
    fn NON_EXISTING_LOAN() {
        panic!("Loan does not exist");
    }
    fn CALLER_NOT_LOAN_TOKEN_HOLDER() {
        panic!("Caller is not the loan token holder");
    }
    fn REFINANCE_BORROWER_MISMATCH(curr_borrower: ContractAddress, new_borrower: ContractAddress) {
        panic!("Current borrower is {:?} and new borrower is {:?}", curr_borrower, new_borrower);
    }
    fn REFINANCE_CREDIT_MISMATCH() {
        panic!("Credit is not the same");
    }
    fn REFINANCE_COLLATERAL_MISMATCH() {
        panic!("Collateral is not the same");
    }
    fn INVALID_LENDER_SPEC_HASH() {
        panic!("Invalid lender spec hash");
    }
    fn INVALID_DURATION() {
        panic!("Invalid duration");
    }
    fn INTEREST_APR_OUT_OF_BOUNDS(current: u256, limit: u256) {
        panic!("Interest APR is out of bounds. Current: {}, Limit: {}", current, limit);
    }
    fn INVALID_EXTENSION_CALLER() {
        panic!("Invalid extension caller");
    }
    fn INVALID_EXTENSION_SINGNER(allowed: ContractAddress, current: ContractAddress) {
        panic!("Invalid extension signer. Allowed: {:?}, Current: {:?}", allowed, current);
    }
    fn INVALID_EXTENSION_DURATION(duration: u64, limit: u64) {
        panic!("Invalid extension duration. Current: {}, Limit: {}", duration, limit);
    }
    fn INVALID_MULTITOKEN_ASSET(category: u8, address: ContractAddress, id: felt252, amount: u256) {
        panic!(
            "Invalid multi token asset. Category: {}, Address: {:?}, ID: {}, Amount: {}",
            category,
            address,
            id,
            amount
        );
    }
}
