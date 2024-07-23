mod unit {
    mod LOAN_test;
    mod config_test;
    mod fee_calculator_test;
    mod hub_test;
    mod revoked_nonce_test;
    mod signature_checker_test;
    mod simple_loan_dutch_auction_proposal_test;
    mod simple_loan_fungible_proposal_test;
    mod simple_loan_list_proposal_test;
    mod simple_loan_proposal_test;
    mod simple_loan_simple_proposal_test;
    mod simple_loan_test;
    mod vault_test;
}

pub mod integration {
    pub mod base_integration_test;
    pub mod protocol_integrity_test;
    pub mod simple_loan_integration_test;
}

pub mod utils {
    pub mod simple_loan_proposal_component_mock;
}
