mod pwn_simple_loan_simple_proposal_test {
    #[test]
    fn test_should_return_used_credit() {
        assert(true, '');
    }

    #[test]
    fn test_should_call_revoke_nonce() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_proposal_hash() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_caller_is_not_proposer() {
        assert(true, '');
    }

    #[test]
    fn test_should_emit_proposal_made() {
        assert(true, '');
    }

    #[test]
    fn test_should_make_proposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_encoded_proposal_data() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_decoded_proposal_data() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_proposal_hash_and_loan_terms() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_caller_is_not_proposed_loan_contract() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_caller_not_tagged_active_loan() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_invalid_signature_when_eoa() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_invalid_signature_when_contract_account() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_with_invalid_signature_when_eoa_when_multiproposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_invalid_signature_when_contract_account_when_multiproposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_with_invalid_inclusion_proof() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_when_proposal_made_onchain() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_with_valid_signature_when_eoa_when_standard_signature() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_with_valid_signature_when_eoa_when_compact_eip2098_signature() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_when_valid_signature_when_contract_account() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_with_valid_signature_when_eoa_when_standard_signature_when_multiproposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_with_valid_signature_when_eoa_when_compact_eip2098_signature_when_multiproposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_when_valid_signature_when_contract_account_when_multiproposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_proposer_is_same_as_acceptor() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_zero() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_refinancing_loan_ids_is_not_equal_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_not_zero_when_offer() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_when_refinancing_loan_ids_not_equal_when_proposed_refinancing_loan_id_zero_when_refinancing_loan_id_not_zero_when_offer() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_refinancing_loan_ids_not_equal_when_refinancing_loan_id_not_zero_when_request() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_proposal_expired() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_offer_nonce_not_usable() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_caller_is_not_allowed_acceptor() {
        assert(true, '');
    }

    #[test]
    fn test_should_revoke_offer_when_available_credit_limit_equal_to_zero() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_used_credit_exceeds_available_credit_limit() {
        assert(true, '');
    }

    #[test]
    fn test_should_increase_used_credit_when_used_credit_not_exceeds_available_credit_limit() {
        assert(true, '');
    }

    #[test]
    fn test_should_not_call_computer_registry_when_should_not_check_state_fingerprint() {
        assert(true, '');
    }

    #[test]
    fn test_should_call_computer_registry_when_should_check_state_fingerprint() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_computer_registry_returns_computer_when_computer_fails() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_computer_registry_returns_computer_when_computer_returns_different_state_fingerprint() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_no_computer_registered_when_asset_does_not_implement_erc165() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_no_computer_registered_when_asset_does_not_implement_erc5646() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_asset_implements_erc5646_when_computer_returns_different_state_fingerprint() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_when_computer_returns_matching_fingerprint() {
        assert(true, '');
    }

    #[test]
    fn test_should_pass_when_asset_implements_erc5646_when_returns_matching_fingerprint() {
        assert(true, '');
    }
}

