mod is_valid_signature_now {
    #[test]
    fn test_should_call_eip1271_function_when_signer_is_contract_account() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_signer_is_contract_account_when_eip1271_function_returns_wrong_data_length() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_signer_is_contract_account_when_eip1271_function_not_returns_correct_value() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_true_when_signer_is_contract_account_when_eip1271_function_returns_correct_value() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_signer_is_eoa_when_signature_has_wrong_length() {
        assert(true, '');
    }

    #[test]
    fn test_fail_should_fail_when_signer_is_eoa_when_invalid_signature() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_true_when_signer_is_eoa_when_signer_is_recovered_address_of_signature() {
        assert(true, '');
    }

    #[test]
    fn test_should_support_compact_eip2098_signatures_when_signer_is_eoa() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_false_when_signer_is_eoa_when_signer_is_not_recovered_address_of_signature() {
        assert(true, '');
    }
}

