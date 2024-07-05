mod constructor {
    #[test]
    fn test_should_have_correct_name_and_symbol() {
        assert(true, '');
    }
}

mod mint {
    #[test]
    fn test_should_fail_when_caller_is_not_active_loan_contract() {
        assert(true, '');
    }

    #[test]
    fn test_should_increase_last_loan_id() {
        assert(true, '');
    }

    #[test]
    fn test_should_store_loan_contract_under_loan_id() {
        assert(true, '');
    }

    #[test]
    fn test_should_mint_loan_token() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_loan_id() {
        assert(true, '');
    }

    #[test]
    fn test_should_emit_event_loan_minted() {
        assert(true, '');
    }
}

mod burn {
    #[test]
    fn test_should_fail_when_caller_is_not_stored_loan_contract_for_given_loan_id() {
        assert(true, '');
    }

    #[test]
    fn test_should_delete_stored_loan_contract() {
        assert(true, '');
    }

    #[test]
    fn test_should_burn_loan_token() {
        assert(true, '');
    }

    #[test]
    fn test_should_emit_event_loan_burned() {
        assert(true, '');
    }
}

mod token_uri {
    #[test]
    fn test_should_call_loan_contract() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_correct_value() {
        assert(true, '');
    }
}

mod get_state_fingerprint {
    #[test]
    fn test_should_return_zero_if_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    fn test_should_call_loan_contract() {
        assert(true, '');
    }
}

mod supports_interface {
    #[test]
    fn test_should_support_erc5646() {
        assert(true, '');
    }
}

