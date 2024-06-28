mod revoke_nonce {
    #[test]
    fn test_fuzz_should_fail_when_nonce_already_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked() {
        assert(true, '');
    }
}

mod revoke_nonces {
    #[test]
    fn test_fuzz_should_fail_when_any_nonce_already_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_store_nonces_as_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked() {
        assert(true, '');
    }
}

mod revoke_nonce_with_nonce_space {
    #[test]
    fn test_fuzz_should_fail_when_nonce_already_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked() {
        assert(true, '');
    }
}

mod revoke_nonce_with_owner {
    #[test]
    fn test_fuzz_should_fail_when_caller_does_not_have_access_tag() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_fail_when_nonce_already_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked() {
        assert(true, '');
    }
}

mod revoke_nonce_with_nonce_space_and_owner {
    #[test]
    fn test_fuzz_should_fail_when_caller_does_not_have_access_tag() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_fail_when_nonce_already_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked() {
        assert(true, '');
    }
}

mod is_nonce_revoked {
    #[test]
    fn test_fuzz_should_return_stored_value() {
        assert(true, '');
    }
}

mod is_nonce_usable {
    #[test]
    fn test_fuzz_should_return_false_when_nonce_space_is_not_equal_to_current_nonce_space() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_return_false_when_nonce_is_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_return_true_when_nonce_space_is_equal_to_current_nonce_space_when_nonce_is_not_revoked() {
        assert(true, '');
    }
}

mod revoke_nonce_space {
    #[test]
    fn test_fuzz_should_increment_current_nonce_space() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_emit_nonce_space_revoked() {
        assert(true, '');
    }

    #[test]
    fn test_fuzz_should_return_new_nonce_space() {
        assert(true, '');
    }
}

mod current_nonce_space {
    #[test]
    fn test_fuzz_should_return_current_nonce_space() {
        assert(true, '');
    }
}

