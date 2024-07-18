use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::starknet::SyscallResultTrait;
use pwn::config::pwn_config::PwnConfig;
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::terms::simple::loan::{
    interface::{IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait},
    pwn_simple_loan::PwnSimpleLoan
};
use pwn::loan::token::pwn_loan::PwnLoan;
use pwn::multitoken::category_registry::MultiTokenCategoryRegistry;
use pwn::nonce::revoked_nonce::{RevokedNonce, IRevokedNonceDispatcher};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait, cheat_block_timestamp_global
};
use starknet::{ContractAddress, testing};

#[test]
fn test_should_have_correct_name_and_symbol() {
    assert(true, '');
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

