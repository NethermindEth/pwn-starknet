use pwn::config::pwn_config::{PwnConfig::MAX_FEE, PwnConfig};
use pwn::interfaces::{
    pool_adapter::IPoolAdapterDispatcher, fingerprint_computer::IStateFingerpringComputerDispatcher
};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnConfig<TState> {
    fn initialize(
        ref self: TState, owner: ContractAddress, fee: u16, fee_collector: ContractAddress
    );
    fn set_fee(ref self: TState, fee: u16);
    fn set_fee_collector(ref self: TState, fee_collector: ContractAddress);
    fn set_loan_metadata_uri(
        ref self: TState, loan_contract: ContractAddress, metadata_uri: ByteArray
    );
    fn set_default_loan_metadata_uri(ref self: TState, metadata_uri: ByteArray);
    fn register_state_fingerprint_computer(
        ref self: TState, asset: ContractAddress, computer: ContractAddress
    );
    fn register_pool_adapter(ref self: TState, pool: ContractAddress, adapter: ContractAddress);
    fn get_state_fingerprint_computer(
        ref self: TState, asset: ContractAddress
    ) -> IStateFingerpringComputerDispatcher;
    fn get_pool_adapter(self: @TState, pool: ContractAddress) -> IPoolAdapterDispatcher;
    fn loan_metadata_uri(self: @TState, loan_contract: ContractAddress) -> ByteArray;
    fn owner(self: @TState) -> ContractAddress;
    fn pending_owner(self: @TState) -> ContractAddress;
    fn accept_ownership(ref self: TState);
    fn transfer_ownership(ref self: TState, new_owner: ContractAddress);
    fn renounce_ownership(ref self: TState);
    fn is_initialized(self: @TState) -> bool;
    fn is_paused(self: @TState) -> bool;
}


fn OWNER() -> starknet::ContractAddress {
    starknet::contract_address_const::<'owner'>()
}
fn FEE_COLLECTOR() -> starknet::ContractAddress {
    starknet::contract_address_const::<'fee_collector'>()
}
fn ACCOUNT_1() -> starknet::ContractAddress {
    starknet::contract_address_const::<'account_1'>()
}
fn LOAN_CONTRACT() -> starknet::ContractAddress {
    starknet::contract_address_const::<'loan_contract'>()
}

fn deploy() -> IPwnConfigDispatcher {
    let contract = declare("PwnConfig").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();

    IPwnConfigDispatcher { contract_address }
}


mod initialize {
    use super::{OWNER, FEE_COLLECTOR, deploy, IPwnConfigDispatcherTrait};

    #[test]
    fn test_should_set_values() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        let owner = super::load(config.contract_address, selector!("Ownable_owner"), 1);
        let fee_collector = super::load(config.contract_address, selector!("fee_collector"), 1);
        let stored_fee = super::load(config.contract_address, selector!("fee"), 1);

        assert_eq!(*owner.at(0), OWNER().into());
        assert_eq!(*fee_collector.at(0), FEE_COLLECTOR().into());
        assert_eq!(*stored_fee.at(0), fee.into());
    }

    #[test]
    #[should_panic()]
    fn test_should_fail_when_called_second_time() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        config.initialize(OWNER(), fee, FEE_COLLECTOR());
    }

    #[test]
    #[should_panic()]
    fn test_should_fail_when_owner_is_zero_address() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(starknet::contract_address_const::<0>(), fee, FEE_COLLECTOR());
    }

    #[test]
    #[should_panic()]
    fn test_should_fail_when_fee_collector_is_zero_address() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, starknet::contract_address_const::<0>());
    }
}

mod set_fee {
    use snforge_std::{spy_events, SpyOn, EventSpy, EventAssertions};
    use super::{OWNER, FEE_COLLECTOR, ACCOUNT_1, deploy, IPwnConfigDispatcherTrait, PwnConfig};

    #[test]
    #[should_panic()]
    fn test_should_fail_when_caller_is_not_owner() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, ACCOUNT_1());
        config.set_fee(99);
    }

    #[test]
    #[should_panic()]
    fn test_should_fail_when_new_value_bigger_than_max_fee() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_fee(super::MAX_FEE + 1);
    }

    #[test]
    fn test_should_set_fee_value() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_fee(super::MAX_FEE);

        let stored_fee = super::load(config.contract_address, selector!("fee"), 1);
        assert_eq!(*stored_fee.at(0), super::MAX_FEE.into());
    }

    #[test]
    fn test_should_emit_event_fee_updated() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        let mut spy = spy_events(SpyOn::One(config.contract_address));
        super::start_cheat_caller_address(config.contract_address, OWNER());

        config.set_fee(super::MAX_FEE);

        spy
        .assert_emitted(
            @array![
                (
                    config.contract_address,
                    PwnConfig::Event::FeeUpdated(
                        PwnConfig::FeeUpdated {
                            old_fee: fee, new_fee: super::MAX_FEE
                        }
                    )
                )
            ]
        );
    }
}

mod set_fee_collector {
    use snforge_std::{spy_events, SpyOn, EventSpy, EventAssertions};
    use super::{OWNER, FEE_COLLECTOR, ACCOUNT_1, deploy, IPwnConfigDispatcherTrait, PwnConfig};

    #[test]
    #[should_panic()]
    fn test_should_fail_when_caller_is_not_owner() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, ACCOUNT_1());
        config.set_fee_collector(ACCOUNT_1());
    }

    #[test]
    #[should_panic()]
    fn test_should_fail_when_setting_zero_address() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_fee_collector(starknet::contract_address_const::<0>());
    }

    #[test]
    fn test_should_set_fee_collector_address() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_fee_collector(ACCOUNT_1());

        let stored_fee = super::load(config.contract_address, selector!("fee_collector"), 1);
        assert_eq!(*stored_fee.at(0), ACCOUNT_1().into());
    }

    #[test]
    fn test_should_emit_event_fee_collector_updated() {
        let fee = 32;
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        let mut spy = spy_events(SpyOn::One(config.contract_address));
        super::start_cheat_caller_address(config.contract_address, OWNER());

        config.set_fee_collector(ACCOUNT_1());

        spy.assert_emitted(
            @array![
                (
                    config.contract_address,
                    PwnConfig::Event::FeeCollectorUpdated(
                        PwnConfig::FeeCollectorUpdated {
                            old_fee_collector: FEE_COLLECTOR(), new_fee_collector: ACCOUNT_1()
                        }
                    )
                )
            ]
        );
    }
}

mod set_loan_metadata_uri {
    use snforge_std::{spy_events, SpyOn, EventSpy, EventAssertions};
    use super::{OWNER, FEE_COLLECTOR, ACCOUNT_1, LOAN_CONTRACT, deploy, IPwnConfigDispatcherTrait, PwnConfig};

    #[test]
    #[should_panic()]
    fn test_should_fail_when_caller_is_not_owner() {
        let fee = 32;
        let meta_uri: ByteArray = "pwn://test-metadata-uri";
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, ACCOUNT_1());
        config.set_loan_metadata_uri(LOAN_CONTRACT(), meta_uri);
    }

    #[test]
    #[should_panic()]
    fn test_should_fail_when_zero_loan_contract() {
        let fee = 32;
        let meta_uri: ByteArray = "pwn://test-metadata-uri";
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_loan_metadata_uri(starknet::contract_address_const::<0>(), meta_uri);
    }

    #[test]
    fn test_should_store_loan_metadata_uri_to_loan_contract() {
        let fee = 32;
        let meta_uri: ByteArray = "pwn://test-metadata-uri";
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_loan_metadata_uri(LOAN_CONTRACT(), meta_uri.clone());

        let stored_uri = config.loan_metadata_uri(LOAN_CONTRACT());
        assert_eq!(stored_uri, meta_uri);
    }

    #[test]
    fn test_should_emit_event_loan_metadata_uri_updated() {
        let fee = 32;
        let config = super::deploy();
        let meta_uri: ByteArray = "pwn://test-metadata-uri";

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        let mut spy = spy_events(SpyOn::One(config.contract_address));
        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_loan_metadata_uri(LOAN_CONTRACT(), meta_uri.clone());

        spy.assert_emitted(
            @array![
                (
                    config.contract_address,
                    PwnConfig::Event::LOANMetadataUriUpdated(
                        PwnConfig::LOANMetadataUriUpdated {
                            loan_contract: LOAN_CONTRACT(), new_uri: meta_uri
                        }
                    )
                )
            ]
        );
    }
}

mod set_default_loan_metadata_uri {
    use snforge_std::{spy_events, SpyOn, EventSpy, EventAssertions};
    use super::{OWNER, FEE_COLLECTOR, ACCOUNT_1, LOAN_CONTRACT, deploy, IPwnConfigDispatcherTrait, PwnConfig};

    #[test]
    #[should_panic()]
    fn test_should_fail_when_caller_is_not_owner() {
        let fee = 32;
        let meta_uri: ByteArray = "pwn://test-metadata-uri";
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, ACCOUNT_1());
        config.set_default_loan_metadata_uri(meta_uri);
    }

    #[test]
    fn test_should_store_default_loan_metadata_uri() {
        let fee = 32;
        let meta_uri: ByteArray = "pwn://test-metadata-uri";
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_default_loan_metadata_uri(meta_uri.clone());

        let stored_uri = super::load(
            config.contract_address,
            super::map_entry_address(selector!("loan_metadata_uri"), array![0].span()),
            1
        );
        assert_eq!(*stored_uri.at(0), meta_uri.len().into());
    }

    #[test]
    fn test_should_emit_event_default_loan_metadata_uri_updated() {
        let fee = 32;
        let config = super::deploy();
        let meta_uri: ByteArray = "pwn://test-metadata-uri";

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        let mut spy = spy_events(SpyOn::One(config.contract_address));
        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_default_loan_metadata_uri(meta_uri.clone());

        spy.assert_emitted(
            @array![
                (
                    config.contract_address,
                    PwnConfig::Event::DefaultLOANMetadataUriUpdated(
                        PwnConfig::DefaultLOANMetadataUriUpdated { new_uri: meta_uri }
                    )
                )
            ]
        );
    }
}

mod loan_metadata_uri {
    use super::{OWNER, FEE_COLLECTOR, ACCOUNT_1, LOAN_CONTRACT, deploy, IPwnConfigDispatcherTrait};

    #[test]
    fn test_should_return_default_loan_metadata_uri_when_no_store_value_for_loan_contract() {
        let fee = 32;
        let meta_uri: ByteArray = "pwn://test-metadata-uri";
        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_default_loan_metadata_uri(meta_uri.clone());

        let stored_uri = config.loan_metadata_uri(LOAN_CONTRACT());
        assert_eq!(stored_uri, meta_uri);
    }

    #[test]
    fn test_should_return_loan_metadata_uri_when_stored_value_for_loan_contract() {
        let fee = 32;
        let default_uri: ByteArray = "pwn://test-default-metadata-uri";
        let loan_uri: ByteArray = "pwn://test-loan-metadata-uri";

        let config = super::deploy();

        config.initialize(OWNER(), fee, FEE_COLLECTOR());

        super::start_cheat_caller_address(config.contract_address, OWNER());
        config.set_default_loan_metadata_uri(default_uri);
        config.set_loan_metadata_uri(LOAN_CONTRACT(), loan_uri.clone());

        let stored_uri = config.loan_metadata_uri(LOAN_CONTRACT());
        assert_eq!(stored_uri, loan_uri);
    }
}
// mod state_fingerprint_computer {
//     #[test]
//     fn test_fuzz_should_return_stored_computer_when_is_registered() {
//         assert(true, '');
//     }
// }

// mod register_state_fingerprint_computer {
//     #[test]
//     fn test_fuzz_should_fail_when_caller_is_not_owner() {
//         assert(true, '');
//     }

//     #[test]
//     fn test_fuzz_should_unregister_computer_when_computer_is_zero_address() {
//         assert(true, '');
//     }

//     #[test]
//     fn test_fuzz_should_fail_when_computer_does_not_support_token() {
//         assert(true, '');
//     }

//     #[test]
//     fn test_fuzz_should_register_computer() {
//         assert(true, '');
//     }
// }

// mod get_pool_adapter {
//     #[test]
//     fn test_fuzz_should_return_stored_adapter_when_is_registered() {
//         assert(true, '');
//     }

//     #[test]
//     fn test_fuzz_should_fail_when_caller_is_not_owner() {
//         assert(true, '');
//     }

//     #[test]
//     fn test_fuzz_should_store_adapter() {
//         assert(true, '');
//     }
// }


