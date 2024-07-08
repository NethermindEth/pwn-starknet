use pwn::multitoken::category_registry::MultitokenCategoryRegistry;
use starknet::ContractAddress;

use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address_global,
};

#[starknet::interface]
pub trait IMultitokenCategoryRegistry<TState> {
    fn register_category_value(ref self: TState, asset_address: ContractAddress, category: u8);
    fn unregister_category_value(ref self: TState, asset_address: ContractAddress);
    fn registered_category_value(self: @TState, asset_address: ContractAddress) -> u8;
    fn owner(self: @TState) -> ContractAddress;
}

fn OWNER() -> starknet::ContractAddress {
    starknet::contract_address_const::<'owner'>()
}
fn ACCOUNT_1() -> starknet::ContractAddress {
    starknet::contract_address_const::<'account_1'>()
}

fn deploy() -> IMultitokenCategoryRegistryDispatcher {
    let contract = declare("MultitokenCategoryRegistry").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();

    IMultitokenCategoryRegistryDispatcher { contract_address }
}

mod constructor {
    use super::{deploy, ACCOUNT_1, OWNER, IMultitokenCategoryRegistryDispatcherTrait};

    #[test]
    fn test_should_set_contract_owner() {
        super::cheat_caller_address_global(ACCOUNT_1());
        let registry = deploy();
        assert_eq!(registry.owner(), ACCOUNT_1());
    }
}

mod register_category_value {
    use snforge_std::{spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait};
    use super::{deploy, ACCOUNT_1, OWNER, IMultitokenCategoryRegistryDispatcherTrait, MultitokenCategoryRegistry};
    use starknet::{ContractAddress};

    #[test]
    #[should_panic]
    fn test_should_fail_when_caller_is_not_owner() {
        let registry = deploy();

        super::cheat_caller_address_global(ACCOUNT_1());
        registry.register_category_value(ACCOUNT_1(), 5);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_category_max_u8_value() {
        let registry = deploy();

        registry.register_category_value(OWNER(), MultitokenCategoryRegistry::CATEGORY_NOT_REGISTERED);
    }

    fn test_fuzz_should_store_incremented_category_value(asset_address: u128, category: u8) {
        let registry = deploy();

        let asset_address : felt252 = asset_address.try_into().unwrap();

        assert_eq!(registry.registered_category_value(asset_address.try_into().unwrap()), 0);

        registry.register_category_value(asset_address.try_into().unwrap(), category);

        assert_eq!(registry.registered_category_value(asset_address.try_into().unwrap()), category + 1);
    }

    #[test]
    fn test_fuzz_should_emit_CategoryRegistered(asset_address: u128, category: u8) {
        let registry = deploy();

        let asset_address : felt252 = asset_address.try_into().unwrap();

        let mut spy = spy_events();
        registry.register_category_value(asset_address.try_into().unwrap(), category);

        spy
            .assert_emitted(
                @array![
                    (
                        registry.contract_address,
                        MultitokenCategoryRegistry::Event::CategoryRegistered(
                            MultitokenCategoryRegistry::CategoryRegistered { asset_address: asset_address.try_into().unwrap(), category}
                        )
                    )
                ]
            );
    }
}

mod unregister_category_value {
    use snforge_std::{spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait};
    use super::{deploy, ACCOUNT_1, OWNER, IMultitokenCategoryRegistryDispatcherTrait, MultitokenCategoryRegistry};
    use starknet::{ContractAddress};

    #[test]
    #[should_panic]
    fn test_should_fail_when_caller_is_not_owner() {
        let registry = deploy();

        super::cheat_caller_address_global(ACCOUNT_1());
        registry.unregister_category_value(ACCOUNT_1());
    }

    fn test_fuzz_should_clear_store(asset_address: u128, category: u8) {
        let registry = deploy();

        let asset_address : felt252 = asset_address.try_into().unwrap();

        registry.register_category_value(asset_address.try_into().unwrap(), category);
        assert_eq!(registry.registered_category_value(asset_address.try_into().unwrap()), category + 1);

        registry.unregister_category_value(asset_address.try_into().unwrap());

        assert_eq!(registry.registered_category_value(asset_address.try_into().unwrap()), 0);
    }

    #[test]
    fn test_fuzz_should_emit_CategoryUnregistered(asset_address: u128) {
        let registry = deploy();

        let asset_address : felt252 = asset_address.try_into().unwrap();

        let mut spy = spy_events();
        registry.unregister_category_value(asset_address.try_into().unwrap());

        spy
            .assert_emitted(
                @array![
                    (
                        registry.contract_address,
                        MultitokenCategoryRegistry::Event::CategoryUnregistered(
                            MultitokenCategoryRegistry::CategoryUnregistered { asset_address: asset_address.try_into().unwrap()}
                        )
                    )
                ]
            );
    }
}

mod registered_category_value {
    use super::{deploy, ACCOUNT_1, OWNER, IMultitokenCategoryRegistryDispatcherTrait, MultitokenCategoryRegistry};
    use starknet::{ContractAddress};

    fn test_fuzz_should_return_category_value_when_registered(asset_address: u128, category: u8) {
        let registry = deploy();

        let asset_address : felt252 = asset_address.try_into().unwrap();

        registry.register_category_value(asset_address.try_into().unwrap(), category);

        assert_eq!(registry.registered_category_value(asset_address.try_into().unwrap()), category + 1);
    }

    #[test]
    fn test_fuzz_should_return_category_not_registered_when_not_registered(asset_address: u128) {
        let registry = deploy();

        let asset_address : felt252 = asset_address.try_into().unwrap();

        assert_eq!(registry.registered_category_value(asset_address.try_into().unwrap()), MultitokenCategoryRegistry::CATEGORY_NOT_REGISTERED);
    }
}