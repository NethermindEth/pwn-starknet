use pwn::hub::pwn_hub::PwnHub;
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    cheat_caller_address_global,
};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnHub<TState> {
    fn set_tag(ref self: TState, address: ContractAddress, tag: felt252, has_tag: bool);
    fn set_tags(
        ref self: TState, addresses: Array<ContractAddress>, tags: Array<felt252>, has_tag: bool
    );
    fn has_tag(ref self: TState, address: ContractAddress, tag: felt252) -> bool;
    fn owner(self: @TState) -> ContractAddress;
}

fn OWNER() -> starknet::ContractAddress {
    starknet::contract_address_const::<'owner'>()
}
fn ACCOUNT_1() -> starknet::ContractAddress {
    starknet::contract_address_const::<'account_1'>()
}

fn deploy() -> IPwnHubDispatcher {
    let contract = declare("PwnHub").unwrap();
    let (contract_address, _) = contract.deploy(@array![starknet::get_contract_address().into()]).unwrap();

    IPwnHubDispatcher { contract_address }
}

mod constructor {
    use super::{deploy, ACCOUNT_1, OWNER, IPwnHubDispatcherTrait};

    #[test]
    fn test_should_set_hub_owner() {
        let hub = deploy();
        assert_eq!(hub.owner(), starknet::get_contract_address());
    }
}

mod set_tag {
    use snforge_std::{spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait};
    use super::{deploy, ACCOUNT_1, OWNER, IPwnHubDispatcherTrait, PwnHub};

    #[test]
    #[should_panic]
    fn test_should_fail_when_caller_is_not_owner() {
        let hub = deploy();

        super::cheat_caller_address_global(ACCOUNT_1());
        hub.set_tag(OWNER(), 'tag', true);
    }

    #[test]
    fn test_should_add_tag_to_address() {
        let hub = deploy();

        hub.set_tag(OWNER(), 'tag', true);

        assert_eq!(hub.has_tag(OWNER(), 'tag'), true);
    }

    #[test]
    fn test_should_remove_tag_from_address() {
        let hub = deploy();

        hub.set_tag(OWNER(), 'tag', true);
        hub.set_tag(OWNER(), 'tag', false);

        assert_eq!(hub.has_tag(OWNER(), 'tag'), false);
    }

    #[test]
    fn test_should_emit_event_tag_set() {
        let hub = deploy();
        let mut spy = spy_events();

        hub.set_tag(OWNER(), 'tag', true);

        spy
            .assert_emitted(
                @array![
                    (
                        hub.contract_address,
                        PwnHub::Event::TagSet(
                            PwnHub::TagSet { contract: OWNER(), tag: 'tag', has_tag: true }
                        )
                    )
                ]
            );
    }
}

mod set_tags {
    use snforge_std::{spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait};
    use super::{deploy, ACCOUNT_1, OWNER, IPwnHubDispatcherTrait, PwnHub};

    #[test]
    #[should_panic]
    fn test_should_fail_when_caller_is_not_owner() {
        let hub = deploy();
        let addresses = array![OWNER(), ACCOUNT_1()];
        let tags = array!['tag', 'tag'];

        super::cheat_caller_address_global(ACCOUNT_1());
        hub.set_tags(addresses, tags, true);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_diff_input_lengths() {
        let hub = deploy();
        let addresses = array![OWNER(), ACCOUNT_1()];
        let tags = array!['tag'];

        hub.set_tags(addresses, tags, true);
    }

    #[test]
    #[should_panic]
    fn test_should_not_fail_when_empty_list() {
        let hub = deploy();
        let addresses = array![OWNER(), ACCOUNT_1()];
        let tags = array![];

        hub.set_tags(addresses, tags, true);
    }

    #[test]
    fn test_should_add_tags_to_address() {
        let hub = deploy();
        let addresses = array![OWNER(), ACCOUNT_1()];
        let tags = array!['tag', 'tag'];

        hub.set_tags(addresses, tags, true);

        assert_eq!(hub.has_tag(OWNER(), 'tag'), true);
        assert_eq!(hub.has_tag(ACCOUNT_1(), 'tag'), true);
    }

    #[test]
    fn test_should_remove_tags_from_address() {
        let hub = deploy();
        let addresses = array![OWNER(), ACCOUNT_1()];
        let tags = array!['tag', 'tag'];

        hub.set_tags(addresses.clone(), tags.clone(), true);

        hub.set_tags(addresses, tags, false);

        assert_eq!(hub.has_tag(OWNER(), 'tag'), false);
        assert_eq!(hub.has_tag(ACCOUNT_1(), 'tag'), false);
    }

    #[test]
    fn test_should_emit_event_tag_set_for_every_set() {
        let hub = deploy();
        let addresses = array![OWNER(), ACCOUNT_1()];
        let tags = array!['tag', 'tag'];

        let mut spy = spy_events();
        hub.set_tags(addresses, tags, true);

        spy
            .assert_emitted(
                @array![
                    (
                        hub.contract_address,
                        PwnHub::Event::TagSet(
                            PwnHub::TagSet { contract: OWNER(), tag: 'tag', has_tag: true }
                        )
                    ),
                    (
                        hub.contract_address,
                        PwnHub::Event::TagSet(
                            PwnHub::TagSet { contract: ACCOUNT_1(), tag: 'tag', has_tag: true }
                        )
                    )
                ]
            );
    }
}

mod has_tag {
    use super::{deploy, ACCOUNT_1, OWNER, IPwnHubDispatcherTrait};

    #[test]
    fn test_should_return_false_when_address_does_not_have_tag() {
        let hub = deploy();

        hub.set_tag(OWNER(), 'tag', true);

        assert_eq!(hub.has_tag(OWNER(), 'tag'), true);
    }

    #[test]
    fn test_should_return_true_when_address_does_have_tag() {
        let hub = deploy();

        assert_eq!(hub.has_tag(OWNER(), 'tag'), false);
    }
}
