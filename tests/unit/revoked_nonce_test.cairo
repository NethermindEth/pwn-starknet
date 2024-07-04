use pwn::hub::pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait};
use pwn::nonce::revoked_nonce::{
    RevokedNonce, IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait
};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    spy_events, SpyOn, EventSpy, EventAssertions
};
use starknet::ContractAddress;

const ACCESS_TAG: felt252 = 0x0103eff1f193a002436d3186efc5fbfa6076935a14ce3513bbc002ce41a5974c;

fn ALICE() -> starknet::ContractAddress {
    starknet::contract_address_const::<'alice'>()
}

fn deploy() -> (IRevokedNonceDispatcher, IPwnHubDispatcher) {
    let contract = declare("PwnHub").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();
    let hub = IPwnHubDispatcher { contract_address };

    let contract = declare("RevokedNonce").unwrap();
    let (contract_address, _) = contract
        .deploy(@array![contract_address.into(), ACCESS_TAG])
        .unwrap();
    let nonce = IRevokedNonceDispatcher { contract_address };

    (nonce, hub)
}

mod revoke_nonce {
    use super::{
        deploy, ALICE, IRevokedNonceDispatcherTrait, map_entry_address, spy_events, SpyOn, EventSpy,
        EventAssertions, RevokedNonce
    };

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_nonce_already_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![ALICE().into(), nonce_space, _nonce].span(),
            ),
            array![true.into()].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce(Option::None, Option::None, _nonce);
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce(Option::None, Option::None, _nonce);

        let is_nonce_revoked = nonce.is_nonce_revoked(ALICE(), nonce_space, _nonce);

        assert_eq!(is_nonce_revoked, true);
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        let mut spy = spy_events(super::SpyOn::One(nonce.contract_address));

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce(Option::None, Option::None, _nonce);

        spy
            .assert_emitted(
                @array![
                    (
                        nonce.contract_address,
                        RevokedNonce::Event::NonceRevoked(
                            RevokedNonce::NonceRevoked {
                                owner: ALICE(), nonce_space, nonce: _nonce
                            }
                        )
                    )
                ]
            );
    }
}

mod revoke_nonces {
    use super::{
        deploy, ALICE, IRevokedNonceDispatcherTrait, map_entry_address, spy_events, SpyOn, EventSpy,
        EventAssertions, RevokedNonce
    };

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_any_nonce_already_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![ALICE().into(), nonce_space, _nonce].span(),
            ),
            array![true.into()].span()
        );

        let nonces = array![_nonce, _nonce + 1];

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonces(nonces);
    }

    #[test]
    fn test_fuzz_should_store_nonces_as_revoked(
        nonce_space: felt252, nonce1: felt252, nonce2: felt252, nonce3: felt252
    ) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        let nonces = array![nonce1, nonce2, nonce3];

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonces(nonces);

        assert_eq!(nonce.is_nonce_revoked(ALICE(), nonce_space, nonce1), true);
        assert_eq!(nonce.is_nonce_revoked(ALICE(), nonce_space, nonce2), true);
        assert_eq!(nonce.is_nonce_revoked(ALICE(), nonce_space, nonce3), true);
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked(
        nonce_space: felt252, nonce1: felt252, nonce2: felt252, nonce3: felt252
    ) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        let nonces = array![nonce1, nonce2, nonce3];

        let mut spy = spy_events(super::SpyOn::One(nonce.contract_address));

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonces(nonces.clone());

        let mut i = 0;
        while i < nonces
            .len() {
                spy
                    .assert_emitted(
                        @array![
                            (
                                nonce.contract_address,
                                RevokedNonce::Event::NonceRevoked(
                                    RevokedNonce::NonceRevoked {
                                        owner: ALICE(), nonce_space, nonce: *nonces.at(i)
                                    }
                                )
                            )
                        ]
                    );

                i += 1;
            };
    }
}

mod revoke_nonce_with_nonce_space {
    use super::{
        deploy, ALICE, IRevokedNonceDispatcherTrait, map_entry_address, spy_events, SpyOn, EventSpy,
        EventAssertions, RevokedNonce
    };

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_nonce_already_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![ALICE().into(), nonce_space, _nonce].span(),
            ),
            array![true.into()].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce(Option::None, Option::Some(nonce_space), _nonce);
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce(Option::None, Option::Some(nonce_space), _nonce);

        assert_eq!(nonce.is_nonce_revoked(ALICE(), nonce_space, _nonce), true);
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked(nonce_space: felt252, _nonce: felt252) {
        let (nonce, _) = deploy();

        let mut spy = spy_events(super::SpyOn::One(nonce.contract_address));

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce(Option::None, Option::Some(nonce_space), _nonce);

        spy
            .assert_emitted(
                @array![
                    (
                        nonce.contract_address,
                        RevokedNonce::Event::NonceRevoked(
                            RevokedNonce::NonceRevoked {
                                owner: ALICE(), nonce_space, nonce: _nonce
                            }
                        )
                    )
                ]
            );
    }
}

mod revoke_nonce_with_owner {
    use super::{
        ACCESS_TAG, ALICE, IRevokedNonceDispatcherTrait, IPwnHubDispatcherTrait, map_entry_address,
        spy_events, SpyOn, EventSpy, EventAssertions, RevokedNonce
    };

    fn ACCESS_ENABLED_ADDRESS() -> starknet::ContractAddress {
        starknet::contract_address_const::<0x1>()
    }

    fn deploy() -> super::IRevokedNonceDispatcher {
        let (nonce, hub) = super::deploy();

        hub.set_tag(ACCESS_ENABLED_ADDRESS(), ACCESS_TAG, true);
        nonce
    }

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_caller_does_not_have_access_tag(caller: u128) {
        let nonce = deploy();

        let caller: felt252 = caller.try_into().unwrap();

        super::start_cheat_caller_address(nonce.contract_address, caller.try_into().unwrap());
        nonce.revoke_nonce(Option::Some(caller.try_into()).unwrap(), Option::None, 1);
    }

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_nonce_already_revoked(
        owner: felt252, nonce_space: felt252, _nonce: felt252
    ) {
        let nonce = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![owner.into()].span(),),
            array![nonce_space].span()
        );

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![owner.into(), nonce_space, _nonce].span(),
            ),
            array![true.into()].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ACCESS_ENABLED_ADDRESS());
        nonce.revoke_nonce(Option::Some(owner.try_into().unwrap()), Option::None, _nonce);
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked(owner: u128, nonce_space: felt252, _nonce: felt252) {
        let nonce = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![owner.into()].span(),),
            array![nonce_space].span()
        );

        let owner: felt252 = owner.try_into().unwrap();
        super::start_cheat_caller_address(nonce.contract_address, ACCESS_ENABLED_ADDRESS());
        nonce.revoke_nonce(Option::Some(owner.try_into().expect('fail 1')), Option::None, _nonce);

        assert_eq!(
            nonce.is_nonce_revoked(owner.try_into().expect('fail 2'), nonce_space, _nonce), true
        );
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked(owner: u128, nonce_space: felt252, _nonce: felt252) {
        let nonce = deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![owner.into()].span(),),
            array![nonce_space].span()
        );

        let mut spy = spy_events(super::SpyOn::One(nonce.contract_address));

        let owner: felt252 = owner.try_into().unwrap();
        super::start_cheat_caller_address(nonce.contract_address, ACCESS_ENABLED_ADDRESS());
        nonce.revoke_nonce(Option::Some(owner.try_into().expect('fail 1')), Option::None, _nonce);

        spy
            .assert_emitted(
                @array![
                    (
                        nonce.contract_address,
                        RevokedNonce::Event::NonceRevoked(
                            RevokedNonce::NonceRevoked {
                                owner: owner.try_into().unwrap(), nonce_space, nonce: _nonce
                            }
                        )
                    )
                ]
            );
    }
}

mod revoke_nonce_with_nonce_space_and_owner {
    use super::{
        ACCESS_TAG, ALICE, IRevokedNonceDispatcherTrait, IPwnHubDispatcherTrait, map_entry_address,
        spy_events, SpyOn, EventSpy, EventAssertions, RevokedNonce
    };

    fn ACCESS_ENABLED_ADDRESS() -> starknet::ContractAddress {
        starknet::contract_address_const::<0x1>()
    }

    fn deploy() -> super::IRevokedNonceDispatcher {
        let (nonce, hub) = super::deploy();

        hub.set_tag(ACCESS_ENABLED_ADDRESS(), ACCESS_TAG, true);
        nonce
    }

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_caller_does_not_have_access_tag(caller: u128) {
        let (nonce, _) = super::deploy();

        let caller: felt252 = caller.try_into().unwrap();
        super::start_cheat_caller_address(nonce.contract_address, caller.try_into().unwrap());
        nonce.revoke_nonce(Option::Some(caller.try_into().expect('fail')), Option::Some(1), 1);
    }

    #[test]
    #[should_panic()]
    fn test_fuzz_should_fail_when_nonce_already_revoked(
        owner: u128, nonce_space: felt252, _nonce: felt252
    ) {
        let nonce = deploy();

        let owner: felt252 = owner.try_into().unwrap();

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![owner.into(), nonce_space, _nonce].span(),
            ),
            array![true.into()].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ACCESS_ENABLED_ADDRESS());
        nonce
            .revoke_nonce(
                Option::Some(owner.try_into().unwrap()), Option::Some(nonce_space), _nonce
            );
    }

    #[test]
    fn test_fuzz_should_store_nonce_as_revoked(owner: u128, nonce_space: felt252, _nonce: felt252) {
        let nonce = deploy();

        let owner: felt252 = owner.try_into().unwrap();

        super::start_cheat_caller_address(nonce.contract_address, ACCESS_ENABLED_ADDRESS());
        nonce
            .revoke_nonce(
                Option::Some(owner.try_into().unwrap()), Option::Some(nonce_space), _nonce
            );

        assert_eq!(nonce.is_nonce_revoked(owner.try_into().unwrap(), nonce_space, _nonce), true);
    }

    #[test]
    fn test_fuzz_should_emit_nonce_revoked(owner: u128, nonce_space: felt252, _nonce: felt252) {
        let nonce = deploy();

        let mut spy = spy_events(super::SpyOn::One(nonce.contract_address));

        let owner: felt252 = owner.try_into().unwrap();
        super::start_cheat_caller_address(nonce.contract_address, ACCESS_ENABLED_ADDRESS());
        nonce
            .revoke_nonce(
                Option::Some(owner.try_into().expect('fail 1')), Option::Some(nonce_space), _nonce
            );

        spy
            .assert_emitted(
                @array![
                    (
                        nonce.contract_address,
                        RevokedNonce::Event::NonceRevoked(
                            RevokedNonce::NonceRevoked {
                                owner: owner.try_into().unwrap(), nonce_space, nonce: _nonce
                            }
                        )
                    )
                ]
            );
    }
}

mod is_nonce_revoked {
    use super::{ALICE, IRevokedNonceDispatcherTrait, map_entry_address,};

    #[test]
    fn test_fuzz_should_return_stored_value(nonce_space: felt252, _nonce: felt252, revoked: u8) {
        let (nonce, _) = super::deploy();

        let revoked: bool = if revoked % 2 == 0 {
            false
        } else {
            true
        };

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![ALICE().into(), nonce_space, _nonce].span(),
            ),
            array![revoked.into()].span()
        );

        assert_eq!(nonce.is_nonce_revoked(ALICE(), nonce_space, _nonce), revoked);
    }
}

mod is_nonce_usable {
    use super::{ALICE, IRevokedNonceDispatcherTrait, map_entry_address,};

    #[test]
    fn test_fuzz_should_return_false_when_nonce_space_is_not_equal_to_current_nonce_space(
        current_nonce_space: felt252, nonce_space: felt252, _nonce: felt252
    ) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![current_nonce_space].span()
        );

        assert_eq!(nonce.is_nonce_usable(ALICE(), nonce_space, _nonce), false);
    }

    #[test]
    fn test_fuzz_should_return_false_when_nonce_is_revoked(_nonce: felt252) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(
                selector!("revoked_nonce"), array![ALICE().into(), 0, _nonce].span(),
            ),
            array![1].span()
        );
    }

    #[test]
    fn test_fuzz_should_return_true_when_nonce_space_is_equal_to_current_nonce_space_when_nonce_is_not_revoked(
        nonce_space: felt252, _nonce: felt252
    ) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        assert_eq!(nonce.is_nonce_usable(ALICE(), nonce_space, _nonce), true);
    }
}

mod revoke_nonce_space {
    use super::{
        ALICE, IRevokedNonceDispatcherTrait, map_entry_address, spy_events, SpyOn, EventSpy,
        EventAssertions, RevokedNonce
    };

    #[test]
    fn test_fuzz_should_increment_current_nonce_space(nonce_space: felt252) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce_space();

        assert_eq!(nonce.current_nonce_space(ALICE()), nonce_space + 1);
    }

    #[test]
    fn test_fuzz_should_emit_nonce_space_revoked(nonce_space: felt252) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        let mut spy = spy_events(super::SpyOn::One(nonce.contract_address));

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        nonce.revoke_nonce_space();

        spy
            .assert_emitted(
                @array![
                    (
                        nonce.contract_address,
                        RevokedNonce::Event::NonceSpaceRevoked(
                            RevokedNonce::NonceSpaceRevoked {
                                owner: ALICE(), nonce_space: nonce_space
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_fuzz_should_return_new_nonce_space(nonce_space: felt252) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        super::start_cheat_caller_address(nonce.contract_address, ALICE());
        let current_nonce_space = nonce.revoke_nonce_space();

        assert_eq!(current_nonce_space, nonce_space + 1);
    }
}

mod current_nonce_space {
    use super::{ALICE, IRevokedNonceDispatcherTrait, map_entry_address,};

    #[test]
    fn test_fuzz_should_return_current_nonce_space(nonce_space: felt252) {
        let (nonce, _) = super::deploy();

        super::store(
            nonce.contract_address,
            map_entry_address(selector!("nonce_space"), array![ALICE().into()].span(),),
            array![nonce_space].span()
        );

        assert_eq!(nonce.current_nonce_space(ALICE()), nonce_space);
    }
}

