use starknet::ContractAddress;

#[starknet::interface]
pub trait IMultitokenCategoryRegistry<TState> {
    fn register_category_value(ref self: TState, asset_address: ContractAddress, category: u8);
    fn unregister_category_value(ref self: TState, asset_address: ContractAddress);
    fn registered_category_value(self: @TState, asset_address: ContractAddress) -> u8;
}

#[starknet::contract]
pub mod MultitokenCategoryRegistry {
    use openzeppelin::access::ownable::ownable::OwnableComponent::InternalTrait;
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::{ContractAddress, get_caller_address};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        registered_category: LegacyMap::<ContractAddress, u8>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        CategoryRegistered: CategoryRegistered,
        CategoryUnregistered: CategoryUnregistered,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CategoryRegistered {
        #[key]
        pub asset_address: ContractAddress,
        #[key]
        pub category: u8,
    }

    #[derive(Drop, starknet::Event)]
   pub struct CategoryUnregistered {
        #[key]
        pub asset_address: ContractAddress,
    }

    pub mod Err {
        pub fn RESERVED_CATEGORY_VALUE() {
            panic!("Cannot use reserved category value");
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.ownable.initializer(starknet::get_caller_address());
    }

    pub const CATEGORY_NOT_REGISTERED: u8 = 255;

    #[abi(embed_v0)]
    impl IMultitokenCategoryRegistryImpl of super::IMultitokenCategoryRegistry<ContractState> {
        fn register_category_value(
            ref self: ContractState, asset_address: ContractAddress, category: u8
        ) {
            self.ownable.assert_only_owner();

            if category == CATEGORY_NOT_REGISTERED {
                Err::RESERVED_CATEGORY_VALUE();
            }

            self.registered_category.write(asset_address, category + 1);

            self.emit(CategoryRegistered { asset_address, category, });
        }

        fn unregister_category_value(ref self: ContractState, asset_address: ContractAddress) {
            self.ownable.assert_only_owner();

            self.registered_category.write(asset_address, 0);

            self.emit(CategoryUnregistered { asset_address, });
        }

        fn registered_category_value(self: @ContractState, asset_address: ContractAddress) -> u8 {
            let category: u8 = self.registered_category.read(asset_address);

            if category == 0 {
                return CATEGORY_NOT_REGISTERED;
            }

            category - 1
        }
    }
}
// NOTE: ERC165 supportsInterface is not implemented in this contract


