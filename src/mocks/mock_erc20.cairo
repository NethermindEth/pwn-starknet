// Mock ERC20 contract
#[starknet::contract]
pub mod MockERC20 {
    use core::starknet::event::EventEmitter;
    use openzeppelin::token::erc20::{
        ERC20Component, ERC20HooksEmptyImpl,
        interface::{IERC20, IERC20Dispatcher, IERC20DispatcherTrait}
    };

    // ERC20 Component
    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    // Exposes snake_case & CamelCase entry points
    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    // Allows the contract access to internal functions
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.erc20.initializer("MockERC20", "M20");
    }

    #[external(v0)]
    fn mint(ref self: ContractState, recipient: starknet::ContractAddress, amount: u256) {
        self.erc20.mint(recipient, amount);
    }
}
