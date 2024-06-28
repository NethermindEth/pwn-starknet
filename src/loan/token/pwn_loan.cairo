use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnLoan<TState> {
    fn mint(ref self: TState, owner: ContractAddress) -> felt252;
    fn burn(ref self: TState, loan_id: felt252);
}

#[starknet::contract]
mod PwnLoan {
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc721::{
        erc721::{ERC721Component, ERC721HooksEmptyImpl}, interface::IERC721_ID
    };
    use pwn::hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use starknet::ContractAddress;

    component!(path: ERC721Component, storage: erc721, event: ERC721Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl ERC721Impl = ERC721Component::ERC721Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721CamelOnlyImpl = ERC721Component::ERC721CamelOnlyImpl<ContractState>;
    impl ERC721InternalImpl = ERC721Component::InternalImpl<ContractState>;
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        hub: IPwnHubDispatcher,
        last_loan_id: felt252,
        loan_contract: LegacyMap::<felt252, ContractAddress>,
        #[substorage(v0)]
        erc721: ERC721Component::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        LoanMinted: LoanMinted,
        LoanBurned: LoanBurned,
        #[flat]
        ERC721Event: ERC721Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct LoanMinted {
        loan_id: felt252,
        loan_contract: ContractAddress,
        owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct LoanBurned {
        loan_id: felt252,
    }

    pub mod Err {
        fn INVALID_LOAN_CONTRACT_CALLER() {
            panic!("PWNLOAN.burn caller is not a loan contract that minted the LOAN token");
        }
        fn CALLER_MISSING_HUB_TAG(tag: felt252) {
            panic!("Caller is missing a PWN Hub tag. Tag: {:?}", tag);
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState, hub: ContractAddress) {}

    #[abi(embed_v0)]
    impl IPwnLoanImpl of super::IPwnLoan<ContractState> {
        fn mint(ref self: ContractState, owner: ContractAddress) -> felt252 {
            0
        }

        fn burn(ref self: ContractState, loan_id: felt252) {}
    }
}
