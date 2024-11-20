use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnLoan<TState> {
    fn mint(ref self: TState, owner: ContractAddress) -> felt252;
    fn burn(ref self: TState, loan_id: felt252);
    fn name(self: @TState) -> ByteArray;
    fn symbol(self: @TState) -> ByteArray;
    fn token_uri(self: @TState, loan_id: felt252) -> ByteArray;
    fn tokenUri(self: @TState, loan_id: felt252) -> ByteArray;
    fn hub(self: @TState) -> ContractAddress;
    fn last_loan_id(self: @TState) -> felt252;
    fn loan_contract(self: @TState, loan_id: felt252) -> ContractAddress;
}

#[starknet::interface]
pub trait IPwnLoadMetadataProvider<TState> {
    fn loan_metadata_uri(ref self: TState) -> ByteArray;
}

//! The `PwnLoan` module is a core component within the PWN ecosystem, enabling the minting,
//! burning, and metadata management of loan tokens. This module integrates ERC721 and SRC5
//! standards, providing a robust framework for handling loan-related tokens.
//!
//! # Features
//!
//! - **Minting and Burning**: Functions for creating and destroying loan tokens, ensuring proper
//!   lifecycle management.
//! - **Metadata Management**: Provides functionalities to access loan token metadata, including
//!   name, symbol, and URI.
//! - **Interface Compliance**: Implements ERC721 and SRC5 interfaces for compatibility with
//!   existing token standards.
//!
//! # Components
//!
//! - `ERC721Component`: A component that provides ERC721 standard functionalities.
//! - `SRC5Component`: A component that ensures SRC5 compliance for introspection capabilities.
//! - `Err`: Contains error handling functions for various invalid operations and conditions.
//!
//! # Constants
//!
//! - `IERC721_ID`: The interface ID for ERC721, used to register the interface within the module.
//! - `IERC5646_ID`: The interface ID for ERC5646, used to register the interface within the module.
//! - `BASE_DOMAIN_SEPARATOR`: A constant used in computing domain separators for hashing purposes.
//!
//! This module is designed to provide a comprehensive and secure system for managing loan tokens,
//! integrating seamlessly with other components of the PWN ecosystem and Starknet platform.

#[starknet::contract]
pub mod PwnLoan {
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc721::{
        erc721::{ERC721Component, ERC721HooksEmptyImpl}, interface::IERC721_ID
    };

    use pwn::interfaces::erc5646::{IERC5646, IERC5646Dispatcher, IERC5646DispatcherTrait, IERC5646_ID};
    use pwn::hub::{pwn_hub_tags, pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait}};
    use starknet::{ContractAddress, get_caller_address, contract_address_const};
    use super::{IPwnLoadMetadataProviderDispatcher, IPwnLoadMetadataProviderDispatcherTrait};

    component!(path: ERC721Component, storage: erc721, event: ERC721Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl ERC721MixinImpl = ERC721Component::ERC721Impl<ContractState>;
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
    pub enum Event {
        LoanMinted: LoanMinted,
        LoanBurned: LoanBurned,
        #[flat]
        ERC721Event: ERC721Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LoanMinted {
        pub loan_id: felt252,
        pub loan_contract: ContractAddress,
        pub owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LoanBurned {
        pub loan_id: felt252,
    }

    pub mod Err {
        pub fn INVALID_LOAN_CONTRACT_CALLER() {
            panic!("PWNLOAN.burn caller is not a loan contract that minted the LOAN token");
        }
        pub fn CALLER_MISSING_HUB_TAG(tag: felt252) {
            panic!("Caller is missing a PWN Hub tag. Tag: {:?}", tag);
        }
    }

    fn only_active_loan(ref self: ContractState, caller: ContractAddress) {
        let has_tag = self.hub.read().has_tag(caller, pwn_hub_tags::ACTIVE_LOAN);
        if !has_tag {
            Err::CALLER_MISSING_HUB_TAG(pwn_hub_tags::ACTIVE_LOAN);
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState, hub: ContractAddress) {
        self.hub.write(IPwnHubDispatcher { contract_address: hub });
        self.erc721.ERC721_name.write("PWN LOAN");
        self.erc721.ERC721_symbol.write("LOAN");

        self.src5.register_interface(IERC721_ID);
        self.src5.register_interface(IERC5646_ID);
    }

    #[abi(embed_v0)]
    impl IPwnLoanImpl of super::IPwnLoan<ContractState> {
        /// Mints a new loan token and assigns it to the specified owner.
        /// 
        /// # Parameters
        /// - `owner`: The `ContractAddress` of the new token's owner.
        ///
        /// # Returns
        /// The unique identifier (`felt252`) for the newly minted loan token.
        ///
        /// # Emits
        /// - `LoanMinted`: Emitted when a new loan token is successfully minted.
        ///
        /// # Errors
        /// - `CALLER_MISSING_HUB_TAG`: If the caller is missing the required hub tag.
        fn mint(ref self: ContractState, owner: ContractAddress) -> felt252 {
            let caller = get_caller_address();
            only_active_loan(ref self, caller);

            self.last_loan_id.write(self.last_loan_id.read() + 1);
            let loan_id: felt252 = self.last_loan_id.read();

            self.loan_contract.write(loan_id, caller);

            self.erc721.mint(owner, loan_id.into());

            self.emit(LoanMinted { loan_id, loan_contract: caller, owner, });

            loan_id
        }

        /// Burns a specified loan token, effectively destroying it.
        ///
        /// # Parameters
        /// - `loan_id`: The unique identifier (`felt252`) of the loan token to be burned.
        ///
        /// # Emits
        /// - `LoanBurned`: Emitted when a loan token is successfully burned.
        ///
        /// # Errors
        /// - `INVALID_LOAN_CONTRACT_CALLER`: If the caller is not the contract that minted the loan token.
        fn burn(ref self: ContractState, loan_id: felt252) {
            if self.loan_contract.read(loan_id) != get_caller_address() {
                Err::INVALID_LOAN_CONTRACT_CALLER();
            }

            self.loan_contract.write(loan_id, contract_address_const::<0>());
            self.erc721.burn(loan_id.into());

            self.emit(LoanBurned { loan_id });
        }

        /// Retrieves the name of the loan token.
        ///
        /// # Returns
        /// A `ByteArray` containing the name of the token.
        fn name(self: @ContractState) -> ByteArray {
            self.erc721.ERC721_name.read()
        }

        /// Retrieves the symbol of the loan token.
        ///
        /// # Returns
        /// A `ByteArray` containing the symbol of the token.
        fn symbol(self: @ContractState) -> ByteArray {
            self.erc721.ERC721_symbol.read()
        }

        /// Retrieves the metadata URI for a specified loan token.
        ///
        /// # Parameters
        /// - `loan_id`: The unique identifier (`felt252`) of the loan token.
        ///
        /// # Returns
        /// A `ByteArray` containing the metadata URI of the token.
        ///
        /// # Errors
        /// - `TOKEN_NOT_OWNED`: If the specified token is not owned by the caller.
        fn token_uri(self: @ContractState, loan_id: felt252) -> ByteArray {
            self.erc721._require_owned(loan_id.into());

            IPwnLoadMetadataProviderDispatcher {
                contract_address: self.loan_contract.read(loan_id)
            }
                .loan_metadata_uri()
        }

        /// Retrieves the metadata URI for a specified loan token.
        /// 
        /// This function is an alias for `token_uri` to support different naming conventions.
        ///
        /// # Parameters
        /// - `loan_id`: The unique identifier (`felt252`) of the loan token.
        ///
        /// # Returns
        /// A `ByteArray` containing the metadata URI of the token.
        ///
        /// # Errors
        /// - `TOKEN_NOT_OWNED`: If the specified token is not owned by the caller.
        fn tokenUri(self: @ContractState, loan_id: felt252) -> ByteArray {
            self.erc721._require_owned(loan_id.into());

            IPwnLoadMetadataProviderDispatcher {
                contract_address: self.loan_contract.read(loan_id)
            }
                .loan_metadata_uri()
        }

        fn hub(self: @ContractState) -> ContractAddress {
            self.hub.read().contract_address
        }

        fn last_loan_id(self: @ContractState) -> felt252 {
            self.last_loan_id.read()
        }

        fn loan_contract(self: @ContractState, loan_id: felt252) -> ContractAddress {
            self.loan_contract.read(loan_id)
        }
    }

    #[abi(embed_v0)]
    impl IERC5646Impl of IERC5646<ContractState> {
        /// Retrieves the state fingerprint for a specified loan token.
        ///
        /// # Parameters
        /// - `token_id`: The unique identifier of the loan token.
        ///
        /// # Returns
        /// - The computed state fingerprint as `felt252`.
        fn get_state_fingerprint(self: @ContractState, token_id: felt252) -> felt252 {
            let loan_contract_address = self.loan_contract.read(token_id);
            if loan_contract_address == contract_address_const::<0>() {
                return 0;
            }

            IERC5646Dispatcher {
                contract_address: loan_contract_address
            }
                .get_state_fingerprint(token_id)
        }
    }

}
