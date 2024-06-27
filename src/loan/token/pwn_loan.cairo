use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnLoan<TState> {
    fn mint(ref self: TState, owner: ContractAddress) -> felt252;
    fn burn(ref self: TState, loan_id: felt252);
}

#[starknet::interface]
pub trait IPwnLoadMetadataProvider<TState> {
    fn loan_metadata_uri(ref self: TState) -> felt252;
}

#[starknet::interface]
pub trait IERC5646<TState> {
    fn get_state_fingerprint(ref self: TState, token_id: felt252) -> felt252;
}

#[starknet::contract]
mod PwnLoan {
    use openzeppelin::token::erc721::erc721::ERC721Component::InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc721::erc721::{ERC721Component, ERC721HooksEmptyImpl};
    use pwn::hub::{pwn_hub_tags, IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use starknet::{ContractAddress, get_caller_address, contract_address_const};
    use super::{IPwnLoadMetadataProviderDispatcher, IPwnLoadMetadataProviderDispatcherTrait};
    use super::IERC5646Dispatcher;

    component!(path: ERC721Component, storage: erc721, event: ERC721Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl ERC721Impl = ERC721Component::ERC721Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721CamelOnlyImpl = ERC721Component::ERC721CamelOnlyImpl<ContractState>;
    impl ERC721MetadataImpl = ERC721Component::ERC721MetadataImpl<ContractState>;
    impl ERC721InternalImpl = ERC721Component::InternalImpl<ContractState>;

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
    }

    #[abi(embed_v0)]
    impl IPwnLoanImpl of super::IPwnLoan<ContractState> {
        fn mint(ref self: ContractState, owner: ContractAddress) -> felt252 {
            let caller = get_caller_address();
            only_active_loan(ref self, caller);

            self.last_loan_id.write(self.last_loan_id.read() + 1);
            let loan_id : felt252 = self.last_loan_id.read();

            self.loan_contract.write(loan_id, caller);

            self.erc721.mint(owner, loan_id.into());

            self.emit(LoanMinted{
                loan_id,
                loan_contract: caller,
                owner,
            })

            loan_id
        }

        fn burn(ref self: ContractState, loan_id: felt252) {
            if self.loan_contract.read(loan_id) != get_caller_address() {
                Err::INVALID_LOAN_CONTRACT_CALLER();
            }

            self.loan_contract.write(loan_id, contract_address_const::<0>());
            self.erc721.burn(loan_id.into());

            self.emit(LoanBurned { loan_id });
        }

        // Impl item function `IPwnLoanImpl::token_uri` is not a member of trait `IPwnLoan`.
        // Q: Where should this function be placed?
        fn token_uri(self: @ContractState, loan_id: felt252) -> felt252 {
            self.erc721._require_owned(loan_id);

            // Method `loan_metadata_uri` not found on type `pwn::token::pwn_loan::IPwnLoadMetadataProviderDispatcher`. Did you import the correct trait and impl?
            // Q: How to fix this?
            IPwnLoadMetadataProviderDispatcher { contract_address: self.loan_contract.read(loan_id) }.loan_metadata_uri()
        }

        // Q: Same as above
        fn get_state_fingerprint(self: @ContractState, loan_id: felt252) -> felt252 {
            let _loan_contract = self.loan_contract.read(loan_id);

            if _loan_contract == contract_address_const::<0>() {
                return 0; // Q: How to format this to bytes32?
            }

            // Method `get_state_fingerprint` not found on type `pwn::token::pwn_loan::IERC5646Dispatcher`. Did you import the correct trait and impl?
            // Q: How to fix this?
            IERC5646Dispatcher { contract_address: _loan_contract }.get_state_fingerprint(loan_id);
        }


    }
}