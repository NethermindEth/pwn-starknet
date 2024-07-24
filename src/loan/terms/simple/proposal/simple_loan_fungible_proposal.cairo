use SimpleLoanFungibleProposal::{Proposal, ProposalValues};
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
pub trait ISimpleLoanFungibleProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal) -> felt252;
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<felt252>,
        signature: Signature,
    ) -> (felt252, Terms);
    fn get_proposal_hash(self: @TState, proposal: Proposal) -> felt252;
    fn encode_proposal_data(
        self: @TState, proposal: Proposal, proposal_values: ProposalValues
    ) -> Array<felt252>;
    fn decode_proposal_data(
        self: @TState, encoded_data: Array<felt252>
    ) -> (Proposal, ProposalValues);
    fn get_credit_amount(
        self: @TState, collateral_amount: u256, credit_per_collateral_unit: u256
    ) -> u256;
}

#[starknet::contract]
pub mod SimpleLoanFungibleProposal {
    use pwn::ContractAddressDefault;
    use pwn::loan::lib::{math, serialization};
    use pwn::loan::terms::simple::proposal::simple_loan_proposal::{
        SimpleLoanProposalComponent, SimpleLoanProposalComponent::ProposalBase
    };
    use pwn::multitoken::library::MultiToken;
    use starknet::ContractAddress;
    use super::{Signature, Terms};

    component!(
        path: SimpleLoanProposalComponent, storage: simple_loan, event: SimpleLoanProposalEvent
    );

    #[abi(embed_v0)]
    impl SimpleLoanProposalImpl =
        SimpleLoanProposalComponent::SimpleLoanProposalImpl<ContractState>;
    impl SimpleLoanProposalInternal = SimpleLoanProposalComponent::InternalImpl<ContractState>;
    // NOTE: we can hard code this by calculating the poseidon hash of the string 
    // in the Solidity contract offline.
    pub const PROPOSAL_TYPEHASH: felt252 =
        0x062dbce0eca7d4486c66e0d48cdd72744db07523b68e9e4dad30aa4bee1356;
    pub const CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR: u256 =
        100_000_000_000_000_000_000_000_000_000_000_000_000;
    pub const FUNGIBLE_PROPOSAL_DATA_LEN: usize = 29;

    #[derive(Copy, Default, Drop, Serde)]
    pub struct Proposal {
        pub collateral_category: MultiToken::Category,
        pub collateral_address: ContractAddress,
        pub collateral_id: felt252,
        pub min_collateral_amount: u256,
        pub check_collateral_state_fingerprint: bool,
        pub collateral_state_fingerprint: felt252,
        pub credit_address: ContractAddress,
        pub credit_per_collateral_unit: u256,
        pub available_credit_limit: u256,
        pub fixed_interest_amount: u256,
        pub accruing_interest_APR: u32,
        pub duration: u64,
        pub expiration: u64,
        pub allowed_acceptor: ContractAddress,
        pub proposer: ContractAddress,
        pub proposer_spec_hash: felt252,
        pub is_offer: bool,
        pub refinancing_loan_id: felt252,
        pub nonce_space: felt252,
        pub nonce: felt252,
        pub loan_contract: ContractAddress,
    }


    #[derive(Copy, Default, Drop, Serde)]
    pub struct ProposalValues {
        pub collateral_amount: u256,
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        simple_loan: SimpleLoanProposalComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ProposalMade: ProposalMade,
        #[flat]
        SimpleLoanProposalEvent: SimpleLoanProposalComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProposalMade {
        pub proposal_hash: felt252,
        pub proposer: ContractAddress,
        pub proposal: Proposal,
    }

    mod Err {
        pub fn MIN_COLLATERAL_AMOUNT_NOT_SET() {
            panic!("Proposal has no minimal collateral amount set");
        }
        pub fn INSUFFICIENT_COLLATERAL_AMOUNT(current: u256, limit: u256) {
            panic!("Insufficient collateral amount. Current: {}, Limit: {}", current, limit);
        }
        pub fn INVALID_PROPOSAL_DATA(len: usize) {
            panic!(
                "Invalid proposal data length: {}, expected: {}",
                len,
                super::FUNGIBLE_PROPOSAL_DATA_LEN
            );
        }
    }


    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        revoke_nonce: ContractAddress,
        config: ContractAddress,
        name: felt252,
        version: felt252
    ) {
        self.simple_loan._initialize(hub, revoke_nonce, config, name, version);
    }

    #[abi(embed_v0)]
    impl SimpleLoanDutchAuctionProposalImpl of super::ISimpleLoanFungibleProposal<ContractState> {
        fn make_proposal(ref self: ContractState, proposal: Proposal) -> felt252 {
            let proposal_hash = self.get_proposal_hash(proposal);
            self.simple_loan._make_proposal(proposal_hash, proposal.proposer);

            self.emit(ProposalMade { proposal_hash, proposer: proposal.proposer, proposal, });

            proposal_hash
        }

        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<felt252>,
            signature: Signature
        ) -> (felt252, super::Terms) {
            if proposal_data.len() != FUNGIBLE_PROPOSAL_DATA_LEN {
                Err::INVALID_PROPOSAL_DATA(proposal_data.len());
            }

            let (proposal, proposal_values) = self.decode_proposal_data(proposal_data);
            // NOTE: add check for proposal data integrity to this and all other proposals

            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            let proposal_hash = self
                .simple_loan
                ._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal);

            if proposal.min_collateral_amount == 0 {
                Err::MIN_COLLATERAL_AMOUNT_NOT_SET();
            }

            if proposal_values.collateral_amount < proposal.min_collateral_amount {
                Err::INSUFFICIENT_COLLATERAL_AMOUNT(
                    proposal_values.collateral_amount, proposal.min_collateral_amount
                );
            }

            let credit_amount = self
                .get_credit_amount(
                    proposal_values.collateral_amount, proposal.credit_per_collateral_unit
                );

            let proposal_base = ProposalBase {
                collateral_address: proposal.collateral_address,
                collateral_id: proposal.collateral_id,
                check_collateral_state_fingerprint: proposal.check_collateral_state_fingerprint,
                collateral_state_fingerprint: proposal.collateral_state_fingerprint,
                credit_amount: credit_amount,
                available_credit_limit: proposal.available_credit_limit,
                expiration: proposal.expiration,
                allowed_acceptor: proposal.allowed_acceptor,
                proposer: proposal.proposer,
                is_offer: proposal.is_offer,
                refinancing_loan_id: proposal.refinancing_loan_id,
                nonce_space: proposal.nonce_space,
                nonce: proposal.nonce,
                loan_contract: proposal.loan_contract,
            };

            self
                .simple_loan
                ._accept_proposal(
                    acceptor,
                    refinancing_loan_id,
                    proposal_hash,
                    proposal_inclusion_proof,
                    signature,
                    proposal_base
                );

            let loan_terms = Terms {
                lender: if proposal.is_offer {
                    proposal.proposer
                } else {
                    acceptor
                },
                borrower: if proposal.is_offer {
                    acceptor
                } else {
                    proposal.proposer
                },
                duration: proposal.duration,
                collateral: MultiToken::Asset {
                    category: proposal.collateral_category,
                    asset_address: proposal.collateral_address,
                    id: proposal.collateral_id,
                    amount: proposal_values.collateral_amount,
                },
                credit: MultiToken::ERC20(proposal.credit_address, credit_amount),
                fixed_interest_amount: proposal.fixed_interest_amount,
                accruing_interest_APR: proposal.accruing_interest_APR,
                lender_spec_hash: if proposal.is_offer {
                    proposal.proposer_spec_hash
                } else {
                    0
                },
                borrower_spec_hash: if proposal.is_offer {
                    0
                } else {
                    proposal.proposer_spec_hash
                },
            };

            (proposal_hash, loan_terms)
        }

        fn get_proposal_hash(self: @ContractState, proposal: Proposal) -> felt252 {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            self.simple_loan._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal)
        }

        fn encode_proposal_data(
            self: @ContractState, proposal: Proposal, proposal_values: ProposalValues
        ) -> Array<felt252> {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);

            let mut serialized_proposal_values = array![];
            proposal_values.serialize(ref serialized_proposal_values);

            serialization::serde_concat(
                serialized_proposal.span(), serialized_proposal_values.span()
            )
        }

        fn decode_proposal_data(
            self: @ContractState, encoded_data: Array<felt252>
        ) -> (Proposal, ProposalValues) {
            if encoded_data.len() != FUNGIBLE_PROPOSAL_DATA_LEN {
                Err::INVALID_PROPOSAL_DATA(encoded_data.len());
            }

            let (proposal_data, proposal_values_data) = serialization::serde_decompose(
                encoded_data.span()
            );
            let proposal = self.decode_serde_proposal(proposal_data);
            let proposal_values = self.decode_serde_proposal_values(proposal_values_data);

            (proposal, proposal_values)
        }

        fn get_credit_amount(
            self: @ContractState, collateral_amount: u256, credit_per_collateral_unit: u256
        ) -> u256 {
            math::mul_div(
                collateral_amount,
                credit_per_collateral_unit,
                CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR
            )
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn decode_serde_proposal(self: @ContractState, data: Span<felt252>) -> Proposal {
            let collateral_category = match *data.at(0) {
                0 => MultiToken::Category::ERC20,
                1 => MultiToken::Category::ERC721,
                2 => MultiToken::Category::ERC1155,
                _ => panic!("Invalid collateral category"),
            };
            let collateral_address: ContractAddress = (*data.at(1))
                .try_into()
                .expect('decode_serde_proposal');
            let min_collateral_low: u128 = (*data.at(3)).try_into().expect('decode_serde_proposal');
            let min_collateral_high: u128 = (*data.at(4))
                .try_into()
                .expect('decode_serde_proposal');
            let credit_address: ContractAddress = (*data.at(7))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_unit_low: u128 = (*data.at(8))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_unit_high: u128 = (*data.at(9))
                .try_into()
                .expect('decode_serde_proposal');
            let credit_limit_low: u128 = (*data.at(10)).try_into().expect('decode_serde_proposal');
            let credit_limit_high: u128 = (*data.at(11)).try_into().expect('decode_serde_proposal');
            let fixed_interest_low: u128 = (*data.at(12))
                .try_into()
                .expect('decode_serde_proposal');
            let fixed_interest_high: u128 = (*data.at(13))
                .try_into()
                .expect('decode_serde_proposal');
            let accruing_interest_APR: u32 = (*data.at(14))
                .try_into()
                .expect('decode_serde_proposal');
            let duration: u64 = (*data.at(15)).try_into().expect('decode_serde_proposal');
            let expiration: u64 = (*data.at(16)).try_into().expect('decode_serde_proposal');
            let allowed_acceptor: ContractAddress = (*data.at(17))
                .try_into()
                .expect('decode_serde_proposal');
            let proposer: ContractAddress = (*data.at(18))
                .try_into()
                .expect('decode_serde_proposal');
            let loan_contract: ContractAddress = (*data.at(24))
                .try_into()
                .expect('decode_serde_proposal');

            Proposal {
                collateral_category,
                collateral_address,
                collateral_id: *data.at(2),
                min_collateral_amount: u256 { low: min_collateral_low, high: min_collateral_high },
                check_collateral_state_fingerprint: if *data.at(5) == 1 {
                    true
                } else {
                    false
                },
                collateral_state_fingerprint: *data.at(6),
                credit_address,
                credit_per_collateral_unit: u256 {
                    low: collateral_unit_low, high: collateral_unit_high
                },
                available_credit_limit: u256 { low: credit_limit_low, high: credit_limit_high },
                fixed_interest_amount: u256 { low: fixed_interest_low, high: fixed_interest_high },
                accruing_interest_APR,
                duration,
                expiration,
                allowed_acceptor,
                proposer,
                proposer_spec_hash: *data.at(19),
                is_offer: if *data.at(20) == 1 {
                    true
                } else {
                    false
                },
                refinancing_loan_id: *data.at(21),
                nonce_space: *data.at(22),
                nonce: *data.at(23),
                loan_contract,
            }
        }

        fn decode_serde_proposal_values(
            self: @ContractState, data: Span<felt252>
        ) -> ProposalValues {
            let amount_low: u128 = (*data.at(0)).try_into().expect('decode_serde_proposal_values');
            let amount_high: u128 = (*data.at(1)).try_into().expect('decode_serde_proposal_values');

            ProposalValues { collateral_amount: u256 { low: amount_low, high: amount_high, }, }
        }
    }
}

