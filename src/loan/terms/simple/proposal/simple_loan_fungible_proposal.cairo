use SimpleLoanFungibleProposal::{Proposal, ProposalValues};
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
trait ISimpleLoanFungibleProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal);
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<felt252>,
        signature: felt252
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
mod SimpleLoanFungibleProposal {
    use pwn::ContractAddressDefault;
    use pwn::loan::lib::serialization;
    use pwn::loan::terms::simple::proposal::simple_loan_proposal::{
        SimpleLoanProposalComponent, SimpleLoanProposalComponent::ProposalBase
    };
    use pwn::multitoken::library::MultiToken;
    use starknet::ContractAddress;

    component!(
        path: SimpleLoanProposalComponent, storage: simple_loan, event: SimpleLoanProposalEvent
    );

    #[abi(embed_v0)]
    impl SimpleLoanProposalImpl =
        SimpleLoanProposalComponent::SimpleLoanProposalImpl<ContractState>;
    impl SimpleLoanProposalInternal = SimpleLoanProposalComponent::InternalImpl<ContractState>;
    // NOTE: we can hard code this by calculating the poseidon hash of the string 
    // in the Solidity contract offline.
    const PROPOSAL_TYPEHASH: felt252 =
        0x062dbce0eca7d4486c66e0d48cdd72744db07523b68e9e4dad30aa4bee1356;

    #[derive(Copy, Default, Drop, Serde)]
    pub struct Proposal {
        collateral_category: MultiToken::Category,
        collateral_address: ContractAddress,
        collateral_id: felt252,
        min_collateral_amount: u256,
        check_collateral_state_fingerprint: bool,
        collateral_state_fingerprint: felt252,
        credit_address: ContractAddress,
        credit_per_collateral_unit: u256,
        available_credit_limit: u256,
        fixed_interest_amount: u256,
        accruing_interest_APR: u32,
        duration: u64,
        auction_start: u64,
        auction_duration: u64,
        allowed_acceptor: ContractAddress,
        proposer: ContractAddress,
        proposer_spec_hash: felt252,
        is_offer: bool,
        refinancing_loan_id: felt252,
        nonce_space: felt252,
        nonce: felt252,
        loan_contract: ContractAddress,
    }


    #[derive(Default, Drop, Serde)]
    pub struct ProposalValues {
        collateral_amount: u256,
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        simple_loan: SimpleLoanProposalComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProposalMade: ProposalMade,
        #[flat]
        SimpleLoanProposalEvent: SimpleLoanProposalComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct ProposalMade {
        proposal_hash: felt252,
        proposer: ContractAddress,
        proposal: Proposal,
    }

    mod Err {
        fn MIN_COLLATERAL_AMOUNT_NOT_SET() {
            panic!("Proposal has no minimal collateral amount set");
        }
        fn INSUFFICIENT_COLLATERAL_AMOUNT(current: u64, limit: u64) {
            panic!("Insufficient collateral amount. Current: {}, Limit: {}", current, limit);
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
        fn make_proposal(ref self: ContractState, proposal: Proposal) {
            let proposal_hash = self.get_proposal_hash(proposal);
            self.simple_loan._make_proposal(proposal_hash, proposal.proposer);

            self.emit(ProposalMade { proposal_hash, proposer: proposal.proposer, proposal, });
        }

        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<felt252>,
            signature: felt252
        ) -> (felt252, super::Terms) {
            (0.try_into().unwrap(), Default::default())
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
            0
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
            let collateral_address: ContractAddress = (*data.at(1)).try_into().unwrap();
            let min_collateral_low: u128 = (*data.at(3)).try_into().unwrap();
            let min_collateral_high: u128 = (*data.at(4)).try_into().unwrap();
            let credit_address: ContractAddress = (*data.at(7)).try_into().unwrap();
            let collateral_unit_low: u128 = (*data.at(8)).try_into().unwrap();
            let collateral_unit_high: u128 = (*data.at(9)).try_into().unwrap();
            let credit_limit_low: u128 = (*data.at(10)).try_into().unwrap();
            let credit_limit_high: u128 = (*data.at(11)).try_into().unwrap();
            let fixed_interest_low: u128 = (*data.at(12)).try_into().unwrap();
            let fixed_interest_high: u128 = (*data.at(13)).try_into().unwrap();
            let accruing_interest_APR: u32 = (*data.at(14)).try_into().unwrap();
            let duration: u64 = (*data.at(15)).try_into().unwrap();
            let auction_start: u64 = (*data.at(16)).try_into().unwrap();
            let auction_duration: u64 = (*data.at(17)).try_into().unwrap();
            let allowed_acceptor: ContractAddress = (*data.at(20)).try_into().unwrap();
            let proposer: ContractAddress = (*data.at(21)).try_into().unwrap();
            let loan_contract: ContractAddress = (*data.at(23)).try_into().unwrap();

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
                auction_start,
                auction_duration,
                allowed_acceptor,
                proposer,
                proposer_spec_hash: *data.at(18),
                is_offer: if *data.at(19) == 1 {
                    true
                } else {
                    false
                },
                refinancing_loan_id: *data.at(20),
                nonce_space: *data.at(21),
                nonce: *data.at(22),
                loan_contract,
            }
        }

        fn decode_serde_proposal_values(
            self: @ContractState, data: Span<felt252>
        ) -> ProposalValues {
            let amount_low: u128 = (*data.at(0)).try_into().unwrap();
            let amount_high: u128 = (*data.at(1)).try_into().unwrap();

            ProposalValues { collateral_amount: u256 { low: amount_low, high: amount_high, }, }
        }
    }
}

