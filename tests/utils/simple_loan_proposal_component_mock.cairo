#[starknet::contract]
pub mod MockSimpleLoanProposal {
    use pwn::loan::terms::simple::proposal::simple_loan_proposal::SimpleLoanProposalComponent;

    component!(
        path: SimpleLoanProposalComponent,
        storage: simple_loan_proposal,
        event: SimpleLoanProposalEvent
    );

    #[storage]
    struct Storage {
        #[substorage(v0)]
        simple_loan_proposal: SimpleLoanProposalComponent::Storage,
    }
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        SimpleLoanProposalEvent: SimpleLoanProposalComponent::Event,
    }
    #[abi(embed_v0)]
    impl SimpleLoanProposalImpl =
        SimpleLoanProposalComponent::SimpleLoanProposalImpl<ContractState>;
    impl SimpleLoanProposalInternalImpl = SimpleLoanProposalComponent::InternalImpl<ContractState>;
}
