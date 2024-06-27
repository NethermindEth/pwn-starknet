#[starknet::contract]
mod PwnSimpleLoan {
    use pwn::loan::terms::simple::loan::{
        types::{
            GetLoanReturnValue, CallerSpec, ExtensionProposal, LenderSpec, Loan, ProposalSpec, Terms
        },
        interface::IPwnSimpleLoan
    };
    use pwn::hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use pwn::loan::token::pwn_loan::{IPwnLoanDispatcher, IPwnLoanDispatcherTrait};
    use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
    use pwn::nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait};
    use pwn::multitoken::category_registry::{IMultitokenCategoryRegistryDispatcher, IMultitokenCategoryRegistryDispatcherTrait};
    use pwn::loan::vault::permit::Permit;
    use pwn::multitoken::library::MultiToken::Asset;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        loans: LegacyMap::<felt252, Loan>,
        extension_proposal_made: LegacyMap::<felt252, bool>,
        hub: IPwnHubDispatcher,
        loan_token: IPwnLoanDispatcher,
        config: IPwnConfigDispatcher,
        revoked_nonce: IRevokedNonceDispatcher,
        category_registry: IMultitokenCategoryRegistryDispatcher
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        LoanCreated: LoanCreated,
        LoanPaidBack: LoanPaidBack,
        LoanClaimed: LoanClaimed,
        LoanExtended: LoanExtended,
        ExtensionProposalMade: ExtensionProposalMade,
    }

    #[derive(Drop, starknet::Event)]
    struct LoanCreated {
        loan_id: felt252,
        proposal_hash: felt252,
        proposal_contract: ContractAddress,
        refinancing_loan_id: felt252,
        terms: Terms,
        lender_spec: LenderSpec,
        extra: Array<felt252>
    }

    #[derive(Drop, starknet::Event)]
    struct LoanPaidBack {
        loan_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct LoanClaimed {
        loan_id: felt252,
        defaulted: bool
    }

    #[derive(Drop, starknet::Event)]
    struct LoanExtended {
        loan_id: felt252,
        original_default_timestamp: u64,
        extended_default_timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ExtensionProposalMade {
        extension_hash: felt252,
    // proposer: ContractAddress,
    // extension_proposal: ExtensionProposal,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        loan_token: ContractAddress,
        config: ContractAddress,
        revoked_nonce: ContractAddress,
        category_registry: ContractAddress
    ) {
        let hub_dispatcher = IPwnHubDispatcher {contract_address: hub};
        let loan_token_dispatcher = IPwnLoanDispatcher {contract_address: loan_token};
        let config_dispatcher = IPwnConfigDispatcher {contract_address: config};
        let revoked_nonce_dispatcher = IRevokedNonceDispatcher {contract_address: revoked_nonce};
        let category_registry_dispatcher = IMultitokenCategoryRegistryDispatcher {contract_address: category_registry};
        self.hub.write(hub_dispatcher);
        self.loan_token.write(loan_token_dispatcher);
        self.config.write(config_dispatcher);
        self.revoked_nonce.write(revoked_nonce_dispatcher);
        self.category_registry.write(category_registry_dispatcher);
    }

    #[abi(embed_v0)]
    impl PwnSimpleLoanImpl of IPwnSimpleLoan<ContractState> {
        fn create_loan(
            ref self: ContractState,
            proposal_spec: ProposalSpec,
            lender_spec: LenderSpec,
            caller_spec: CallerSpec,
            extra: Option<Array<felt252>>
        ) -> felt252 {
            0
        }

        fn repay_loan(ref self: ContractState, loan_id: felt252, permit_data: felt252) {}

        fn claim_loan(ref self: ContractState, loan_id: felt252) {}

        fn try_claim_repaid_loan(
            ref self: ContractState,
            loan_id: felt252,
            credit_amount: u256,
            loan_owner: ContractAddress
        ) {}

        fn make_extension_proposal(ref self: ContractState, extension: ExtensionProposal) {}

        fn extend_loan(
            ref self: ContractState,
            extension: ExtensionProposal,
            signature: felt252,
            permit_data: felt252
        ) {}

        fn get_lender_spec_hash(self: @ContractState, calladata: Array<felt252>) -> felt252 {
            0
        }

        fn get_loan_repayment_amount(self: @ContractState, loan_id: felt252) -> u256 {
            0
        }

        fn get_extension_hash(self: @ContractState, extension: ExtensionProposal) -> felt252 {
            0
        }

        fn get_loan(self: @ContractState, loan_id: felt252) -> GetLoanReturnValue {
            Default::default()
        }

        fn get_is_valid_asset(self: @ContractState, asset: Asset) -> bool {
            true
        }

        fn get_loan_metadata_uri(self: @ContractState) -> ByteArray {
            Default::default()
        }

        fn get_state_fingerprint(self: @ContractState) -> felt252 {
            0
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn _check_permit(
            ref self: ContractState, credit_address: ContractAddress, permit: Permit
        ) {}

        fn _check_refinance_loan_terms(
            ref self: ContractState, loan_id: felt252, loan_terms: Terms
        ) {}

        fn _create_loan(ref self: ContractState, terms: Terms, lender_spec: LenderSpec) {}

        fn _settle_new_loan(ref self: ContractState, terms: Terms, lender_spec: LenderSpec) {}

        fn _settle_loan_refinance(
            ref self: ContractState,
            refinancing_loan_id: felt252,
            loan_terms: Terms,
            lender_spec: LenderSpec,
            extra: Array<felt252>
        ) {}

        fn _withdraw_credit_from_pool(
            ref self: ContractState, credit: Asset, loan_terms: Terms, lender_spec: LenderSpec
        ) {}

        fn _check_loan_can_be_repaid(ref self: ContractState, status: u8, default_timestamp: u64) {}

        fn _update_repaid_loan(ref self: ContractState, loan_id: felt252) {}

        fn _load_accrued_interest(ref self: ContractState, loan: Loan) -> u256 {
            0
        }

        fn _settle_loan_claim(ref self: ContractState, loan_id: felt252, defaulted: bool) {}

        fn _delete_loan(ref self: ContractState, loan_id: felt252) {}

        fn _get_loan_status(ref self: ContractState, loan_id: felt252) -> u8 {
            0
        }

        fn _check_valid_asset(ref self: ContractState, asset: Asset) {}
    }
}
