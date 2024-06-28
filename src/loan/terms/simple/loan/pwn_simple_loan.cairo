#[starknet::contract]
mod PwnSimpleLoan {
    use openzeppelin::token::erc721::{interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait}};
    use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
    use pwn::hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use pwn::loan::lib::fee_calculator;
    use pwn::loan::terms::simple::loan::error;
    use pwn::loan::terms::simple::loan::{
        types::{
            GetLoanReturnValue, CallerSpec, ExtensionProposal, LenderSpec, Loan, ProposalSpec, Terms
        },
        interface::IPwnSimpleLoan
    };
    use pwn::loan::token::pwn_loan::{IPwnLoanDispatcher, IPwnLoanDispatcherTrait};
    use pwn::loan::vault::permit::{Permit};
    use pwn::loan::vault::permit;
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::category_registry::{
        IMultitokenCategoryRegistryDispatcher, IMultitokenCategoryRegistryDispatcherTrait
    };
    use pwn::multitoken::library::MultiToken::Asset;
    use pwn::nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait};
    use starknet::ContractAddress;

    component!(path: PwnVaultComponent, storage: vault, event: VaultEvent);

    #[storage]
    struct Storage {
        loans: LegacyMap::<felt252, Loan>,
        extension_proposal_made: LegacyMap::<felt252, bool>,
        hub: IPwnHubDispatcher,
        loan_token: IPwnLoanDispatcher,
        config: IPwnConfigDispatcher,
        revoked_nonce: IRevokedNonceDispatcher,
        category_registry: IMultitokenCategoryRegistryDispatcher,
        #[substorage(v0)]
        vault: PwnVaultComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        LoanCreated: LoanCreated,
        LoanPaidBack: LoanPaidBack,
        LoanClaimed: LoanClaimed,
        LoanExtended: LoanExtended,
        ExtensionProposalMade: ExtensionProposalMade,
        VaultEvent: PwnVaultComponent::Event
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
        let hub_dispatcher = IPwnHubDispatcher { contract_address: hub };
        let loan_token_dispatcher = IPwnLoanDispatcher { contract_address: loan_token };
        let config_dispatcher = IPwnConfigDispatcher { contract_address: config };
        let revoked_nonce_dispatcher = IRevokedNonceDispatcher { contract_address: revoked_nonce };
        let category_registry_dispatcher = IMultitokenCategoryRegistryDispatcher {
            contract_address: category_registry
        };
        self.hub.write(hub_dispatcher);
        self.loan_token.write(loan_token_dispatcher);
        self.config.write(config_dispatcher);
        self.revoked_nonce.write(revoked_nonce_dispatcher);
        self.category_registry.write(category_registry_dispatcher);
    }

    impl IPwnVault = PwnVaultComponent::InternalImpl<ContractState>;

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
        fn _check_permit(ref self: ContractState, credit_address: ContractAddress, permit: Permit) {
            let caller = starknet::get_caller_address();
            let const_address = starknet::contract_address_const::<'0'>();
            if (permit.asset != const_address) {
                if (permit.owner != caller) {
                    permit::Err::InvalidPermitOwner(current: permit.owner, expected: caller);
                }
                if (permit.asset != credit_address) {
                    permit::Err::InvalidPermitAsset(
                        current: permit.asset, expected: credit_address
                    );
                }
            }
        }

        fn _check_refinance_loan_terms(
            ref self: ContractState, loan_id: felt252, loan_terms: Terms
        ) {
            let loan = self.loans.read(loan_id);

            if (loan.credit_address != loan_terms.credit.asset_address
                || loan_terms.credit.amount == 0) {
                error::Err::REFINANCE_CREDIT_MISMATCH();
            }

            if (loan.collateral.category != loan_terms.collateral.category
                || loan.collateral.asset_address != loan_terms.collateral.asset_address
                || loan.collateral.id != loan_terms.collateral.id
                || loan.collateral.amount != loan_terms.collateral.amount) {
                error::Err::REFINANCE_COLLATERAL_MISMATCH();
            }

            if (loan.borrower != loan_terms.borrower) {
                error::Err::REFINANCE_BORROWER_MISMATCH(
                    currrent_borrower: loan.borrower, new_borrower: loan_terms.borrower
                );
            }
        }

        fn _create_loan(ref self: ContractState, loan_terms: Terms, lender_spec: LenderSpec) {
            let loan_id = self.loan_token.read().mint(loan_terms.lender);
            let current_timestamp = starknet::get_execution_info()
                .unbox()
                .block_info
                .unbox()
                .block_timestamp;
            let loan = Loan {
                status: 2,
                credit_address: loan_terms.credit.asset_address,
                original_source_of_funds: lender_spec.source_of_funds,
                start_timestamp: current_timestamp,
                default_timestamp: current_timestamp + loan_terms.duration,
                borrower: loan_terms.borrower,
                original_lender: loan_terms.lender,
                accruing_interest_APR: loan_terms.accruing_interest_APR,
                fixed_interest_amount: loan_terms.fixed_interest_amount,
                principal_amount: loan_terms.credit.amount,
                collateral: loan_terms.collateral
            };
            self.loans.write(loan_id, loan);
        }

        fn _settle_new_loan(ref self: ContractState, loan_terms: Terms, lender_spec: LenderSpec) {
            self.vault._pull(loan_terms.collateral, loan_terms.borrower);
            if (lender_spec.source_of_funds != loan_terms.lender) {
                self._withdraw_credit_from_pool(loan_terms.credit, loan_terms, lender_spec);
            }

            let (fee_amount, new_loan_amount) = fee_calculator::calculate_fee_amount(
                self.config.read().get_fee(), loan_terms.credit.amount
            );

            let mut credit_helper = loan_terms.credit;

            if (fee_amount > 0) {
                credit_helper.amount = fee_amount.try_into().unwrap();
                self
                    .vault
                    ._push_from(
                        credit_helper, loan_terms.lender, self.config.read().get_fee_collector()
                    );
            }

            credit_helper.amount = new_loan_amount;
            self.vault._push_from(credit_helper, loan_terms.lender, loan_terms.borrower);
        }

        fn _settle_loan_refinance(
            ref self: ContractState,
            refinancing_loan_id: felt252,
            loan_terms: Terms,
            lender_spec: LenderSpec,
            extra: Array<felt252>
        ) {
            let loan = self.loans.read(refinancing_loan_id);
            let erc721_dispatcher = ERC721ABIDispatcher {
                contract_address: self.loan_token.read().contract_address
            };
            // @note: owner_of needs u256 and here the id is in felt252
            let loan_owner = erc721_dispatcher.owner_of(refinancing_loan_id.try_into().unwrap());
            let repayment_amount = self.get_loan_repayment_amount(refinancing_loan_id);
            let (fee_amount, new_loan_amount) = fee_calculator::calculate_fee_amount(
                self.config.read().get_fee(), loan_terms.credit.amount
            );
        }

        fn _withdraw_credit_from_pool(
            ref self: ContractState, credit: Asset, loan_terms: Terms, lender_spec: LenderSpec
        ) {
            let pool_adapter = self.config.read().get_pool_adapter(lender_spec.source_of_funds);
            let const_address = starknet::contract_address_const::<0>();
            if (pool_adapter.contract_address == const_address) {
                error::Err::INVALID_SOURCE_OF_FUNDS(source_of_funds: lender_spec.source_of_funds);
            }
            if (credit.amount > 0) {
                self
                    .vault
                    ._withdraw_from_pool(
                        credit, pool_adapter, lender_spec.source_of_funds, loan_terms.lender
                    );
            }
        }

        fn _check_loan_can_be_repaid(ref self: ContractState, status: u8, default_timestamp: u64) {
            if (status == 0) {
                error::Err::NON_EXISTING_LOAN();
            }

            if (status != 2) {
                error::Err::LOAN_NOT_RUNNING();
            }
            let current_timestamp = starknet::get_execution_info()
                .unbox()
                .block_info
                .unbox()
                .block_timestamp;
            if (default_timestamp <= current_timestamp) {
                error::Err::LOAN_DEFAULTED(default_timestamp);
            }
        }

        fn _update_repaid_loan(ref self: ContractState, loan_id: felt252) {
            let mut loan = self.loans.read(loan_id);
            loan.status = 3;
            loan.fixed_interest_amount = self._loan_accrued_interest(loan.clone());
            loan.accruing_interest_APR = 0;
            self.loans.write(loan_id, loan);
            self.emit(Event::LoanPaidBack(LoanPaidBack { loan_id: loan_id }));
        }

        fn _loan_accrued_interest(ref self: ContractState, loan: Loan) -> u256 {
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
