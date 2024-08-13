#!/bin/bash

# Declare the contracts
declare_contract() {
    local contract_name=$1
    local contract_file=$2

    echo "Declaring Cairo 1 class for $contract_name..."
    
    # Run the command and capture the output
    output=$(starkli declare "$contract_file" -w --compiler-version 2.6.2)

    # Write the output to the appropriate file based on the STARKNET_NETWORK
    echo "$contract_name: $output" >> "deployments/$STARKNET_NETWORK/declared-classes.txt"
    echo "Class hash for $contract_name saved to deployments/$STARKNET_NETWORK/declared-classes.txt"
}

# Determine the file path based on the STARKNET_NETWORK environment variable
output_dir="deployments/$STARKNET_NETWORK"
output_file="$output_dir/declared-classes.txt"

# Create the directory if it doesn't exist
mkdir -p "$output_dir"

# Remove existing declared-classes.txt file if it exists
rm -f "$output_file"

# Declare each contract and save the class hash
declare_contract "PwnHub" target/dev/pwn_PwnHub.contract_class.json
declare_contract "PwnConfig" target/dev/pwn_PwnConfig.contract_class.json
declare_contract "RevokedNonce" target/dev/pwn_RevokedNonce.contract_class.json
declare_contract "SimpleLoanSimpleProposal" target/dev/pwn_SimpleLoanSimpleProposal.contract_class.json
declare_contract "SimpleLoanFungibleProposal" target/dev/pwn_SimpleLoanFungibleProposal.contract_class.json
declare_contract "SimpleLoanDutchAuctionProposal" target/dev/pwn_SimpleLoanDutchAuctionProposal.contract_class.json
declare_contract "SimpleLoanListProposal" target/dev/pwn_SimpleLoanListProposal.contract_class.json
declare_contract "PwnLoan" target/dev/pwn_PwnLoan.contract_class.json
declare_contract "MultiTokenCategoryRegistry" target/dev/pwn_MultiTokenCategoryRegistry.contract_class.json
declare_contract "PwnSimpleLoan" target/dev/pwn_PwnSimpleLoan.contract_class.json
