pub fn serde_concat(left: Span<felt252>, right: Span<felt252>) -> Array<felt252> {
    let left_len = left.len();
    let mut out: Array<felt252> = array![left_len.into()];
    let mut i = 0;
    while i < left_len {
        out.append(*left.at(i));
        i += 1;
    };

    let right_len = right.len();
    out.append(right_len.into());
    let mut j = 0;
    while j < right_len {
        out.append(*right.at(j));
        j += 1;
    };

    out
}

pub fn serde_decompose(input: Span<felt252>) -> (Span<felt252>, Span<felt252>) {
    let left_len: usize = (*input.at(0)).try_into().expect('serde failed to convert');
    let right_len: usize = (*input.at(left_len + 1)).try_into().expect('serde failed to convert');

    let mut left: Array<felt252> = array![];
    let mut i = 1;
    while i <= left_len {
        left.append(*input.at(i));
        i += 1;
    };

    let mut right: Array<felt252> = array![];
    let mut j = left_len + 2;
    while j < left_len + 2 + right_len {
        right.append(*input.at(j));
        j += 1;
    };

    (left.span(), right.span())
}


#[cfg(test)]
mod tests {
    use pwn::loan::terms::simple::proposal::simple_loan_dutch_auction_proposal::SimpleLoanDutchAuctionProposal::{
        Proposal, ProposalValues
    };
    use super::{serde_concat, serde_decompose};

    #[test]
    fn test_serde_concat() {
        let left: Array<felt252> = array![1, 2, 3];
        let right: Array<felt252> = array![4, 5, 6, 7];
        let out = serde_concat(left.span(), right.span());
        assert_eq!(out, array![3, 1, 2, 3, 4, 4, 5, 6, 7]);
    }

    #[test]
    fn test_serde_decompose() {
        let input: Array<felt252> = array![3, 1, 2, 3, 4, 4, 5, 6, 7];
        let (left, right) = serde_decompose(input.span());
        assert_eq!(left, array![1, 2, 3].span());
        assert_eq!(right, array![4, 5, 6, 7].span());
    }

    #[test]
    fn test_serde_struct() {
        let proposal: Proposal = Default::default();
        let proposal_values: ProposalValues = Default::default();

        let mut serialized_proposal = array![];
        proposal.serialize(ref serialized_proposal);
        // println!("serialized_proposal: {:?}", serialized_proposal);

        let mut serialized_proposal_values = array![];
        proposal_values.serialize(ref serialized_proposal_values);

        let expected = array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    
        assert_eq!(serialized_proposal, expected);
    }
}
