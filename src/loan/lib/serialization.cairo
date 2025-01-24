/// Concatenates two `Span<felt252>` slices into a single `Array<felt252>`.
///
/// The output format includes the lengths of both slices at the beginning
/// followed by the elements of each slice.
///
/// # Parameters
///
/// - `left`: The first `Span<felt252>` slice to concatenate.
/// - `right`: The second `Span<felt252>` slice to concatenate.
///
/// # Returns
///
/// - An `Array<felt252>` containing the concatenated elements of `left` and `right` with their lengths.
///
/// # Panics
///
/// - Panics if the conversion of lengths to `felt252` fails.
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

/// Decomposes a single `Span<felt252>` into two separate spans.
///
/// The input format should start with the lengths of the two components
/// followed by their respective elements.
///
/// # Parameters
///
/// - `input`: The `Span<felt252>` containing the concatenated elements and their lengths.
///
/// # Returns
///
/// - A tuple containing two `Span<felt252>` slices representing the original components.
///
/// # Panics
///
/// - Panics if the input span is empty
/// - Panics if the conversion of lengths from `felt252` fails
/// - Panics if either the left or right length is zero or negative
/// - Panics if the input is too short to contain both length indicators
/// - Panics if the total input length doesn't match exactly (left_len + right_len + 2)
pub fn serde_decompose(input: Span<felt252>) -> (Span<felt252>, Span<felt252>) {
    // Check if input is empty
    assert(!input.is_empty(), 'Input span cannot be empty');

    // Get and validate left length
    let left_len: usize = (*input.at(0)).try_into().expect('serde failed to convert');
    assert(left_len > 0, 'Left length must be positive');

    // Ensure input has enough elements for left_len and right_len
    assert(input.len() >= left_len + 2, 'Input too short for lengths');

    // Get and validate right length
    let right_len: usize = (*input.at(left_len + 1)).try_into().expect('serde failed to convert');
    assert(right_len > 0, 'Right length must be positive');

    // Validate total length matches expected
    assert(input.len() == left_len + right_len + 2, 'Input length mismatch');

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

        let mut serialized_proposal_values = array![];
        proposal_values.serialize(ref serialized_proposal_values);

        let expected = array![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];

        assert_eq!(serialized_proposal, expected);
    }

    #[test]
    #[should_panic(expected: ('Input span cannot be empty',))]
    fn test_serde_decompose_empty_input() {
        let input: Array<felt252> = array![];
        let (_, _) = serde_decompose(input.span());
    }

    #[test]
    #[should_panic(expected: ('Left length must be positive',))]
    fn test_serde_decompose_zero_left_length() {
        let input: Array<felt252> = array![0, 1, 2, 3];
        let (_, _) = serde_decompose(input.span());
    }

    #[test]
    #[should_panic(expected: ('Input too short for lengths',))]
    fn test_serde_decompose_insufficient_length() {
        // Claims left_len is 3 but only has 2 elements after the length
        let input: Array<felt252> = array![3, 1, 2];
        let (_, _) = serde_decompose(input.span());
    }

    #[test]
    #[should_panic(expected: ('Input length mismatch',))]
    fn test_serde_decompose_length_mismatch() {
        // Claims left_len=2, right_len=2, but has extra elements
        let input: Array<felt252> = array![2, 1, 2, 2, 3, 4, 5];
        let (_, _) = serde_decompose(input.span());
    }

    #[test]
    #[should_panic(expected: ('Right length must be positive',))]
    fn test_serde_decompose_zero_right_length() {
        let input: Array<felt252> = array![1, 42, 0];
        let (_, _) = serde_decompose(input.span());
    }
}
