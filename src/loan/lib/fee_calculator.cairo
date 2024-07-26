use pwn::loan::lib::math;

/// Calculates the fee amount and the resulting loan amount after applying the fee.
///
/// # Parameters
///
/// - `fee`: The fee rate as a basis point value (i.e., hundredths of a percent, with 10,000 basis points equaling 100%).
/// - `loan_amount`: The original amount of the loan in u256 format.
///
/// # Returns
///
/// - A tuple containing:
///   - The fee amount as a u16 value.
///   - The loan amount after deducting the fee, as a u256 value.
///
/// # Behavior
///
/// - If the fee is zero, the function returns the original loan amount and a fee amount of zero.
/// - The function calculates the fee amount using the formula:
///   `fee_amount = (loan_amount * fee) / 10,000`.
/// - It then subtracts the calculated fee amount from the original loan amount to determine the final loan amount.
pub fn calculate_fee_amount(fee: u16, loan_amount: u256) -> (u256, u256) {
    if fee == 0 {
        return (0, loan_amount);
    }

    let fee_amount: u256 = math::mul_div(loan_amount, fee.into(), 10_000);
    (fee_amount, loan_amount - fee_amount.into())
}
