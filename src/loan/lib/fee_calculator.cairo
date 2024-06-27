use pwn::loan::lib::math;

pub fn calculate_fee_amount(fee: u16, loan_amount: u256) -> (u16, u256) {
    if fee == 0 {
        return (0, loan_amount);
    }

    let fee_amount: u16 = math::mul_div(loan_amount, fee.into(), 10_000)
        .try_into()
        .expect('fee_amount overflow');

    (fee_amount, loan_amount - fee_amount.into())
}
