// mod costructor {
    #[test]
    fn should_initialize_with_zero_values() {
        assert(true);
    }
// }

mod initialize {
    #[test]
    fn should_set_values() {}

    #[test]
    #[should_panic()]
    fn should_fail_when_called_second_time() {}

    #[test]
    #[should_panic()]
    fn should_fail_when_called_second_time() {}

    #[test]
    #[should_panic()]
    fn should_fail_when_owner_is_zero_address() {}

    #[test]
    #[should_panic()]
    fn should_fail_when_collecter_is_zero_address() {}
}

mod set_fee {
#[test]
#[should_panic()]
fn should_fail_when_caller_is_not_owner() {}

#[test]
#[should_panic()]
fn should_fail_when_value_bigger_than_max_fee() {}

#[test]
fn should_set_fee_value() {}

#[test]
fn should_emit_event_FeeUpdated() {}
}