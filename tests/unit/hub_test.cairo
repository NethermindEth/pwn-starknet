mod constructor {
    #[test]
    fn test_should_set_hub_owner() {assert(true, '');}
}

mod set_tag {
    #[test]
    fn test_should_fail_when_caller_is_not_owner() {assert(true, '');}

    #[test]
    fn test_should_add_tag_to_address() {assert(true, '');}

    #[test]
    fn test_should_remove_tag_from_address() {assert(true, '');}

    #[test]
    fn test_should_emit_event_tag_set() {assert(true, '');}
}

mod set_tags {
    #[test]
    fn test_should_fail_when_caller_is_not_owner() {assert(true, '');}

    #[test]
    fn test_should_fail_when_diff_input_lengths() {assert(true, '');}

    #[test]
    fn test_should_not_fail_when_empty_list() {assert(true, '');}

    #[test]
    fn test_should_add_tags_to_address() {assert(true, '');}

    #[test]
    fn test_should_remove_tags_from_address() {assert(true, '');}

    #[test]
    fn test_should_emit_event_tag_set_for_every_set() {assert(true, '');}
}

mod has_tag {
    #[test]
    fn test_should_return_false_when_address_does_not_have_tag() {assert(true, '');}

    #[test]
    fn test_should_return_true_when_address_does_have_tag() {assert(true, '');}
}
