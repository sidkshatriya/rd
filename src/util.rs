pub fn running_under_rd() -> bool {
    let maybe_under = option_env!("RUNNING_UNDER_RD");
    maybe_under.is_some()
}
