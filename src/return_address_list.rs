use crate::{remote_ptr::RemotePtr, session::task::Task};

/// A list of return addresses extracted from the stack. The tuple
/// (perfcounter ticks, regs, return addresses) may be needed to disambiguate
/// states that aren't unique in (perfcounter ticks, regs).
/// When return addresses can't be extracted, some suffix of the list may be
/// all zeroes.
#[derive(Eq, PartialEq, Default)]
pub struct ReturnAddressList {
    pub addresses: [RemotePtr<u8>; Self::COUNT],
}

impl ReturnAddressList {
    pub const COUNT: usize = 8;
}

impl ReturnAddressList {
    /// Capture return addresses from |t|'s stack. The returned
    /// address list may not be actual return addresses (in optimized code,
    /// will probably not be), but they will be a function of the task's current
    /// state, so may be useful for distinguishing this state from other states.
    pub fn new(_t: &dyn Task) -> ReturnAddressList {
        unimplemented!()
    }
}
