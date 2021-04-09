use crate::{arch::Architecture, remote_ptr::RemotePtr, session::task::Task};
use std::{mem::size_of_val, slice::from_raw_parts_mut};

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
    pub fn new(t: &dyn Task) -> ReturnAddressList {
        let mut result = Default::default();
        compute_return_addresses(&mut result, t);
        result
    }
}

fn read_bytes_no_breakpoints(t: &dyn Task, p: RemotePtr<u8>, out: &mut [u8]) -> bool {
    if t.read_bytes_fallible(p, out) != Ok(out.len()) {
        return false;
    }

    t.vm().replace_breakpoints_with_original_values(out, p);

    true
}

fn return_addresses_x86ish<Arch: Architecture>(result: &mut ReturnAddressList, t: &dyn Task) {
    // Immediately after a function call the return address is on the stack at
    // SP. After BP is pushed, but before it's initialized for the new stack
    // frame, the return address is on the stack at SP+wordsize. Just
    // capture those words now. We could inspect the code for known prologs/
    // epilogs but that misses cases such as calling into optimized code
    // or PLT stubs (which start with 'jmp'). Since it doesn't matter if we
    // capture addresses that aren't real return addresses, just capture those
    // words unconditionally.
    let mut frame: [Arch::size_t; 2] = [0u8.into(); 2];
    let mut frame_sl: &mut [u8] =
        unsafe { from_raw_parts_mut(&raw mut frame as *mut u8, size_of_val(&frame)) };

    let mut next_address: usize = 0;
    // Make sure the data we fetch here does not depend on where breakpoints have
    // been set. We don't want these results to vary because we call this in
    // some contexts with internal breakpoints set and in other contexts without
    // them set.
    let sp = t.regs_ref().sp().into();
    if read_bytes_no_breakpoints(t, sp, &mut frame_sl) {
        result.addresses[0] = Arch::size_t_as_usize(frame[0]).into();
        result.addresses[1] = Arch::size_t_as_usize(frame[1]).into();
        next_address = 2;
    }

    let mut bp = t.regs_ref().bp().into();
    for i in next_address..ReturnAddressList::COUNT {
        if !read_bytes_no_breakpoints(t, bp, &mut frame_sl) {
            break;
        }
        result.addresses[i] = Arch::size_t_as_usize(frame[1]).into();
        bp = Arch::size_t_as_usize(frame[0]).into();
    }
}

fn compute_return_addresses(result: &mut ReturnAddressList, t: &dyn Task) {
    rd_arch_function_selfless!(return_addresses_x86ish, t.arch(), result, t);
}
