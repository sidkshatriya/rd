use crate::event::Event;
use crate::extra_registers::ExtraRegisters;
use crate::registers::Registers;
use crate::ticks::Ticks;
use libc::pid_t;

pub type FrameTime = i64;

/// We DONT want Copy
#[derive(Clone)]
pub struct TraceFrame {
    pub(super) global_time: FrameTime,
    pub(super) tid_: pid_t,
    pub(super) ev: Event,
    pub(super) ticks_: Ticks,
    pub(super) monontonic_time: f64,
    pub(super) recorded_regs: Registers,
    /// Only used when has_exec_info, but variable length (and usually not
    /// present) so we don't want to stuff it into exec_info
    pub(super) recorded_extra_regs: ExtraRegisters,
}
