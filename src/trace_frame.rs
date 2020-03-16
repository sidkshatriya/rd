use crate::event::Event;
use crate::extra_registers::ExtraRegisters;
use crate::registers::Registers;
use crate::ticks::Ticks;
use libc::pid_t;

pub type FrameTime = i64;

/// We DONT want Copy
#[derive(Clone)]
pub struct TraceFrame {
    global_time: FrameTime,
    tid_: pid_t,
    ev: Event,
    ticks_: Ticks,
    monontonic_time: f64,
    recorded_regs: Registers,
    /// Only used when has_exec_info, but variable length (and usually not
    /// present) so we don't want to stuff it into exec_info
    recorded_extra_regs: ExtraRegisters,
}
