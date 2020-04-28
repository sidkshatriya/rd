use crate::{
    event::Event,
    extra_registers::{ExtraRegisters, Format},
    registers::Registers,
    ticks::Ticks,
};
use libc::pid_t;
use std::{
    io,
    io::{stdout, Write},
};

/// DIFF NOTE: This is i64 in rr
pub type FrameTime = u64;

/// We DONT want Copy
#[derive(Clone)]
pub struct TraceFrame {
    pub(super) global_time: FrameTime,
    pub(super) tid_: pid_t,
    pub(super) ev: Event,
    pub(super) ticks_: Ticks,
    pub(super) monotonic_time_: f64,
    /// @TODO Is it useful for the next 2 of these to be Option<> ?
    pub(super) recorded_regs: Registers,
    /// Only used when has_exec_info, but variable length (and usually not
    /// present) so we don't want to stuff it into exec_info
    pub(super) recorded_extra_regs: ExtraRegisters,
}

impl TraceFrame {
    pub fn new_with(
        global_time: FrameTime,
        tid: pid_t,
        event: Event,
        tick_count: Ticks,
        monotonic_time: f64,
    ) -> TraceFrame {
        TraceFrame {
            global_time,
            tid_: tid,
            ev: event,
            ticks_: tick_count,
            monotonic_time_: monotonic_time,
            // @TODO Is this what we really want?
            recorded_regs: Registers::default(),
            recorded_extra_regs: ExtraRegisters::default(),
        }
    }

    pub fn new() -> TraceFrame {
        TraceFrame {
            global_time: 0,
            tid_: 0,
            ev: Event::default(),
            ticks_: 0,
            monotonic_time_: 0.0,
            // @TODO Is this what we really want?
            recorded_regs: Registers::default(),
            recorded_extra_regs: ExtraRegisters::default(),
        }
    }

    pub fn time(&self) -> FrameTime {
        self.global_time
    }
    pub fn tid(&self) -> pid_t {
        self.tid_
    }
    pub fn event(&self) -> &Event {
        &self.ev
    }
    pub fn ticks(&self) -> Ticks {
        self.ticks_
    }
    pub fn monotonic_time(&self) -> f64 {
        self.monotonic_time_
    }

    pub fn regs_ref(&self) -> &Registers {
        &self.recorded_regs
    }
    pub fn extra_regs_ref(&self) -> &ExtraRegisters {
        &self.recorded_extra_regs
    }

    /// Log a human-readable representation of this to |out|
    /// (defaulting to stdout), including a newline character.
    /// A human-friendly format is used. Does not emit a trailing '}'
    /// (so the caller can add more fields to the record).
    ///
    /// Defaults to stdout if `out` is `None`.
    pub fn dump(&self, maybe_out: Option<&mut dyn Write>) -> io::Result<()> {
        let sout = &mut stdout();
        let out = maybe_out.unwrap_or(sout);
        write!(
            out,
            "{{\n  real_time:{:.6} global_time:{}, event:`{}' ",
            self.monotonic_time(),
            self.time(),
            self.event()
        )?;
        if self.event().is_syscall_event() {
            write!(out, "(state:{}) ", self.event().syscall().state)?;
        }
        write!(out, "tid:{}, ticks:{}\n", self.tid(), self.ticks())?;
        if !self.event().record_regs() {
            return Ok(());
        }

        self.regs_ref().write_register_file_compact(out)?;
        if self.recorded_extra_regs.format() != Format::None {
            write!(out, " ")?;
            self.recorded_extra_regs.write_register_file_compact(out)?;
        }
        write!(out, "\n")
    }
    /// Log a human-readable representation of this to |out|
    /// (defaulting to stdout), including a newline character.  An
    /// easily machine-parseable format is dumped.
    ///
    /// Defaults to stdout if `out` is `None`.
    pub fn dump_raw(&self, maybe_out: Option<&mut dyn Write>) -> io::Result<()> {
        let sout = &mut stdout();
        let out = maybe_out.unwrap_or(sout);
        write!(
            out,
            " {} {} {} {}",
            self.time(),
            self.tid(),
            // Cast the event_type as a i32
            self.event().event_type() as i32,
            self.ticks()
        )?;
        if !self.event().record_regs() {
            write!(out, "\n")?;
            return Ok(());
        }

        self.regs_ref().write_register_file_for_trace_raw(out)?;
        write!(out, "\n")
    }
}
