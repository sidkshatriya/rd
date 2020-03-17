use crate::event::Switchable;
use crate::file_monitor::{FileMonitor, FileMonitorType, LazyOffset, Range};
use crate::flags::Flags;
use crate::task::Task;
use nix::unistd::write;

/// A FileMonitor to track writes to rr's stdout/stderr fds.
/// StdioMonitor prevents syscallbuf from buffering output to those fds. It
/// adds the optional stdio markers. During replay, it echoes stdio writes.
pub struct StdioMonitor {
    original_fd: i32,
}

impl FileMonitor for StdioMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::Stdio
    }

    /// Make writes to stdout/stderr blocking, to avoid nondeterminism in the
    /// order in which the kernel actually performs such writes.
    /// This theoretically introduces the possibility of deadlock between rr's
    /// tracee and some external program reading rr's output
    /// via a pipe ... but that seems unlikely to bite in practice.
    ///
    /// Also, if stdio-marking is enabled, prepend the stdio write with
    /// "[rr <pid> <global-time>]".  This allows users to more easily correlate
    /// stdio with trace event numbers.
    fn will_write(&self, t: &dyn Task) -> Switchable {
        if Flags::get().mark_stdio && t.session().borrow().visible_execution() {
            let prefix = format!("[rr {} {}]", t.tgid(), t.trace_time());
            let result = write(self.original_fd, prefix.as_bytes());
            if result.is_err() || result.unwrap() != prefix.len() {
                ed_assert!(t, false, "Couldn't write to fd: {}", self.original_fd);
            }
        }

        Switchable::PreventSwitch
    }

    /// During replay, echo writes to stdout/stderr.
    fn did_write<'b, 'a: 'b>(&mut self, rv: &[Range], l: &mut LazyOffset<'b, 'a>) {
        unimplemented!()
    }
}
