use crate::{
    event::Switchable,
    file_monitor::{FileMonitor, FileMonitorType, LazyOffset, Range},
    flags::Flags,
    session::task::Task,
};
use nix::unistd::write;

/// A FileMonitor to track writes to rr's stdout/stderr fds.
/// StdioMonitor prevents syscallbuf from buffering output to those fds. It
/// adds the optional stdio markers. During replay, it echoes stdio writes.
pub struct StdioMonitor {
    original_fd: i32,
}

impl StdioMonitor {
    /// Create a StdioMonitor that monitors writes to rr's original_fd
    /// (STDOUT_FILENO or STDERR_FILENO).
    /// Note that it's possible for a tracee to have a StdioMonitor associated
    /// with a different fd, thanks to dup() etc.
    pub fn new(original_fd: i32) -> StdioMonitor {
        StdioMonitor { original_fd }
    }
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
    /// "[rd <pid> <global-time>]".  This allows users to more easily correlate
    /// stdio with trace event numbers.
    fn will_write(&self, t: &dyn Task) -> Switchable {
        if Flags::get().mark_stdio
            && t.session().visible_execution()
            && t.session().done_initial_exec()
        {
            let prefix = if Flags::get().extra_compat {
                format!("[rr {} {}]", t.tgid(), t.trace_time())
            } else {
                format!("[rd {} {}]", t.tgid(), t.trace_time())
            };

            let maybe_result = write(self.original_fd, prefix.as_bytes());
            match maybe_result {
                Err(e) => ed_assert!(
                    t,
                    false,
                    "Couldn't write to fd `{}': {:?}",
                    self.original_fd,
                    e
                ),
                Ok(result) if result != prefix.len() => ed_assert!(
                    t,
                    false,
                    "Couldn't write to fd `{}': {} != {}",
                    self.original_fd,
                    result,
                    prefix.len()
                ),
                Ok(_) => (),
            }
        }

        Switchable::PreventSwitch
    }

    /// During replay, echo writes to stdout/stderr.
    fn did_write<'b, 'a: 'b>(&mut self, ranges: &[Range], l: &mut LazyOffset<'b, 'a>) {
        let session_rc = l.t.session();

        match session_rc.as_replay() {
            None => {}
            Some(rs) => {
                if rs.flags().redirect_stdio && rs.visible_execution() {
                    for r in ranges {
                        let mut buf: Vec<u8> = vec![0; r.length];
                        l.t.read_bytes_helper(r.data, &mut buf, None);
                        let maybe_result = write(self.original_fd, &buf);
                        match maybe_result {
                            Err(e) => ed_assert!(
                                l.t,
                                false,
                                "Couldn't write to fd `{}': {:?}",
                                self.original_fd,
                                e
                            ),
                            Ok(result) if result != buf.len() => ed_assert!(
                                l.t,
                                false,
                                "Couldn't write to fd `{}': {} != {}",
                                self.original_fd,
                                result,
                                buf.len()
                            ),
                            Ok(_) => (),
                        }
                    }
                }
            }
        }
    }
}
