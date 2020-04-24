use crate::commands::rd_options::{RdOptions, RdSubCommand};
use crate::commands::RdCommand;
use crate::trace::trace_reader::TraceReader;
use crate::trace::trace_task_event::{TraceTaskEvent, TraceTaskEventVariant};
use crate::wait_status::WaitType;
use libc::pid_t;
use std::collections::HashMap;
use std::fmt::Write as fmtWrite;
use std::io;
use std::io::{stdout, Write};
use std::path::PathBuf;

pub struct PsCommand {
    trace_dir: Option<PathBuf>,
}

impl PsCommand {
    pub fn new(options: &RdOptions) -> PsCommand {
        match options.cmd.clone() {
            RdSubCommand::Ps { trace_dir } => PsCommand { trace_dir },
            _ => panic!("Unexpected RdSubCommand variant. Not a `Ps` variant!"),
        }
    }
}

impl RdCommand for PsCommand {
    fn run(&mut self) -> io::Result<()> {
        self.ps(&mut stdout())
    }
}

type TidPidMap = HashMap<pid_t, pid_t>;

impl PsCommand {
    fn ps(&mut self, out: &mut dyn Write) -> io::Result<()> {
        let mut trace = TraceReader::new(self.trace_dir.as_ref());
        write!(out, "PID\tPPID\tEXIT\tCMD\n")?;

        let mut events: Vec<TraceTaskEvent> = Vec::new();
        while let Some(r) = trace.read_task_event(None) {
            events.push(r);
        }

        let not_exec = match events[0].event_variant() {
            TraceTaskEventVariant::Exec(_) => false,
            _ => true,
        };
        if events.is_empty() || not_exec {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid Trace. No task events found or the first task event was not an Exec",
            ));
        }

        let mut tid_to_pid = HashMap::<pid_t, pid_t>::new();

        let initial_tid = events[0].tid();
        tid_to_pid.insert(initial_tid, initial_tid);
        write!(
            out,
            "{}\t--\t{}\t",
            initial_tid,
            find_exit_code(initial_tid, &events, &tid_to_pid)
        )?;
        write_exec_cmd_line(&events[0], out)?;

        for (i, e) in events.iter().enumerate() {
            update_tid_to_pid_map(&mut tid_to_pid, e);

            match e.event_variant() {
                TraceTaskEventVariant::Clone(c)
                    if (c.clone_flags() & libc::CLONE_THREAD != libc::CLONE_THREAD) =>
                {
                    let pid = tid_to_pid[&e.tid()];
                    write!(out, "{}", e.tid())?;
                    if c.own_ns_tid() != e.tid() {
                        write!(out, " ({})", c.own_ns_tid())?;
                    }
                    write!(
                        out,
                        "\t{}\t{}\t",
                        tid_to_pid[&c.parent_tid()],
                        find_exit_code(pid, &events[i..], &tid_to_pid)
                    )?;

                    let maybe_cmd_line_index: Option<usize> =
                        find_cmd_line(pid, &events, i, &tid_to_pid);
                    match maybe_cmd_line_index {
                        None => {
                            // The main thread exited. All other threads must too, so there
                            // is no more opportunity for e's pid to exec.
                            write!(out, "(forked without exec)\n")?
                        }
                        Some(cmd_line_index) => {
                            write_exec_cmd_line(&events[cmd_line_index], out)?;
                        }
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
}

fn update_tid_to_pid_map(tid_to_pid: &mut TidPidMap, e: &TraceTaskEvent) {
    match e.event_variant() {
        TraceTaskEventVariant::Clone(c) => {
            if c.clone_flags() & libc::CLONE_THREAD == libc::CLONE_THREAD {
                // thread clone. Record thread's pid.
                tid_to_pid.insert(e.tid(), c.parent_tid());
            } else {
                // Some kind of fork. This task is its own pid.
                tid_to_pid.insert(e.tid(), e.tid());
            }
        }
        TraceTaskEventVariant::Exit(_) => {
            tid_to_pid.remove(&e.tid());
        }
        _ => (),
    }
}

fn find_exit_code(pid: pid_t, events: &[TraceTaskEvent], current_tid_to_pid: &TidPidMap) -> String {
    let mut tid_to_pid = current_tid_to_pid.clone();
    for e in events {
        match e.event_variant() {
            TraceTaskEventVariant::Exit(ex)
                if (tid_to_pid[&e.tid()] == pid && count_tids_for_pid(&tid_to_pid, pid) == 1) =>
            {
                let status = ex.exit_status();
                match status.wait_type() {
                    WaitType::Exit => return status.exit_code().unwrap().to_string(),
                    WaitType::FatalSignal => return (-status.fatal_sig().unwrap()).to_string(),
                    w => {
                        fatal!("Unexpected WaitType {:?}", w);
                        unreachable!();
                    }
                }
            }
            _ => (),
        }
        update_tid_to_pid_map(&mut tid_to_pid, e);
    }
    "none".into()
}

fn count_tids_for_pid(tid_to_pid: &TidPidMap, pid: pid_t) -> usize {
    let mut found = 0;
    for &pid_from_map in tid_to_pid.values() {
        if pid_from_map == pid {
            found += 1;
        }
    }
    found
}

fn find_cmd_line(
    pid: pid_t,
    events: &[TraceTaskEvent],
    current_event: usize,
    current_tid_to_pid: &TidPidMap,
) -> Option<usize> {
    let mut tid_to_pid = current_tid_to_pid.clone();
    for (i, e) in events.iter().skip(current_event).enumerate() {
        match e.event_variant() {
            TraceTaskEventVariant::Exec(_) if tid_to_pid[&e.tid()] == pid => {
                return Some(i + current_event)
            }
            TraceTaskEventVariant::Exit(_)
                if (tid_to_pid[&e.tid()] == pid && count_tids_for_pid(&tid_to_pid, pid) == 1) =>
            {
                return None
            }
            _ => (),
        }
        update_tid_to_pid_map(&mut tid_to_pid, e);
    }
    None
}

fn write_exec_cmd_line(event: &TraceTaskEvent, out: &mut dyn Write) -> io::Result<()> {
    let mut first = true;
    for word in event.exec_type().cmd_line() {
        if !first {
            write!(out, " ")?;
        } else {
            first = false;
        }
        let mut word_s = String::new();
        write!(word_s, "{:?}", word).unwrap();
        // WORKAROUND. OsString debug print has leading and trailing `"`
        write!(out, "{}", word_s.trim_matches('"'))?;
    }
    write!(out, "\n")
}
