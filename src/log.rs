use crate::kernel_metadata::errno_name;
use backtrace::Backtrace;
use nix::errno::errno;
use std::{
    collections::HashMap,
    env,
    env::var_os,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Result, Write},
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[derive(Clone)]
struct LogModule {
    name: String,
    level: LogLevel,
}

#[derive(Copy, Clone, Eq, PartialEq, PartialOrd)]
pub enum LogLevel {
    LogFatal,
    LogError,
    LogWarn,
    LogInfo,
    LogDebug,
}

use crate::session::task::Task;
pub use LogLevel::*;

struct LogGlobals {
    level_map: HashMap<String, LogLevel>,
    log_modules_cache: HashMap<String, LogModule>,
    logging_stream: String,
    // Possibly buffered
    log_file: Box<dyn Write + Send>,
    default_level: LogLevel,
}

/// @TODO Will this work in all situations?
/// Is this what we want?
extern "C" fn flush_log_buffer() {
    let mut maybe_log_lock = LOG_GLOBALS.lock();
    match &mut maybe_log_lock {
        Ok(lock) => {
            lock.log_file.flush().unwrap_or(());
        }
        Err(_) => panic!("Could not obtain lock on rd log. Can't flush log buffer"),
    };
}

lazy_static! {
    static ref LOG_GLOBALS: Mutex<LogGlobals> = {
        let maybe_filename = var_os("RD_LOG_FILE");
        let maybe_append_filename = var_os("RD_APPEND_LOG_FILE");
        // @TODO Ok to simply add Sync + Send?
        let mut f: Box<dyn Write + Sync + Send>;
        if let Some(filename) = maybe_filename {
            f = Box::new(File::create(&filename).expect(&format!("Error. Could not create filename `{:?}' specified in environment variable RD_LOG_FILE", filename)));
        } else if let Some(append_filename) = maybe_append_filename {
            f = Box::new(OpenOptions::new().append(true).create(true).open(&append_filename).expect(&format!("Error. Could not append to filename `{:?}' specified in env variable RD_APPEND_LOG_FILE", append_filename)));
        } else {
            f = Box::new(io::stderr());
        }

        let maybe_buf_size = env::var("RD_LOG_BUFFER");
        if let Ok(buf_size) = maybe_buf_size {
            let log_buffer_size = buf_size.parse::<usize>().expect(&format!("Error. Could not parse `{:?}' in environment var `RD_LOG_BUFFER' as a number", buf_size));
            f = Box::new(BufWriter::with_capacity(log_buffer_size, f));
        }

        let ret = unsafe {
            libc::atexit(flush_log_buffer)
        };
        assert_eq!(ret, 0);

        Mutex::new(LogGlobals {
            level_map: HashMap::new(),
            log_modules_cache: HashMap::new(),
            logging_stream: String::new(),
            // Possibly buffered
            log_file: f,
            default_level: LogError,
        })
    };
}

/// Given a module name, what is its log level?
fn get_log_level(module_name: &str, l: &MutexGuard<LogGlobals>) -> LogLevel {
    // We DONT lowercase here as filenames are usually case sensitive on Linux.
    let maybe_log_level = l.level_map.get(module_name);
    if let Some(log_level) = maybe_log_level {
        *log_level
    } else {
        l.default_level
    }
}

/// Given a filename what is the corresponding module name?
fn filename_to_module_name(filename: &str) -> String {
    let path = Path::new(filename);
    // Note: DONT lowercase this.
    path.file_stem().unwrap().to_string_lossy().to_string()
}

/// Given the filename get the corresponding LogModule.
fn get_log_module(filename: &str, l: &mut MutexGuard<LogGlobals>) -> LogModule {
    let maybe_log_module = l.log_modules_cache.get(filename);
    if let Some(log_module) = maybe_log_module {
        log_module.to_owned()
    } else {
        let name = filename_to_module_name(filename);
        let level = get_log_level(&name, l);
        let m = LogModule { level, name };
        l.log_modules_cache.insert(filename.to_owned(), m.clone());
        m
    }
}

fn set_all_logging(level: LogLevel, l: &mut MutexGuard<LogGlobals>) {
    l.default_level = level;
    l.level_map.clear();
    l.log_modules_cache.clear();
}

fn set_logging(module_name: &str, level: LogLevel, l: &mut MutexGuard<LogGlobals>) {
    l.level_map.insert(module_name.to_owned(), level);
    l.log_modules_cache.clear();
}

fn log_name(level: LogLevel) -> String {
    match level {
        LogFatal => "FATAL".into(),
        LogError => "ERROR".into(),
        LogWarn => "WARN".into(),
        LogInfo => "INFO".into(),
        LogDebug => "DEBUG".into(),
    }
}

pub struct NewLineTerminatingOstream {
    enabled: bool,
    level: LogLevel,
    message: Vec<u8>,
    lock: MutexGuard<'static, LogGlobals>,
}

impl NewLineTerminatingOstream {
    fn new(
        level: LogLevel,
        filename: &str,
        line: u32,
        func_name: &str,
        always_enabled: bool,
    ) -> NewLineTerminatingOstream {
        let mut lock = LOG_GLOBALS.lock().unwrap();
        let m = get_log_module(filename, &mut lock);
        let enabled = always_enabled || level <= m.level;
        let mut this = NewLineTerminatingOstream {
            message: Vec::new(),
            enabled,
            level,
            lock,
        };
        if enabled {
            if level == LogDebug {
                write!(this, "[{}] ", m.name).unwrap();
            } else {
                write_prefix(&mut this, level, filename, line, func_name);
            }
        }

        this
    }
}

impl Drop for NewLineTerminatingOstream {
    fn drop(&mut self) {
        if self.enabled {
            self.write(b"\n").unwrap();
            // This flushes self.message *to* the log file
            // (which could be stderr or a log file or a buffered writer that wraps stderr
            //  or a buffered writer that wraps some log file).
            // BUT, It does NOT flush the log file itself.
            self.flush().unwrap_or(());
        }
    }
}

impl Write for NewLineTerminatingOstream {
    /// Write the text stored in the `message` member to the log file.
    fn flush(&mut self) -> Result<()> {
        if self.message.len() > 0 && self.enabled {
            self.lock.log_file.write_all(&self.message)?;
            // We DONT flush the log file. This is handled automatically.
        }
        self.message.clear();
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.enabled {
            self.message.extend_from_slice(buf);
        }

        // Need to pretend these were written even if buffer was not enabled.
        // Otherwise we get a `Err` value
        // Custom { kind: WriteZero, error: "failed to write whole buffer" }
        Ok(buf.len())
    }
}

pub fn write_prefix(
    stream: &mut dyn Write,
    level: LogLevel,
    filename: &str,
    line: u32,
    func_name: &str,
) {
    write!(stream, "[{} ", log_name(level)).unwrap();
    if level <= LogError {
        write!(stream, "{}:{} ", filename, line).unwrap();
    }

    write!(stream, "{}()", func_name).unwrap();
    let err = errno();
    if level <= LogWarn && err != 0 {
        write!(stream, " errno: {}", errno_name(err)).unwrap();
    }
    write!(stream, "] ").unwrap();
}

pub fn log(
    log_level: LogLevel,
    filename: &str,
    line: u32,
    module_path: &str,
    always_enabled: bool,
) -> NewLineTerminatingOstream {
    NewLineTerminatingOstream::new(log_level, filename, line, module_path, always_enabled)
}

/// Outputs to (possibly write buffered) log file (or stderr if no log file was specified)
/// After this program continues normally.
macro_rules! log {
    ($log_level:expr, $($args:tt)+) => {
        {
            use std::io::Write;
            let mut stream = crate::log::log(
                $log_level,
                file!(),
                line!(),
                module_path!(),
                false
            );
            write!(stream, $($args)+).unwrap()
        }
    };
}

/// Outputs to (possibly write buffered) log file (or stderr if no log file was specified)
/// Prints out the backtrace to stderr and aborts.
macro_rules! fatal {
    ($($args:tt)+) => {
        {
            {
                use std::io::Write;
                use crate::log::LogFatal;
                let mut stream = crate::log::log(
                    LogFatal,
                    file!(),
                    line!(),
                    module_path!(),
                    true
                );
                write!(stream, $($args)+).unwrap();
            }
            crate::log::notifying_abort(backtrace::Backtrace::new());
        }
    };
}

/// Output to stderr always. No backtrace -- simply exit.
macro_rules! clean_fatal {
    ($($args:tt)+) => {
        use std::io::Write;
        use std::io::stderr;
        crate::log::write_prefix(&mut stderr(), LogFatal, file!(), line!(), module_path!());
        write!(stderr(), $($args)+).unwrap();
        write!(stderr(), "\n").unwrap();
        std::process::exit(1);
    };
}

/// Dump the stacktrace and abort.
pub fn notifying_abort(bt: Backtrace) {
    // @TODO running under test monitor stuff.
    dump_rd_stack(bt);
    std::process::abort();
}

/// Write the backtrace to stderr.
fn dump_rd_stack(bt: Backtrace) {
    write!(io::stderr(), "=== Start rd backtrace:\n").unwrap();
    write!(io::stderr(), "{:?}", bt).unwrap();
    write!(io::stderr(), "=== End rd backtrace\n").unwrap();
}

// If asserting fails, start an emergency debug session
macro_rules! ed_assert {
    ($task:expr, $cond:expr) => {
        {
            use crate::session::task::task_inner::task_inner::TaskInner;
            // For type checking. Will use this param later though.
            let t : &TaskInner = $task;
            if !$cond {
                {
                    use std::io::Write;
                    use crate::log::LogFatal;
                    let mut stream = crate::log::log(
                        LogFatal,
                        file!(),
                        line!(),
                        module_path!(),
                        true
                    );
                    write!(stream, "\n (task {} (rec: {}) at time {})", t.tid, t.rec_tid, t.trace_time()).unwrap();
                    write!(stream, "Assertion `{}' failed to hold. ", stringify!($cond)).unwrap();
                }
                // @TODO this should be replaced with starting an emergency debug session
                crate::log::notifying_abort(backtrace::Backtrace::new());
            }
        }
    };
    ($task:expr, $cond:expr, $($args:tt)+) => {
        {
            use crate::session::task::task_inner::task_inner::TaskInner;
            // For type checking. Will use this param later though.
            let t : &TaskInner = $task;
            if !$cond {
                {
                    use std::io::Write;
                    use crate::log::LogFatal;
                    let mut stream = crate::log::log(
                        LogFatal,
                        file!(),
                        line!(),
                        module_path!(),
                        true
                    );
                    write!(stream, "\n (task {} (rec: {}) at time {})", t.tid, t.rec_tid, t.trace_time()).unwrap();
                    write!(stream, "Assertion `{}' failed to hold. ", stringify!($cond)).unwrap();
                    write!(stream, $($args)+).unwrap();
                }
                // @TODO this should be replaced with starting an emergency debug session
                crate::log::notifying_abort(backtrace::Backtrace::new());
            }
        }
    };
}

fn emergency_debug(_t: &dyn Task) {
    unimplemented!()
}
