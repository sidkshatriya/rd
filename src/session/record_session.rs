use super::{session_common::kill_all_tasks, SessionSharedPtr};
use crate::{
    commands::record_command::RecordCommand,
    event::Switchable,
    kernel_abi::{
        common::preload_interface::{
            SYSCALLBUF_ENABLED_ENV_VAR,
            SYSCALLBUF_LIB_FILENAME,
            SYSCALLBUF_LIB_FILENAME_PADDED,
        },
        SupportedArch,
    },
    log::{LogDebug, LogError},
    scheduler::Scheduler,
    scoped_fd::ScopedFd,
    seccomp_filter_rewriter::SeccompFilterRewriter,
    session::{
        session_inner::session_inner::SessionInner,
        task::{Task, TaskSharedPtr},
        Session,
    },
    taskish_uid::TaskUid,
    thread_group::ThreadGroupSharedPtr,
    trace::{trace_stream::TraceStream, trace_writer::TraceWriter},
    util::{
        find,
        good_random,
        CPUIDData,
        CPUID_GETEXTENDEDFEATURES,
        CPUID_GETFEATURES,
        CPUID_GETXSAVE,
    },
    wait_status::WaitStatus,
};
use goblin::elf::Elf;
use libc::{pid_t, S_IFREG};
use nix::{
    fcntl::OFlag,
    sys::stat::stat,
    unistd::{access, read, AccessFlags},
};
use std::{
    cell::{Ref, RefCell, RefMut},
    convert::AsRef,
    env,
    ffi::{OsStr, OsString},
    fs,
    ops::{Deref, DerefMut},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

const CPUID_RDRAND_FLAG: u32 = 1 << 30;
const CPUID_RTM_FLAG: u32 = 1 << 11;
const CPUID_RDSEED_FLAG: u32 = 1 << 18;
const CPUID_XSAVEOPT_FLAG: u32 = 1 << 0;

#[derive(Clone, Eq, PartialEq)]
pub struct DisableCPUIDFeatures {
    /// in: EAX=0x01
    features_ecx: u32,
    features_edx: u32,
    /// in: EAX=0x07 ECX=0
    extended_features_ebx: u32,
    extended_features_ecx: u32,
    extended_features_edx: u32,
    /// in: EAX=0x0D ECX=1
    xsave_features_eax: u32,
}

impl Default for DisableCPUIDFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl DisableCPUIDFeatures {
    pub fn new() -> Self {
        Self {
            features_ecx: 0,
            features_edx: 0,
            extended_features_ebx: 0,
            extended_features_ecx: 0,
            extended_features_edx: 0,
            xsave_features_eax: 0,
        }
    }

    pub fn from(features: (u32, u32), features_ext: (u32, u32, u32), features_xsave: u32) -> Self {
        Self {
            features_ecx: features.0,
            features_edx: features.1,
            extended_features_ebx: features_ext.0,
            extended_features_ecx: features_ext.1,
            extended_features_edx: features_ext.2,
            xsave_features_eax: features_xsave,
        }
    }

    pub fn any_features_disabled(&self) -> bool {
        self.features_ecx != 0
            || self.features_edx != 0
            || self.extended_features_ebx != 0
            || self.extended_features_ecx != 0
            || self.extended_features_edx != 0
            || self.xsave_features_eax != 0
    }
    pub fn amend_cpuid_data(&self, eax_in: u32, ecx_in: u32, cpuid_data: &mut CPUIDData) {
        match eax_in {
            CPUID_GETFEATURES => {
                cpuid_data.ecx &= !(CPUID_RDRAND_FLAG | self.features_ecx);
                cpuid_data.edx &= !self.features_edx;
            }
            CPUID_GETEXTENDEDFEATURES => {
                if ecx_in == 0 {
                    cpuid_data.ebx &=
                        !(CPUID_RDSEED_FLAG | CPUID_RTM_FLAG | self.extended_features_ebx);
                    cpuid_data.ecx &= !self.extended_features_ecx;
                    cpuid_data.edx &= !self.extended_features_edx;
                }
            }
            CPUID_GETXSAVE => {
                if ecx_in == 1 {
                    // Always disable XSAVEOPT because it's nondeterministic,
                    // possibly depending on context switching behavior. Intel
                    // recommends not using it from user space.
                    cpuid_data.eax &= !(CPUID_XSAVEOPT_FLAG | self.xsave_features_eax);
                }
            }
            _ => (),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TraceUuid {
    pub bytes: [u8; 16],
}

impl TraceUuid {
    pub fn inner_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn generate_new() -> TraceUuid {
        let mut bytes = [0u8; 16];
        good_random(&mut bytes);
        TraceUuid { bytes }
    }

    pub fn zero() -> TraceUuid {
        let bytes = [0u8; 16];
        TraceUuid { bytes }
    }

    pub fn from_array(bytes: [u8; 16]) -> TraceUuid {
        TraceUuid { bytes }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SyscallBuffering {
    EnableSycallBuf,
    DisableSyscallBuf,
}

/// DIFF NOTE: Subsumes RecordResult and RecordStatus from rr
#[derive(Clone, Eq, PartialEq)]
pub enum RecordResult {
    /// Some execution was recorded. record_step() can be called again.
    StepContinue,
    /// All tracees are dead. record_step() should not be called again.
    StepExited(WaitStatus),
    /// Spawning the initial tracee failed. The OsString represents the error message.
    StepSpawnFailed(OsString),
}

pub struct RecordSession {
    session_inner: SessionInner,
    trace_out: TraceWriter,
    scheduler_: RefCell<Scheduler>,
    initial_thread_group: ThreadGroupSharedPtr,
    seccomp_filter_rewriter_: SeccompFilterRewriter,
    trace_id: Box<TraceUuid>,
    disable_cpuid_features_: DisableCPUIDFeatures,
    ignore_sig: i32,
    continue_through_sig: i32,
    last_task_switchable: Switchable,
    syscall_buffer_size_: usize,
    syscallbuf_desched_sig_: u8,
    use_syscall_buffer_: bool,

    use_file_cloning_: bool,
    use_read_cloning_: bool,
    /// When true, try to increase the probability of finding bugs.
    enable_chaos_: bool,
    asan_active_: bool,
    /// When true, wait for all tracees to exit before finishing recording.
    wait_for_all_: bool,

    output_trace_dir: OsString,
}

impl Drop for RecordSession {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl RecordSession {
    pub fn trace_writer(&self) -> &TraceWriter {
        &self.trace_out
    }

    pub fn trace_writer_mut(&mut self) -> &mut TraceWriter {
        &mut self.trace_out
    }

    /// Record some tracee execution.
    /// This may block. If blocking is interrupted by a signal, will return
    /// StepContinue.
    /// Typically you'd call this in a loop until it returns something other than
    /// StepContinue.
    /// Note that when this returns, some tasks may be running (not in a ptrace-
    /// stop). In particular, up to one task may be executing user code and any
    /// number of tasks may be blocked in syscalls.
    pub fn record_step(&self) -> RecordResult {
        unimplemented!()
    }

    /// Flush buffers and write a termination record to the trace. Don't call
    /// record_step() after this.
    pub fn terminate_recording(&self) {
        unimplemented!()
    }

    /// DIFF NOTE: Param list very different from rr.
    /// Takes the whole &RecordCommand for simplicity.
    pub fn create(options: &RecordCommand) -> SessionSharedPtr {
        // The syscallbuf library interposes some critical
        // external symbols like XShmQueryExtension(), so we
        // preload it whether or not syscallbuf is enabled. Indicate here whether
        // syscallbuf is enabled.
        if options.use_syscall_buffer == SyscallBuffering::DisableSyscallBuf {
            env::remove_var(SYSCALLBUF_ENABLED_ENV_VAR);
        } else {
            env::set_var(SYSCALLBUF_ENABLED_ENV_VAR, "1");
            check_perf_event_paranoid();
        }

        let mut env: Vec<(OsString, OsString)> = env::vars_os().collect();
        env.extend_from_slice(&options.extra_env);

        let full_path = lookup_by_path(&options.args[0]);
        let exe_info: ExeInfo = read_exe_info(&full_path);

        // LD_PRELOAD the syscall interception lib
        let syscall_buffer_lib_path = find_helper_library(SYSCALLBUF_LIB_FILENAME);
        if !syscall_buffer_lib_path.is_empty() {
            let mut ld_preload = Vec::<u8>::new();
            match &exe_info.libasan_path {
                Some(libasan_path) => {
                    log!(LogDebug, "Prepending {:?} to LD_PRELOAD", libasan_path);
                    // Put an LD_PRELOAD entry for it before our preload library, because
                    // it checks that it's loaded first
                    ld_preload.extend_from_slice(libasan_path.as_bytes());
                    ld_preload.push(b':');
                }
                None => (),
            }

            ld_preload.extend_from_slice(syscall_buffer_lib_path.as_bytes());
            ld_preload.extend_from_slice(SYSCALLBUF_LIB_FILENAME_PADDED.as_bytes());
            inject_ld_helper_library(&mut env, &OsStr::new("LD_PRELOAD"), ld_preload);
        }

        env.push(("RUNNING_UNDER_RD".into(), "1".into()));
        // Stop Mesa using the GPU
        env.push(("LIBGL_ALWAYS_SOFTWARE".into(), "1".into()));
        // Stop sssd from using shared-memory with its daemon
        env.push(("SSS_NSS_USE_MEMCACHE".into(), "NO".into()));

        // Disable Gecko's "wait for gdb to attach on process crash" behavior, since
        // it is useless when running under rr.
        env.push(("MOZ_GDB_SLEEP".into(), "0".into()));

        // If we have CPUID faulting, don't use these environment hacks. We don't
        // need them and the user might want to use them themselves for other reasons.
        if !SessionInner::has_cpuid_faulting() {
            // OpenSSL uses RDRAND, but we can disable it. These bitmasks are inverted
            // and ANDed with the results of CPUID. The number below is 2^62, which is the
            // bit for RDRAND support.
            env.push(("OPENSSL_ia32cap".into(), "~4611686018427387904:~0".into()));
            // Disable Qt's use of RDRAND/RDSEED/RTM
            env.push(("QT_NO_CPU_FEATURE".into(), "rdrand rdseed rtm".into()));
        }

        unimplemented!()
    }

    pub fn scheduler(&self) -> Ref<'_, Scheduler> {
        self.scheduler_.borrow()
    }

    pub fn scheduler_mut(&self) -> RefMut<'_, Scheduler> {
        self.scheduler_.borrow_mut()
    }

    pub fn syscallbuf_desched_sig(&self) -> u8 {
        self.syscallbuf_desched_sig_
    }

    pub fn use_file_cloning(&self) -> bool {
        self.use_file_cloning_
    }
    pub fn use_syscall_buffer(&self) -> bool {
        self.use_syscall_buffer_
    }
    pub fn trace_stream(&self) -> Option<&TraceStream> {
        Some(&self.trace_out)
    }
    pub fn trace_stream_mut(&mut self) -> Option<&mut TraceStream> {
        Some(&mut self.trace_out)
    }
}

impl Deref for RecordSession {
    type Target = SessionInner;

    fn deref(&self) -> &Self::Target {
        &self.session_inner
    }
}

impl DerefMut for RecordSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_inner
    }
}

impl Session for RecordSession {
    /// Forwarded method
    fn kill_all_tasks(&self) {
        kill_all_tasks(self)
    }

    fn on_destroy_task(&self, _t: TaskUid) {
        unimplemented!()
    }

    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn new_task(
        &self,
        _tid: pid_t,
        _rec_tid: Option<pid_t>,
        _serial: u32,
        _a: SupportedArch,
    ) -> Box<dyn Task> {
        unimplemented!()
    }

    fn on_create(&self, _t: TaskSharedPtr) {
        unimplemented!()
    }
}

fn check_perf_event_paranoid() {
    let fd = ScopedFd::open_path("/proc/sys/kernel/perf_event_paranoid", OFlag::O_RDONLY);
    if fd.is_open() {
        let mut buf = [0u8; 100];
        match read(fd.as_raw(), &mut buf) {
            Ok(siz) if siz != 0 => {
                let int_str = String::from_utf8_lossy(&buf[0..siz]);
                let maybe_val = int_str.trim().parse::<usize>();
                match maybe_val {
                    Ok(val) if val > 1 => {
                        clean_fatal!("rd needs `/proc/sys/kernel/perf_event_paranoid` <= 1, but it is {}.\n\
                                      Change it to 1, or use 'rd record -n' (slow).\n\
                                      Consider putting 'kernel.perf_event_paranoid = 1' in /etc/sysctl.conf", val);
                    }
                    Err(e) => {
                        clean_fatal!(
                            "Error while parsing file `/proc/sys/kernel/perf_event_paranoid`: {:?}",
                            e
                        );
                    }
                    _ => (),
                }
            }
            // @TODO This should actually be just Ok(0) but Rust doesn't accept it and says
            // patterns are not exhaustive.
            Ok(_) => {
                clean_fatal!(
                    "Read 0 bytes from `/proc/sys/kernel/perf_event_paranoid`.\n\
                             Need to read non-zero number of bytes."
                );
            }
            Err(e) => {
                clean_fatal!(
                    "Error while reading file `/proc/sys/kernel/perf_event_paranoid`: {:?}",
                    e
                );
            }
        }
    } else {
        log!(
            LogError,
            "Could not open `/proc/sys/kernel/perf_event_paranoid`. Continuing anyway."
        );
    }
}

fn find_helper_library<T: AsRef<OsStr>>(_lib: T) -> OsString {
    unimplemented!()
}

#[derive(Clone, Default)]
struct ExeInfo {
    /// None if anything fails
    libasan_path: Option<OsString>,
    has_asan_symbols: bool,
}

fn read_exe_info<T: AsRef<OsStr>>(full_path: T) -> ExeInfo {
    let maybe_data = fs::read(full_path.as_ref());

    let data = match maybe_data {
        Err(e) => fatal!("Error while reading {:?}: {:?}", full_path.as_ref(), e),
        Ok(data) => data,
    };

    match Elf::parse(&data) {
        Err(e) => fatal!("Error while Elf parsing {:?}: {:?}", full_path.as_ref(), e),
        Ok(_elf_file) => unimplemented!(),
    }
}

fn lookup_by_path<T: AsRef<OsStr>>(file: T) -> OsString {
    let file_ostr = file.as_ref();
    if find(file_ostr.as_bytes(), b"/").is_none() {
        return file_ostr.to_owned();
    }
    match env::var_os("PATH") {
        Some(path) => {
            let path_vec = path.into_vec();
            let dirs = path_vec.split(|&c| c == b':');
            for dir in dirs {
                let mut full_path = Vec::<u8>::new();
                full_path.extend_from_slice(dir);
                full_path.push(b'/');
                full_path.extend_from_slice(file_ostr.as_bytes());

                match stat(full_path.as_slice()) {
                    Ok(st) if st.st_mode & S_IFREG == S_IFREG => {
                        if access(full_path.as_slice(), AccessFlags::X_OK).is_ok() {
                            return OsString::from_vec(full_path);
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                }
            }
            file_ostr.to_owned()
        }
        None => file_ostr.to_owned(),
    }
}

fn inject_ld_helper_library(_env: &mut Vec<(OsString, OsString)>, _name: &OsStr, _value: Vec<u8>) {
    unimplemented!()
}
