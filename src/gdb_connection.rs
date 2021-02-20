use crate::{
    gdb_register::GdbRegister,
    log::LogLevel::{LogDebug, LogInfo},
    registers::MAX_REG_SIZE_BYTES,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::SessionSharedPtr,
    sig::Sig,
};
use libc::pid_t;
use nix::{
    errno::Errno,
    poll::{poll, PollFd, PollFlags},
    unistd,
    Error,
};
use std::{
    ffi::{OsStr, OsString},
    fmt::{self, Display},
    io::Write,
    os::unix::ffi::OsStrExt,
};

include!(concat!(
    env!("OUT_DIR"),
    "/gdb_request_bindings_generated.rs"
));

macro_rules! parser_assert {
    ( $x:expr ) => {{
        // DIFF NOTE: In rr the logic is ever so slightly different.
        // In rr there is a fputs followed by a debug_assert and exit.
        assert!($x, "Failed to parse gdb request");
    }};
}

macro_rules! parser_assert_eq {
    ( $x:expr, $y:expr ) => {{
        assert_eq!($x, $y, "Failed to parse gdb request");
    }};
}

const INTERRUPT_CHAR: u8 = b'\x03';

/// Represents a possibly-undefined register `name`.  `size` indicates how
/// many bytes of `value` are valid, if any.
#[derive(Clone, Default, Debug)]
pub struct GdbRegisterValue {
    pub name: GdbRegister,
    pub value: GdbRegisterValueData,
    pub defined: bool,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub enum GdbRegisterValueData {
    Value([u8; MAX_REG_SIZE_BYTES]),
    Value1(u8),
    Value2(u16),
    Value4(u32),
    Value8(u64),
}

impl Default for GdbRegisterValueData {
    fn default() -> Self {
        // Pick something arbitrary
        GdbRegisterValueData::Value8(0)
    }
}

impl GdbRegisterValue {
    pub fn value1(&self) -> u8 {
        match self.value {
            GdbRegisterValueData::Value1(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value2(&self) -> u16 {
        match self.value {
            GdbRegisterValueData::Value2(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value4(&self) -> u32 {
        match self.value {
            GdbRegisterValueData::Value4(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value8(&self) -> u64 {
        match self.value {
            GdbRegisterValueData::Value8(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value(&self) -> Vec<u8> {
        match self.value {
            GdbRegisterValueData::Value(v) => v[0..self.size].to_owned(),
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
}

/// Descriptor for task.  Note: on linux, we can uniquely identify any thread
/// by its `tid` (in rd's pid namespace).
#[derive(Clone, PartialEq, Eq)]
pub struct GdbThreadId {
    pub pid: pid_t,
    pub tid: pid_t,
}

impl Default for GdbThreadId {
    fn default() -> Self {
        GdbThreadId { pid: -1, tid: -1 }
    }
}

impl GdbThreadId {
    const ANY: GdbThreadId = GdbThreadId::new(0, 0);
    const ALL: GdbThreadId = GdbThreadId::new(-1, -1);

    const fn new(pid: pid_t, tid: pid_t) -> Self {
        GdbThreadId { pid, tid }
    }
}

impl Display for GdbThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}.{}", self.pid, self.tid)
    }
}

#[derive(Clone)]
pub struct GdbRequest {
    pub type_: GdbRequestType,
    pub value: GdbRequestValue,
    pub target: GdbThreadId,
    pub suppress_debugger_stop: bool,
}

#[derive(Clone)]
pub enum GdbRequestValue {
    GdbRequestNone,
    GdbRequestMem(gdb_request::Mem),
    GdbRequestWatch(gdb_request::Watch),
    GdbRequestRestart(gdb_request::Restart),
    GdbRequestRegisterValue(GdbRegisterValue),
    GdbRequestText(OsString),
    GdbRequestCont(gdb_request::Cont),
    GdbRequestTls(gdb_request::Tls),
    GdbRequestSymbol(gdb_request::Symbol),
    GdbRequestFileSetfs(gdb_request::FileSetfs),
    GdbRequestFileOpen(gdb_request::FileOpen),
    GdbRequestFilePread(gdb_request::FilePread),
    GdbRequestFileClose(gdb_request::FileClose),
}

impl GdbRequest {
    pub fn new(maybe_type: Option<GdbRequestType>) -> GdbRequest {
        let type_ = maybe_type.unwrap_or(DREQ_NONE);
        let value = match type_ {
            DREQ_NONE => GdbRequestValue::GdbRequestNone,
            t if t >= DREQ_MEM_FIRST && t <= DREQ_MEM_LAST => {
                GdbRequestValue::GdbRequestMem(Default::default())
            }
            t if t >= DREQ_WATCH_FIRST && t <= DREQ_WATCH_LAST => {
                GdbRequestValue::GdbRequestWatch(Default::default())
            }
            t if t >= DREQ_REG_FIRST && t <= DREQ_REG_LAST => {
                GdbRequestValue::GdbRequestRegisterValue(Default::default())
            }
            DREQ_RESTART => GdbRequestValue::GdbRequestRestart(Default::default()),
            DREQ_CONT => GdbRequestValue::GdbRequestCont(Default::default()),
            DREQ_RR_CMD => GdbRequestValue::GdbRequestText(Default::default()),
            DREQ_TLS => GdbRequestValue::GdbRequestTls(Default::default()),
            DREQ_QSYMBOL => GdbRequestValue::GdbRequestSymbol(Default::default()),
            DREQ_FILE_SETFS => GdbRequestValue::GdbRequestFileSetfs(Default::default()),
            DREQ_FILE_OPEN => GdbRequestValue::GdbRequestFileOpen(Default::default()),
            DREQ_FILE_PREAD => GdbRequestValue::GdbRequestFilePread(Default::default()),
            DREQ_FILE_CLOSE => GdbRequestValue::GdbRequestFileClose(Default::default()),
            _ => panic!("Unknown DREQ: {}", type_),
        };

        GdbRequest {
            type_,
            value,
            target: GdbThreadId::ANY,
            suppress_debugger_stop: false,
        }
    }

    /// Return nonzero if this requires that program execution be resumed in some way.
    pub fn is_resume_request(&self) -> bool {
        self.type_ == DREQ_CONT
    }
    pub fn mem(&self) -> &gdb_request::Mem {
        match &self.value {
            GdbRequestValue::GdbRequestMem(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn watch(&self) -> &gdb_request::Watch {
        match &self.value {
            GdbRequestValue::GdbRequestWatch(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn restart(&self) -> &gdb_request::Restart {
        match &self.value {
            GdbRequestValue::GdbRequestRestart(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn reg(&self) -> &GdbRegisterValue {
        match &self.value {
            GdbRequestValue::GdbRequestRegisterValue(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn cont(&self) -> &gdb_request::Cont {
        match &self.value {
            GdbRequestValue::GdbRequestCont(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn text(&self) -> &OsStr {
        match &self.value {
            GdbRequestValue::GdbRequestText(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn tls(&self) -> &gdb_request::Tls {
        match &self.value {
            GdbRequestValue::GdbRequestTls(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn sym(&self) -> &gdb_request::Symbol {
        match &self.value {
            GdbRequestValue::GdbRequestSymbol(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_setfs(&self) -> &gdb_request::FileSetfs {
        match &self.value {
            GdbRequestValue::GdbRequestFileSetfs(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_open(&self) -> &gdb_request::FileOpen {
        match &self.value {
            GdbRequestValue::GdbRequestFileOpen(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_pread(&self) -> &gdb_request::FilePread {
        match &self.value {
            GdbRequestValue::GdbRequestFilePread(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_close(&self) -> &gdb_request::FileClose {
        match &self.value {
            GdbRequestValue::GdbRequestFileClose(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn mem_mut(&mut self) -> &mut gdb_request::Mem {
        match &mut self.value {
            GdbRequestValue::GdbRequestMem(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn watch_mut(&mut self) -> &mut gdb_request::Watch {
        match &mut self.value {
            GdbRequestValue::GdbRequestWatch(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn restart_mut(&mut self) -> &mut gdb_request::Restart {
        match &mut self.value {
            GdbRequestValue::GdbRequestRestart(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn reg_mut(&mut self) -> &mut GdbRegisterValue {
        match &mut self.value {
            GdbRequestValue::GdbRequestRegisterValue(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn cont_mut(&mut self) -> &mut gdb_request::Cont {
        match &mut self.value {
            GdbRequestValue::GdbRequestCont(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn text_mut(&mut self) -> &mut OsString {
        match &mut self.value {
            GdbRequestValue::GdbRequestText(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn tls_mut(&mut self) -> &mut gdb_request::Tls {
        match &mut self.value {
            GdbRequestValue::GdbRequestTls(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn sym_mut(&mut self) -> &mut gdb_request::Symbol {
        match &mut self.value {
            GdbRequestValue::GdbRequestSymbol(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_setfs_mut(&mut self) -> &mut gdb_request::FileSetfs {
        match &mut self.value {
            GdbRequestValue::GdbRequestFileSetfs(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_open_mut(&mut self) -> &mut gdb_request::FileOpen {
        match &mut self.value {
            GdbRequestValue::GdbRequestFileOpen(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_pread_mut(&mut self) -> &mut gdb_request::FilePread {
        match &mut self.value {
            GdbRequestValue::GdbRequestFilePread(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
    pub fn file_close_mut(&mut self) -> &mut gdb_request::FileClose {
        match &mut self.value {
            GdbRequestValue::GdbRequestFileClose(v) => v,
            _ => panic!(
                "Unexpected GdbRequestValue enum variant. GdbRequestType was: {}",
                self.type_
            ),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum GdbRestartType {
    RestartFromPrevious,
    RestartFromEvent,
    RestartFromCheckpoint,
}

impl Default for GdbRestartType {
    fn default() -> Self {
        // Arbitrary
        GdbRestartType::RestartFromPrevious
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum GdbActionType {
    ActionContinue,
    ActionStep,
}

#[derive(Clone)]
pub struct GdbContAction {
    pub type_: GdbActionType,
    pub target: GdbThreadId,
    /// rr allows a 0 signal. We represent that by Option<Sig> where None becomes the 0 signal
    pub maybe_signal_to_deliver: Option<Sig>,
}

impl GdbContAction {
    pub fn new(
        maybe_type: Option<GdbActionType>,
        maybe_target: Option<GdbThreadId>,
        maybe_signal_to_deliver: Option<Sig>,
    ) -> GdbContAction {
        GdbContAction {
            type_: maybe_type.unwrap_or(GdbActionType::ActionContinue),
            target: maybe_target.unwrap_or(GdbThreadId::ANY),
            maybe_signal_to_deliver,
        }
    }
}

pub mod gdb_request {
    use super::{GdbContAction, GdbRestartType};
    use crate::{
        remote_ptr::{RemotePtr, Void},
        replay_timeline::RunDirection,
    };
    use libc::pid_t;
    use std::ffi::OsString;

    #[derive(Default, Clone)]
    pub struct Mem {
        pub addr: usize,
        pub len: usize,
        /// For SET_MEM requests, the |len| raw bytes that are to be written.
        /// For SEARCH_MEM requests, the bytes to search for.
        pub data: Vec<u8>,
    }

    #[derive(Default, Clone)]
    pub struct Watch {
        pub addr: usize,
        pub kind: i32,
        pub conditions: Vec<Vec<u8>>,
    }

    #[derive(Default, Clone)]
    pub struct Restart {
        pub param: i32,
        pub param_str: OsString,
        pub type_: GdbRestartType,
    }

    #[derive(Default, Clone)]
    pub struct Cont {
        pub run_direction: RunDirection,
        pub actions: Vec<GdbContAction>,
    }

    #[derive(Default, Clone)]
    pub struct Tls {
        pub offset: usize,
        pub load_module: RemotePtr<Void>,
    }

    #[derive(Default, Clone)]
    pub struct Symbol {
        pub has_address: bool,
        pub address: RemotePtr<Void>,
        pub name: OsString,
    }

    #[derive(Default, Clone)]
    pub struct FileSetfs {
        pub pid: pid_t,
    }

    #[derive(Default, Clone)]
    pub struct FileOpen {
        pub file_name: OsString,
        /// In system format, not gdb's format
        pub flags: i32,
        pub mode: i32,
    }

    #[derive(Default, Clone)]
    pub struct FilePread {
        pub fd: i32,
        pub size: usize,
        pub offset: u64,
    }

    #[derive(Default, Clone)]
    pub struct FileClose {
        pub fd: i32,
    }
}

#[derive(Copy, Clone)]
pub struct GdbConnectionFeatures {
    reverse_execution: bool,
}

impl Default for GdbConnectionFeatures {
    fn default() -> Self {
        Self {
            reverse_execution: true,
        }
    }
}

/// This struct wraps up the state of the gdb protocol, so that we can
/// offer a (mostly) stateless interface to clients.
pub struct GdbConnection {
    /// Current request to be processed.
    req: GdbRequest,
    /// Thread to be resumed.
    resume_thread: GdbThreadId,
    /// Thread for get/set requests.
    query_thread: GdbThreadId,
    /// gdb and rd don't work well together in multi-process and
    /// multi-exe-image debugging scenarios, so we pretend only
    /// this thread group exists when interfacing with gdb
    tgid: pid_t,
    cpu_features_: u32,
    /// true when "no-ack mode" enabled, in which we don't have
    /// to send ack packets back to gdb.  This is a huge perf win.
    no_ack: bool,
    sock_fd: ScopedFd,
    /// buffered input from gdb
    inbuf: Vec<u8>,
    /// index of '#' character
    packetend: usize,
    /// buffered output from gdb
    outbuf: Vec<u8>,
    features_: GdbConnectionFeatures,
    connection_alive_: bool,
    /// client supports multiprocess extension
    multiprocess_supported_: bool,
}

impl GdbConnection {
    /// Call this when the target of |req| is needed to fulfill the
    /// request, but the target is dead.  This situation is a symptom of a
    /// gdb or rr bug.
    pub fn notify_no_such_thread(_req: &GdbRequest) {
        unimplemented!()
    }

    /// Finish a DREQ_RESTART request.  Should be invoked after replay
    /// restarts and prior GdbConnection has been restored.
    pub fn notify_restart() {
        unimplemented!()
    }

    /// Return the current request made by the debugger host, that needs to
    /// be satisfied.  This function will block until either there's a
    /// debugger host request that needs a response, or until a request is
    /// made to resume execution of the target.  In the latter case,
    /// calling this function multiple times will return an appropriate
    /// resume request each time (see above).
    ///
    /// The target should peek at the debugger request in between execution
    /// steps.  A new request may need to be serviced.
    pub fn get_request() -> GdbRequest {
        unimplemented!()
    }

    /// Notify the host that this process has exited with |code|.
    pub fn notify_exit_code(_code: i32) {
        unimplemented!()
    }

    /// Notify the host that this process has exited from |sig|.
    pub fn notify_exit_signal(_sig: Sig) {
        unimplemented!()
    }

    /// Notify the host that a resume request has "finished", i.e., the
    /// target has stopped executing for some reason.  |sig| is the signal
    /// that stopped execution, or 0 if execution stopped otherwise.
    pub fn notify_stop(_which: GdbThreadId, _sig: Sig, _watch_addr: Option<usize>) {
        unimplemented!()
    }

    /// Notify the debugger that a restart request failed.
    pub fn notify_restart_failed() {
        unimplemented!()
    }

    /// Tell the host that |thread| is the current thread.
    pub fn reply_get_current_thread(_thread: GdbThreadId) {
        unimplemented!()
    }

    /// Reply with the target thread's |auxv| pairs. |auxv.empty()|
    /// if there was an error reading the auxiliary vector.
    pub fn reply_get_auxv(_auxv: &[u8]) {
        unimplemented!()
    }

    /// Reply with the target thread's executable file name
    pub fn reply_get_exec_file(_exec_file: &OsStr) {
        unimplemented!()
    }

    /// |alive| is true if the requested thread is alive, false if dead.
    pub fn reply_get_is_thread_alive(_alive: bool) {
        unimplemented!()
    }

    /// |info| is a string containing data about the request target that
    /// might be relevant to the debugger user.
    pub fn reply_get_thread_extra_info(_info: &OsStr) {
        unimplemented!()
    }

    /// |ok| is true if req->target can be selected, false otherwise.
    pub fn reply_select_thread(_ok: bool) {
        unimplemented!()
    }

    /// The first |mem.size()| bytes of the request were read into |mem|.
    /// |mem.size()| must be less than or equal to the length of the request.
    pub fn reply_get_mem(_mem: &[u8]) {
        unimplemented!()
    }

    /// |ok| is true if a SET_MEM request succeeded, false otherwise.  This
    /// function *must* be called whenever a SET_MEM request is made,
    /// regardless of success/failure or special interpretation.
    pub fn reply_set_mem(_ok: bool) {
        unimplemented!()
    }

    /// Reply to the DREQ_SEARCH_MEM request.
    /// |found| is true if we found the searched-for bytes starting at address
    /// |addr|.
    pub fn reply_search_mem(_found: bool, _addr: RemotePtr<Void>) {
        unimplemented!()
    }

    /// Reply to the DREQ_GET_OFFSETS request.
    pub fn reply_get_offsets(/* TODO*/) {
        unimplemented!()
    }

    /// Send |value| back to the debugger host.  |value| may be undefined.
    pub fn reply_get_reg(_value: &GdbRegisterValue) {
        unimplemented!()
    }

    /// Send |file| back to the debugger host.  |file| may contain
    /// undefined register values.
    pub fn reply_get_regs(_file: &[GdbRegisterValue]) {
        unimplemented!()
    }

    /// Pass |ok = true| iff the requested register was successfully set.
    pub fn reply_set_reg(_ok: bool) {
        unimplemented!()
    }

    /// Reply to the DREQ_GET_STOP_REASON request.
    pub fn reply_get_stop_reason(_which: GdbThreadId, _sig: Sig) {
        unimplemented!()
    }

    /// |threads| contains the list of live threads, of which there are
    /// |len|.
    pub fn reply_get_thread_list(_threads: &[GdbThreadId]) {
        unimplemented!()
    }

    /// |ok| is true if the request was successfully applied, false if
    /// not.
    pub fn reply_watchpoint_request(_ok: bool) {
        unimplemented!()
    }

    /// DREQ_DETACH was processed.
    ///
    /// There's no functional reason to reply to the detach request.
    /// However, some versions of gdb expect a response and time out
    /// awaiting it, wasting developer time.
    pub fn reply_detach() {
        unimplemented!()
    }

    /// Pass the siginfo_t and its size (as requested by the debugger) in
    /// |si_bytes| and |num_bytes| if successfully read.  Otherwise pass
    /// |si_bytes = nullptr|.
    pub fn reply_read_siginfo(_si_bytes: &[u8]) {
        unimplemented!()
    }

    /// Not yet implemented, but call this after a WRITE_SIGINFO request
    /// anyway.
    pub fn reply_write_siginfo(/* TODO*/) {
        unimplemented!()
    }

    /// Send a manual text response to a rr cmd (maintenance) packet.
    pub fn reply_rd_cmd(_text: &OsStr) {
        unimplemented!()
    }

    /// Send a qSymbol response to gdb, requesting the address of the
    /// symbol |name|.
    pub fn send_qsymbol(_name: &OsStr) {
        unimplemented!()
    }

    /// The "all done" response to a qSymbol packet from gdb.
    pub fn qsymbols_finished() {
        unimplemented!()
    }

    /// Respond to a qGetTLSAddr packet.  If |ok| is true, then respond
    /// with |address|.  If |ok| is false, respond with an error.
    pub fn reply_tls_addr(_ok: bool, _addr: RemotePtr<Void>) {
        unimplemented!()
    }

    /// Respond to a vFile:setfs
    pub fn reply_setfs(_err: i32) {
        unimplemented!()
    }

    /// Respond to a vFile:open
    pub fn reply_open(_fd: i32, _err: i32) {
        unimplemented!()
    }

    /// Respond to a vFile:pread
    pub fn reply_pread(_bytes: &[u8], _err: i32) {
        unimplemented!()
    }

    /// Respond to a vFile:close
    pub fn reply_close(_err: i32) {
        unimplemented!()
    }

    /// Create a checkpoint of the given Session with the given id. Delete the
    /// existing checkpoint with that id if there is one.
    ///
    /// DIFF NOTE: The checkpoint id is signed in rr
    /// DIFF NOTE: In rr we pass in a ReplaySession shared pointer
    fn created_checkpoint(_checkpoint: SessionSharedPtr, _checkpoint_id: u32) {
        unimplemented!()
    }

    /// Delete the checkpoint with the given id. Silently fail if the checkpoint
    /// does not exist.

    /// DIFF NOTE: The checkpoint id is signed in rr
    pub fn delete_checkpoint(_checkpoint_id: u32) {
        unimplemented!()
    }

    /// Get the checkpoint with the given id. Return null if not found.
    pub fn get_checkpoint(_checkpoint_id: u32) -> SessionSharedPtr {
        unimplemented!()
    }

    /// Return true if there's a new packet to be read/process (whether
    /// incomplete or not), and false if there isn't one.
    pub fn sniff_packet() -> bool {
        unimplemented!()
    }

    pub fn features(&self) -> GdbConnectionFeatures {
        self.features_
    }

    pub fn set_cpu_features(&mut self, features: u32) {
        self.cpu_features_ = features
    }

    pub fn cpu_features(&self) -> u32 {
        self.cpu_features_
    }

    pub fn new(_tgid: pid_t, _features: GdbConnectionFeatures) -> GdbConnection {
        unimplemented!()
    }

    /// Wait for a debugger client to connect to |dbg|'s socket.  Blocks
    /// indefinitely.
    pub fn await_debugger(_listen_fd: &ScopedFd) {
        unimplemented!()
    }

    ///  Returns false if the connection has been closed
    pub fn is_connection_alive() -> bool {
        unimplemented!()
    }

    /// read() incoming data exactly one time, successfully.  May block.
    fn read_data_once(&mut self) {
        // Wait until there's data, instead of busy-looping on EAGAIN.
        poll_incoming(&self.sock_fd, -1 /* wait forever */);
        let mut buf = [0u8; 4096];
        let result = unistd::read(self.sock_fd.as_raw(), &mut buf);
        match result {
            Ok(0) | Err(_) => {
                log!(
                    LogInfo,
                    "Could not read data from gdb socket, marking connection as closed"
                );
                self.connection_alive_ = false;
            }
            Ok(nread) => {
                self.inbuf.extend_from_slice(&buf[0..nread]);
            }
        }
    }

    /// Send all pending output to gdb.  May block.
    fn write_flush(&mut self) {
        let mut write_index: usize = 0;

        log!(
            LogDebug,
            "write_flush: {:?}",
            OsStr::from_bytes(&self.outbuf)
        );

        while write_index < self.outbuf.len() {
            poll_outgoing(&self.sock_fd, -1 /*wait forever*/);
            let result = unistd::write(self.sock_fd.as_raw(), &mut self.outbuf[write_index..]);
            match result {
                Err(_) => {
                    log!(
                        LogInfo,
                        "Could not write data to gdb socket, marking connection as closed",
                    );
                    self.connection_alive_ = false;
                    self.outbuf.clear();
                    return;
                }
                Ok(nwritten) => {
                    write_index += nwritten;
                }
            }
        }

        self.outbuf.clear();
    }

    fn write_data_raw(&mut self, data: &[u8]) {
        self.outbuf.extend_from_slice(data);
    }

    fn write_hex(&mut self, hex: usize) {
        let mut buf: Vec<u8> = Vec::new();

        write!(buf, "{:02x}", hex).unwrap();
        self.write_data_raw(&buf);
    }

    fn write_packet_bytes(&mut self, data: &[u8]) {
        let mut checksum: u8 = 0;

        self.write_data_raw(b"$");
        for &b in data {
            checksum = checksum.overflowing_add(b).0;
        }
        self.write_data_raw(data);
        self.write_data_raw(b"#");
        self.write_hex(checksum as usize);
    }

    /// NOTE: This function is intended to write a null terminated c-string in rr
    fn write_packet(_data: &[u8]) {
        unimplemented!()
    }

    /// DIFF NOTE: prefix is a null terminated c-string in rr. here its just a slice.
    fn write_binary_packet(&mut self, pfx: &[u8], data: &[u8]) {
        let pfx_num_chars = pfx.len();
        let num_bytes = data.len();
        let mut buf = Vec::<u8>::with_capacity(2 * num_bytes + pfx_num_chars);

        buf.extend_from_slice(pfx);
        for &b in data {
            match b {
                b'#' | b'$' | b'}' | b'*' => {
                    buf.push(b'}');
                    buf.push(b ^ 0x20);
                }
                _ => {
                    buf.push(b);
                }
            }
        }

        log!(
            LogDebug,
            " ***** NOTE: writing binary data, upcoming debug output may be truncated"
        );

        self.write_packet_bytes(&buf);
    }

    /// DIFF NOTE: prefix is a null terminated c-string in rr. here its just a slice.
    fn write_hex_bytes_packet_with_prefix(&mut self, prefix: &[u8], data: &[u8]) {
        let mut buf = Vec::<u8>::with_capacity(prefix.len() + 2 * data.len());
        buf.extend_from_slice(prefix);
        for &b in data {
            write!(buf, "{:02x}", b).unwrap();
        }
        self.write_packet_bytes(&buf);
    }

    fn write_hex_bytes_packet(&mut self, data: &[u8]) {
        self.write_hex_bytes_packet_with_prefix(&[], data)
    }

    fn write_xfer_response(_data: &[u8], _offset: u64, _len: u64) {
        unimplemented!()
    }

    /// Consume bytes in the input buffer until start-of-packet ('$') or
    /// the interrupt character is seen.  Does not block.  Return true if
    /// seen, false if not.
    fn skip_to_packet_start(&mut self) -> bool {
        let mut maybe_end = None;
        // Can we make this more efficient?
        // XXX we want memcspn() here
        for i in 0..self.inbuf.len() {
            if self.inbuf[i] == b'$' || self.inbuf[i] == INTERRUPT_CHAR {
                maybe_end = Some(i);
                break;
            }
        }
        match maybe_end {
            None => {
                // Discard all read bytes, which we don't care about
                self.inbuf.clear();
                return false;
            }
            Some(end) => {
                // Discard bytes up to start-of-packet
                self.inbuf.drain(..end);
            }
        }

        parser_assert!(1 <= self.inbuf.len());
        parser_assert!(b'$' == self.inbuf[0] || INTERRUPT_CHAR == self.inbuf[0]);

        true
    }

    /// Block until the sequence of bytes
    ///
    ///    "[^$]*\$[^#]*#.*"
    ///
    /// has been read from the client fd.  This is one (or more) gdb
    /// packet(s).
    fn read_packet() {
        unimplemented!()
    }

    /// Return true if we need to do something in a debugger request,
    /// false if we already handled the packet internally.
    fn xfer(_name: &OsStr, _args: &[&OsStr]) -> bool {
        unimplemented!()
    }

    /// Return true if we need to do something in a debugger request,
    /// false if we already handled the packet internally.
    fn query(_payload: &[u8]) -> bool {
        unimplemented!()
    }

    /// Return true if we need to do something in a debugger request,
    /// false if we already handled the packet internally.
    fn set_var(_payload: &[u8]) -> bool {
        unimplemented!()
    }

    /// Return true if we need to do something in a debugger request,
    /// false if we already handled the packet internally.
    fn process_vpacket(_payload: &[u8]) -> bool {
        unimplemented!()
    }

    /// Return true if we need to do something in a debugger request,
    /// false if we already handled the packet internally.
    fn process_bpacket(_payload: &[u8]) -> bool {
        unimplemented!()
    }

    /// Return true if we need to do something in a debugger request,
    /// false if we already handled the packet internally.
    fn process_packet() -> bool {
        unimplemented!()
    }

    fn consume_request() {
        unimplemented!()
    }

    fn send_stop_reply_packet(_thread: GdbThreadId, _sig: Sig, _watch_addr: Option<usize>) {
        unimplemented!()
    }

    fn send_file_error_reply(&mut self, system_errno: i32) {
        let gdb_err;
        match system_errno {
            libc::EPERM => {
                gdb_err = 1;
            }
            libc::ENOENT => {
                gdb_err = 2;
            }
            libc::EINTR => {
                gdb_err = 4;
            }
            libc::EBADF => {
                gdb_err = 9;
            }
            libc::EACCES => {
                gdb_err = 13;
            }
            libc::EFAULT => {
                gdb_err = 14;
            }
            libc::EBUSY => {
                gdb_err = 16;
            }
            libc::EEXIST => {
                gdb_err = 17;
            }
            libc::ENODEV => {
                gdb_err = 19;
            }
            libc::ENOTDIR => {
                gdb_err = 20;
            }
            libc::EISDIR => {
                gdb_err = 21;
            }
            libc::EINVAL => {
                gdb_err = 22;
            }
            libc::ENFILE => {
                gdb_err = 23;
            }
            libc::EMFILE => {
                gdb_err = 24;
            }
            libc::EFBIG => {
                gdb_err = 27;
            }
            libc::ENOSPC => {
                gdb_err = 28;
            }
            libc::ESPIPE => {
                gdb_err = 29;
            }
            libc::EROFS => {
                gdb_err = 30;
            }
            libc::ENAMETOOLONG => {
                gdb_err = 91;
            }
            _ => {
                gdb_err = 9999;
            }
        };
        let mut buf = Vec::<u8>::new();
        write!(buf, "F-01,{:x}", gdb_err).unwrap();
        self.write_packet_bytes(&buf);
    }
}

fn poll_incoming(sock_fd: &ScopedFd, timeout_ms: i32) {
    poll_socket(
        sock_fd,
        PollFlags::POLLIN, /* TODO: |POLLERR */
        timeout_ms,
    );
}

fn poll_outgoing(sock_fd: &ScopedFd, timeout_ms: i32) {
    poll_socket(
        sock_fd,
        PollFlags::POLLOUT, /* TODO: |POLLERR */
        timeout_ms,
    );
}

/// Poll for data to or from gdb, waiting `timeoutMs`.  0 means "don't
/// wait", and -1 means "wait forever".  Return true if data is ready.
fn poll_socket(sock_fd: &ScopedFd, events: PollFlags, timeout_ms: i32) -> bool {
    let mut pfds = [PollFd::new(sock_fd.as_raw(), events)];

    match poll(&mut pfds, timeout_ms) {
        Ok(ret) if ret > 0 => return true,
        Err(Error::Sys(err)) if err != Errno::EINTR => log!(LogInfo, "gdb socket has been closed"),
        _ => (),
    }

    false
}

fn decode_ascii_encoded_hex_str(encoded: &[u8]) -> String {
    let enc_len = encoded.len();
    parser_assert_eq!(enc_len % 2, 0);
    let mut decoded_str = String::new();
    for i in 0..enc_len {
        let enc_byte_str = std::str::from_utf8(&encoded[2 * i..2 * i + 2]).unwrap();
        let c_u8 = u8::from_str_radix(enc_byte_str, 16).unwrap();
        parser_assert!(c_u8 < 128);
        let c: char = c_u8.into();
        decoded_str.push(c);
    }

    decoded_str
}
