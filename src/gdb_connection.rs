use crate::{
    gdb_register::GdbRegister,
    registers::MAX_REG_SIZE_BYTES,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::SessionSharedPtr,
    sig::Sig,
};
use libc::pid_t;
use std::ffi::OsStr;

/// Represents a possibly-undefined register `name`.  `size` indicates how
/// many bytes of `value` are valid, if any.
#[derive(Clone, Debug)]
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

/// @TODO
pub struct GdbThreadId;

/// @TODO
pub struct GdbRequest;

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
    fn read_data_once() {
        unimplemented!()
    }

    /// Send all pending output to gdb.  May block.
    fn write_flush() {
        unimplemented!()
    }

    fn write_data_raw(_data: &[u8]) {
        unimplemented!()
    }

    /// @TODO: Correct size chosen?
    fn write_hex(_hex: usize) {
        unimplemented!()
    }

    fn write_packet_bytes(_data: &[u8]) {
        unimplemented!()
    }

    fn write_packet(_data: &[u8]) {
        unimplemented!()
    }

    /// DIFF NOTE: num_bytes is a ssize_t in rr
    fn write_binary_packet(_pfx: &[u8], _data: &[u8]) {
        unimplemented!()
    }

    fn write_hex_bytes_packet_with_prefix(_prefix: &[u8], _data: &[u8]) {
        unimplemented!()
    }

    fn write_hex_bytes_packet(_data: &[u8]) {
        unimplemented!()
    }

    fn write_xfer_response(_data: &[u8], _offset: u64, _len: u64) {
        unimplemented!()
    }

    /// Consume bytes in the input buffer until start-of-packet ('$') or
    /// the interrupt character is seen.  Does not block.  Return true if
    /// seen, false if not.
    fn skip_to_packet_start() -> bool {
        unimplemented!()
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

    fn send_file_error_reply(_system_errno: i32) {
        unimplemented!()
    }
}
