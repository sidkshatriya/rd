use crate::{
    bindings::thread_db,
    remote_ptr::{RemotePtr, Void},
    thread_group::ThreadGroup,
};
use libc::pid_t;
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_void, OsString},
};

type TdTaDeleteFn = extern "C" fn(ta: *mut thread_db::td_thragent_t) -> thread_db::td_err_e;

type TdThrTlsGetAddrFn = extern "C" fn(
    th: *const thread_db::td_thrhandle_t,
    map_address: thread_db::psaddr_t,
    offset: thread_db::size_t,
    address: *mut thread_db::psaddr_t,
) -> thread_db::td_err_e;

type TdTaMapLwp2ThrFn = extern "C" fn(
    ta: *const thread_db::td_thragent_t,
    lwpid: thread_db::lwpid_t,
    th: *mut thread_db::td_thrhandle_t,
) -> thread_db::td_err_e;

type TdTaNewFn = extern "C" fn(
    ps: *mut thread_db::ps_prochandle,
    ta: *mut *mut thread_db::td_thragent_t,
) -> thread_db::td_err_e;

/// This is declared as incomplete by the libthread_db API and is
/// expected to be defined by the API user.  We define it to hold just
/// pointers back to the thread group and to the ThreadDb object.
#[repr(C)]
struct ps_prochandle {
    thread_group: *mut ThreadGroup,
    db: *mut ThreadDb,
    tgid: pid_t,
}

/// This provides an interface to libthread_db.so to help with TLS
/// lookup. In principle there could be one instance per process, but we only
/// support one instance for the GdbServer's target process.
///
/// The overall approach is that a libthread_db.so is loaded into rr
/// when this class is initialized (see |load_library|).  This provides
/// the GdbServer with a list of symbols whose addresses might be
/// needed in order to resolve TLS accesses.
///
/// Then, when the address of a TLS variable is requested by the
/// debugger, GdbServer calls |get_tls_address|.  This uses the
/// libthread_db "new" function ("td_ta_new"); if this succeeds then
/// ThreadDb proceeds to use other APIs to find the desired address.
///
/// ThreadDb works on a callback model, using symbols provided by the
/// hosting application.  These are all defined in ThreadDb.cc.
pub struct ThreadDb {
    /// True if libthread_db has been successfully initialized, if all
    /// the functions exist, and if the list of needed symbol names has
    /// been computed.
    loaded: bool,

    /// The external handle for this thread, for libthread_db.
    prochandle: ps_prochandle,

    /// The internal handle for this thread, from libthread_db.
    internal_handle: *mut thread_db::td_thragent_t,

    /// Handle on the libthread_db library itself.
    thread_db_library: *mut c_void,

    /// Functions from libthread_db.
    td_ta_delete_fn: TdTaDeleteFn,
    td_thr_tls_get_addr_fn: TdThrTlsGetAddrFn,
    td_ta_map_lwp2thr_fn: TdTaMapLwp2ThrFn,
    td_ta_new_fn: TdTaNewFn,

    /// Set of all symbol names.
    symbol_names: HashSet<OsString>,

    /// Map from symbol names to addresses.
    symbols: HashMap<OsString, RemotePtr<Void>>,
}
