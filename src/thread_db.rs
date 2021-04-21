use crate::{
    bindings::thread_db,
    log::LogDebug,
    remote_ptr::{RemotePtr, Void},
    thread_group::ThreadGroup,
};
use libc::pid_t;
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_void, CStr, OsStr, OsString},
    os::unix::ffi::OsStrExt,
};

const LIBRARY_NAME: &'static [u8] = b"libthread_db.so.1\0";

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

type TdSymbolListFn = extern "C" fn() -> *mut *const ::std::os::raw::c_char;

/// This is declared as incomplete by the libthread_db API and is
/// expected to be defined by the API user.  We define it to hold just
/// pointers back to the thread group and to the ThreadDb object.
#[repr(C)]
struct ps_prochandle {
    thread_group: *mut ThreadGroup,
    db: *mut ThreadDb,
    tgid: pid_t,
}

impl Default for ps_prochandle {
    fn default() -> Self {
        Self {
            thread_group: std::ptr::null_mut(),
            db: std::ptr::null_mut(),
            tgid: 0,
        }
    }
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
    td_ta_delete_fn: *mut TdTaDeleteFn,
    td_thr_tls_get_addr_fn: *mut TdThrTlsGetAddrFn,
    td_ta_map_lwp2thr_fn: *mut TdTaMapLwp2ThrFn,
    td_ta_new_fn: *mut TdTaNewFn,

    /// Set of all symbol names.
    symbol_names: HashSet<&'static CStr>,

    /// Map from symbol names to addresses.
    symbols: HashMap<OsString, RemotePtr<Void>>,
}

impl Default for ThreadDb {
    fn default() -> Self {
        ThreadDb {
            loaded: false,
            prochandle: Default::default(),
            internal_handle: std::ptr::null_mut(),
            thread_db_library: std::ptr::null_mut(),
            td_ta_delete_fn: std::ptr::null_mut(),
            td_thr_tls_get_addr_fn: std::ptr::null_mut(),
            td_ta_map_lwp2thr_fn: std::ptr::null_mut(),
            td_ta_new_fn: std::ptr::null_mut(),
            symbol_names: Default::default(),
            symbols: Default::default(),
        }
    }
}

impl ThreadDb {
    /// @TODO DIFF NOTE: private in rr
    pub fn load_library(&mut self) -> bool {
        if !self.thread_db_library.is_null() {
            log!(LogDebug, "load_library already loaded: {:?}", self.loaded);
            return self.loaded;
        }

        self.thread_db_library =
            unsafe { libc::dlopen(LIBRARY_NAME.as_ptr() as _, libc::RTLD_NOW) };
        if self.thread_db_library.is_null() {
            log!(LogDebug, "load_library dlopen failed: {:?}", unsafe {
                CStr::from_ptr(libc::dlerror())
            });
            return false;
        }

        let td_symbol_list_fn: *mut TdSymbolListFn;

        self.td_thr_tls_get_addr_fn =
            self.find_function(b"td_thr_tls_get_addr") as *mut TdThrTlsGetAddrFn;
        if self.td_thr_tls_get_addr_fn.is_null() {
            return false;
        }

        self.td_ta_delete_fn = self.find_function(b"td_ta_delete") as *mut TdTaDeleteFn;
        if self.td_ta_delete_fn.is_null() {
            return false;
        }

        td_symbol_list_fn = self.find_function(b"td_symbol_list") as *mut TdSymbolListFn;
        if td_symbol_list_fn.is_null() {
            return false;
        }

        self.td_ta_new_fn = self.find_function(b"td_ta_new") as *mut TdTaNewFn;
        if self.td_ta_new_fn.is_null() {
            return false;
        }

        self.td_ta_map_lwp2thr_fn =
            self.find_function(b"td_ta_map_lwp2thr") as *mut TdTaMapLwp2ThrFn;
        if self.td_ta_map_lwp2thr_fn.is_null() {
            return false;
        }

        unsafe {
            let mut syms = (*td_symbol_list_fn)();
            while !std::ptr::eq(*syms, std::ptr::null()) {
                // @TODO Is CStr what we want here?
                self.symbol_names.insert(CStr::from_ptr(*syms));
                syms = syms.add(1);
            }
        }
        // Good to go.
        self.loaded = true;
        log!(LogDebug, "load_library OK");
        true
    }

    fn find_function(&self, name: &[u8]) -> *mut c_void {
        let ret = unsafe { libc::dlsym(self.thread_db_library, name.as_ptr() as _) };
        if ret.is_null() {
            log!(
                LogDebug,
                "load_library failed to find {:?}",
                OsStr::from_bytes(&name[0..name.len() - 1])
            );
        }
        ret
    }
}
