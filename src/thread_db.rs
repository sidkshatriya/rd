use crate::{
    bindings::{kernel::user_regs_struct, thread_db},
    log::LogDebug,
    remote_ptr::{RemotePtr, Void},
    thread_group::ThreadGroup,
};
use libc::pid_t;
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_void, CStr, OsStr, OsString},
    mem,
    os::{raw::c_char, unix::ffi::OsStrExt},
    ptr::copy_nonoverlapping,
    slice,
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
pub struct ps_prochandle {
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
///
/// DIFF NOTE: loaded struct member not there in rd
pub struct ThreadDb {
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
    symbol_names: HashSet<&'static CStr>,

    /// Map from symbol names to addresses.
    symbols: HashMap<OsString, RemotePtr<Void>>,
}

impl Drop for ThreadDb {
    fn drop(&mut self) {
        if !self.internal_handle.is_null() {
            (self.td_ta_delete_fn)(self.internal_handle);
        }
        if !self.thread_db_library.is_null() {
            unsafe { libc::dlclose(self.thread_db_library) };
        }
    }
}

impl ThreadDb {
    pub fn new(tgid: pid_t) -> Box<ThreadDb> {
        let thread_db_library = unsafe { libc::dlopen(LIBRARY_NAME.as_ptr() as _, libc::RTLD_NOW) };
        if thread_db_library.is_null() {
            fatal!("load_library dlopen failed: {:?}", unsafe {
                CStr::from_ptr(libc::dlerror())
            });
        }

        let ptr = find_function(thread_db_library, b"td_thr_tls_get_addr\0");
        if ptr.is_null() {
            fatal!("Could not find function td_thr_tls_get_addr");
        }
        let td_thr_tls_get_addr_fn: TdThrTlsGetAddrFn = unsafe { mem::transmute(ptr) };

        let ptr = find_function(thread_db_library, b"td_ta_delete\0");
        if ptr.is_null() {
            fatal!("Could not find function td_ta_delete");
        }
        let td_ta_delete_fn: TdTaDeleteFn = unsafe { mem::transmute(ptr) };

        let ptr = find_function(thread_db_library, b"td_symbol_list\0");
        if ptr.is_null() {
            fatal!("Could not find function td_symbol_list");
        }
        let td_symbol_list_fn: TdSymbolListFn = unsafe { mem::transmute(ptr) };

        let ptr = find_function(thread_db_library, b"td_ta_new\0");
        if ptr.is_null() {
            fatal!("Could not find function td_ta_new");
        }
        let td_ta_new_fn: TdTaNewFn = unsafe { mem::transmute(ptr) };

        let ptr = find_function(thread_db_library, b"td_ta_map_lwp2thr\0");
        if ptr.is_null() {
            fatal!("Could not find function td_ta_map_lwp2thr");
        }
        let td_ta_map_lwp2thr_fn: TdTaMapLwp2ThrFn = unsafe { mem::transmute(ptr) };

        let mut symbol_names: HashSet<&CStr> = HashSet::new();
        unsafe {
            let mut syms = td_symbol_list_fn();
            while !std::ptr::eq(*syms, std::ptr::null()) {
                // @TODO Is CStr what we want here?
                symbol_names.insert(CStr::from_ptr(*syms));
                syms = syms.add(1);
            }
        }
        log!(LogDebug, "load_library OK");
        let mut b = Box::new(ThreadDb {
            prochandle: Default::default(),
            internal_handle: std::ptr::null_mut(),
            thread_db_library,
            td_ta_delete_fn,
            td_thr_tls_get_addr_fn,
            td_ta_map_lwp2thr_fn,
            td_ta_new_fn,
            symbol_names,
            symbols: Default::default(),
        });

        b.prochandle.db = &raw mut *b;
        b.prochandle.tgid = tgid;

        b
    }

    fn query_symbol(&self, _symbol: &CStr, _addr: &mut RemotePtr<u8>) -> bool {
        unimplemented!()
    }
}

fn find_function(thread_db_library: *mut c_void, name: &[u8]) -> *mut c_void {
    let ret = unsafe { libc::dlsym(thread_db_library, name.as_ptr() as _) };
    if ret.is_null() {
        log!(
            LogDebug,
            "load_library failed to find {:?}",
            OsStr::from_bytes(&name[0..name.len() - 1])
        );
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn ps_pglobal_lookup(
    h: *mut ps_prochandle,
    _: *const c_char,
    symbol: *const c_char,
    sym_addr: *mut thread_db::psaddr_t,
) -> thread_db::ps_err_e {
    let mut addr = RemotePtr::<Void>::null();
    let cstr_symbol = CStr::from_ptr(symbol);
    if !(*(*h).db).query_symbol(cstr_symbol, &mut addr) {
        log!(LogDebug, "ps_pglobal_lookup {:?} failed", cstr_symbol);
        return thread_db::PS_NOSYM;
    }
    *sym_addr = addr.as_usize() as _;
    log!(
        LogDebug,
        "ps_pglobal_lookup {:?} OK",
        CStr::from_ptr(symbol)
    );
    thread_db::PS_OK
}

#[no_mangle]
pub unsafe extern "C" fn ps_pdread(
    h: *mut ps_prochandle,
    addr: thread_db::psaddr_t,
    buffer: *mut c_void,
    len: libc::size_t,
) -> thread_db::ps_err_e {
    if (*h).thread_group.is_null() {
        fatal!("unexpected ps_pdread call with uninitialized thread_group");
    }
    let mut ok = true;
    let uaddr = RemotePtr::<u8>::new(addr as usize);
    // We need any task associated with the thread group.  Here we assume
    // that all the tasks in the thread group share VM, which is enforced
    // by clone(2).
    let task = (*(*h).thread_group).task_set().iter().next().unwrap();
    let buf = slice::from_raw_parts_mut(buffer as *mut u8, len);
    task.read_bytes_helper(uaddr, buf, Some(&mut ok));
    log!(LogDebug, "ps_pdread {:?}", ok);
    if ok {
        thread_db::PS_OK
    } else {
        thread_db::PS_ERR
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_pdwrite(
    _: *mut ps_prochandle,
    _: thread_db::psaddr_t,
    _: *const c_void,
    _: thread_db::size_t,
) -> thread_db::ps_err_e {
    fatal!("ps_pdwrite not implemented");
}

#[no_mangle]
pub unsafe extern "C" fn ps_lgetregs(
    h: *mut ps_prochandle,
    rec_tid: thread_db::lwpid_t,
    result: *mut thread_db::elf_greg_t,
) -> thread_db::ps_err_e {
    if (*h).thread_group.is_null() {
        fatal!("unexpected ps_lgetregs call with uninitialized thread_group");
    }
    // DIFF NOTE: In rr there is simply a debug_assert to make sure task is not null; we unwrap
    let task = (*(*h).thread_group)
        .session()
        .find_task_from_rec_tid(rec_tid)
        .unwrap();

    let regs = task.regs_ref().get_ptrace();
    copy_nonoverlapping(
        &regs as *const user_regs_struct as *const u8,
        result as *mut u8,
        mem::size_of_val(&regs),
    );
    log!(LogDebug, "ps_lgetregs OK");
    thread_db::PS_OK
}

#[no_mangle]
pub unsafe extern "C" fn ps_lsetregs(
    _: *mut ps_prochandle,
    _: thread_db::lwpid_t,
    _: *mut thread_db::elf_greg_t,
) -> thread_db::ps_err_e {
    fatal!("ps_lsetregs not implemented");
}

#[no_mangle]
pub unsafe extern "C" fn ps_lgetfpregs(
    _: *mut ps_prochandle,
    _: thread_db::lwpid_t,
    _: *mut thread_db::prfpregset_t,
) -> thread_db::ps_err_e {
    fatal!("ps_lgetfpregs not implemented");
}

#[no_mangle]
pub extern "C" fn ps_lsetfpregs(
    _: *mut ps_prochandle,
    _: thread_db::lwpid_t,
    _: *const thread_db::prfpregset_t,
) -> thread_db::ps_err_e {
    fatal!("ps_lsetfpregs not implemented");
}

#[no_mangle]
pub unsafe extern "C" fn ps_getpid(h: *mut ps_prochandle) -> libc::pid_t {
    let tgid = (*h).tgid;
    log!(LogDebug, "ps_getpid {}", tgid);
    tgid
}

#[no_mangle]
pub unsafe extern "C" fn ps_get_thread_area(
    h: *mut ps_prochandle,
    rec_tid: thread_db::lwpid_t,
    _val: i32,
    _base: *mut thread_db::psaddr_t,
) -> thread_db::ps_err_e {
    if (*h).thread_group.is_null() {
        fatal!("unexpected ps_get_thread_area call with uninitialized thread_group");
    }
    // DIFF NOTE: In rr there is simply a debug_assert to make sure task is not null; we unwrap
    let _task = (*(*h).thread_group)
        .session()
        .find_task_from_rec_tid(rec_tid)
        .unwrap();

    unimplemented!()
}
