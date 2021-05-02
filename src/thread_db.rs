use crate::{
    bindings::{kernel::user_regs_struct, thread_db},
    kernel_abi::SupportedArch,
    log::LogDebug,
    remote_ptr::{RemotePtr, Void},
    session::task::TaskSharedPtr,
    thread_group::ThreadGroup,
};
use libc::pid_t;
use std::{
    collections::{BTreeMap, BTreeSet},
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
    ps: *mut ps_prochandle,
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
/// The overall approach is that a libthread_db.so is loaded into rd
/// This provides the GdbServer with a list of symbols whose addresses might be
/// needed in order to resolve TLS accesses.
///
/// Then, when the address of a TLS variable is requested by the
/// debugger, GdbServer calls `get_tls_address`.  This uses the
/// libthread_db "new" function ("td_ta_new"); if this succeeds then
/// ThreadDb proceeds to use other APIs to find the desired address.
///
/// ThreadDb works on a callback model, using symbols provided by the
/// hosting application.  These are all defined in ThreadDb.cc.
///
/// DIFF NOTE: `loaded` struct member not there in rd
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
    symbol_names: BTreeSet<OsString>,

    /// Map from symbol names to addresses.
    symbols: BTreeMap<OsString, RemotePtr<Void>>,
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
    /// Look up a TLS address for thread |rec_tid|.  |offset| and
    /// |load_module| are as specified in the qGetTLSAddr packet.  If the
    /// address is found, set |*result| and return true.  Otherwise,
    /// return false.
    pub fn get_tls_address(
        &mut self,
        thread_group: &mut ThreadGroup,
        rec_tid: pid_t,
        offset: u64,
        load_module: RemotePtr<Void>,
        result: &mut RemotePtr<Void>,
    ) -> bool {
        self.prochandle.thread_group = thread_group as *mut _;
        if !self.initialize() {
            self.prochandle.thread_group = std::ptr::null_mut();
            return false;
        }

        let mut th: thread_db::td_thrhandle_t = Default::default();
        if (self.td_ta_map_lwp2thr_fn)(self.internal_handle, rec_tid, &mut th) != thread_db::TD_OK {
            self.prochandle.thread_group = std::ptr::null_mut();
            return false;
        }

        let load_module_addr: thread_db::psaddr_t = load_module.as_usize() as *mut _;
        let mut addr: thread_db::psaddr_t = std::ptr::null_mut();
        if (self.td_thr_tls_get_addr_fn)(&th, load_module_addr, offset, &mut addr)
            != thread_db::TD_OK
        {
            self.prochandle.thread_group = std::ptr::null_mut();
            return false;
        }
        self.prochandle.thread_group = std::ptr::null_mut();
        *result = RemotePtr::from(addr as usize);
        true
    }

    fn initialize(&mut self) -> bool {
        if !self.internal_handle.is_null() {
            return true;
        }

        // DIFF NOTE: There is a call to load_library here: not needed??

        if (self.td_ta_new_fn)(&mut self.prochandle, &mut self.internal_handle) != thread_db::TD_OK
        {
            log!(LogDebug, "initialize td_ta_new_fn failed");
            return false;
        }

        log!(LogDebug, "initialize OK");
        true
    }

    /// Return a set of the names of all the symbols that might be needed
    /// by libthread_db.  Also clears the current mapping of symbol names
    /// to addresses.
    ///
    /// DIFF NOTE: Does NOT take a thread group as a param
    pub fn get_symbols_and_clear_map(&mut self) -> Vec<OsString> {
        // If we think the symbol locations might have changed, then we
        // probably need to recreate the handle.
        if !self.internal_handle.is_null() {
            (self.td_ta_delete_fn)(self.internal_handle);
            self.internal_handle = std::ptr::null_mut();
        }
        // DIFF NOTE: In rr there is a call to load_libary() here.
        // We don't need it
        self.symbols.clear();
        self.prochandle.thread_group = std::ptr::null_mut();
        self.symbol_names.iter().cloned().collect()
    }

    /// Note that the symbol |name| has the given address.
    pub fn register_symbol(&mut self, name: OsString, address: RemotePtr<Void>) {
        log!(LogDebug, "register_symbol {:?}", name);
        self.symbols.insert(name, address);
    }

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

        let mut symbol_names: BTreeSet<OsString> = Default::default();
        unsafe {
            let mut syms = td_symbol_list_fn();
            while !std::ptr::eq(*syms, std::ptr::null()) {
                symbol_names.insert(OsStr::from_bytes(CStr::from_ptr(*syms).to_bytes()).to_owned());
                syms = syms.add(1);
            }
        }
        log!(LogDebug, "load_library OK");
        // Enclose in a Box so as to keep prochandle.db
        // which is a kind of self pointer, stable
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

        b.prochandle.db = &mut *b as *mut ThreadDb;
        b.prochandle.tgid = tgid;

        b
    }

    /// Look up the symbol |name|.  If found, set |*address| and return
    /// true.  If not found, return false.
    fn query_symbol(&self, symbol: &OsStr, addr: &mut RemotePtr<u8>) -> bool {
        if let Some(&found) = self.symbols.get(symbol) {
            *addr = found;
            return true;
        }
        false
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
    let osstr_symbol = OsStr::from_bytes(CStr::from_ptr(symbol).to_bytes());
    if !(*(*h).db).query_symbol(osstr_symbol, &mut addr) {
        log!(LogDebug, "ps_pglobal_lookup {:?} failed", osstr_symbol);
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
    val: i32,
    base: *mut thread_db::psaddr_t,
) -> thread_db::ps_err_e {
    if (*h).thread_group.is_null() {
        fatal!("unexpected ps_get_thread_area call with uninitialized thread_group");
    }
    // DIFF NOTE: In rr there is simply a debug_assert to make sure task is not null; we unwrap
    let task: TaskSharedPtr = (*(*h).thread_group)
        .session()
        .find_task_from_rec_tid(rec_tid)
        .unwrap();

    if task.arch() == SupportedArch::X86 {
        let uval = val as u32;
        for area in task.thread_areas().iter() {
            if area.entry_number == uval {
                *base = area.base_addr as *mut c_void;
                return thread_db::PS_OK;
            }
        }
        log!(LogDebug, "ps_get_thread_area 32 failed");
        return thread_db::PS_ERR;
    }

    let result;
    match val {
        libc::FS => {
            result = task.regs_ref().fs_base();
        }
        libc::GS => {
            result = task.regs_ref().gs_base();
        }
        _ => {
            log!(LogDebug, "ps_get_thread_area PS_BADADDR");
            return thread_db::PS_BADADDR;
        }
    }

    *base = result as *mut c_void;
    thread_db::PS_OK
}
