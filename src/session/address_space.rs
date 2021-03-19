pub mod kernel_map_iterator;
pub mod kernel_mapping;
pub mod memory_range;

use crate::{
    event::Event,
    kernel_abi::{is_execve_syscall, SupportedArch},
    log::LogLevel::LogError,
    preload_interface::{RD_PAGE_ADDR, RD_PAGE_SYSCALL_INSTRUCTION_END, RD_PAGE_SYSCALL_STUB_SIZE},
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::{
            address_space::{AddressSpace, Mapping},
            kernel_map_iterator::KernelMapIterator,
            kernel_mapping::KernelMapping,
            memory_range::MemoryRange,
        },
        task::Task,
    },
    util::{find, resource_path},
};
use libc::{dev_t, pid_t};
use nix::{
    sys::{
        mman::{MapFlags, ProtFlags},
        stat::stat,
    },
    unistd::read,
};
use std::{
    cmp::min,
    collections::BTreeSet,
    convert::TryInto,
    ffi::{OsStr, OsString},
    mem::size_of,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

#[derive(Copy, Debug, Clone, Eq, PartialEq)]
pub enum BreakpointType {
    BkptNone = 0,
    /// Trap for internal rd purposes, f.e. replaying async
    /// signals.
    BkptInternal = 1,
    /// Trap on behalf of a debugger user.
    BkptUser = 2,
}

/// NB: these random-looking enumeration values are chosen to
/// match the numbers programmed into x86 debug registers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum WatchType {
    WatchExec = 0x00,
    WatchWrite = 0x01,
    WatchReadWrite = 0x03,
}

#[derive(Copy, Clone)]
#[repr(usize)]
pub enum DebugStatus {
    DsWatchpointAny = 0xf,
    DsSingleStep = 1 << 14,
}

bitflags! {
   pub struct MappingFlags: u32 {
        /// This mapping represents a syscallbuf. It needs to handled specially
        /// during checksumming since its contents are not fully restored by the
        /// replay.
        const IS_SYSCALLBUF = 0x1;
        /// This mapping is used as our thread-local variable area for this
        /// address space
        const IS_THREAD_LOCALS = 0x2;
        /// This mapping is used for syscallbuf patch stubs
        const IS_PATCH_STUBS = 0x4;
        /// This mapping is the rd page
        const IS_RD_PAGE = 0x8;
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Traced {
    Traced,
    Untraced,
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Privileged {
    Privileged,
    Unprivileged,
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Enabled {
    RecordingOnly,
    ReplayOnly,
    RecordingAndReplay,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum HandleHeap {
    TreatHeapAsAnonymous,
    RespectHeap,
}

/// Must match generate_rd_page.py
const ENTRY_POINTS: [SyscallType; 8] = [
    SyscallType::new(
        Traced::Traced,
        Privileged::Unprivileged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Traced,
        Privileged::Privileged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Unprivileged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Unprivileged,
        Enabled::ReplayOnly,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Unprivileged,
        Enabled::RecordingOnly,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Privileged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Privileged,
        Enabled::ReplayOnly,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Privileged,
        Enabled::RecordingOnly,
    ),
];

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct SyscallType {
    pub traced: Traced,
    pub privileged: Privileged,
    pub enabled: Enabled,
}

impl SyscallType {
    pub const fn new(traced: Traced, privileged: Privileged, enabled: Enabled) -> SyscallType {
        SyscallType {
            traced,
            privileged,
            enabled,
        }
    }
}

/// A distinct watchpoint, corresponding to the information needed to
/// program a single x86 debug register.
#[derive(Copy, Clone, Debug)]
pub struct WatchConfig {
    pub addr: RemotePtr<Void>,
    pub num_bytes: usize,
    pub type_: WatchType,
}

impl WatchConfig {
    pub fn new(addr: RemotePtr<Void>, num_bytes: usize, type_: WatchType) -> WatchConfig {
        WatchConfig {
            addr,
            num_bytes,
            type_,
        }
    }
}

pub mod address_space {
    use super::*;
    use crate::{
        arch::Architecture,
        auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem},
        emu_fs::EmuFileSharedPtr,
        kernel_abi::{
            syscall_instruction,
            syscall_number_for_brk,
            syscall_number_for_close,
            syscall_number_for_munmap,
            syscall_number_for_openat,
            SupportedArch,
        },
        log::LogLevel::LogDebug,
        monitored_shared_memory::MonitoredSharedMemorySharedPtr,
        monkey_patcher::MonkeyPatcher,
        preload_interface::{PRELOAD_THREAD_LOCALS_SIZE, RD_PAGE_ADDR, RD_PAGE_FF_BYTES},
        preload_interface_arch::rdcall_init_preload_params,
        rd::RD_RESERVED_ROOT_DIR_FD,
        registers::Registers,
        remote_code_ptr::RemoteCodePtr,
        remote_ptr::RemotePtr,
        scoped_fd::ScopedFd,
        session::{
            address_space::{
                kernel_map_iterator::KernelMapIterator,
                kernel_mapping::KernelMapping,
                memory_range::{MemoryRange, MemoryRangeKey},
                BreakpointType::BkptNone,
                MappingFlags,
            },
            task::{
                record_task::RecordTask,
                task_common::{read_mem, read_val_mem, write_val_mem, write_val_mem_with_flags},
                task_inner::WriteFlags,
                Task,
                TaskSharedPtr,
                WeakTaskPtrSet,
            },
            SessionSharedPtr,
            SessionSharedWeakPtr,
        },
        taskish_uid::{AddressSpaceUid, TaskUid},
        trace::trace_frame::FrameTime,
        util::{ceil_page_size, floor_page_size, page_size, read_auxv, uses_invisible_guard_page},
    };
    use core::ffi::c_void;
    use libc::{
        dev_t,
        ino_t,
        pid_t,
        stat,
        EACCES,
        ENOENT,
        MADV_DOFORK,
        MADV_DONTFORK,
        O_RDONLY,
        PROT_GROWSDOWN,
        PROT_GROWSUP,
    };
    use nix::{fcntl::OFlag, sys::mman::munmap, unistd::getpid};
    use std::{
        cell::{Cell, Ref, RefCell, RefMut},
        cmp::{max, min},
        collections::{
            btree_map::{Range, RangeMut},
            hash_map::Iter as HashMapIter,
            BTreeMap,
            HashMap,
            HashSet,
        },
        ffi::{OsStr, OsString},
        ops::{
            Bound::{self, Included, Unbounded},
            Drop,
        },
        ptr::NonNull,
        rc::{Rc, Weak},
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn find_offset_of_syscall_instruction_in(arch: SupportedArch, vdso: &[u8]) -> Option<usize> {
        let instruction = syscall_instruction(arch);
        let instruction_size = instruction.len();
        let limit = vdso.len() - instruction.len();
        for i in 1..limit {
            if vdso[i..i + instruction_size] == *instruction {
                return Some(i);
            }
        }

        return None;
    }

    #[derive(Clone)]
    pub struct Mapping {
        pub map: KernelMapping,
        /// The corresponding KernelMapping in the recording. During recording,
        /// equal to 'map'.
        pub recorded_map: KernelMapping,
        /// Multiple Mapping-s might point to the same EmuFile.
        pub emu_file: Option<EmuFileSharedPtr>,
        /// @TODO This used to be a Box<stat>. Should be OK though.
        pub mapped_file_stat: Option<stat>,
        /// If this mapping has been mapped into the local address space,
        /// this is the address of the first byte of the equivalent local mapping.
        /// This mapping is always mapped as PROT_READ|PROT_WRITE regardless of the
        /// mapping's permissions in the tracee. Also note that it is the caller's
        /// responsibility to keep this alive at least as long as this mapping is
        /// present in the address space.
        pub local_addr: Option<NonNull<c_void>>,
        /// Multiple Mapping-s might point to the same MonitoredSharedMemory object.
        pub monitored_shared_memory: Option<MonitoredSharedMemorySharedPtr>,
        /// Flags indicate mappings that require special handling. Adjacent mappings
        /// may only be merged if their `flags` value agree.
        pub flags: MappingFlags,
    }

    impl Mapping {
        pub fn new(
            map: KernelMapping,
            recorded_map: KernelMapping,
            emu_file: Option<EmuFileSharedPtr>,
            mapped_file_stat: Option<stat>,
            local_addr: Option<NonNull<c_void>>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> Mapping {
            Mapping {
                map,
                recorded_map,
                emu_file,
                mapped_file_stat,
                local_addr,
                monitored_shared_memory: monitored,
                flags: MappingFlags::empty(),
            }
        }
    }

    pub type MemoryMap = BTreeMap<MemoryRangeKey, Mapping>;

    pub type AddressSpaceSharedPtr = Rc<AddressSpace>;
    pub type AddressSpaceSharedWeakPtr = Weak<AddressSpace>;

    pub struct Maps<'a> {
        memory_map: Ref<'a, MemoryMap>,
        lower_bound: Bound<MemoryRangeKey>,
        upper_bound: Bound<MemoryRangeKey>,
    }

    impl<'a> Maps<'a> {
        pub fn starting_at(outer: &'a AddressSpace, start: RemotePtr<Void>) -> Maps<'a> {
            Maps {
                memory_map: outer.mem.borrow(),
                // Note the 0 size range.
                lower_bound: Included(MemoryRangeKey(MemoryRange::from_range(start, start))),
                upper_bound: Unbounded,
            }
        }

        pub fn containing_or_after(outer: &'a AddressSpace, start: RemotePtr<Void>) -> Maps<'a> {
            Maps {
                memory_map: outer.mem.borrow(),
                lower_bound: Included(MemoryRangeKey(MemoryRange::new_range(start, 1))),
                upper_bound: Unbounded,
            }
        }

        pub fn from_range(outer: &'a AddressSpace, range: MemoryRange) -> Maps<'a> {
            Maps {
                memory_map: outer.mem.borrow(),
                // Note that we ignore the range.end() and create a new memory range with a length of 1
                lower_bound: Included(MemoryRangeKey(MemoryRange::new_range(range.start(), 1))),
                upper_bound: Unbounded,
            }
        }

        pub fn into_mem(self) -> Ref<'a, MemoryMap> {
            self.memory_map
        }
    }

    impl<'a, 'b> IntoIterator for &'b Maps<'a> {
        type Item = (&'b MemoryRangeKey, &'b Mapping);
        type IntoIter = Range<'b, MemoryRangeKey, Mapping>;

        fn into_iter(self) -> Self::IntoIter {
            self.memory_map.range((self.lower_bound, self.upper_bound))
        }
    }

    pub struct MapsMut<'a> {
        memory_map: RefMut<'a, MemoryMap>,
        lower_bound: Bound<MemoryRangeKey>,
        upper_bound: Bound<MemoryRangeKey>,
    }

    impl<'a> MapsMut<'a> {
        pub fn starting_at(outer: &'a mut AddressSpace, start: RemotePtr<Void>) -> MapsMut<'a> {
            MapsMut {
                memory_map: outer.mem.borrow_mut(),
                // Note the 0 size range.
                lower_bound: Included(MemoryRangeKey(MemoryRange::from_range(start, start))),
                upper_bound: Unbounded,
            }
        }

        pub fn containing_or_after(outer: &'a AddressSpace, start: RemotePtr<Void>) -> MapsMut<'a> {
            MapsMut {
                memory_map: outer.mem.borrow_mut(),
                lower_bound: Included(MemoryRangeKey(MemoryRange::new_range(start, 1))),
                upper_bound: Unbounded,
            }
        }

        pub fn from_range(outer: &'a AddressSpace, range: MemoryRange) -> MapsMut<'a> {
            MapsMut {
                memory_map: outer.mem.borrow_mut(),
                // Note that we ignore the range.end() and create a new memory range with a length of 1
                lower_bound: Included(MemoryRangeKey(MemoryRange::new_range(range.start(), 1))),
                upper_bound: Unbounded,
            }
        }

        pub fn into_mem(self) -> RefMut<'a, MemoryMap> {
            self.memory_map
        }
    }

    impl<'a, 'b> IntoIterator for &'b mut MapsMut<'a> {
        type Item = (&'b MemoryRangeKey, &'b mut Mapping);
        type IntoIter = RangeMut<'b, MemoryRangeKey, Mapping>;

        fn into_iter(self) -> Self::IntoIter {
            self.memory_map
                .range_mut((self.lower_bound, self.upper_bound))
        }
    }

    /// Represents a refcount set on a particular address.  Because there
    /// can be multiple refcounts of multiple types set on a single
    /// address, Breakpoint stores explicit USER and INTERNAL breakpoint
    /// refcounts.  Clients adding/removing breakpoints at this addr must
    /// call ref()/unref() as appropriate.
    /// NOTE: This could be made Copy easily. But we don't for now and keep
    /// it consistent with Watchpoint which also NOT Copy.
    #[derive(Clone)]
    struct Breakpoint {
        /// "Refcounts" of breakpoints set at `addr`.  The breakpoint
        /// object must be unique since we have to save the overwritten
        /// data, and we can't enforce the order in which breakpoints
        /// are set/removed.
        /// Note: These are signed integers in rr.
        pub internal_count: u32,
        pub user_count: u32,
        pub overwritten_data: u8,
    }

    /// In rr there are a lot of DEBUG_ASSERTs but we don't need them
    /// as struct members are u32 and any attempt to make them negative
    /// will cause a panic in the debug build.
    impl Breakpoint {
        pub fn new(overwritten_data: u8) -> Breakpoint {
            Breakpoint {
                internal_count: 0,
                user_count: 0,
                overwritten_data,
            }
        }

        /// Method is called ref() in rr.
        pub fn do_ref(&mut self, which: BreakpointType) {
            let v: &mut u32 = self.counter(which);
            *v += 1;
        }

        /// Method is called unref() in rr.
        pub fn do_unref(&mut self, which: BreakpointType) -> u32 {
            let v: &mut u32 = self.counter(which);
            *v -= 1;
            self.internal_count + self.user_count
        }

        /// Called Breakpoint::type() in rr.
        pub fn bp_type(&self) -> BreakpointType {
            // NB: USER breakpoints need to be processed before
            // INTERNAL ones.  We want to give the debugger a
            // chance to dispatch commands before we attend to the
            // internal rd business.  So if there's a USER "ref"
            // on the breakpoint, treat it as a USER breakpoint.
            if self.user_count > 0 {
                BreakpointType::BkptUser
            } else {
                BreakpointType::BkptInternal
            }
        }

        pub fn data_length(&self) -> usize {
            1
        }

        pub fn original_data(&self) -> u8 {
            self.overwritten_data
        }

        pub fn counter(&mut self, which: BreakpointType) -> &mut u32 {
            if which == BreakpointType::BkptUser {
                &mut self.user_count
            } else {
                &mut self.internal_count
            }
        }
    }

    type BreakpointMap = HashMap<RemoteCodePtr, Breakpoint>;
    type BreakpointMapIter<'a> = HashMapIter<'a, RemoteCodePtr, Breakpoint>;

    /// XXX one is tempted to merge Breakpoint and Watchpoint into a single
    /// entity, but the semantics are just different enough that separate
    /// objects are easier for now.
    ///
    /// Track the watched accesses of a contiguous range of memory
    /// addresses.
    #[derive(Clone)]
    struct Watchpoint {
        /// Watchpoints stay alive until all watched access typed have
        /// been cleared.  We track refcounts of each watchable access
        /// separately.
        /// NOTE: These are signed integers in rr.
        /// These are accompanied with a lot of DEBUG_ASSERTs to ensure
        /// these remain >= 0.
        /// In rd we keep them as unsigned because any attempts to make them
        /// negative will result in a panic in the debug build.
        pub exec_count: u32,
        pub read_count: u32,
        pub write_count: u32,
        /// Debug registers allocated for read/exec access checking.
        /// Write watchpoints are always triggered by checking for actual memory
        /// value changes. Read/exec watchpoints can't be triggered that way, so
        /// we look for these registers being triggered instead.
        /// @TODO might we want to have some of these as Option types?
        pub debug_regs_for_exec_read: Vec<u8>,
        pub value_bytes: Vec<u8>,
        pub valid: bool,
        pub changed: bool,
    }

    impl Watchpoint {
        pub fn new(num_bytes: usize) -> Watchpoint {
            Watchpoint {
                exec_count: 0,
                read_count: 0,
                write_count: 0,
                // @TODO is this default what we really need?
                debug_regs_for_exec_read: Vec::new(),
                value_bytes: Vec::with_capacity(num_bytes),
                valid: false,
                changed: false,
            }
        }
        pub fn watch(&mut self, which: RwxBits) {
            if which.contains(RwxBits::EXEC_BIT) {
                self.exec_count += 1;
            }
            if which.contains(RwxBits::READ_BIT) {
                self.read_count += 1;
            }
            if which.contains(RwxBits::WRITE_BIT) {
                self.write_count += 1;
            }
        }
        pub fn unwatch(&mut self, which: RwxBits) -> u32 {
            if which.contains(RwxBits::EXEC_BIT) {
                self.exec_count -= 1;
            }
            if which.contains(RwxBits::READ_BIT) {
                self.read_count -= 1;
            }
            if which.contains(RwxBits::WRITE_BIT) {
                self.write_count -= 1;
            }
            self.exec_count + self.read_count + self.write_count
        }

        pub fn watched_bits(&self) -> RwxBits {
            let mut watched = RwxBits::empty();
            if self.exec_count > 0 {
                watched |= RwxBits::EXEC_BIT;
            }
            if self.read_count > 0 {
                watched |= RwxBits::READ_BIT;
            }
            if self.write_count > 0 {
                watched |= RwxBits::WRITE_BIT;
            }
            watched
        }
    }

    #[derive(Copy, Clone, Eq, PartialEq)]
    enum WatchPointFilter {
        AllWatchpoints,
        ChangedWatchpoints,
    }

    #[derive(Copy, Clone, Eq, PartialEq)]
    enum WillSetTaskState {
        SettingTaskState,
        NotSettingTaskState,
    }

    #[derive(Copy, Clone, Eq, PartialEq)]
    enum IterateHow {
        IterateDefault,
        IterateContiguous,
    }

    bitflags! {
        struct RwxBits: u32 {
            const EXEC_BIT = 1 << 0;
            const READ_BIT = 1 << 1;
            const WRITE_BIT = 1 << 2;
            const READ_WRITE_BITS = Self::READ_BIT.bits | Self::WRITE_BIT.bits;
        }
    }

    /// Models the address space for a set of tasks.  This includes the set
    /// of mapped pages, and the resources those mappings refer to.
    pub struct AddressSpace {
        /// The struct Deref-s and DerefMut-s to task_set.
        task_set: RefCell<WeakTaskPtrSet>,
        /// All breakpoints set in this VM.
        breakpoints: RefCell<BreakpointMap>,
        /// Path of the real executable image this address space was
        /// exec()'d with.
        exe: OsString,
        /// Pid of first task for this address space
        leader_tid_: pid_t,
        /// Serial number of first task for this address space
        leader_serial: u32,
        exec_count: u32,
        /// Only valid during recording
        brk_start: Cell<RemotePtr<Void>>,
        /// Current brk. Not necessarily page-aligned.
        brk_end: Cell<RemotePtr<Void>>,
        /// All segments mapped into this address space.
        mem: RefCell<MemoryMap>,
        /// Sizes of SYSV shm segments, by address. We use this to determine the size
        /// of memory regions unmapped via shmdt().
        shm_sizes: RefCell<HashMap<RemotePtr<Void>, usize>>,
        monitored_mem: RefCell<HashSet<RemotePtr<Void>>>,
        /// madvise DONTFORK regions
        dont_fork: RefCell<BTreeSet<MemoryRange>>,
        /// The session that created this.  We save a ref to it so that
        /// we can notify it when we die.
        /// `session_` in rr.
        session_: SessionSharedWeakPtr,
        /// tid of the task whose thread-locals are in preload_thread_locals
        thread_locals_tuid_: Cell<TaskUid>,
        /// First mapped byte of the vdso.
        vdso_start_addr: Cell<RemotePtr<Void>>,
        /// The monkeypatcher that's handling this address space.
        /// @TODO Try avoiding the Rc??
        monkeypatch_state: Option<Rc<RefCell<MonkeyPatcher>>>,
        /// The watchpoints set for tasks in this VM.  Watchpoints are
        /// programmed per Task, but we track them per address space on
        /// behalf of debuggers that assume that model.
        watchpoints: RefCell<HashMap<MemoryRange, Watchpoint>>,
        saved_watchpoints: RefCell<Vec<HashMap<MemoryRange, Watchpoint>>>,
        /// Tracee memory is read and written through this fd, which is
        /// opened for the tracee's magic /proc/{tid}/mem device.  The
        /// advantage of this over ptrace is that we can access it even
        /// when the tracee isn't at a ptrace-stop.  It's also
        /// theoretically faster for large data transfers, which rd can
        /// do often.
        ///
        /// Users of child_mem_fd should fall back to ptrace-based memory
        /// access when child_mem_fd is not open.
        child_mem_fd: RefCell<ScopedFd>,
        traced_syscall_ip_: Cell<RemoteCodePtr>,
        // @TODO Convert this into a plain Cell<RemoteCodePtr> ?
        privileged_traced_syscall_ip_: Cell<Option<RemoteCodePtr>>,
        syscallbuf_enabled_: Cell<bool>,

        saved_auxv_: RefCell<Vec<u8>>,

        /// The time of the first event that ran code for a task in this address space.
        /// 0 if no such event has occurred.
        /// @TODO should this be an Option?
        first_run_event_: Cell<FrameTime>,
    }

    impl AddressSpace {
        pub fn task_set(&self) -> Ref<WeakTaskPtrSet> {
            self.task_set.borrow()
        }
        pub fn task_set_mut(&self) -> RefMut<WeakTaskPtrSet> {
            self.task_set.borrow_mut()
        }
        /// Call this after a new task has been cloned within this
        /// address space.
        /// DIFF NOTE: Additional param `active_task`
        pub fn after_clone(
            &self,
            active_task: &mut dyn Task,
            cloned_from_thread: Option<&mut dyn Task>,
        ) {
            self.allocate_watchpoints(active_task, cloned_from_thread);
        }

        /// Call this after a successful execve syscall has completed. At this point
        /// it is safe to perform remote syscalls.
        pub fn post_exec_syscall(&self, t: &mut dyn Task) {
            // First locate a syscall instruction we can use for remote syscalls.
            self.traced_syscall_ip_
                .set(self.find_syscall_instruction(t));
            self.privileged_traced_syscall_ip_.set(None);
            // Now remote syscalls work, we can open_mem_fd.
            t.open_mem_fd();

            // Set up AutoRemoteSyscalls again now that the mem-fd is open.
            let mut remote = AutoRemoteSyscalls::new(t);
            // Now we can set up the "rd page" at its fixed address. This gives
            // us traced and untraced syscall instructions at known, fixed addresses.
            self.map_rd_page(&mut remote);
            // Set up the preload_thread_locals shared area.
            remote.create_shared_mmap(
                PRELOAD_THREAD_LOCALS_SIZE,
                Some(Self::preload_thread_locals_start()),
                OsStr::new("preload_thread_locals"),
                None,
                None,
                None,
            );
            let mut flags = self.mapping_flags_of_mut(Self::preload_thread_locals_start());
            *flags = *flags | MappingFlags::IS_THREAD_LOCALS;
        }

        /// Change the program data break of this address space to
        /// `addr`. Only called during recording!
        pub fn brk(&self, t: &dyn Task, addr: RemotePtr<Void>, prot: ProtFlags) {
            log!(LogDebug, "brk({})", addr);

            let old_brk: RemotePtr<Void> = ceil_page_size(self.brk_end.get());
            let new_brk: RemotePtr<Void> = ceil_page_size(addr);
            if old_brk < new_brk {
                self.map(
                    t,
                    old_brk,
                    new_brk - old_brk,
                    prot,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    0,
                    OsStr::new("[heap]"),
                    KernelMapping::NO_DEVICE,
                    KernelMapping::NO_INODE,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
            } else {
                self.unmap(t, new_brk, old_brk - new_brk);
            }
            self.brk_end.set(addr);
        }

        /// This can only be called during recording.
        pub fn current_brk(&self) -> RemotePtr<Void> {
            debug_assert!(!self.brk_end.get().is_null());
            self.brk_end.get()
        }

        /// Dump a representation of `self` to a String similar to /proc/{tid}/maps.
        pub fn dump(&self) -> String {
            let mut out = String::new();
            out += &format!(
                "  (heap: {}-{})\n",
                self.brk_start.get(),
                self.brk_end.get()
            );
            for (_, m) in self.mem.borrow().iter() {
                let km = &m.map;
                out += &format!("{}{}\n", km, stringify_flags(m.flags));
            }
            out
        }

        /// Return tid of the first task for this address space.
        pub fn leader_tid(&self) -> pid_t {
            self.leader_tid_
        }

        /// Return AddressSpaceUid for this address space.
        pub fn uid(&self) -> AddressSpaceUid {
            AddressSpaceUid::new_with(self.leader_tid_, self.leader_serial, self.exec_count)
        }

        #[inline]
        pub fn session(&self) -> SessionSharedPtr {
            self.session_.upgrade().unwrap()
        }

        // An upgrade can fail sometimes e.g the Session Rc is being drop()-ed.
        // Use this method instead of session() if that may be happening
        // e.g. in drop() of AddressSpace...
        pub fn try_session(&self) -> Option<SessionSharedPtr> {
            self.session_.upgrade()
        }

        #[inline]
        pub fn session_weak(&self) -> &SessionSharedWeakPtr {
            &self.session_
        }

        /// Return the path this address space was exec()'d with.
        pub fn exe_image(&self) -> &OsStr {
            &self.exe
        }

        /// Assuming the last retired instruction has raised a SIGTRAP
        /// and might be a breakpoint trap instruction, return the type
        /// of breakpoint set at `ip() - sizeof(breakpoint_insn)`, if
        /// one exists.  Otherwise return BkptNone.
        pub fn get_breakpoint_type_for_retired_insn(&self, ip: RemoteCodePtr) -> BreakpointType {
            let addr = ip.decrement_by_bkpt_insn_length(SupportedArch::X86);
            self.get_breakpoint_type_at_addr(addr)
        }

        /// Return the type of breakpoint that's been registered for
        /// `addr`.
        pub fn get_breakpoint_type_at_addr(&self, addr: RemoteCodePtr) -> BreakpointType {
            self.breakpoints
                .borrow()
                .get(&addr)
                .map_or(BkptNone, |bp| bp.bp_type())
        }

        /// Returns true when the breakpoint at `addr` is in private
        /// non-writeable memory. When this returns true, the breakpoint can't be
        /// overwritten by the tracee without an intervening mprotect or mmap
        /// syscall.
        pub fn is_breakpoint_in_private_read_only_memory(
            &self,
            addr: RemoteCodePtr,
            active_task: &mut dyn Task,
        ) -> bool {
            // @TODO Its unclear why we need to iterate instead of just using
            // AddressSpace::mapping_of() to check breakpoint prot() and flags().
            for (_, m) in &self.maps_containing_or_after(addr.to_data_ptr::<Void>()) {
                if m.map.start()
                    >= addr
                        .increment_by_bkpt_insn_length(active_task.arch())
                        .to_data_ptr::<Void>()
                {
                    break;
                }
                if m.map.prot().contains(ProtFlags::PROT_WRITE)
                    || m.map.flags().contains(MapFlags::MAP_SHARED)
                {
                    return false;
                }
            }
            true
        }

        /// Return true if there's a breakpoint instruction at `ip`. This might
        /// be an explicit instruction, even if there's no breakpoint set via our API.
        pub fn is_breakpoint_instruction(t: &mut dyn Task, ip: RemoteCodePtr) -> bool {
            let mut ok = true;
            return read_val_mem::<u8>(t, ip.to_data_ptr::<u8>(), Some(&mut ok))
                == Self::BREAKPOINT_INSN
                && ok;
        }

        /// The buffer `dest` of length `dest.len()` represents the contents of tracee
        /// memory at `addr`. Replace the bytes in `dest` that have been overwritten
        /// by breakpoints with the original data that was replaced by the breakpoints.
        pub fn replace_breakpoints_with_original_values(
            &self,
            dest: &mut [u8],
            addr: RemotePtr<u8>,
        ) {
            for (k, v) in self.breakpoints.borrow().iter() {
                let bkpt_location = k.to_data_ptr::<u8>();
                let start = max(addr, bkpt_location);
                let end = min(addr + dest.len(), bkpt_location + v.data_length());
                if start < end {
                    // @TODO this code only works with x86/x64. Make generic like rr.
                    *dest.get_mut(start - addr).unwrap() = v.overwritten_data;
                }
            }
        }

        /// Map `num_bytes` into this address space at `addr`, with
        /// `prot` protection and `flags`.  The pages are (possibly
        /// initially) backed starting at `offset` of `res`. `fsname`, `device` and
        /// `inode` are values that will appear in the /proc/<pid>/maps entry.
        /// `mapped_file_stat` is a complete copy of the 'stat' data for the mapped
        /// file, or null if this isn't a file mapping or isn't during recording.
        /// `*recorded_map` is the mapping during recording, or null if the mapping
        /// during recording is known to be the same as the new map (e.g. because
        /// we are recording!).
        /// `local_addr` is the local address of the memory shared with the tracee,
        /// or null if it's not shared with the tracee. AddressSpace takes ownership
        /// of the shared memory and is responsible for unmapping it.
        pub fn map(
            &self,
            t: &dyn Task,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            prot: ProtFlags,
            flags: MapFlags,
            // DIFF NOTE: This is an i64 in rr
            offset_bytes: u64,
            fsname: &OsStr,
            device: dev_t,
            inode: ino_t,
            mapped_file_stat: Option<libc::stat>,
            record_map: Option<&KernelMapping>,
            emu_file: Option<EmuFileSharedPtr>,
            local_addr: Option<NonNull<c_void>>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> KernelMapping {
            log!(
                LogDebug,
                "mmap({}, {} = {:#x}, {:?} = {:#x}, {:?} = {:#x}, {} = {:#x})",
                addr,
                num_bytes,
                num_bytes,
                prot,
                prot.bits(),
                flags,
                flags.bits(),
                offset_bytes,
                offset_bytes
            );
            let num_bytes = ceil_page_size(num_bytes);
            let m = KernelMapping::new_with_opts(
                addr,
                addr + num_bytes,
                fsname,
                device,
                inode,
                prot,
                flags & KernelMapping::MAP_FLAGS_MASK,
                offset_bytes,
            );

            // DIFF NOTE: @TODO in rr a 0 length mapping accepted. Is this correct?
            debug_assert!(num_bytes > 0);

            remove_range(
                &mut self.dont_fork.borrow_mut(),
                MemoryRange::new_range(addr, num_bytes),
            );

            // The mmap() man page doesn't specifically describe
            // what should happen if an existing map is
            // "overwritten" by a new map (of the same resource).
            // In testing, the behavior seems to be as if the
            // overlapping region is unmapped and then remapped
            // per the arguments to the second call.
            self.unmap_internal(t, addr, num_bytes);

            let actual_recorded_map = record_map.map_or(m.clone(), |km| km.clone());
            // During an emulated exec, we will explicitly map in a (copy of) the VDSO
            // at the recorded address.
            if actual_recorded_map.is_vdso() {
                self.vdso_start_addr.set(addr);
            }

            self.map_and_coalesce(
                t,
                m.clone(),
                actual_recorded_map,
                emu_file,
                mapped_file_stat,
                local_addr,
                monitored,
            );

            m
        }

        /// Return the mapping and mapped resource for the byte at address 'addr'.
        pub fn mapping_of(&self, addr: RemotePtr<Void>) -> Option<Ref<Mapping>> {
            // A size of 1 will allow .intersects() to become true in a containing map.
            let mr = MemoryRange::new_range(addr, 1);
            let maps = Maps::from_range(self, mr);
            match maps.into_iter().next() {
                Some((&k, found_mapping)) if found_mapping.map.contains_ptr(addr) => {
                    let mem_ref = maps.into_mem();

                    Some(Ref::map(mem_ref, |memory_map: &MemoryMap| {
                        memory_map.get(&k).unwrap()
                    }))
                }
                _ => None,
            }
        }

        pub fn mapping_of_mut(&self, addr: RemotePtr<Void>) -> Option<RefMut<Mapping>> {
            // A size of 1 will allow .intersects() to become true in a containing map.
            let mr = MemoryRange::new_range(addr, 1);
            let mut maps = MapsMut::from_range(self, mr);
            match maps.into_iter().next() {
                Some((&k, found_mapping)) if found_mapping.map.contains_ptr(addr) => {
                    let mem_ref = maps.into_mem();

                    Some(RefMut::map(mem_ref, |memory_map: &mut MemoryMap| {
                        memory_map.get_mut(&k).unwrap()
                    }))
                }
                _ => None,
            }
        }

        /// Detach local mapping and return it.
        pub fn detach_local_mapping(&self, addr: RemotePtr<Void>) -> Option<NonNull<c_void>> {
            match self.mapping_of_mut(addr) {
                Some(mut found_mapping) if found_mapping.local_addr.is_some() => {
                    found_mapping.local_addr.take()
                }
                _ => None,
            }
        }

        /// Return a mut ref to the flags of the mapping at this address, allowing
        /// manipulation.
        ///
        /// Assume a mapping exists at addr, otherwise panics.
        pub fn mapping_flags_of_mut(&self, addr: RemotePtr<Void>) -> RefMut<MappingFlags> {
            RefMut::map(self.mapping_of_mut(addr).unwrap(), |m| &mut m.flags)
        }

        /// If the given memory region is mapped into the local address space, obtain
        /// the local address from which the `size` bytes at `addr` can be accessed.
        ///
        /// NOTE: The return is a static lifetime as we can always construct an arbitrary slice
        /// from raw parts if we just had local_addr
        pub fn local_mapping_mut(
            &self,
            addr: RemotePtr<Void>,
            size: usize,
        ) -> Option<&'static mut [u8]> {
            let maybe_map = self.mapping_of(addr);
            if let Some(found_map) = maybe_map {
                // Fall back to the slow path if we can't get the entire region
                if size > found_map.map.end() - addr {
                    return None;
                }
                if let Some(found_local_addr) = found_map.local_addr {
                    let offset = addr - found_map.map.start();
                    let data = unsafe {
                        std::slice::from_raw_parts_mut::<u8>(
                            found_local_addr.as_ptr().cast::<u8>().add(offset),
                            size,
                        )
                    };
                    return Some(data);
                }
            }

            None
        }

        /// If the given memory region is mapped into the local address space, obtain
        /// the local address from which the `size` bytes at `addr` can be accessed.
        pub fn local_mapping(&self, addr: RemotePtr<Void>, size: usize) -> Option<&'static [u8]> {
            self.local_mapping_mut(addr, size).map(|data| &*data)
        }

        /// Return true if the rd page is mapped at its expected address.
        pub fn has_rd_page(&self) -> bool {
            let found_mapping = self.mapping_of(RD_PAGE_ADDR.into());
            found_mapping.is_some()
        }

        pub fn maps(&self) -> Maps {
            Maps::starting_at(self, RemotePtr::null())
        }

        /// If addr is a map start address then all maps including addr and after
        /// If addr is NOT a map start then all maps that come AFTER addr
        pub fn maps_starting_at(&self, addr: RemotePtr<Void>) -> Maps {
            Maps::starting_at(self, addr)
        }

        pub fn maps_containing_or_after(&self, start: RemotePtr<Void>) -> Maps {
            Maps::containing_or_after(self, start)
        }

        pub fn monitored_addrs(&self) -> Ref<HashSet<RemotePtr<Void>>> {
            self.monitored_mem.borrow()
        }

        /// Change the protection bits of [addr, addr + num_bytes) to
        /// `prot`.
        pub fn protect(
            &self,
            t: &dyn Task,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            prot: ProtFlags,
        ) {
            log!(
                LogDebug,
                "mprotect({}, {} = {:#x}, {:?} = {:#x})",
                addr,
                num_bytes,
                num_bytes,
                prot,
                prot.bits()
            );

            let mut last_overlap: Option<MemoryRangeKey> = None;
            let protector = |slf: &Self, m_key: MemoryRangeKey, rem: MemoryRange| {
                // Important !
                let m = slf.mem.borrow().get(&m_key).unwrap().clone();
                log!(LogDebug, "  protecting ({}) ...", rem);

                slf.remove_from_map(*m.map);

                // PROT_GROWSDOWN means that if this is a grows-down segment
                // (which for us means "stack") then the change should be
                // extended to the start of the segment.
                // We don't try to handle the analogous PROT_GROWSUP, because we
                // don't understand the idea of a grows-up segment.
                let new_start: RemotePtr<Void>;
                if m.map.start() < rem.start() && prot.contains(ProtFlags::PROT_GROWSDOWN) {
                    new_start = m.map.start();
                    log!(
                        LogDebug,
                        "  PROT_GROWSDOWN: expanded region down to {}",
                        new_start
                    );
                } else {
                    new_start = rem.start();
                }
                log!(LogDebug, "  erased ({})", m.map);

                // If the first segment we protect underflows the
                // region, remap the underflow region with previous
                // prot.
                let monitored = m.monitored_shared_memory.clone();
                if m.map.start() < new_start {
                    let mut underflow = Mapping::new(
                        m.map.subrange(m.map.start(), rem.start()),
                        m.recorded_map.subrange(m.recorded_map.start(), rem.start()),
                        m.emu_file.clone(),
                        m.mapped_file_stat.clone(),
                        m.local_addr.clone(),
                        monitored,
                    );
                    underflow.flags = m.flags;
                    slf.add_to_map(underflow);
                }
                // Remap the overlapping region with the new prot.
                let new_end = min(rem.end(), m.map.end());

                let new_prot =
                    prot & (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC);
                let new_local_addr = m.local_addr.map(|addr| unsafe {
                    NonNull::new(addr.as_ptr().add(new_start - m.map.start())).unwrap()
                });

                let new_monitored = m.monitored_shared_memory.clone().map(|r| {
                    r.borrow()
                        .subrange(new_start - m.map.start(), new_end - new_start)
                });

                let mut overlap = Mapping::new(
                    m.map.subrange(new_start, new_end).set_prot(new_prot),
                    m.recorded_map
                        .subrange(new_start, new_end)
                        .set_prot(new_prot),
                    m.emu_file.clone(),
                    m.mapped_file_stat.clone(),
                    new_local_addr,
                    new_monitored,
                );
                overlap.flags = m.flags;
                last_overlap = Some(MemoryRangeKey(*overlap.map));
                slf.add_to_map(overlap);

                // If the last segment we protect overflows the
                // region, remap the overflow region with previous
                // prot.
                if rem.end() < m.map.end() {
                    let new_local = m.local_addr.map(|addr| unsafe {
                        NonNull::new(addr.as_ptr().add(rem.end() - m.map.start())).unwrap()
                    });

                    let new_monitored = m.monitored_shared_memory.clone().map(|r| {
                        r.borrow()
                            .subrange(rem.end() - m.map.start(), m.map.end() - rem.end())
                    });
                    let mut overflow = Mapping::new(
                        m.map.subrange(rem.end(), m.map.end()),
                        m.recorded_map.subrange(rem.end(), m.map.end()),
                        m.emu_file.clone(),
                        m.mapped_file_stat.clone(),
                        new_local,
                        new_monitored,
                    );
                    overflow.flags = m.flags;
                    slf.add_to_map(overflow);
                }
            };

            self.for_each_in_range(addr, num_bytes, protector, IterateHow::IterateContiguous);
            match last_overlap {
                Some(last_overlap_key) => {
                    // All mappings that we altered which might need coalescing
                    // are adjacent to `last_overlap_key`.
                    self.coalesce_around(t, last_overlap_key);
                }
                None => (),
            }
        }

        /// Fix up mprotect registers parameters to take account of PROT_GROWSDOWN.
        pub fn fixup_mprotect_growsdown_parameters(&self, t: &mut dyn Task) {
            ed_assert!(
                t,
                !(t.regs_ref().arg3() & PROT_GROWSUP as usize == PROT_GROWSUP as usize)
            );
            if t.regs_ref().arg3() & PROT_GROWSDOWN as usize == PROT_GROWSDOWN as usize {
                let mut r: Registers = t.regs_ref().clone();
                let maybe_mapping = self.mapping_of(r.arg1().into());
                if r.arg1() == floor_page_size(r.arg1()) && maybe_mapping.is_some() {
                    let km_flags = maybe_mapping.as_ref().unwrap().map.flags();
                    let new_start = maybe_mapping.unwrap().map.start();
                    if km_flags.contains(MapFlags::MAP_GROWSDOWN) {
                        r.set_arg2(r.arg1() + r.arg2() - new_start.as_usize());
                        r.set_arg1(new_start.as_usize());
                        r.set_arg3(r.arg3() & !(PROT_GROWSDOWN as usize));
                        t.set_regs(&r);
                    }
                }
            }
        }

        /// Move the mapping [old_addr, old_addr + old_num_bytes) to
        /// [new_addr, old_addr + new_num_bytes), preserving metadata.
        pub fn remap(
            &self,
            t: &dyn Task,
            old_addr: RemotePtr<Void>,
            mut old_num_bytes: usize,
            new_addr: RemotePtr<Void>,
            mut new_num_bytes: usize,
        ) {
            log!(
                LogDebug,
                "mremap({}, {}, {}, {})",
                old_addr,
                old_num_bytes,
                new_addr,
                new_num_bytes
            );
            old_num_bytes = ceil_page_size(old_num_bytes);

            let m: Mapping = self.mapping_of(old_addr).unwrap().clone();
            debug_assert!(m.monitored_shared_memory.is_none());

            // @TODO Why not have these asserts??
            // debug_assert_eq!(m.map.end(), old_addr + old_num_bytes);
            // debug_assert_eq!(m.map.start(), old_addr);

            let km = m
                .map
                .subrange(old_addr, min(m.map.end(), old_addr + old_num_bytes));

            self.unmap_internal(t, old_addr, old_num_bytes);

            // DIFF NOTE: @TODO rr allows new_num_bytes to be 0. Is that correct?
            // man mremap(2) seems to dissallow it.
            debug_assert!(new_num_bytes != 0);
            new_num_bytes = ceil_page_size(new_num_bytes);

            let maybe_next: Option<MemoryRange> = self
                .dont_fork
                .borrow()
                .range((
                    Included(MemoryRange::new_range(old_addr, old_num_bytes)),
                    Unbounded,
                ))
                .next()
                .copied();
            if maybe_next.is_some() && (maybe_next.unwrap().start() < old_addr + old_num_bytes) {
                // mremap fails if some but not all pages are marked DONTFORK
                debug_assert!(
                    maybe_next.unwrap() == MemoryRange::new_range(old_addr, old_num_bytes)
                );
                remove_range(
                    &mut self.dont_fork.borrow_mut(),
                    MemoryRange::new_range(old_addr, old_num_bytes),
                );
                add_range(
                    &mut self.dont_fork.borrow_mut(),
                    MemoryRange::new_range(new_addr, new_num_bytes),
                );
            } else {
                remove_range(
                    &mut self.dont_fork.borrow_mut(),
                    MemoryRange::new_range(old_addr, old_num_bytes),
                );
                remove_range(
                    &mut self.dont_fork.borrow_mut(),
                    MemoryRange::new_range(new_addr, new_num_bytes),
                );
            }

            self.unmap_internal(t, new_addr, new_num_bytes);

            let new_end = new_addr + new_num_bytes;
            self.map_and_coalesce(
                t,
                km.set_range(new_addr, new_end),
                m.recorded_map.set_range(new_addr, new_end),
                m.emu_file,
                m.mapped_file_stat,
                None,
                None,
            );
        }

        /// Notify that data was written to this address space by rd or
        /// by the kernel.
        /// `flags` can contain values from Task::WriteFlags.
        pub fn notify_written(&self, addr: RemotePtr<Void>, num_bytes: usize, flags: WriteFlags) {
            if !(flags.contains(WriteFlags::IS_BREAKPOINT_RELATED)) {
                self.update_watchpoint_values(addr, addr + num_bytes);
            }
            self.session().accumulate_bytes_written(num_bytes as u64);
        }

        /// Assumes any weak pointer can be upgraded but does not assume task_set is NOT empty.
        pub fn any_task_from_task_set(&self) -> Option<TaskSharedPtr> {
            self.task_set().iter().next()
        }

        /// Ensure a breakpoint of `type` is set at `addr`.
        ///
        /// DIFF NOTE: In rr a random task is pulled out from the task set
        /// Here we explicitly pass in the task to perform any read/writes
        pub fn add_breakpoint(
            &self,
            t: &mut dyn Task,
            addr: RemoteCodePtr,
            type_: BreakpointType,
        ) -> bool {
            let found = self.breakpoints.borrow().get(&addr).is_some();
            if found {
                self.breakpoints
                    .borrow_mut()
                    .get_mut(&addr)
                    .unwrap()
                    .do_ref(type_);
            } else {
                let mut overwritten_data = [0u8; 1];
                let read_result =
                    t.read_bytes_fallible(addr.to_data_ptr::<u8>(), &mut overwritten_data);
                match read_result {
                    Ok(read) if read == size_of::<u8>() => (),
                    _ => return false,
                }

                write_val_mem_with_flags::<u8>(
                    t,
                    addr.to_data_ptr::<u8>(),
                    &Self::BREAKPOINT_INSN,
                    None,
                    WriteFlags::IS_BREAKPOINT_RELATED,
                );

                let mut bp = Breakpoint::new(overwritten_data[0]);
                bp.do_ref(type_);
                self.breakpoints.borrow_mut().insert(addr, bp);
            }
            true
        }

        /// Remove a `type` reference to the breakpoint at `addr`.  If
        /// the removed reference was the last, the breakpoint is
        /// destroyed.
        /// DIFF NOTE: Additional param `active_task`
        pub fn remove_breakpoint(
            &self,
            addr: RemoteCodePtr,
            type_: BreakpointType,
            active_task: &mut dyn Task,
        ) {
            let mut can_destroy_bp = false;
            match self.breakpoints.borrow_mut().get_mut(&addr) {
                Some(bp) => {
                    if bp.do_unref(type_) == 0 {
                        can_destroy_bp = true;
                    }
                }
                _ => (),
            }
            if can_destroy_bp {
                self.destroy_breakpoint_at(addr, active_task);
            }
        }
        /// Destroy all breakpoints in this VM, regardless of their
        /// reference counts.
        /// DIFF NOTE: Additional param `active_task`
        pub fn remove_all_breakpoints(&self, active_task: &mut dyn Task) {
            let mut bps_to_destroy = Vec::new();
            for bp in self.breakpoints.borrow().keys() {
                bps_to_destroy.push(*bp);
            }

            for bp in bps_to_destroy {
                self.destroy_breakpoint_at(bp, active_task)
            }
        }

        /// Temporarily remove the breakpoint at `addr`.
        pub fn suspend_breakpoint_at(&self, addr: RemoteCodePtr) {
            match self.breakpoints.borrow().get(&addr) {
                Some(bp) => {
                    let t = self.any_task_from_task_set().unwrap();
                    write_val_mem::<u8>(
                        t.borrow_mut().as_mut(),
                        addr.to_data_ptr::<u8>(),
                        &bp.overwritten_data,
                        None,
                    );
                }
                None => (),
            }
        }

        /// Restore any temporarily removed breakpoint at `addr`.
        pub fn restore_breakpoint_at(&self, addr: RemoteCodePtr) {
            match self.breakpoints.borrow().get(&addr) {
                Some(_bp) => {
                    let t = self.any_task_from_task_set().unwrap();
                    write_val_mem::<u8>(
                        t.borrow_mut().as_mut(),
                        addr.to_data_ptr::<u8>(),
                        &Self::BREAKPOINT_INSN,
                        None,
                    );
                }
                None => (),
            }
        }

        /// Manage watchpoints.  Analogous to breakpoint-managing
        /// methods above, except that watchpoints can be set for an
        /// address range.
        /// DIFF NOTE: Additional param `active_task`
        pub fn add_watchpoint(
            &self,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            type_: WatchType,
            active_task: &mut dyn Task,
        ) -> bool {
            let range = range_for_watchpoint(addr, num_bytes);
            if self.watchpoints.borrow_mut().get_mut(&range).is_none() {
                let insert_result = self
                    .watchpoints
                    .borrow_mut()
                    .insert(range, Watchpoint::new(num_bytes));
                // Its a new key
                debug_assert!(insert_result.is_none());
                self.update_watchpoint_value(&range, None);
            }
            self.watchpoints
                .borrow_mut()
                .get_mut(&range)
                .unwrap()
                .watch(Self::access_bits_of(type_));

            self.allocate_watchpoints(active_task, None)
        }

        /// DIFF NOTE: Additional param `active_task`
        pub fn remove_watchpoint(
            &self,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            type_: WatchType,
            active_task: &mut dyn Task,
        ) {
            let r = range_for_watchpoint(addr, num_bytes);
            if let Some(wp) = self.watchpoints.borrow_mut().get_mut(&r) {
                if 0 == wp.unwatch(Self::access_bits_of(type_)) {
                    self.watchpoints.borrow_mut().remove(&r);
                }
            }
            self.allocate_watchpoints(active_task, None);
        }

        /// DIFF NOTE: Additional param `active_task` and `maybe_cloned_from_thread`
        /// To solve already borrowed possibility in the task.
        pub fn remove_all_watchpoints(
            &self,
            active_task: &mut dyn Task,
            maybe_cloned_from_thread: Option<&mut dyn Task>,
        ) {
            self.watchpoints.borrow_mut().clear();
            self.allocate_watchpoints(active_task, maybe_cloned_from_thread);
        }
        pub fn all_watchpoints(&self) -> Vec<WatchConfig> {
            self.get_watchpoints_internal(WatchPointFilter::AllWatchpoints)
        }

        /// Save all watchpoint state onto a stack.
        pub fn save_watchpoints(&self) {
            // CHECK: Is clone what we really want?
            self.saved_watchpoints
                .borrow_mut()
                .push(self.watchpoints.borrow().clone());
        }
        /// Pop all watchpoint state from the saved-state stack.
        /// DIFF NOTE: Additional param `active_task`
        pub fn restore_watchpoints(&self, active_task: &mut dyn Task) -> bool {
            debug_assert!(!self.saved_watchpoints.borrow().is_empty());
            *self.watchpoints.borrow_mut() = self.saved_watchpoints.borrow_mut().pop().unwrap();
            self.allocate_watchpoints(active_task, None)
        }

        /// Notify that at least one watchpoint was hit --- recheck them all.
        /// Returns true if any watchpoint actually triggered. Note that
        /// debug_status can indicate a hit watchpoint that doesn't actually
        /// trigger, because the value of a write-watchpoint did not change.
        /// Likewise, debug_status can indicate a watchpoint wasn't hit that
        /// actually was (because in some configurations, e.g. VMWare
        /// hypervisor with 32-bit x86 guest, debug_status watchpoint bits
        /// are known to not be set on singlestep).
        pub fn notify_watchpoint_fired(
            &self,
            debug_status: usize,
            address_of_singlestep_start: RemoteCodePtr,
        ) -> bool {
            let mut triggered = false;
            for (k, w) in self.watchpoints.borrow_mut().iter_mut() {
                // On Skylake/4.14.13-300.fc27.x86_64 at least, we have observed a
                // situation where singlestepping through the instruction before a hardware
                // execution watchpoint causes singlestep completion *and* also reports the
                // hardware execution watchpoint being triggered. The latter is incorrect.
                // This could be a HW issue or a kernel issue. Work around it by ignoring
                // triggered watchpoints that aren't on the instruction we just tried to
                // execute.
                let watched_bits = w.watched_bits();
                let read_triggered = watched_bits.contains(RwxBits::READ_BIT)
                    && watchpoint_triggered(debug_status, &w.debug_regs_for_exec_read);
                let exec_triggered = watched_bits.contains(RwxBits::EXEC_BIT)
                    && (address_of_singlestep_start.is_null()
                        || k.start() == address_of_singlestep_start.to_data_ptr::<Void>())
                    && watchpoint_triggered(debug_status, &w.debug_regs_for_exec_read);
                if read_triggered || exec_triggered {
                    w.changed = true;
                    triggered = true;
                }
            }

            let mut for_update_watchpoint: Vec<MemoryRange> = Vec::new();
            for (range, w) in self.watchpoints.borrow().iter() {
                let watched_bits = w.watched_bits();
                if watched_bits.contains(RwxBits::WRITE_BIT) {
                    for_update_watchpoint.push(*range);
                }
            }

            for range in &for_update_watchpoint {
                if self.update_watchpoint_value(range, Some(true)) {
                    triggered = true;
                }
            }
            triggered
        }

        /// Return true if any watchpoint has fired. Will keep returning true until
        /// consume_watchpoint_changes() is called.
        pub fn has_any_watchpoint_changes(&self) -> bool {
            for v in self.watchpoints.borrow().values() {
                if v.changed {
                    return true;
                }
            }
            false
        }

        /// Return true if an EXEC watchpoint has fired at addr since the last
        /// consume_watchpoint_changes.
        pub fn has_exec_watchpoint_fired(&self, addr: RemoteCodePtr) -> bool {
            for (k, v) in self.watchpoints.borrow().iter() {
                if v.changed && v.exec_count > 0 && k.start() == addr.to_data_ptr::<Void>() {
                    return true;
                }
            }
            false
        }

        /// Return all changed watchpoints in `watches` and clear their changed flags.
        pub fn consume_watchpoint_changes(&self) -> Vec<WatchConfig> {
            self.get_watchpoints_internal(WatchPointFilter::ChangedWatchpoints)
        }

        pub fn set_shm_size(&self, addr: RemotePtr<Void>, bytes: usize) {
            self.shm_sizes.borrow_mut().insert(addr, bytes);
        }

        /// Dies if no shm size is registered for the address.
        pub fn get_shm_size(&self, addr: RemotePtr<Void>) -> usize {
            *self.shm_sizes.borrow().get(&addr).unwrap()
        }
        /// Returns true it the key was present in the map
        pub fn remove_shm_size(&self, addr: RemotePtr<Void>) -> bool {
            self.shm_sizes.borrow_mut().remove(&addr).is_some()
        }

        /// Make [addr, addr + num_bytes) inaccessible within this
        /// address space.
        pub fn unmap(&self, t: &dyn Task, addr: RemotePtr<Void>, num_bytes: usize) {
            log!(
                LogDebug,
                "munmap({}, {} = {:#x})",
                addr,
                num_bytes,
                num_bytes
            );
            let num_bytes = ceil_page_size(num_bytes);

            if num_bytes == 0 {
                return;
            }

            remove_range(
                &mut self.dont_fork.borrow_mut(),
                MemoryRange::new_range(addr, num_bytes),
            );

            self.unmap_internal(t, addr, num_bytes);
        }

        /// Notification of madvise call.
        pub fn advise(&self, _t: &dyn Task, addr: RemotePtr<Void>, num_bytes: usize, advice: i32) {
            log!(LogDebug, "madvise({}, {}, {})", addr, num_bytes, advice);
            let num_bytes = ceil_page_size(num_bytes);

            match advice {
                MADV_DONTFORK => add_range(
                    &mut self.dont_fork.borrow_mut(),
                    MemoryRange::new_range(addr, num_bytes),
                ),
                MADV_DOFORK => remove_range(
                    &mut self.dont_fork.borrow_mut(),
                    MemoryRange::new_range(addr, num_bytes),
                ),
                _ => (),
            }
        }

        /// Return the vdso mapping of this.
        ///
        /// Panics if there is no Mapping of the vdso
        pub fn vdso(&self) -> KernelMapping {
            debug_assert!(!self.vdso_start_addr.get().is_null());
            self.mapping_of(self.vdso_start_addr.get())
                .unwrap()
                .map
                .clone()
        }

        /// Verify that this cached address space matches what the
        /// kernel thinks it should be.
        pub fn verify(&self, t: &dyn Task) {
            ed_assert!(t, self.task_set().has(t.weak_self_ptr()));

            if thread_group_in_exec(t) {
                return;
            }

            log!(LogDebug, "Verifying address space for task {}", t.tid);

            let mb = self.mem.borrow();
            let mut mem_it = mb.values();
            let mut kernel_it = KernelMapIterator::new(t);
            let mut mem_m = mem_it.next();
            let mut kernel_m = kernel_it.next();
            while mem_m.is_some() && kernel_m.is_some() {
                let mut km: KernelMapping = kernel_m.unwrap();
                kernel_m = kernel_it.next();
                while kernel_m.is_some() && try_merge_adjacent(&mut km, &kernel_m.clone().unwrap())
                {
                    kernel_m = kernel_it.next();
                }

                let mut vm = mem_m.unwrap().map.clone();
                mem_m = mem_it.next();
                while mem_m.is_some() && try_merge_adjacent(&mut vm, &mem_m.unwrap().map) {
                    mem_m = mem_it.next();
                }

                assert_segments_match(t, &vm, &km);
            }

            ed_assert!(t, mem_m.is_none() && kernel_m.is_none());
        }

        pub fn has_breakpoints(&self) -> bool {
            !self.breakpoints.borrow().is_empty()
        }
        pub fn has_watchpoints(&self) -> bool {
            !self.watchpoints.borrow().is_empty()
        }

        /// Encoding of the `int $3` instruction.
        pub const BREAKPOINT_INSN: u8 = 0xCC;

        pub fn mem_fd(&self) -> Ref<ScopedFd> {
            self.child_mem_fd.borrow()
        }

        pub fn mem_fd_mut(&self) -> RefMut<ScopedFd> {
            self.child_mem_fd.borrow_mut()
        }

        pub fn set_mem_fd(&self, fd: ScopedFd) {
            *self.child_mem_fd.borrow_mut() = fd;
        }

        pub fn monkeypatcher(&self) -> Option<Rc<RefCell<MonkeyPatcher>>> {
            self.monkeypatch_state.clone()
        }

        pub fn at_preload_init(&self, t: &mut dyn Task) {
            rd_arch_function!(self, at_preload_init_arch, t.arch(), t)
        }

        /// The address of the syscall instruction from which traced syscalls made by
        /// the syscallbuf will originate.
        pub fn traced_syscall_ip(&self) -> RemoteCodePtr {
            self.traced_syscall_ip_.get()
        }

        /// The address of the syscall instruction from which privileged traced
        /// syscalls made by the syscallbuf will originate.
        pub fn privileged_traced_syscall_ip(&self) -> Option<RemoteCodePtr> {
            self.privileged_traced_syscall_ip_.get()
        }

        pub fn syscallbuf_enabled(&self) -> bool {
            self.syscallbuf_enabled_.get()
        }

        /// We'll map a page of memory here into every exec'ed process for our own
        /// use.
        pub fn rd_page_start() -> RemotePtr<Void> {
            RemotePtr::<Void>::new(RD_PAGE_ADDR)
        }

        /// This might not be the length of an actual system page, but we allocate
        /// at least this much space.
        pub fn rd_page_size() -> usize {
            4096
        }
        pub fn rd_page_end() -> RemotePtr<Void> {
            Self::rd_page_start() + Self::rd_page_size()
        }

        pub fn preload_thread_locals_start() -> RemotePtr<Void> {
            Self::rd_page_start() + page_size()
        }
        pub fn preload_thread_locals_size() -> usize {
            PRELOAD_THREAD_LOCALS_SIZE
        }

        pub fn rd_page_syscall_exit_point(
            traced: Traced,
            privileged: Privileged,
            enabled: Enabled,
        ) -> RemoteCodePtr {
            for (i, e) in ENTRY_POINTS.iter().enumerate() {
                if e.traced == traced && e.privileged == privileged && e.enabled == enabled {
                    // @TODO check this.
                    return exit_ip_from_index(i);
                }
            }

            unreachable!()
        }
        pub fn rd_page_syscall_entry_point(
            traced: Traced,
            privileged: Privileged,
            enabled: Enabled,
            _arch: SupportedArch,
        ) -> RemoteCodePtr {
            for (i, e) in ENTRY_POINTS.iter().enumerate() {
                if e.traced == traced && e.privileged == privileged && e.enabled == enabled {
                    // @TODO check this.
                    return entry_ip_from_index(i);
                }
            }

            unreachable!()
        }

        /// DIFF NOTE: rr returns a std vector.
        pub fn rd_page_syscalls() -> &'static [SyscallType] {
            &ENTRY_POINTS
        }

        pub fn rd_page_syscall_from_exit_point(ip: RemoteCodePtr) -> Option<SyscallType> {
            for i in 0..ENTRY_POINTS.len() {
                if exit_ip_from_index(i) == ip {
                    return Some(ENTRY_POINTS[i]);
                }
            }

            None
        }

        pub fn rd_page_syscall_from_entry_point(ip: RemoteCodePtr) -> Option<SyscallType> {
            for i in 0..ENTRY_POINTS.len() {
                if entry_ip_from_index(i) == ip {
                    return Some(ENTRY_POINTS[i]);
                }
            }

            None
        }

        /// Return a pointer to 8 bytes of 0xFF
        pub fn rd_page_ff_bytes() -> RemotePtr<u8> {
            RD_PAGE_FF_BYTES.into()
        }

        /// Locate a syscall instruction in t's VDSO.
        /// This gives us a way to execute remote syscalls without having to write
        /// a syscall instruction into executable tracee memory (which might not be
        /// possible with some kernels, e.g. PaX).
        pub fn find_syscall_instruction(&self, t: &mut dyn Task) -> RemoteCodePtr {
            static OFFSET_TO_SYSCALL_IN_X86: AtomicUsize = AtomicUsize::new(0);
            static OFFSET_TO_SYSCALL_IN_X64: AtomicUsize = AtomicUsize::new(0);

            let arch = t.arch();
            let mut offset = match arch {
                SupportedArch::X86 => OFFSET_TO_SYSCALL_IN_X86.load(Ordering::SeqCst),
                SupportedArch::X64 => OFFSET_TO_SYSCALL_IN_X64.load(Ordering::SeqCst),
            };

            if offset == 0 {
                let vdso = read_mem::<u8>(t, self.vdso().start(), self.vdso().size(), None);
                let maybe_offset = find_offset_of_syscall_instruction_in(arch, &vdso);
                match maybe_offset {
                    None => ed_assert!(t, false, "No syscall instruction found in VDSO"),
                    Some(calc_offset) => {
                        assert_ne!(calc_offset, 0);
                        offset = calc_offset;
                        match arch {
                            SupportedArch::X86 => {
                                OFFSET_TO_SYSCALL_IN_X86.store(calc_offset, Ordering::SeqCst)
                            }
                            SupportedArch::X64 => {
                                OFFSET_TO_SYSCALL_IN_X64.store(calc_offset, Ordering::SeqCst)
                            }
                        };
                    }
                };
            }

            RemoteCodePtr::from_val(self.vdso().start().as_usize() + offset)
        }

        /// Task `t` just forked from this address space. Apply dont_fork settings.
        pub fn did_fork_into(&self, t: &mut dyn Task) {
            for range in self.dont_fork.borrow().iter() {
                // During recording we execute MADV_DONTFORK so the forked child will
                // have had its dontfork areas unmapped by the kernel already
                if !t.session().is_recording() {
                    let mut remote = AutoRemoteSyscalls::new(t);
                    let arch = remote.arch();
                    rd_infallible_syscall!(
                        remote,
                        syscall_number_for_munmap(arch),
                        range.start().as_usize(),
                        range.size()
                    );
                }
                t.vm().unmap(t, range.start(), range.size());
            }
        }

        pub fn set_first_run_event(&self, event: FrameTime) {
            self.first_run_event_.set(event);
        }
        pub fn first_run_event(&self) -> FrameTime {
            self.first_run_event_.get()
        }

        pub fn saved_auxv(&self) -> Ref<[u8]> {
            Ref::map(self.saved_auxv_.borrow(), |v| v.as_slice())
        }
        pub fn save_auxv(&self, t: &mut dyn Task) {
            *self.saved_auxv_.borrow_mut() = read_auxv(t);
        }

        /// Reads the /proc/<pid>/maps entry for a specific address. Does no caching.
        /// If performed on a file in a btrfs file system, this may return the
        /// wrong device number! If you stick to anonymous or special file
        /// mappings, this should be OK.
        pub fn read_kernel_mapping(t: &dyn Task, addr: RemotePtr<Void>) -> KernelMapping {
            read_kernel_mapping(t.tid, addr)
        }

        /// Same as read_kernel_mapping, but reads rd's own memory map.
        pub fn read_local_kernel_mapping(addr: *const u8) -> KernelMapping {
            read_kernel_mapping(getpid().as_raw(), RemotePtr::new(addr as usize))
        }

        pub fn chaos_mode_min_stack_size() -> usize {
            8 * 1024 * 1024
        }

        pub fn chaos_mode_find_free_memory(&self, _t: &RecordTask, _len: usize) -> RemotePtr<Void> {
            unimplemented!()
        }

        /// We assume this method always succeeds
        ///
        /// If `maybe_after` is None, then starts finding free memory from the beginning of address
        /// space, i.e. at address 0.
        pub fn find_free_memory(
            &self,
            required_space: usize,
            maybe_after: Option<RemotePtr<Void>>,
        ) -> RemotePtr<Void> {
            let after = maybe_after.unwrap_or(RemotePtr::null());
            let maps = self.maps_starting_at(after);
            let mut iter = maps.into_iter();
            // This has to succeed otherwise we panic!
            let mut current = iter.next().unwrap().1;
            loop {
                let maybe_next = iter.next().map(|v| v.1);
                match maybe_next {
                    None => {
                        // If there is an overflow, rust will complain
                        if current.map.end() + required_space >= current.map.end() {
                            break;
                        }
                    }
                    Some(found_next) => {
                        if current.map.end() + required_space <= found_next.map.start() {
                            break;
                        }
                    }
                }
                current = maybe_next.unwrap();
            }

            current.map.end()
        }

        /// The return value indicates whether we (re)created the preload_thread_locals
        /// area.
        pub fn post_vm_clone(&self, t: &mut dyn Task) -> bool {
            let maybe_m = self.mapping_of(Self::preload_thread_locals_start());
            if maybe_m.is_some()
                && !maybe_m
                    .unwrap()
                    .flags
                    .contains(MappingFlags::IS_THREAD_LOCALS)
            {
                // The tracee already has a mapping at this address that doesn't belong to
                // us. Don't touch it.
                return false;
            }

            // Otherwise, the preload_thread_locals mapping is non-existent or ours.
            // Recreate it.
            let mut remote = AutoRemoteSyscalls::new(t);
            remote.create_shared_mmap(
                PRELOAD_THREAD_LOCALS_SIZE,
                Some(Self::preload_thread_locals_start()),
                OsStr::new("preload_thread_locals"),
                None,
                None,
                None,
            );
            *self.mapping_flags_of_mut(Self::preload_thread_locals_start()) |=
                MappingFlags::IS_THREAD_LOCALS;

            true
        }

        /// TaskUid for the task whose locals are stored in the preload_thread_locals
        /// area.
        ///
        /// Note that TaskUid is Copy
        pub fn thread_locals_tuid(&self) -> TaskUid {
            self.thread_locals_tuid_.get()
        }

        /// Note that TaskUid is Copy
        pub fn set_thread_locals_tuid(&self, tuid: TaskUid) {
            self.thread_locals_tuid_.set(tuid);
        }

        /// Call this when the memory at [addr,addr+len) was externally overwritten.
        /// This will attempt to update any breakpoints that may be set within the
        /// range (resetting them and storing the new value).
        pub fn maybe_update_breakpoints(&self, t: &mut dyn Task, addr: RemotePtr<u8>, len: usize) {
            for (k, v) in self.breakpoints.borrow_mut().iter_mut() {
                let bp_addr = k.to_data_ptr::<u8>();
                if addr <= bp_addr && bp_addr < addr + len {
                    // This breakpoint was overwritten. Note the new data and reset the
                    // breakpoint.
                    let mut ok = true;
                    v.overwritten_data = read_val_mem::<u8>(t, bp_addr, Some(&mut ok));
                    ed_assert!(t, ok);
                    write_val_mem::<u8>(t, bp_addr, &Self::BREAKPOINT_INSN, None);
                }
            }
        }

        /// Call this to ensure that the mappings in `range` during replay has the same length
        /// and is collapsed to a single mapping. The caller guarantees that all the
        /// mappings in the range can be coalesced (because they corresponded to a single
        /// mapping during recording).
        /// The end of the range might be in the middle of a mapping.
        /// The start of the range might also be in the middle of a mapping.
        pub fn ensure_replay_matches_single_recorded_mapping(
            &self,
            t: &mut dyn Task,
            range: MemoryRange,
        ) {
            // The only case where we eagerly coalesced during recording but not replay should
            // be where we mapped private memory beyond-end-of-file.
            // Don't do an actual coalescing check here; we rely on the caller to tell us
            // the range to coalesce.
            ed_assert_eq!(t, range.start(), floor_page_size(range.start()));
            ed_assert_eq!(t, range.end(), ceil_page_size(range.end()));

            let fixer = |slf: &Self, m_key: MemoryRangeKey, range: MemoryRange| {
                // Important !
                let mapping = slf.mem.borrow().get(&m_key).unwrap().clone();
                if *mapping.map == range {
                    // Existing single mapping covers entire range; nothing to do.
                    return;
                }

                // These should be null during replay
                ed_assert!(t, mapping.mapped_file_stat.is_none());
                // These should not be in use for a beyond-end-of-file mapping
                ed_assert!(t, mapping.local_addr.is_none());
                // The mapping should be private
                ed_assert!(t, mapping.map.flags().contains(MapFlags::MAP_PRIVATE));
                ed_assert!(t, mapping.emu_file.is_none());
                ed_assert!(t, mapping.monitored_shared_memory.is_none());
                // Flagged mappings shouldn't be coalescable ever
                ed_assert!(t, mapping.flags.is_empty());

                if !(mapping.map.flags().contains(MapFlags::MAP_ANONYMOUS)) {
                    // Direct-mapped piece. Turn it into an anonymous mapping.
                    let mut buffer: Vec<u8> = Vec::with_capacity(mapping.map.size());
                    buffer.resize(mapping.map.size(), 0);
                    t.read_bytes_helper(mapping.map.start(), &mut buffer, None);
                    {
                        let mut remote = AutoRemoteSyscalls::new(t);
                        remote.infallible_mmap_syscall(
                            Some(mapping.map.start()),
                            buffer.len(),
                            mapping.map.prot(),
                            mapping.map.flags() | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                            -1,
                            0,
                        );
                    }
                    t.write_bytes_helper(mapping.map.start(), &buffer, None, WriteFlags::empty());

                    // We replace the entire mapping even if part of it falls outside the desired range.
                    // That's OK, this replacement preserves behaviour, it's simpler, even if a bit
                    // less efficient in weird cases.
                    slf.mem.borrow_mut().remove(&MemoryRangeKey(*mapping.map));
                    let anonymous_km = KernelMapping::new_with_opts(
                        mapping.map.start(),
                        mapping.map.end(),
                        OsStr::new(""),
                        KernelMapping::NO_DEVICE,
                        KernelMapping::NO_INODE,
                        mapping.map.prot(),
                        mapping.map.flags() | MapFlags::MAP_ANONYMOUS,
                        0,
                    );
                    let new_mapping =
                        Mapping::new(anonymous_km, mapping.recorded_map, None, None, None, None);
                    slf.mem.borrow_mut().insert(
                        MemoryRange::from_range(mapping.map.start(), mapping.map.end()).into(),
                        new_mapping,
                    );
                }
            };

            self.for_each_in_range(
                range.start(),
                range.size(),
                fixer,
                IterateHow::IterateDefault,
            );

            self.coalesce_around(t, range.into());
        }

        /// Dump process maps as string
        ///
        /// DIFF NOTE: Method is called print_process_maps() in rr and outputs to std err
        /// Here we output as a String for more flexibility
        ///
        /// Another difference with rr is that we print our internal representation of data rather
        /// than output the raw line obtained from /proc/{}/maps. This is likely to catch more
        /// issues.
        pub fn dump_process_maps(t: &dyn Task) -> String {
            let mut out = String::new();
            let iter = KernelMapIterator::new(t);
            for km in iter {
                out += &format!("{}\n", km);
            }

            out
        }

        /// Constructor
        ///
        /// Called after a successful execve to set up the new AddressSpace.
        /// Also called once for the initial spawn.
        pub(in super::super) fn new_after_execve(
            t: &mut dyn Task,
            exe: &OsStr,
            exec_count: u32,
        ) -> AddressSpace {
            let patcher = if t.session().is_recording() {
                Some(Rc::new(RefCell::new(MonkeyPatcher::new())))
            } else {
                None
            };

            let addr_space = AddressSpace {
                exe: exe.to_owned(),
                leader_tid_: t.rec_tid,
                leader_serial: t.tuid().serial(),
                exec_count,
                session_: Rc::downgrade(&t.session()),
                monkeypatch_state: patcher,
                syscallbuf_enabled_: Default::default(),
                first_run_event_: Default::default(),
                // Implicit
                breakpoints: Default::default(),
                watchpoints: Default::default(),
                mem: Default::default(),
                shm_sizes: Default::default(),
                monitored_mem: Default::default(),
                dont_fork: Default::default(),
                saved_watchpoints: Default::default(),
                child_mem_fd: Default::default(),
                privileged_traced_syscall_ip_: Default::default(),
                saved_auxv_: Default::default(),
                // Is this what we want?
                task_set: Default::default(),
                // Is TaskUid::new() what we want?
                thread_locals_tuid_: Default::default(),
                // These are set below. Are both OK??
                traced_syscall_ip_: Default::default(),
                vdso_start_addr: Default::default(),
                // Hmm...
                brk_start: Default::default(),
                brk_end: Default::default(),
            };

            // TODO: this is a workaround of
            // https://github.com/rr-debugger/rr/issues/1113 .
            if addr_space.session().done_initial_exec() {
                addr_space.populate_address_space(t);
                debug_assert!(!addr_space.vdso_start_addr.get().is_null());
            } else {
                // Setup traced_syscall_ip_ now because we need to do AutoRemoteSyscalls
                // (for open_mem_fd) before the first exec. We rely on the fact that we
                // haven't execed yet, so the address space layout is the same.
                addr_space.traced_syscall_ip_.set(RemoteCodePtr::from_val(
                    rd_syscall_addr as *const fn() as usize,
                ));
            }

            addr_space
        }

        /// Constructor
        ///
        /// Called when an AddressSpace is cloned due to a fork() or a Session
        /// clone. After this, and the task is properly set up, post_vm_clone will
        /// be called.
        pub(in super::super) fn new_after_fork_or_session_clone(
            session: SessionSharedWeakPtr,
            o: &AddressSpace,
            leader_tid: pid_t,
            leader_serial: u32,
            exec_count: u32,
        ) -> AddressSpace {
            let maybe_monkey_patcher = match o.monkeypatch_state.as_ref() {
                Some(rc) => Some(Rc::new(RefCell::new(rc.borrow().clone()))),
                None => None,
            };
            let mut addr_space = AddressSpace {
                exe: o.exe.clone(),
                leader_tid_: leader_tid,
                leader_serial,
                exec_count,
                brk_start: o.brk_start.clone(),
                brk_end: o.brk_end.clone(),
                mem: o.mem.clone(),
                shm_sizes: o.shm_sizes.clone(),
                monitored_mem: o.monitored_mem.clone(),
                session_: session.clone(),
                vdso_start_addr: o.vdso_start_addr.clone(),
                monkeypatch_state: maybe_monkey_patcher,
                traced_syscall_ip_: o.traced_syscall_ip_.clone(),
                privileged_traced_syscall_ip_: o.privileged_traced_syscall_ip_.clone(),
                syscallbuf_enabled_: o.syscallbuf_enabled_.clone(),
                saved_auxv_: o.saved_auxv_.clone(),
                first_run_event_: Default::default(),
                watchpoints: o.watchpoints.clone(),
                breakpoints: o.breakpoints.clone(),
                // rr does not explicitly initialize these.
                child_mem_fd: Default::default(),
                dont_fork: Default::default(),
                task_set: Default::default(),
                // Is TaskUid::new() what we want?
                thread_locals_tuid_: Default::default(),
                saved_watchpoints: Default::default(),
            };

            for (_, m) in addr_space.mem.borrow_mut().iter_mut() {
                // The original address space continues to have exclusive ownership of
                // all local mappings.
                m.local_addr = None;
            }

            if !Rc::ptr_eq(&addr_space.session(), &o.session()) {
                // Cloning into a new session means we're checkpointing.
                addr_space.first_run_event_ = o.first_run_event_.clone();
            }
            // cloned tasks will automatically get cloned debug registers and
            // cloned address-space memory, so we don't need to do any more work here.

            addr_space
        }

        /// After an exec, populate the new address space of `t` with
        /// the existing mappings we find in /proc/maps.
        fn populate_address_space(&self, t: &dyn Task) {
            let mut found_proper_stack = false;
            let iter = KernelMapIterator::new(t);
            for km in iter {
                if km.is_stack() {
                    found_proper_stack = true;
                    break;
                }
            }

            // If we're being recorded by rd, we'll see the outer rd's rd_page and
            // preload_thread_locals. In post_exec() we'll remap those with our
            // own mappings. That's OK because a) the rd_page contents are the same
            // anyway and immutable and b) the preload_thread_locals page is only
            // used by the preload library, and the preload library only knows about
            // the inner rd. i.e. as far as the outer rd is concerned, the tracee is
            // not doing syscall buffering.

            let mut found_stacks = 0;
            let iter = KernelMapIterator::new(t);
            for km in iter {
                let mut map_flags = km.flags();
                let mut start = km.start();
                let is_stack = if found_proper_stack {
                    km.is_stack()
                } else {
                    could_be_stack(&km)
                };

                if is_stack {
                    found_stacks += 1;
                    map_flags |= MapFlags::MAP_GROWSDOWN;
                    if uses_invisible_guard_page() {
                        // MAP_GROWSDOWN segments really occupy one additional page before
                        // the start address shown by /proc/<pid>/maps --- unless that page
                        // is already occupied by another mapping.
                        if !self.mapping_of(start - page_size()).is_some() {
                            start -= page_size();
                        }
                    }
                }

                self.map(
                    t,
                    start,
                    km.end() - start,
                    km.prot(),
                    map_flags,
                    km.file_offset_bytes(),
                    km.fsname(),
                    check_device(&km),
                    km.inode(),
                    None,
                    None,
                    None,
                    None,
                    None,
                );
            }
            ed_assert_eq!(t, found_stacks, 1);
        }

        /// DIFF NOTE: @TODO In rr `num_bytes` is signed. Why?
        fn unmap_internal(&self, _t: &dyn Task, addr: RemotePtr<Void>, num_bytes: usize) {
            log!(
                LogDebug,
                "munmap({}, {} = {:#x})",
                addr,
                num_bytes,
                num_bytes
            );

            let unmapper = |slf: &Self, m_key: MemoryRangeKey, rem: MemoryRange| {
                log!(LogDebug, "  unmapping ({}) ...", rem);

                let m = slf.mem.borrow().get(&m_key).unwrap().clone();
                slf.remove_from_map(*m.map);

                log!(LogDebug, "  erased ({}) ...", m.map);

                // If the first segment we unmap underflows the unmap
                // region, remap the underflow region.
                let monitored = m.monitored_shared_memory.clone();
                if m.map.start() < rem.start() {
                    let mut underflow = Mapping::new(
                        m.map.subrange(m.map.start(), rem.start()),
                        m.recorded_map.subrange(m.map.start(), rem.start()),
                        m.emu_file.clone(),
                        m.mapped_file_stat.clone(),
                        m.local_addr,
                        monitored,
                    );
                    underflow.flags = m.flags;
                    slf.add_to_map(underflow);
                }
                // If the last segment we unmap overflows the unmap
                // region, remap the overflow region.
                if rem.end() < m.map.end() {
                    let new_local = m.local_addr.map(|addr| unsafe {
                        NonNull::new(addr.as_ptr().add(rem.end() - m.map.start())).unwrap()
                    });

                    let new_monitored = m.monitored_shared_memory.clone().map(|r| {
                        r.borrow()
                            .subrange(rem.end() - m.map.start(), m.map.end() - rem.end())
                    });
                    let mut overflow = Mapping::new(
                        m.map.subrange(rem.end(), m.map.end()),
                        m.recorded_map.subrange(rem.end(), m.map.end()),
                        m.emu_file,
                        m.mapped_file_stat,
                        new_local,
                        new_monitored,
                    );
                    overflow.flags = m.flags;
                    slf.add_to_map(overflow);
                }

                match m.local_addr {
                    Some(local_addr) => {
                        let size = min(rem.size(), m.map.size() - (rem.start() - m.map.start()));
                        let res = unsafe {
                            let addr = local_addr.as_ptr().add(rem.start() - m.map.start());
                            munmap(addr, size)
                        };

                        match res {
                            Err(e) => fatal!("Can't munmap: {:?}", e),
                            Ok(_) => (),
                        }
                    }
                    None => (),
                }
            };
            self.for_each_in_range(addr, num_bytes, unmapper, IterateHow::IterateDefault);
            self.update_watchpoint_values(addr, addr + num_bytes);
        }

        /// Also sets brk_ptr.
        fn map_rd_page(&self, remote: &mut AutoRemoteSyscalls) {
            let prot = ProtFlags::PROT_EXEC | ProtFlags::PROT_READ;
            let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED;

            let file_name: OsString;
            let arch = remote.arch();

            let path = find_rd_page_file(remote.task());
            let mut child_path = AutoRestoreMem::push_cstr(remote, path.as_os_str());
            // skip leading '/' since we want the path to be relative to the root fd
            let remote_path_addr = child_path.get().unwrap() + 1usize;
            let child_fd: i32 = rd_syscall!(
                child_path,
                syscall_number_for_openat(arch),
                RD_RESERVED_ROOT_DIR_FD,
                remote_path_addr.as_usize(),
                O_RDONLY
            ) as i32;

            if child_fd >= 0 {
                child_path.infallible_mmap_syscall(
                    Some(Self::rd_page_start()),
                    Self::rd_page_size(),
                    prot,
                    flags,
                    child_fd,
                    0,
                );

                let fstat: libc::stat = child_path.task().stat_fd(child_fd);
                file_name = child_path.task().file_name_of_fd(child_fd);

                rd_infallible_syscall!(child_path, syscall_number_for_close(arch), child_fd);

                self.map(
                    child_path.task(),
                    Self::rd_page_start(),
                    Self::rd_page_size(),
                    prot,
                    flags,
                    0,
                    &file_name,
                    fstat.st_dev,
                    fstat.st_ino,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
            } else {
                ed_assert!(
                    child_path.task(),
                    child_fd != -ENOENT,
                    "rd_page file not found: {:?}",
                    path
                );
                ed_assert!(
                    child_path.task(),
                    child_fd == -EACCES,
                    "Unexpected error mapping rd_page"
                );
                flags |= MapFlags::MAP_ANONYMOUS;
                child_path.infallible_mmap_syscall(
                    Some(Self::rd_page_start()),
                    Self::rd_page_size(),
                    prot,
                    flags,
                    -1,
                    0,
                );
                let page = ScopedFd::open_path(path.as_os_str(), OFlag::O_RDONLY);
                ed_assert!(
                    child_path.task(),
                    page.is_open(),
                    "Error opening rd_page ourselves"
                );
                // @TODO Different from rr. Make sure this is correct.
                file_name = child_path.task().file_name_of_fd(page.as_raw());

                let page_data: Vec<u8> = read_all(child_path.task(), &page);
                child_path.task_mut().write_bytes_helper(
                    Self::rd_page_start(),
                    &page_data,
                    None,
                    WriteFlags::empty(),
                );

                self.map(
                    child_path.task(),
                    Self::rd_page_start(),
                    Self::rd_page_size(),
                    prot,
                    flags,
                    0,
                    &file_name,
                    0,
                    0,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
            }
            *self.mapping_flags_of_mut(Self::rd_page_start()) = MappingFlags::IS_RD_PAGE;

            if child_path.task().session().is_recording() {
                // brk() will not have been called yet so the brk area is empty.
                self.brk_start.set(
                    (rd_infallible_syscall!(child_path, syscall_number_for_brk(arch), 0) as usize)
                        .into(),
                );
                self.brk_end.set(self.brk_start.get());
                ed_assert!(child_path.task(), !self.brk_end.get().is_null());
            }

            self.traced_syscall_ip_
                .set(Self::rd_page_syscall_entry_point(
                    Traced::Traced,
                    Privileged::Unprivileged,
                    Enabled::RecordingAndReplay,
                    child_path.arch(),
                ));
            self.privileged_traced_syscall_ip_
                .set(Some(Self::rd_page_syscall_entry_point(
                    Traced::Traced,
                    Privileged::Privileged,
                    Enabled::RecordingAndReplay,
                    child_path.arch(),
                )));
        }

        // DIFF NOTE: In rr this method takes 2 params but the second param is different.
        // `maybe_mark_changed_if_changed` default value is false.
        fn update_watchpoint_value(
            &self,
            watchpoint_range: &MemoryRange,
            maybe_mark_changed_if_changed: Option<bool>,
        ) -> bool {
            let mut valid = true;
            let mut value_bytes: Vec<u8>;
            let changed: bool;
            let mark_changed_if_changed = maybe_mark_changed_if_changed.unwrap_or(false);
            {
                value_bytes = self
                    .watchpoints
                    .borrow()
                    .get(&watchpoint_range)
                    .unwrap()
                    .value_bytes
                    .clone();
                let t = self.task_set().iter().next().unwrap();
                for i in 0..value_bytes.len() {
                    value_bytes[i] = 0xFF;
                }
                let mut addr: RemotePtr<Void> = watchpoint_range.start();
                let mut num_bytes: usize = watchpoint_range.size();
                let mut bytes_read: usize;
                while num_bytes > 0 {
                    let buf_pos = addr.as_usize() - watchpoint_range.start().as_usize();
                    let bytes_read_res = t
                        .borrow_mut()
                        .read_bytes_fallible(addr, &mut value_bytes[buf_pos..buf_pos + num_bytes]);
                    match bytes_read_res {
                        Ok(0) | Err(_) => {
                            valid = false;
                            // advance to next page and try to read more. We want to know
                            // when the valid part of a partially invalid watchpoint changes.
                            bytes_read =
                                min(num_bytes, (floor_page_size(addr) + page_size()) - addr);
                        }
                        Ok(nread) => bytes_read = nread,
                    }
                    addr += bytes_read;
                    num_bytes -= bytes_read;
                }

                let wb = self.watchpoints.borrow();
                let watchpoint_original = wb.get(&watchpoint_range).unwrap();
                changed = valid != watchpoint_original.valid
                    || unsafe {
                        libc::memcmp(
                            value_bytes.as_ptr().cast(),
                            watchpoint_original.value_bytes.as_ptr().cast(),
                            value_bytes.len(),
                        )
                    } != 0;
            }
            let mut mbm = self.watchpoints.borrow_mut();
            let mut watchpoint_original_mut = mbm.get_mut(watchpoint_range).unwrap();
            watchpoint_original_mut.valid = valid;
            watchpoint_original_mut.value_bytes = value_bytes;
            if mark_changed_if_changed && changed {
                watchpoint_original_mut.changed = true;
            }

            changed
        }

        fn update_watchpoint_values(&self, start: RemotePtr<Void>, end: RemotePtr<Void>) {
            let r = MemoryRange::from_range(start, end);
            let mut intersects: Vec<MemoryRange> = Vec::new();
            for k in self.watchpoints.borrow().keys() {
                if k.intersects(&r) {
                    intersects.push(*k);
                }
            }
            for mr in intersects {
                self.update_watchpoint_value(&mr, Some(true));
                // We do nothing to track kernel reads of read-write watchpoints...
            }
        }
        fn get_watchpoints_internal(&self, filter: WatchPointFilter) -> Vec<WatchConfig> {
            let mut result: Vec<WatchConfig> = Vec::new();
            for (r, v) in self.watchpoints.borrow_mut().iter_mut() {
                if filter == WatchPointFilter::ChangedWatchpoints {
                    if !v.changed {
                        continue;
                    }
                    v.changed = false;
                }
                let watching = v.watched_bits();
                if watching.contains(RwxBits::EXEC_BIT) {
                    result.push(WatchConfig::new(r.start(), r.size(), WatchType::WatchExec));
                }
                if watching.contains(RwxBits::READ_BIT) {
                    result.push(WatchConfig::new(
                        r.start(),
                        r.size(),
                        WatchType::WatchReadWrite,
                    ));
                } else if watching.contains(RwxBits::WRITE_BIT) {
                    result.push(WatchConfig::new(r.start(), r.size(), WatchType::WatchWrite));
                }
            }
            result
        }

        fn get_watch_configs(&self, will_set_task_state: WillSetTaskState) -> Vec<WatchConfig> {
            let mut result: Vec<WatchConfig> = Vec::new();
            for (r, v) in self.watchpoints.borrow_mut().iter_mut() {
                let mut assigned_regs: Option<&mut Vec<u8>> = None;
                let watching = v.watched_bits();
                if will_set_task_state == WillSetTaskState::SettingTaskState {
                    v.debug_regs_for_exec_read.clear();
                    assigned_regs = Some(&mut v.debug_regs_for_exec_read);
                }
                if watching.contains(RwxBits::EXEC_BIT) {
                    configure_watch_registers(
                        &mut result,
                        r,
                        WatchType::WatchExec,
                        &mut assigned_regs,
                    );
                }
                if watching.contains(RwxBits::READ_BIT) {
                    configure_watch_registers(
                        &mut result,
                        r,
                        WatchType::WatchReadWrite,
                        &mut assigned_regs,
                    );
                } else if watching.contains(RwxBits::WRITE_BIT) {
                    configure_watch_registers(&mut result, r, WatchType::WatchWrite, &mut None);
                }
            }
            result
        }

        /// Construct a minimal set of watchpoints to be enabled based
        /// on `set_watchpoint()` calls, and program them for each task
        /// in this address space.
        /// DIFF NOTE: Additional param `active_task` and `cloned_from_thread`.
        /// In most situations `cloned_from_thread` can be set to None.
        /// To solve already borrowed possibility for the tasks
        fn allocate_watchpoints(
            &self,
            active_task: &mut dyn Task,
            maybe_cloned_from_thread: Option<&mut dyn Task>,
        ) -> bool {
            let mut regs = self.get_watch_configs(WillSetTaskState::SettingTaskState);

            let mut except_vec = Vec::new();
            let mut active_task_same_task_set = false;
            if self.task_set().has(active_task.weak_self_ptr()) {
                except_vec.push(active_task.weak_self_ptr());
                active_task_same_task_set = true;
            }

            let mut cloned_from_thread_same_task_set = false;
            match maybe_cloned_from_thread.as_ref() {
                Some(cloned_from_thread) => {
                    if self.task_set().has(cloned_from_thread.weak_self_ptr()) {
                        except_vec.push(cloned_from_thread.weak_self_ptr());
                        cloned_from_thread_same_task_set = true;
                    }
                }
                None => (),
            }

            if regs.len() <= 0x7f {
                let mut ok = true;
                if active_task_same_task_set && !active_task.set_debug_regs(&regs) {
                    ok = false;
                }

                if cloned_from_thread_same_task_set {
                    match maybe_cloned_from_thread.as_ref() {
                        Some(cloned_from_thread) => {
                            if !cloned_from_thread.set_debug_regs(&regs) {
                                ok = false;
                            }
                        }
                        None => (),
                    }
                }

                for t in self.task_set().iter_except_vec(except_vec.clone()) {
                    if !t.borrow_mut().set_debug_regs(&regs) {
                        ok = false;
                    }
                }
                if ok {
                    return true;
                }
            }

            regs.clear();
            if active_task_same_task_set {
                active_task.set_debug_regs(&regs);
            }
            if cloned_from_thread_same_task_set {
                maybe_cloned_from_thread
                    .map(|cloned_from_thread| cloned_from_thread.set_debug_regs(&mut regs));
            }
            for t2 in self.task_set().iter_except_vec(except_vec) {
                t2.borrow_mut().set_debug_regs(&regs);
            }

            for v in self.watchpoints.borrow_mut().values_mut() {
                v.debug_regs_for_exec_read.clear();
            }

            false
        }

        /// Merge the mappings adjacent to `key` in memory that are
        /// semantically "adjacent mappings" of the same resource as
        /// well, for example have adjacent file offsets and the same
        /// prot and flags.
        fn coalesce_around(&self, t: &dyn Task, key: MemoryRangeKey) {
            let mut new_m: Mapping;
            let first_k: MemoryRangeKey;
            let last_k: MemoryRangeKey;

            {
                let mb = self.mem.borrow();
                let mut forward_iterator = mb.range((Included(key), Unbounded));
                let mut backward_iterator = mb.range((Unbounded, Included(key)));
                let mut first_kv = backward_iterator.next_back().unwrap();
                while let Some(prev_kv) = backward_iterator.next_back() {
                    if !is_coalescable(prev_kv.1, first_kv.1) {
                        break;
                    } else {
                        assert_coalesceable(t, &prev_kv.1, &first_kv.1);
                        first_kv = prev_kv;
                    }
                }

                let mut last_kv = forward_iterator.next().unwrap();
                while let Some(next_kv) = forward_iterator.next() {
                    if !is_coalescable(&last_kv.1, &next_kv.1) {
                        break;
                    } else {
                        assert_coalesceable(t, &last_kv.1, &next_kv.1);
                        last_kv = next_kv;
                    }
                }

                if first_kv.0 == last_kv.0 {
                    log!(LogDebug, "  no mappings to coalesce");
                    return;
                }

                new_m = Mapping::new(
                    first_kv.1.map.extend(last_kv.0.end()),
                    first_kv.1.recorded_map.extend(last_kv.0.end()),
                    first_kv.1.emu_file.clone(),
                    first_kv.1.mapped_file_stat.clone(),
                    first_kv.1.local_addr,
                    first_kv.1.monitored_shared_memory.clone(),
                );
                new_m.flags = first_kv.1.flags;
                log!(LogDebug, "  coalescing {}", new_m.map);
                first_k = *first_kv.0;
                last_k = *last_kv.0;
            }

            // monitored-memory currently isn't coalescable so we don't need to
            // adjust monitored_mem
            let mut to_remove: Vec<MemoryRangeKey> = Vec::new();
            for (k, _) in self
                .mem
                .borrow()
                .range((Included(first_k), Included(last_k)))
            {
                to_remove.push(*k);
            }

            for k in to_remove {
                self.mem.borrow_mut().remove(&k);
            }

            let result = self
                .mem
                .borrow_mut()
                .insert(MemoryRangeKey(*new_m.map), new_m);
            debug_assert!(result.is_none());
        }

        /// Erase `it` from `breakpoints` and restore any memory in
        /// this it may have overwritten.
        ///
        /// Assumes there IS a breakpoint at `addr` or will panic
        ///
        /// Called destroy_breakpoint() in rr.
        /// DIFF NOTE: Additional param `active_task`
        fn destroy_breakpoint_at(&self, addr: RemoteCodePtr, active_task: &mut dyn Task) {
            // @TODO In an earlier version of this method there was the possibility that there was
            // no task in the task set. In the new version we always assume there is an active
            // task. Check whether this assumption will not cause any problems.
            let data = self
                .breakpoints
                .borrow()
                .get(&addr)
                .unwrap()
                .overwritten_data;
            log!(LogDebug, "Writing back {:#x} at {}", data, addr);
            write_val_mem_with_flags::<u8>(
                active_task,
                addr.to_data_ptr::<u8>(),
                &data,
                None,
                WriteFlags::IS_BREAKPOINT_RELATED,
            );
            self.breakpoints.borrow_mut().remove(&addr);
        }

        /// For each mapped segment overlapping [addr, addr +
        /// num_bytes), call `f`.  Pass `f` the overlapping mapping,
        /// and the range of addresses remaining to be iterated over.
        ///
        /// Pass `IterateContiguous` to stop iterating when the last
        /// contiguous mapping after `addr` within the region is seen.
        ///
        /// `IterateDefault` will iterate all mappings in the region.
        fn for_each_in_range<F: FnMut(&Self, MemoryRangeKey, MemoryRange)>(
            &self,
            addr: RemotePtr<Void>,
            // DIFF NOTE: This is signed in rr.
            num_bytes: usize,
            mut f: F,
            how: IterateHow,
        ) {
            let region_start = floor_page_size(addr);
            let mut last_f_mapped_end = region_start;
            let region_end = ceil_page_size(addr + num_bytes);
            while last_f_mapped_end < region_end {
                // Invariant: `rem` is always exactly the region of
                // memory remaining to be examined for pages to be
                // f-mapped.
                let rem = MemoryRange::from_range(last_f_mapped_end, region_end);

                // The next Mapping to iterate may not be contiguous with
                // the last one seen.
                let range: MemoryRangeKey;
                {
                    let maps = Maps::from_range(self, rem);
                    // Note that this iterator is set afresh every for-each iteration!
                    let mut iter = maps.into_iter();
                    let result = iter.next();
                    match result {
                        Some((r, _)) => {
                            range = *r;
                        }
                        None => {
                            log!(LogDebug, "  not found, done.");
                            return;
                        }
                    }
                }
                // `f` is allowed to erase Mappings.
                if rem.end() <= range.start() {
                    log!(
                        LogDebug,
                        "  mapping at {} out of range, done.",
                        range.start()
                    );
                    return;
                }

                // range.start() < region_start would happen for the first region iterated
                if IterateHow::IterateContiguous == how
                    && !(range.start() < region_start || rem.start() == range.start())
                {
                    log!(
                        LogDebug,
                        "  discontiguous mapping at {}, done.",
                        range.start()
                    );
                    return;
                }

                // fmap!
                f(self, range, rem);

                // Maintain the loop invariant.
                last_f_mapped_end = range.end();
            }
        }

        /// Map `km` into this address space, and coalesce any
        /// mappings that are adjacent to `km`.
        fn map_and_coalesce(
            &self,
            t: &dyn Task,
            km: KernelMapping,
            recorded_km: KernelMapping,
            emu_file: Option<EmuFileSharedPtr>,
            mapped_file_stat: Option<libc::stat>,
            local_addr: Option<NonNull<c_void>>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) {
            log!(LogDebug, "  mapping {}", km);

            if monitored.is_some() {
                self.monitored_mem.borrow_mut().insert(km.start());
            }

            let mr_key: MemoryRangeKey = MemoryRangeKey(*km);
            let km_start = km.start();
            let km_end = km.end();
            self.mem.borrow_mut().insert(
                mr_key,
                Mapping::new(
                    km,
                    recorded_km,
                    emu_file,
                    mapped_file_stat,
                    local_addr,
                    monitored,
                ),
            );
            self.coalesce_around(t, mr_key);

            self.update_watchpoint_values(km_start, km_end);
        }

        fn remove_from_map(&self, range: MemoryRange) {
            self.mem.borrow_mut().remove(&MemoryRangeKey(range));
            self.monitored_mem.borrow_mut().remove(&range.start());
        }

        fn add_to_map(&self, m: Mapping) {
            let start_addr = m.map.start();
            if m.monitored_shared_memory.is_some() {
                self.monitored_mem.borrow_mut().insert(start_addr);
            }
            self.mem.borrow_mut().insert(MemoryRangeKey(*m.map), m);
        }

        fn at_preload_init_arch<Arch: Architecture>(&self, t: &mut dyn Task) {
            let addr = t.regs_ref().arg1();
            let params = read_val_mem(
                t,
                RemotePtr::<rdcall_init_preload_params<Arch>>::new(addr),
                None,
            );

            let tracee_syscallbuf_enabled = params.syscallbuf_enabled != 0;
            let tracee_syscallbuf_status = if tracee_syscallbuf_enabled {
                "enabled"
            } else {
                "disabled"
            };

            if t.session().is_recording() {
                let tracer_syscallbuf_enabled =
                    t.session().as_record().unwrap().use_syscall_buffer();
                let tracer_syscallbuf_status = if tracer_syscallbuf_enabled {
                    "enabled"
                } else {
                    "disabled"
                };
                ed_assert!(
                    t,
                    tracee_syscallbuf_enabled == tracer_syscallbuf_enabled,
                    "Tracee thinks syscallbuf is {}, but tracer thinks it is {}",
                    tracee_syscallbuf_status,
                    tracer_syscallbuf_status
                );
            }

            if !tracee_syscallbuf_enabled {
                return;
            }

            self.syscallbuf_enabled_.set(true);

            if t.session().is_recording() {
                self.monkeypatch_state
                    .as_ref()
                    .unwrap()
                    .borrow_mut()
                    .patch_at_preload_init(t.as_rec_mut_unwrap());
            }
        }

        /// Return the access bits above needed to watch `type`.
        fn access_bits_of(type_: WatchType) -> RwxBits {
            match type_ {
                WatchType::WatchExec => RwxBits::EXEC_BIT,
                WatchType::WatchWrite => RwxBits::WRITE_BIT,
                WatchType::WatchReadWrite => RwxBits::READ_WRITE_BITS,
            }
        }
    }

    impl Drop for AddressSpace {
        fn drop(&mut self) {
            // DIFF NOTE: @TODO this assertion is not present in rr.
            // Might there be any situations where the program is correct but
            // the assertion fails to hold?
            debug_assert_eq!(self.task_set().len(), 0);
            for (_, m) in self.mem.borrow().iter() {
                match m.local_addr {
                    Some(local) => match unsafe { munmap(local.as_ptr(), m.map.size()) } {
                        Err(e) => fatal!("Can't munmap: {:?}", e),
                        Ok(_) => (),
                    },
                    None => (),
                }
            }
            self.try_session()
                .map(|sess| sess.on_destroy_vm(self.uid()));
        }
    }
}

fn configure_watch_registers(
    regs: &mut Vec<WatchConfig>,
    range: &MemoryRange,
    watchtype: WatchType,
    maybe_assigned_regs: &mut Option<&mut Vec<u8>>,
) {
    // Zero-sized WatchConfigs return no ranges here, so are ignored.
    let mut split_ranges = split_range(range);

    if watchtype == WatchType::WatchWrite && range.size() > 1 {
        // We can suppress spurious write-watchpoint triggerings by checking
        // whether memory values have changed. So we can sometimes conserve
        // debug registers by upgrading an unaligned range to an aligned range
        // of a larger size.
        let align: usize;
        if range.size() <= 2 {
            align = 2;
        } else if range.size() <= 4 || size_of::<usize>() <= 4 {
            align = 4;
        } else {
            align = 8;
        }
        let aligned_start = RemotePtr::new(range.start().as_usize() & !(align - 1));
        let aligned_end = RemotePtr::new((range.end().as_usize() + (align - 1)) & !(align - 1));
        let split = split_range(&MemoryRange::from_range(aligned_start, aligned_end));
        // If the aligned range doesn't reduce register usage, use the original
        // split to avoid spurious triggerings
        if split.len() < split_ranges.len() {
            split_ranges = split;
        }
    }

    for r in &split_ranges {
        match maybe_assigned_regs {
            Some(assigned_regs) => assigned_regs.push(regs.len().try_into().unwrap()),
            _ => (),
        }
        regs.push(WatchConfig::new(r.start(), r.size(), watchtype));
    }
}

fn split_range(range: &MemoryRange) -> Vec<MemoryRange> {
    let mut result = Vec::new();
    let mut r: MemoryRange = *range;
    while r.size() > 0 {
        if (size_of::<usize>() < 8 || !try_split_unaligned_range(&mut r, 8, &mut result))
            && !try_split_unaligned_range(&mut r, 4, &mut result)
            && !try_split_unaligned_range(&mut r, 2, &mut result)
        {
            let ret = try_split_unaligned_range(&mut r, 1, &mut result);
            debug_assert!(ret);
        }
    }
    result
}

fn try_split_unaligned_range(
    range: &mut MemoryRange,
    bytes: usize,
    result: &mut Vec<MemoryRange>,
) -> bool {
    if range.start().as_usize() & (bytes - 1) != 0 || range.size() < bytes {
        return false;
    }

    result.push(MemoryRange::new_range(range.start(), bytes));
    range.start_ = range.start() + bytes;
    true
}

fn stringify_flags(flags: MappingFlags) -> &'static str {
    if flags.is_empty() {
        return "";
    }

    if flags.contains(MappingFlags::IS_SYSCALLBUF) {
        return " [syscallbuf]";
    }

    if flags.contains(MappingFlags::IS_THREAD_LOCALS) {
        return " [thread_locals]";
    }

    if flags.contains(MappingFlags::IS_PATCH_STUBS) {
        return " [patch_stubs]";
    }

    return "[unknown_flags]";
}

fn exit_ip_from_index(i: usize) -> RemoteCodePtr {
    RemoteCodePtr::from_val(
        RD_PAGE_ADDR + RD_PAGE_SYSCALL_STUB_SIZE * i + RD_PAGE_SYSCALL_INSTRUCTION_END,
    )
}

fn entry_ip_from_index(i: usize) -> RemoteCodePtr {
    RemoteCodePtr::from_val(RD_PAGE_ADDR + RD_PAGE_SYSCALL_STUB_SIZE * i)
}

fn assert_coalesceable(t: &dyn Task, lower: &Mapping, higher: &Mapping) {
    // @TODO check the equality check.
    let emu_file_comparison = match lower.emu_file.clone() {
        Some(lower_emu) => match higher.emu_file.clone() {
            Some(higher_emu) => lower_emu.as_ptr() == higher_emu.as_ptr(),
            None => false,
        },
        None => higher.emu_file.is_none(),
    };
    ed_assert!(t, emu_file_comparison);
    let local_addr_comparison = match lower.local_addr {
        Some(lower_local) => match higher.local_addr {
            Some(higher_local) => {
                lower_local.as_ptr() as usize + lower.map.size() == higher_local.as_ptr() as usize
            }
            None => false,
        },
        None => higher.local_addr.is_none(),
    };
    ed_assert!(t, local_addr_comparison);
    ed_assert_eq!(t, lower.flags, higher.flags);
    ed_assert!(
        t,
        lower.monitored_shared_memory.is_none() && higher.monitored_shared_memory.is_none()
    );
}

fn is_coalescable(mleft: &Mapping, mright: &Mapping) -> bool {
    if !is_adjacent_mapping(&mleft.map, &mright.map, HandleHeap::RespectHeap, None)
        || !is_adjacent_mapping(
            &mleft.recorded_map,
            &mright.recorded_map,
            HandleHeap::RespectHeap,
            None,
        )
    {
        return false;
    }

    return mleft.flags == mright.flags;
}

/// Return true iff `mleft` and `mright` are located adjacently in memory
/// with the same metadata, and map adjacent locations of the same
/// underlying (real) device.
fn is_adjacent_mapping(
    mleft: &KernelMapping,
    mright: &KernelMapping,
    handle_heap: HandleHeap,
    maybe_flags_to_check: Option<MapFlags>,
) -> bool {
    if mleft.end() != mright.start() {
        return false;
    }

    let flags_to_check: MapFlags = maybe_flags_to_check.unwrap_or(MapFlags::all());
    if ((mleft.flags() ^ mright.flags()) & flags_to_check != MapFlags::empty())
        || mleft.prot() != mright.prot()
    {
        return false;
    }
    if !normalized_file_names_equal(mleft, mright, handle_heap) {
        return false;
    }
    if mleft.device() != mright.device() || mleft.inode() != mright.inode() {
        return false;
    }
    if mleft.is_real_device()
        && mleft.file_offset_bytes() + mleft.size() as u64 != mright.file_offset_bytes()
    {
        return false;
    }

    return true;
}

fn normalized_file_names_equal(
    km1: &KernelMapping,
    km2: &KernelMapping,
    handle_heap: HandleHeap,
) -> bool {
    if km1.is_stack() || km2.is_stack() {
        // The kernel seems to use "[stack:<tid>]" for any mapping area containing
        // thread `tid`'s stack pointer. When the thread exits, the next read of
        // the maps doesn't treat the area as stack at all. We don't want to track
        // thread exits, so if one of the mappings is a stack, skip the name
        // comparison. Device and inode numbers will still be checked.
        return true;
    }
    if handle_heap == HandleHeap::TreatHeapAsAnonymous && (km1.is_heap() || km2.is_heap()) {
        // The kernel's heuristics for treating an anonymous mapping as "[heap]"
        // are obscure. Just skip the name check. Device and inode numbers will
        // still be checked.
        return true;
    }
    // We don't track when a file gets deleted, so it's possible for the kernel
    // to have " (deleted)" when we don't.
    strip_deleted(km1.fsname()) == strip_deleted(km2.fsname())
}

fn strip_deleted(s: &OsStr) -> &OsStr {
    let maybe_loc = find(s.as_bytes(), b" (deleted)");
    match maybe_loc {
        Some(loc) => OsStr::from_bytes(&s.as_bytes()[0..loc]),
        None => s,
    }
}

fn remove_range(ranges: &mut BTreeSet<MemoryRange>, range: MemoryRange) {
    while let Some(matched_range) = ranges.get(&range).map(|r| *r) {
        // Must remove first before we add because of possible overlaps
        ranges.remove(&matched_range);

        if matched_range.start() < range.start() {
            ranges.insert(MemoryRange::from_range(
                matched_range.start(),
                range.start(),
            ));
        }
        if range.end() < matched_range.end() {
            ranges.insert(MemoryRange::from_range(range.end(), matched_range.end()));
        }
    }
}

fn add_range(ranges: &mut BTreeSet<MemoryRange>, range: MemoryRange) {
    // Remove overlapping ranges
    remove_range(ranges, range);
    ranges.insert(range);
    // We could coalesce adjacent ranges, but there's probably no need.
}

/// We do not allow a watchpoint to watch the last byte of memory addressable
/// by rd. This avoids constructing a MemoryRange that wraps around.
/// For 64-bit builds this is no problem because addresses at the top of memory
/// are in kernel space. For 32-bit builds it seems impossible to map the last
/// page of memory in Linux so we should be OK there too.
/// Note that zero-length watchpoints are OK. configure_watch_registers just
/// ignores them.
fn range_for_watchpoint(addr: RemotePtr<Void>, num_bytes: usize) -> MemoryRange {
    let p = addr.as_usize();
    let max_len = std::usize::MAX - p;
    MemoryRange::new_range(addr, min(num_bytes, max_len))
}

fn find_rd_page_file(t: &dyn Task) -> OsString {
    let mut path: Vec<u8> = Vec::from(resource_path().as_bytes());
    path.extend_from_slice(b"share/rd/rd_page_");
    match t.arch() {
        SupportedArch::X86 => path.extend_from_slice(b"32"),
        SupportedArch::X64 => path.extend_from_slice(b"64"),
    }
    if !t.session().is_recording() {
        path.extend_from_slice(b"_replay");
    }

    OsString::from_vec(path)
}

fn read_all(t: &dyn Task, fd: &ScopedFd) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    let mut result = Vec::<u8>::new();
    loop {
        let ret = read(fd.as_raw(), &mut buf);
        match ret {
            Ok(0) => {
                return result;
            }
            Ok(nread) => {
                result.extend_from_slice(&buf[0..nread]);
            }
            Err(e) => ed_assert!(t, false, "Error in performing read from fd {}: {:?}", fd, e),
        }
    }
}

/// Returns true if a task in t's task-group other than t is doing an exec.
fn thread_group_in_exec(t: &dyn Task) -> bool {
    if !t.session().is_recording() {
        return false;
    }

    for tt in t.thread_group().task_set().iter_except(t.weak_self_ptr()) {
        let rf = tt.borrow();
        let rt = rf.as_record_task().unwrap();
        let ev: &Event = rt.ev();
        if ev.is_syscall_event()
            && is_execve_syscall(ev.syscall_event().number, ev.syscall_event().arch())
        {
            return true;
        }
    }

    false
}

fn check_device(km: &KernelMapping) -> dev_t {
    let maybe_first = km.fsname().as_bytes().get(0);
    match maybe_first {
        Some(c) if *c != b'/' => km.device(),
        _ => {
            // btrfs files can return the wrong device number in /proc/<pid>/maps
            let ret = stat(km.fsname());
            match ret {
                Ok(st) => st.st_dev,
                Err(_) => km.device(),
            }
        }
    }
}

fn could_be_stack(km: &KernelMapping) -> bool {
    // On 4.1.6-200.fc22.x86_64 we observe that during exec of the rr_exec_stub
    // during replay, when the process switches from 32-bit to 64-bit, the 64-bit
    // registers seem truncated to 32 bits during the initial PTRACE_GETREGS so
    // our sp looks wrong and /proc/<pid>/maps doesn't identify the region as
    // stack.
    // On stub execs there should only be one read-writable memory area anyway.
    km.prot() == (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
        && km.fsname() == ""
        && km.device() == KernelMapping::NO_DEVICE
        && km.inode() == KernelMapping::NO_INODE
}

/// If `left_m` and `right_m` are adjacent (see
/// `is_adjacent_mapping()`), write a merged segment descriptor to
/// `*left_m` and return true.  Otherwise return false.
fn try_merge_adjacent(left_m: &mut KernelMapping, right_m: &KernelMapping) -> bool {
    if is_adjacent_mapping(
        left_m,
        right_m,
        HandleHeap::TreatHeapAsAnonymous,
        Some(KernelMapping::CHECKABLE_FLAGS_MASK),
    ) {
        *left_m = KernelMapping::new_with_opts(
            left_m.start(),
            right_m.end(),
            left_m.fsname(),
            left_m.device(),
            left_m.inode(),
            right_m.prot(),
            right_m.flags(),
            left_m.file_offset_bytes(),
        );
        return true;
    }

    false
}

fn assert_segments_match(t: &dyn Task, m: &KernelMapping, km: &KernelMapping) {
    let mut err: &'static str = "";
    if m.start() != km.start() {
        err = "starts differ";
    } else if m.end() != km.end() {
        err = "ends differ";
    } else if m.prot() != km.prot() {
        err = "prots differ";
    } else if (m.flags() ^ km.flags()) & KernelMapping::CHECKABLE_FLAGS_MASK != MapFlags::empty() {
        err = "flags differ";
    } else if !normalized_file_names_equal(m, km, HandleHeap::TreatHeapAsAnonymous)
        && !(km.is_heap() && m.fsname().is_empty())
        && !(m.is_heap() && km.fsname().is_empty())
        && !km.is_vdso()
    {
        // Due to emulated exec, the kernel may identify any of our anonymous maps
        // as [heap] (or not).
        // Kernels before 3.16 have a bug where any mapping at the original VDSO
        // address is marked [vdso] even if the VDSO was unmapped and replaced by
        // something else, so if the kernel reports [vdso] it may be spurious and
        // we skip this check. See kernel commit
        // a62c34bd2a8a3f159945becd57401e478818d51c.
        err = "filenames differ";
    } else if normalized_device_number(m) != normalized_device_number(km) {
        err = "devices_differ";
    } else if m.inode() != km.inode() {
        err = "inodes differ";
    }
    if err.len() > 0 {
        log!(
            LogError,
            "cached mmap:\n{}\n/proc/{}/maps:\n{}\n",
            t.vm().dump(),
            t.tid,
            AddressSpace::dump_process_maps(t)
        );
        ed_assert!(t, false, "\nCached mapping {} should be {}; {}", m, km, err);
    }
}

fn normalized_device_number(m: &KernelMapping) -> dev_t {
    let maybe_first = m.fsname().as_bytes().get(0);
    match maybe_first {
        Some(c) if *c != b'/' => m.device(),
        _ => {
            // btrfs files can report the wrong device number in /proc/<pid>/maps, so
            // restrict ourselves to checking whether the device number is != 0
            if m.device() != KernelMapping::NO_DEVICE {
                // Find a better way to return an "out of band" value like -1.
                -1i64 as dev_t
            } else {
                m.device()
            }
        }
    }
}

pub fn read_kernel_mapping(tid: pid_t, addr: RemotePtr<Void>) -> KernelMapping {
    let range = MemoryRange::new_range(addr, 1);
    let iter = KernelMapIterator::new_from_tid(tid);
    for km in iter {
        if km.contains(&range) {
            return km;
        }
    }

    // Assume this method always is able to find the mapping
    panic!("Unable to find any mapping at {:#x}", addr.as_usize());
}

/// Just a place that rd's AutoSyscall functionality can use as a syscall
/// instruction in rd's address space for use before we have exec'd.
#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub extern "C" fn rd_syscall_addr() {
    unsafe {
        llvm_asm!("syscall" :::: "volatile");
        llvm_asm!("nop" :::: "volatile");
        llvm_asm!("nop" :::: "volatile");
        llvm_asm!("nop" :::: "volatile");
    }
}

#[no_mangle]
#[cfg(target_arch = "x86")]
pub extern "C" fn rd_syscall_addr() {
    unsafe {
        llvm_asm!("int $$0x80" :::: "volatile");
        llvm_asm!("nop" :::: "volatile");
        llvm_asm!("nop" :::: "volatile");
        llvm_asm!("nop" :::: "volatile");
    }
}

/// DIFF NOTE: n is signed in rr
const fn dr_watchpoint(n: u32) -> u32 {
    return 1u32 << n;
}

/// DIFF NOTE: regs is an signed i.e. i8 array in rr
fn watchpoint_triggered(debug_status: usize, regs: &[u8]) -> bool {
    for reg in regs {
        // @TODO Will these casts cause any problems?
        let w = dr_watchpoint(*reg as u32) as usize;
        if debug_status & w == w {
            return true;
        }
    }
    false
}
