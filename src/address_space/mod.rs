pub mod kernel_mapping;
pub mod memory_range;
use crate::address_space::memory_range::MemoryRange;
use crate::kernel_abi::common::preload_interface::{
    RD_PAGE_ADDR, RD_PAGE_SYSCALL_INSTRUCTION_END, RD_PAGE_SYSCALL_STUB_SIZE,
};
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::RemotePtr;
use crate::remote_ptr::Void;
use nix::sys::mman::{MapFlags, ProtFlags};
use std::convert::TryInto;
use std::mem::size_of;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum BreakpointType {
    BkptNone = 0,
    /// Trap for internal rr purposes, f.e. replaying async
    /// signals.
    BkptInternal = 1,
    /// Trap on behalf of a debugger user.
    BkptUser = 2,
}

/// NB: these random-looking enumeration values are chosen to
/// match the numbers programmed into x86 debug registers.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum WatchType {
    WatchExec = 0x00,
    WatchWrite = 0x01,
    WatchReadWrite = 0x03,
}

#[derive(Copy, Clone, Eq, PartialEq)]
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
    Unpriviledged,
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Enabled {
    RecordingOnly,
    ReplayOnly,
    RecordingAndReplay,
}

/// Must match generate_rr_page.py
const ENTRY_POINTS: [SyscallType; 8] = [
    SyscallType::new(
        Traced::Traced,
        Privileged::Unpriviledged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Traced,
        Privileged::Privileged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Unpriviledged,
        Enabled::RecordingAndReplay,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Unpriviledged,
        Enabled::ReplayOnly,
    ),
    SyscallType::new(
        Traced::Untraced,
        Privileged::Unpriviledged,
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
    traced: Traced,
    privileged: Privileged,
    enabled: Enabled,
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
#[derive(Copy, Clone)]
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
    use crate::address_space::kernel_mapping::KernelMapping;
    use crate::address_space::memory_range::{MemoryRange, MemoryRangeKey};
    use crate::address_space::BreakpointType::BkptNone;
    use crate::address_space::MappingFlags;
    use crate::auto_remote_syscalls::AutoRemoteSyscalls;
    use crate::emu_fs::EmuFileSharedPtr;
    use crate::kernel_abi::common::preload_interface::{PRELOAD_THREAD_LOCALS_SIZE, RD_PAGE_ADDR};
    use crate::kernel_abi::{syscall_instruction, SupportedArch};
    use crate::log::LogLevel::LogDebug;
    use crate::monitored_shared_memory::MonitoredSharedMemorySharedPtr;
    use crate::monkey_patcher::MonkeyPatcher;
    use crate::property_table::PropertyTable;
    use crate::remote_code_ptr::RemoteCodePtr;
    use crate::remote_ptr::RemotePtr;
    use crate::scoped_fd::ScopedFd;
    use crate::session::session_inner::session_inner::SessionInner;
    use crate::session::{SessionSharedPtr, SessionSharedWeakPtr};
    use crate::task::common::{read_mem, read_val_mem, write_val_mem, write_val_mem_with_flags};
    use crate::task::record_task::record_task::RecordTask;
    use crate::task::task_inner::task_inner::WriteFlags;
    use crate::task::{Task, TaskSharedPtr};
    use crate::task_set::TaskSet;
    use crate::taskish_uid::AddressSpaceUid;
    use crate::taskish_uid::TaskUid;
    use crate::trace_frame::FrameTime;
    use crate::util::{ceil_page_size, floor_page_size};
    use core::ffi::c_void;
    use libc::stat;
    use libc::{dev_t, ino_t, pid_t};
    use nix::sys::mman::munmap;
    use std::cell::{Ref, RefCell, RefMut};
    use std::cmp::min;
    use std::collections::btree_map::{Range, RangeMut};
    use std::collections::hash_map::Iter as HashMapIter;
    use std::collections::HashSet;
    use std::collections::{BTreeMap, HashMap};
    use std::io;
    use std::io::Write;
    use std::ops::Bound::{Included, Unbounded};
    use std::ops::Drop;
    use std::ops::{Deref, DerefMut};
    use std::rc::{Rc, Weak};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn find_offset_of_syscall_instruction_in(arch: SupportedArch, vdso: &[u8]) -> Option<usize> {
        let instruction = syscall_instruction(arch);
        let instruction_size = instruction.len();
        let limit = vdso.len() - instruction.len();
        for i in 1..limit {
            if vdso.get(i..i + instruction_size).unwrap() == instruction {
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
        pub local_addr: Option<*mut c_void>,
        /// Multiple Mapping-s might point to the same MonitoredSharedMemory object.
        pub monitored_shared_memory: Option<MonitoredSharedMemorySharedPtr>,
        /// Flags indicate mappings that require special handling. Adjacent mappings
        /// may only be merged if their `flags` value agree.
        pub flags: MappingFlags,
    }

    impl Mapping {
        pub fn new(
            map: &KernelMapping,
            recorded_map: &KernelMapping,
            emu_file: Option<EmuFileSharedPtr>,
            mapped_file_stat: Option<stat>,
            local_addr: Option<*mut c_void>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> Mapping {
            Mapping {
                map: map.clone(),
                recorded_map: recorded_map.clone(),
                emu_file,
                mapped_file_stat,
                local_addr,
                monitored_shared_memory: monitored,
                flags: MappingFlags::empty(),
            }
        }
    }

    pub type MemoryMap = BTreeMap<MemoryRangeKey, Mapping>;

    pub type AddressSpaceSharedPtr = Rc<RefCell<AddressSpace>>;
    pub type AddressSpaceSharedWeakPtr = Weak<RefCell<AddressSpace>>;
    pub type AddressSpaceRef<'a> = Ref<'a, AddressSpace>;
    pub type AddressSpaceRefMut<'a> = RefMut<'a, AddressSpace>;

    pub struct Maps<'a> {
        outer: &'a AddressSpace,
        range: MemoryRange,
    }

    impl<'a> Maps<'a> {
        pub fn new(outer: &'a AddressSpace, start: RemotePtr<Void>) -> Maps {
            Maps {
                outer,
                range: MemoryRange::from_range(start, start),
            }
        }

        pub fn new_from_range(outer: &'a AddressSpace, range: MemoryRange) -> Maps {
            Maps { outer, range }
        }
    }

    impl<'a> IntoIterator for Maps<'a> {
        type Item = (&'a MemoryRangeKey, &'a Mapping);
        type IntoIter = Range<'a, MemoryRangeKey, Mapping>;

        fn into_iter(self) -> Self::IntoIter {
            self.outer
                .mem
                .range((Included(MemoryRangeKey(self.range)), Unbounded))
        }
    }

    pub struct MapsMut<'a> {
        outer: &'a mut AddressSpace,
        range: MemoryRange,
    }

    impl<'a> MapsMut<'a> {
        pub fn new(outer: &'a mut AddressSpace, start: RemotePtr<Void>) -> MapsMut {
            MapsMut {
                outer,
                range: MemoryRange::from_range(start, start),
            }
        }

        pub fn new_from_range(outer: &'a mut AddressSpace, range: MemoryRange) -> MapsMut {
            MapsMut { outer, range }
        }
    }

    impl<'a> IntoIterator for MapsMut<'a> {
        type Item = (&'a MemoryRangeKey, &'a mut Mapping);
        type IntoIter = RangeMut<'a, MemoryRangeKey, Mapping>;

        fn into_iter(self) -> Self::IntoIter {
            self.outer
                .mem
                .range_mut((Included(MemoryRangeKey(self.range)), Unbounded))
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
        task_set: TaskSet,
        /// All breakpoints set in this VM.
        breakpoints: BreakpointMap,
        /// Path of the real executable image this address space was
        /// exec()'d with.
        exe: String,
        /// Pid of first task for this address space
        leader_tid_: pid_t,
        /// Serial number of first task for this address space
        leader_serial: u32,
        exec_count: u32,
        /// Only valid during recording
        brk_start: RemotePtr<Void>,
        /// Current brk. Not necessarily page-aligned.
        brk_end: RemotePtr<Void>,
        /// All segments mapped into this address space.
        mem: MemoryMap,
        /// Sizes of SYSV shm segments, by address. We use this to determine the size
        /// of memory regions unmapped via shmdt().
        shm_sizes: HashMap<RemotePtr<Void>, usize>,
        monitored_mem: HashSet<RemotePtr<Void>>,
        /// madvise DONTFORK regions
        dont_fork: HashSet<MemoryRange>,
        /// The session that created this.  We save a ref to it so that
        /// we can notify it when we die.
        /// `session_` in rr.
        session_: SessionSharedWeakPtr,
        /// tid of the task whose thread-locals are in preload_thread_locals
        thread_locals_tuid_: TaskUid,
        /// First mapped byte of the vdso.
        vdso_start_addr: RemotePtr<Void>,
        /// The monkeypatcher that's handling this address space.
        monkeypatch_state: Option<MonkeyPatcher>,
        /// The watchpoints set for tasks in this VM.  Watchpoints are
        /// programmed per Task, but we track them per address space on
        /// behalf of debuggers that assume that model.
        watchpoints: HashMap<MemoryRange, Watchpoint>,
        saved_watchpoints: Vec<HashMap<MemoryRange, Watchpoint>>,
        /// Tracee memory is read and written through this fd, which is
        /// opened for the tracee's magic /proc/[tid]/mem device.  The
        /// advantage of this over ptrace is that we can access it even
        /// when the tracee isn't at a ptrace-stop.  It's also
        /// theoretically faster for large data transfers, which rd can
        /// do often.
        ///
        /// Users of child_mem_fd should fall back to ptrace-based memory
        /// access when child_mem_fd is not open.
        child_mem_fd: ScopedFd,
        traced_syscall_ip_: RemoteCodePtr,
        privileged_traced_syscall_ip_: Option<RemoteCodePtr>,
        syscallbuf_enabled_: bool,

        saved_auxv_: Vec<u8>,

        /// The time of the first event that ran code for a task in this address space.
        /// 0 if no such event has occurred.
        /// @TODO should this be an Option?
        first_run_event_: FrameTime,
    }

    impl AddressSpace {
        /*pub fn new() -> AddressSpace<'a> {
            AddressSpace {
                task_set: TaskSet::new(),
            }
        }*/

        /// Call this after a new task has been cloned within this
        /// address space.
        pub fn after_clone(&mut self) {
            self.allocate_watchpoints();
        }

        /// Call this after a successful execve syscall has completed. At this point
        /// it is safe to perform remote syscalls.
        pub fn post_exec_syscall(&mut self, t: &mut dyn Task) {
            // First locate a syscall instruction we can use for remote syscalls.
            self.traced_syscall_ip_ = self.find_syscall_instruction(t);
            self.privileged_traced_syscall_ip_ = None;
            // Now remote syscalls work, we can open_mem_fd.
            t.open_mem_fd();

            // Set up AutoRemoteSyscalls again now that the mem-fd is open.
            let mut remote = AutoRemoteSyscalls::new(t);
            // Now we can set up the "rd page" at its fixed address. This gives
            // us traced and untraced syscall instructions at known, fixed addresses.
            self.map_rd_page(&remote);
            // Set up the preload_thread_locals shared area.
            remote.create_shared_mmap(
                PRELOAD_THREAD_LOCALS_SIZE,
                Some(Self::preload_thread_locals_start()),
                "preload_thread_locals",
                None,
                None,
                None,
            );
            let flags = self
                .mapping_flags_of_mut(Self::preload_thread_locals_start())
                .unwrap();
            *flags = *flags | MappingFlags::IS_THREAD_LOCALS;
        }

        /// Change the program data break of this address space to
        /// `addr`. Only called during recording!
        pub fn brk(&mut self, t: &dyn Task, addr: RemotePtr<Void>, prot: ProtFlags) {
            log!(LogDebug, "brk({})", addr);

            let old_brk: RemotePtr<Void> = ceil_page_size(self.brk_end);
            let new_brk: RemotePtr<Void> = ceil_page_size(addr);
            if old_brk < new_brk {
                self.map(
                    t,
                    old_brk,
                    new_brk - old_brk,
                    prot,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    0,
                    "[heap]",
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
            self.brk_end = addr;
        }

        /// This can only be called during recording.
        pub fn current_brk(&self) -> RemotePtr<Void> {
            debug_assert!(!self.brk_end.is_null());
            self.brk_end
        }

        /// Dump a representation of `self` to &mut dyn Write
        /// similar to /proc/[tid]/maps.
        pub fn dump(&self, f: &mut dyn Write) -> io::Result<()> {
            write!(f, "  (heap: {}-{})\n", self.brk_start, self.brk_end)?;
            for (_, m) in &self.mem {
                let km = &m.map;
                write!(f, "{}{}\n", km, stringify_flags(m.flags))?;
            }
            Ok(())
        }

        /// Return tid of the first task for this address space.
        pub fn leader_tid(&self) -> pid_t {
            self.leader_tid_
        }

        /// Return AddressSpaceUid for this address space.
        pub fn uid() -> AddressSpaceUid {
            unimplemented!()
        }

        pub fn session(&self) -> SessionSharedPtr {
            self.session_.upgrade().unwrap()
        }

        pub fn arch(&self) -> SupportedArch {
            // Return the arch() of the first task in the address space
            self.task_set
                .iter()
                .next()
                .unwrap()
                .upgrade()
                .unwrap()
                .borrow()
                .arch()
        }

        /// Return the path this address space was exec()'d with.
        pub fn exe_image(&self) -> &String {
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
                .get(&addr)
                .map_or(BkptNone, |bp| bp.bp_type())
        }

        /// Returns true when the breakpoint at `addr` is in private
        /// non-writeable memory. When this returns true, the breakpoint can't be
        /// overwritten by the tracee without an intervening mprotect or mmap
        /// syscall.
        pub fn is_breakpoint_in_private_read_only_memory(&self, addr: RemoteCodePtr) -> bool {
            // @TODO Its unclear why we need to iterate instead of just using
            // AddressSpace::mapping_of() to check breakpoint prot() and flags().
            for (_, m) in self.maps_containing_or_after(addr.to_data_ptr::<Void>()) {
                if m.map.start()
                    >= addr
                        .increment_by_bkpt_insn_length(self.arch())
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

        /// The buffer `dest` of length `length` represents the contents of tracee
        /// memory at `addr`. Replace the bytes in `dest` that have been overwritten
        /// by breakpoints with the original data that was replaced by the breakpoints.
        pub fn replace_breakpoints_with_original_values(
            &self,
            dest: &mut [u8],
            addr: RemotePtr<u8>,
        ) {
            unimplemented!()
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
            &mut self,
            t: &dyn Task,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            prot: ProtFlags,
            flags: MapFlags,
            offset_bytes: i64,
            fsname: &str,
            device: dev_t,
            inode: ino_t,
            mapped_file_stat: Option<Box<libc::stat>>,
            record_map: Option<&KernelMapping>,
            emu_file: Option<EmuFileSharedPtr>,
            local_addr: Option<*const c_void>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> KernelMapping {
            unimplemented!()
        }

        /// Return the mapping and mapped resource for the byte at address 'addr'.
        pub fn mapping_of(&self, addr: RemotePtr<Void>) -> Option<&Mapping> {
            // A size of 1 will allow .intersects() to become true in a containing map.
            // @TODO This floor_page_size() call does not seem necessary
            let mr = MemoryRange::new_range(floor_page_size(addr), 1);
            let maps = Maps::new_from_range(self, mr);
            match maps.into_iter().next() {
                Some((_, found_mapping)) if found_mapping.map.contains_ptr(addr) => {
                    Some(found_mapping)
                }
                _ => None,
            }
        }

        pub fn mapping_of_mut(&mut self, addr: RemotePtr<Void>) -> Option<&mut Mapping> {
            // A size of 1 will allow .intersects() to become true in a containing map.
            // @TODO This floor_page_size() call does not seem necessary
            let mr = MemoryRange::new_range(floor_page_size(addr), 1);
            let maps = MapsMut::new_from_range(self, mr);
            match maps.into_iter().next() {
                Some((_, found_mapping)) if found_mapping.map.contains_ptr(addr) => {
                    Some(found_mapping)
                }
                _ => None,
            }
        }

        /// Detach local mapping and return it.
        pub fn detach_local_mapping(&mut self, addr: RemotePtr<Void>) -> Option<*mut c_void> {
            match self.mapping_of_mut(addr) {
                Some(found_mapping) if found_mapping.local_addr.is_some() => {
                    found_mapping.local_addr.take()
                }
                _ => None,
            }
        }

        /// Return a reference to the flags of the mapping at this address, allowing
        /// manipulation.
        pub fn mapping_flags_of_mut(&mut self, addr: RemotePtr<Void>) -> Option<&mut MappingFlags> {
            self.mapping_of_mut(addr).map(|m| &mut m.flags)
        }

        /// If the given memory region is mapped into the local address space, obtain
        /// the local address from which the `size` bytes at `addr` can be accessed.
        pub fn local_mapping_mut(&self, addr: RemotePtr<Void>, size: usize) -> Option<&mut [u8]> {
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
                            found_local_addr.cast::<u8>().add(offset),
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
        pub fn local_mapping(&self, addr: RemotePtr<Void>, size: usize) -> Option<&[u8]> {
            self.local_mapping_mut(addr, size).map(|data| &*data)
        }

        /// Return true if the rd page is mapped at its expected address.
        pub fn has_rd_page(&self) -> bool {
            let found_mapping = self.mapping_of(RD_PAGE_ADDR.into());
            found_mapping.is_some()
        }

        pub fn maps(&self) -> Maps {
            Maps::new(self, RemotePtr::new())
        }
        pub fn maps_starting_at(&self, start: RemotePtr<Void>) -> Maps {
            Maps::new(self, start)
        }
        pub fn maps_containing_or_after(&self, start: RemotePtr<Void>) -> Maps {
            match self.mapping_of(start) {
                Some(found) => Maps::new(self, found.map.start()),
                None => Maps::new(self, start),
            }
        }

        pub fn monitored_addrs(&self) -> &HashSet<RemotePtr<Void>> {
            &self.monitored_mem
        }

        /// Change the protection bits of [addr, addr + num_bytes) to
        /// `prot`.
        pub fn protect(
            &mut self,
            t: &dyn Task,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            prot: ProtFlags,
        ) {
            log!(LogDebug, "mprotect({}, {}, {:?})", addr, num_bytes, prot);

            let mut last_overlap: MemoryRange = MemoryRange::new();
            let protector = |slf: &mut Self, m_key: MemoryRangeKey, rem: MemoryRange| {
                // Important !
                let m = slf.mem.get(&m_key).unwrap().clone();
                log!(LogDebug, "  protecting ({}) ...", rem);

                slf.remove_from_map(&m.map);

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
                        &m.map.subrange(m.map.start(), rem.start()),
                        &m.recorded_map.subrange(m.recorded_map.start(), rem.start()),
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
                let new_local_addr = m
                    .local_addr
                    .map(|addr| unsafe { addr.add(new_start - m.map.start()) });

                let new_monitored = m.monitored_shared_memory.clone().map(|r| {
                    r.borrow()
                        .subrange(new_start - m.map.start(), new_end - new_start)
                });

                let mut overlap = Mapping::new(
                    &m.map.subrange(new_start, new_end).set_prot(new_prot),
                    &m.recorded_map
                        .subrange(new_start, new_end)
                        .set_prot(new_prot),
                    m.emu_file.clone(),
                    m.mapped_file_stat.clone(),
                    new_local_addr,
                    new_monitored,
                );
                overlap.flags = m.flags;
                last_overlap = *overlap.map;
                slf.add_to_map(overlap);

                // If the last segment we protect overflows the
                // region, remap the overflow region with previous
                // prot.
                if rem.end() < m.map.end() {
                    let new_local = m
                        .local_addr
                        .map(|addr| unsafe { addr.add(rem.end() - m.map.start()) });

                    let new_monitored = m.monitored_shared_memory.clone().map(|r| {
                        r.borrow()
                            .subrange(rem.end() - m.map.start(), m.map.end() - rem.end())
                    });
                    let mut overflow = Mapping::new(
                        &m.map.subrange(rem.end(), m.map.end()),
                        &m.recorded_map.subrange(rem.end(), m.map.end()),
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
            if last_overlap.size() > 0 {
                // All mappings that we altered which might need coalescing
                // are adjacent to |last_overlap|.
                self.coalesce_around(t, &Maps::new_from_range(self, last_overlap));
            }
        }

        /// Fix up mprotect registers parameters to take account of PROT_GROWSDOWN.
        pub fn fixup_mprotect_growsdown_parameters(&self, t: &dyn Task) {
            unimplemented!()
        }

        /// Move the mapping [old_addr, old_addr + old_num_bytes) to
        /// [new_addr, old_addr + new_num_bytes), preserving metadata.
        pub fn remap(
            &self,
            t: &dyn Task,
            old_addr: RemotePtr<Void>,
            old_num_bytes: usize,
            new_addr: RemotePtr<Void>,
            new_num_bytes: usize,
        ) {
            unimplemented!()
        }

        /// Notify that data was written to this address space by rr or
        /// by the kernel.
        /// `flags` can contain values from Task::WriteFlags.
        pub fn notify_written(
            &mut self,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            flags: WriteFlags,
        ) {
            if !(flags.contains(WriteFlags::IS_BREAKPOINT_RELATED)) {
                self.update_watchpoint_values(addr, addr + num_bytes);
            }
            self.session()
                .borrow_mut()
                .accumulate_bytes_written(num_bytes as u64);
        }

        /// Assumes any weak pointer can be upgraded but does not assume task_set is NOT empty.
        pub fn any_task_from_task_set(&self) -> Option<TaskSharedPtr> {
            self.task_set()
                .iter()
                .next()
                .map_or(None, |v| Some(v.upgrade().unwrap()))
        }

        /// Ensure a breakpoint of `type` is set at `addr`.
        pub fn add_breakpoint(&mut self, addr: RemoteCodePtr, type_: BreakpointType) -> bool {
            match self.breakpoints.get_mut(&addr) {
                None => {
                    let overwritten_data: u8 = 0;
                    // Grab a random task from the VM so we can use its
                    // read/write_mem() helpers.
                    let rc_t = self.any_task_from_task_set().unwrap();
                    let read_result = rc_t.borrow_mut().read_bytes_fallible(
                        addr.to_data_ptr::<u8>(),
                        &mut overwritten_data.to_le_bytes(),
                    );
                    match read_result {
                        Ok(read) if read == size_of::<u8>() => (),
                        _ => return false,
                    }

                    write_val_mem_with_flags::<u8>(
                        rc_t.borrow_mut().as_mut(),
                        addr.to_data_ptr::<u8>(),
                        &Self::BREAKPOINT_INSN,
                        None,
                        WriteFlags::IS_BREAKPOINT_RELATED,
                    );

                    let bp = Breakpoint::new(overwritten_data);
                    self.breakpoints.insert(addr, bp);
                }
                Some(bp) => {
                    bp.do_ref(type_);
                }
            }
            true
        }

        /// Remove a `type` reference to the breakpoint at `addr`.  If
        /// the removed reference was the last, the breakpoint is
        /// destroyed.
        pub fn remove_breakpoint(&mut self, addr: RemoteCodePtr, type_: BreakpointType) {
            match self.breakpoints.get_mut(&addr) {
                Some(bp) => {
                    if bp.do_unref(type_) == 0 {
                        self.destroy_breakpoint_at(addr);
                    }
                }
                _ => (),
            }
        }
        /// Destroy all breakpoints in this VM, regardless of their
        /// reference counts.
        pub fn remove_all_breakpoints(&mut self) {
            let mut bps_to_destroy = Vec::new();
            for bp in self.breakpoints.keys() {
                bps_to_destroy.push(*bp);
            }

            for bp in bps_to_destroy {
                self.destroy_breakpoint_at(bp)
            }
        }

        /// Temporarily remove the breakpoint at `addr`.
        pub fn suspend_breakpoint_at(&self, addr: RemoteCodePtr) {
            match self.breakpoints.get(&addr) {
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
            match self.breakpoints.get(&addr) {
                Some(bp) => {
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
        pub fn add_watchpoint(
            &self,
            addr: RemotePtr<Void>,
            num_bytes: usize,
            type_: WatchType,
        ) -> bool {
            unimplemented!()
        }
        pub fn remove_watchpoint(&self, addr: RemotePtr<Void>, num_bytes: usize, type_: WatchType) {
            unimplemented!()
        }
        pub fn remove_all_watchpoints(&mut self) {
            self.watchpoints.clear();
            self.allocate_watchpoints();
        }
        pub fn all_watchpoints(&self) -> Vec<WatchConfig> {
            unimplemented!()
        }

        /// Save all watchpoint state onto a stack.
        pub fn save_watchpoints() {
            unimplemented!()
        }
        /// Pop all watchpoint state from the saved-state stack.
        pub fn restore_watchpoints() -> bool {
            unimplemented!()
        }

        /// Notify that at least one watchpoint was hit --- recheck them all.
        /// Returns true if any watchpoint actually triggered. Note that
        /// debug_status can indicate a hit watchpoint that doesn't actually
        /// trigger, because the value of a write-watchpoint did not change.
        /// Likewise, debug_status can indicate a watchpoint wasn't hit that
        /// actually was (because in some configurations, e.g. VMWare
        /// hypervisor with 32-bit x86 guest, debug_status watchpoint bits
        /// are known to not be set on singlestep).
        /// @TODO debug_status param type
        pub fn notify_watchpoint_fired(
            &self,
            debug_status: usize,
            address_of_singlestep_start: RemoteCodePtr,
        ) -> bool {
            unimplemented!()
        }

        /// Return true if any watchpoint has fired. Will keep returning true until
        /// consume_watchpoint_changes() is called.
        pub fn has_any_watchpoint_changes(&self) -> bool {
            unimplemented!()
        }

        /// Return true if an EXEC watchpoint has fired at addr since the last
        /// consume_watchpoint_changes.
        pub fn has_exec_watchpoint_fired(&self, addr: RemoteCodePtr) {
            unimplemented!()
        }

        /// Return all changed watchpoints in `watches` and clear their changed flags.
        pub fn consume_watchpoint_changes(&self) -> Vec<WatchConfig> {
            unimplemented!()
        }

        pub fn set_shm_size(&self, addr: RemotePtr<Void>, bytes: usize) {
            unimplemented!()
        }

        /// Dies if no shm size is registered for the address.
        pub fn get_shm_size(&self, addr: RemotePtr<Void>) -> usize {
            *self.shm_sizes.get(&addr).unwrap()
        }
        /// Returns true it the key was present in the map
        pub fn remove_shm_size(&mut self, addr: RemotePtr<Void>) -> bool {
            self.shm_sizes.remove(&addr).is_some()
        }

        /// Make [addr, addr + num_bytes) inaccessible within this
        /// address space.
        pub fn unmap(&self, t: &dyn Task, addr: RemotePtr<Void>, snum_bytes: usize) {
            unimplemented!()
        }

        /// Notification of madvise call.
        pub fn advise(&self, t: &dyn Task, addr: RemotePtr<Void>, num_bytes: usize, advice: i32) {
            unimplemented!()
        }

        /// Return the vdso mapping of this.
        ///
        /// Panics if there is no Mapping of the vdso
        pub fn vdso(&self) -> KernelMapping {
            debug_assert!(!self.vdso_start_addr.is_null());
            self.mapping_of(self.vdso_start_addr).unwrap().map.clone()
        }

        /// Verify that this cached address space matches what the
        /// kernel thinks it should be.
        pub fn verify(&self, t: &dyn Task) {
            unimplemented!()
        }

        pub fn has_breakpoints(&self) -> bool {
            !self.breakpoints.is_empty()
        }
        pub fn has_watchpoints(&self) -> bool {
            !self.watchpoints.is_empty()
        }

        /// Encoding of the `int $3` instruction.
        pub const BREAKPOINT_INSN: u8 = 0xCC;

        pub fn mem_fd(&self) -> &ScopedFd {
            &self.child_mem_fd
        }
        pub fn mem_fd_mut(&mut self) -> &mut ScopedFd {
            &mut self.child_mem_fd
        }
        pub fn set_mem_fd(&mut self, fd: ScopedFd) {
            self.child_mem_fd = fd;
        }

        pub fn monkeypatcher(&self) -> &MonkeyPatcher {
            unimplemented!()
        }

        pub fn at_preload_init(&self, t: &dyn Task) {
            unimplemented!()
        }

        /// The address of the syscall instruction from which traced syscalls made by
        /// the syscallbuf will originate.
        pub fn traced_syscall_ip(&self) -> RemoteCodePtr {
            self.traced_syscall_ip_
        }

        /// The address of the syscall instruction from which privileged traced
        /// syscalls made by the syscallbuf will originate.
        pub fn privileged_traced_syscall_ip(&self) -> Option<RemoteCodePtr> {
            self.privileged_traced_syscall_ip_
        }

        pub fn syscallbuf_enabled(&self) -> bool {
            self.syscallbuf_enabled_
        }

        /// We'll map a page of memory here into every exec'ed process for our own
        /// use.
        pub fn rd_page_start() -> RemotePtr<Void> {
            RemotePtr::<Void>::new_from_val(RD_PAGE_ADDR)
        }

        /// This might not be the length of an actual system page, but we allocate
        /// at least this much space.
        pub fn rd_page_size() -> u32 {
            4096
        }
        pub fn rd_page_end() -> RemotePtr<Void> {
            unimplemented!()
        }

        pub fn preload_thread_locals_start() -> RemotePtr<Void> {
            Self::rd_page_start()
        }
        pub fn preload_thread_locals_size() -> usize {
            PRELOAD_THREAD_LOCALS_SIZE
        }

        pub fn rd_page_syscall_exit_point(
            traced: Traced,
            privileged: Privileged,
            enabled: Enabled,
        ) -> RemoteCodePtr {
            unimplemented!()
        }
        pub fn rd_page_syscall_entry_point(
            traced: Traced,
            privileged: Privileged,
            enabled: Enabled,
            arch: SupportedArch,
        ) -> RemoteCodePtr {
            for (i, e) in ENTRY_POINTS.iter().enumerate() {
                if e.traced == traced && e.privileged == privileged && e.enabled == enabled {
                    return entry_ip_from_index(i);
                }
            }

            unreachable!()
        }

        /// @TODO what about just returning &'static ENTRY_POINTS?
        pub fn rd_page_syscalls() -> Vec<SyscallType> {
            ENTRY_POINTS.to_vec()
        }

        pub fn rd_page_syscall_from_exit_point(ip: RemoteCodePtr) -> SyscallType {
            for i in 0..ENTRY_POINTS.len() {
                if exit_ip_from_index(i) == ip {
                    return ENTRY_POINTS[i];
                }
            }

            unreachable!()
        }

        pub fn rd_page_syscall_from_entry_point(ip: RemoteCodePtr) -> SyscallType {
            for i in 0..ENTRY_POINTS.len() {
                if entry_ip_from_index(i) == ip {
                    return ENTRY_POINTS[i];
                }
            }

            unreachable!()
        }

        /// Return a pointer to 8 bytes of 0xFF
        pub fn rd_page_ff_bytes() -> RemotePtr<u8> {
            unimplemented!()
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
                ed_assert!(
                    t,
                    maybe_offset.is_some(),
                    "No syscall instruction found in VDSO"
                );
                offset = maybe_offset.unwrap();
                assert!(offset != 0);
                match arch {
                    SupportedArch::X86 => OFFSET_TO_SYSCALL_IN_X86.store(offset, Ordering::SeqCst),
                    SupportedArch::X64 => OFFSET_TO_SYSCALL_IN_X64.store(offset, Ordering::SeqCst),
                };
            }

            RemoteCodePtr::from_val(self.vdso().start().as_usize() + offset)
        }

        /// Task `t` just forked from this address space. Apply dont_fork settings.
        pub fn did_fork_into(t: &dyn Task) {
            unimplemented!()
        }

        pub fn set_first_run_event(event: FrameTime) {
            unimplemented!()
        }
        pub fn first_run_event() -> FrameTime {
            unimplemented!()
        }

        pub fn saved_auxv(&self) -> &[u8] {
            unimplemented!()
        }
        pub fn save_auxv(t: &dyn Task) {
            unimplemented!()
        }

        /// Reads the /proc/<pid>/maps entry for a specific address. Does no caching.
        /// If performed on a file in a btrfs file system, this may return the
        /// wrong device number! If you stick to anonymous or special file
        /// mappings, this should be OK.
        pub fn read_kernel_mapping(t: &dyn Task, addr: RemotePtr<Void>) -> KernelMapping {
            unimplemented!()
        }

        /// Same as read_kernel_mapping, but reads rd's own memory map.
        pub fn read_local_kernel_mapping(addr: *const u8) -> KernelMapping {
            unimplemented!()
        }

        pub fn chaos_mode_min_stack_size() -> u32 {
            8 * 1024 * 1024
        }

        pub fn chaos_mode_find_free_memory(t: &RecordTask, len: usize) -> RemotePtr<Void> {
            unimplemented!()
        }
        pub fn find_free_memory(len: usize, after: Option<RemotePtr<Void>>) -> RemotePtr<Void> {
            unimplemented!()
        }

        pub fn properties(&self) -> &PropertyTable {
            unimplemented!()
        }

        /// The return value indicates whether we (re)created the preload_thread_locals
        /// area.
        pub fn post_vm_clone(t: &dyn Task) {
            unimplemented!()
        }

        /// TaskUid for the task whose locals are stored in the preload_thread_locals
        /// area.
        pub fn thread_locals_tuid(&self) -> &TaskUid {
            unimplemented!()
        }
        pub fn set_thread_locals_tuid(&mut self, tuid: &TaskUid) {
            unimplemented!()
        }

        /// Call this when the memory at [addr,addr+len) was externally overwritten.
        /// This will attempt to update any breakpoints that may be set within the
        /// range (resetting them and storing the new value).
        pub fn maybe_update_breakpoints(t: &dyn Task, addr: RemotePtr<u8>, len: usize) {
            unimplemented!()
        }

        /// Call this to ensure that the mappings in `range` during replay has the same length
        /// is collapsed to a single mapping. The caller guarantees that all the
        /// mappings in the range can be coalesced (because they corresponded to a single
        /// mapping during recording).
        /// The end of the range might be in the middle of a mapping.
        /// The start of the range might also be in the middle of a mapping.
        pub fn ensure_replay_matches_single_recorded_mapping(t: &dyn Task, range: MemoryRange) {
            unimplemented!()
        }

        /// Print process maps.
        pub fn print_process_maps(t: &dyn Task) {
            unimplemented!()
        }

        /// Called after a successful execve to set up the new AddressSpace.
        /// Also called once for the initial spawn.
        fn new_after_execve(t: &dyn Task, exe: &str, exec_count: u32) -> AddressSpace {
            unimplemented!()
        }

        /// Called when an AddressSpace is cloned due to a fork() or a Session
        /// clone. After this, and the task is properly set up, post_vm_clone will
        /// be called.
        fn new_after_fork_or_session_clone(
            session: &SessionInner,
            o: &AddressSpace,
            leader_tid: pid_t,
            leader_serial: u32,
            exec_count: u32,
        ) -> AddressSpace {
            unimplemented!()
        }

        /// After an exec, populate the new address space of `t` with
        /// the existing mappings we find in /proc/maps.
        fn populate_address_space(&mut self, t: &dyn Task) {
            unimplemented!()
        }

        /// @TODO In rr `num_bytes` is signed. Why?
        fn unmap_internal(&mut self, t: &dyn Task, addr: RemotePtr<Void>, num_bytes: usize) {
            log!(LogDebug, "munmap({}, {}), ", addr, num_bytes);

            let unmapper = |slf: &mut Self, m_key: MemoryRangeKey, rem: MemoryRange| {
                log!(LogDebug, "  unmapping ({}) ...", rem);

                let m = slf.mem.get(&m_key).unwrap().clone();
                slf.remove_from_map(&m.map);

                log!(LogDebug, "  erased ({}) ...", m.map);

                // If the first segment we unmap underflows the unmap
                // region, remap the underflow region.
                let monitored = m.monitored_shared_memory.clone();
                if m.map.start() < rem.start() {
                    let mut underflow = Mapping::new(
                        &m.map.subrange(m.map.start(), rem.start()),
                        &m.recorded_map.subrange(m.map.start(), rem.start()),
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
                    let new_local = m
                        .local_addr
                        .map(|addr| unsafe { addr.add(rem.end() - m.map.start()) });

                    let new_monitored = m.monitored_shared_memory.clone().map(|r| {
                        r.borrow()
                            .subrange(rem.end() - m.map.start(), m.map.end() - rem.end())
                    });
                    let mut overflow = Mapping::new(
                        &m.map.subrange(rem.end(), m.map.end()),
                        &m.recorded_map.subrange(rem.end(), m.map.end()),
                        m.emu_file,
                        m.mapped_file_stat,
                        new_local,
                        new_monitored,
                    );
                    overflow.flags = m.flags;
                    slf.add_to_map(overflow);
                }

                if m.local_addr.is_some() {
                    if unsafe {
                        munmap(
                            m.local_addr.unwrap().add(rem.start() - m.map.start()),
                            rem.size(),
                        )
                    }
                    .is_err()
                    {
                        fatal!("Can't munmap");
                    }
                }
            };
            self.for_each_in_range(addr, num_bytes, unmapper, IterateHow::IterateDefault);
            self.update_watchpoint_values(addr, addr + num_bytes);
        }

        /// Also sets brk_ptr.
        fn map_rd_page(&mut self, remote: &AutoRemoteSyscalls) {
            unimplemented!()
        }

        fn update_watchpoint_value(&self, range: &MemoryRange, watchpoint: &Watchpoint) {
            unimplemented!()
        }

        fn update_watchpoint_values(&self, start: RemotePtr<Void>, end: RemotePtr<Void>) {
            unimplemented!()
        }
        fn get_watchpoints_internal(&self, filter: WatchPointFilter) -> Vec<WatchConfig> {
            unimplemented!()
        }

        fn get_watch_configs(&mut self, will_set_task_state: WillSetTaskState) -> Vec<WatchConfig> {
            let mut result: Vec<WatchConfig> = Vec::new();
            for (r, v) in &mut self.watchpoints {
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
        fn allocate_watchpoints(&mut self) -> bool {
            let mut regs = self.get_watch_configs(WillSetTaskState::SettingTaskState);

            if regs.len() <= 0x7f {
                let mut ok = true;
                for t in self.task_set() {
                    if !t.upgrade().unwrap().borrow_mut().set_debug_regs(&mut regs) {
                        ok = false;
                    }
                }
                if ok {
                    return true;
                }
            }

            regs.clear();
            for t2 in self.task_set() {
                t2.upgrade().unwrap().borrow_mut().set_debug_regs(&mut regs);
            }
            for (_, v) in &mut self.watchpoints {
                v.debug_regs_for_exec_read.clear();
            }
            return false;
        }

        /// Merge the mappings adjacent to `it` in memory that are
        /// semantically "adjacent mappings" of the same resource as
        /// well, for example have adjacent file offsets and the same
        /// prot and flags.
        fn coalesce_around(&self, t: &dyn Task, it: &Maps) {
            unimplemented!()
        }

        /// Erase `it` from `breakpoints` and restore any memory in
        /// this it may have overwritten.
        ///
        /// Assumes there IS a breakpoint at `addr` or will panic
        ///
        /// Called destroy_breakpoint() in rr.
        fn destroy_breakpoint_at(&mut self, addr: RemoteCodePtr) {
            match self.any_task_from_task_set() {
                None => return,
                Some(t) => {
                    let data = self.breakpoints.get(&addr).unwrap().overwritten_data;
                    log!(LogDebug, "Writing back {:x} at {}", data, addr);
                    write_val_mem_with_flags::<u8>(
                        t.borrow_mut().as_mut(),
                        addr.to_data_ptr::<u8>(),
                        &data,
                        None,
                        WriteFlags::IS_BREAKPOINT_RELATED,
                    );
                }
            }
            self.breakpoints.remove(&addr);
        }

        /// For each mapped segment overlapping [addr, addr +
        /// num_bytes), call `f`.  Pass `f` the overlapping mapping,
        /// and the range of addresses remaining to be iterated over.
        ///
        /// Pass `IterateContiguous` to stop iterating when the last
        /// contiguous mapping after `addr` within the region is seen.
        ///
        /// `IterateDefault` will iterate all mappings in the region.
        fn for_each_in_range<F: FnMut(&mut Self, MemoryRangeKey, MemoryRange)>(
            &mut self,
            addr: RemotePtr<Void>,
            // @TODO this is signed in rr.
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
                    let mut iter = Maps::new_from_range(self, rem).into_iter();
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

        /// Map `m` of `r` into this address space, and coalesce any
        /// mappings of `r` that are adjacent to `m`.
        fn map_and_coalesce(
            &self,
            t: &dyn Task,
            m: &KernelMapping,
            recorded_map: &KernelMapping,
            emu_file: EmuFileSharedPtr,
            mapped_file_stat: libc::stat,
            local_addr: *const u8,
            monitored: MonitoredSharedMemorySharedPtr,
        ) {
            unimplemented!()
        }

        fn remove_from_map(&mut self, range: &MemoryRange) {
            unimplemented!()
        }

        fn add_to_map(&mut self, m: Mapping) {
            unimplemented!()
        }

        /// Call this only during recording.
        fn at_preload_init_arch<Arch>(&self, t: &dyn Task) {
            unimplemented!()
        }

        /// Return the access bits above needed to watch `type`.
        fn access_bits_of(type_: WatchType) -> RwxBits {
            unimplemented!()
        }
    }

    impl Deref for AddressSpace {
        type Target = TaskSet;
        fn deref(&self) -> &Self::Target {
            &self.task_set
        }
    }

    impl DerefMut for AddressSpace {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.task_set
        }
    }

    impl Drop for AddressSpace {
        fn drop(&mut self) {
            for (_, m) in &self.mem {
                match m.local_addr {
                    Some(local) => {
                        if unsafe { munmap(local, m.map.size()) }.is_err() {
                            fatal!("Can't munmap");
                        }
                    }
                    _ => (),
                }
            }
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
        let aligned_start = RemotePtr::new_from_val(range.start().as_usize() & !(align - 1));
        let aligned_end =
            RemotePtr::new_from_val((range.end().as_usize() + (align - 1)) & !(align - 1));
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
