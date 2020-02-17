pub mod kernel_mapping;
pub mod memory_range;
use crate::remote_ptr::RemotePtr;

#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub enum WatchType {
    WatchExec = 0x00,
    WatchWrite = 0x01,
    WatchReadWrite = 0x03,
}

#[derive(Copy, Clone)]
pub enum DebugStatus {
    DsWatchpointAny = 0xf,
    DsSingleStep = 1 << 14,
}

#[derive(Copy, Clone)]
pub enum MappingFlags {
    FlagNone = 0x0,
    /// This mapping represents a syscallbuf. It needs to handled specially
    /// during checksumming since its contents are not fully restored by the
    /// replay.
    IsSyscallbuf = 0x1,
    /// This mapping is used as our thread-local variable area for this
    /// address space
    IsThreadLocals = 0x2,
    /// This mapping is used for syscallbuf patch stubs
    IsPatchStubs = 0x4,
    /// This mapping is the rd page
    IsRdPage = 0x8,
}

#[derive(Copy, Clone)]
pub enum Traced {
    Traced,
    Untraced,
}
#[derive(Copy, Clone)]
pub enum Privileged {
    Privileged,
    Unpriviledged,
}
#[derive(Copy, Clone)]
pub enum Enabled {
    RecordingOnly,
    ReplayOnly,
    RecordingAndReplay,
}

#[derive(Copy, Clone)]
pub struct SyscallType {
    traced: Traced,
    priviledged: Privileged,
    enabled: Enabled,
}

/// A distinct watchpoint, corresponding to the information needed to
/// program a single x86 debug register.
pub struct WatchConfig {
    pub addr: RemotePtr<u8>,
    pub num_bytes: usize,
    pub type_: WatchType,
}

impl WatchConfig {
    pub fn new(addr: RemotePtr<u8>, num_bytes: usize, type_: WatchType) -> WatchConfig {
        WatchConfig {
            addr,
            num_bytes,
            type_,
        }
    }
}

mod address_space {
    use super::*;
    use crate::address_space::kernel_mapping::KernelMapping;
    use crate::address_space::memory_range::MemoryRange;
    use crate::emu_fs::EmuFileSharedPtr;
    use crate::kernel_abi::SupportedArch;
    use crate::monitored_shared_memory::MonitoredSharedMemorySharedPtr;
    use crate::monkey_patcher::MonkeyPatcher;
    use crate::property_table::PropertyTable;
    use crate::record_task::RecordTask;
    use crate::remote_code_ptr::RemoteCodePtr;
    use crate::remote_ptr::RemotePtr;
    use crate::scoped_fd::ScopedFd;
    use crate::session::Session;
    use crate::task::Task;
    use crate::task_set::TaskSet;
    use crate::taskish_uid::AddressSpaceUid;
    use crate::taskish_uid::TaskUid;
    use crate::trace_frame::FrameTime;
    use libc::{dev_t, ino_t, pid_t};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::collections::HashSet;
    use std::ops::Drop;
    use std::ops::{Deref, DerefMut};
    use std::rc::Rc;

    pub struct Mapping {}

    pub type MemoryMap = BTreeMap<MemoryRange, Mapping>;

    pub type AddressSpaceSharedPtr<'a> = Rc<RefCell<AddressSpace<'a>>>;

    pub struct Maps {}

    /// Models the address space for a set of tasks.  This includes the set
    /// of mapped pages, and the resources those mappings refer to.
    pub struct AddressSpace<'a> {
        task_set: TaskSet<'a>,
    }

    impl<'a> AddressSpace<'a> {
        pub fn new() -> AddressSpace<'a> {
            AddressSpace {
                task_set: TaskSet::new(),
            }
        }

        /// Call this after a new task has been cloned within this
        /// address space.
        pub fn after_clone(&self) {
            unimplemented!()
        }

        /// Call this after a successful execve syscall has completed. At this point
        /// it is safe to perform remote syscalls.
        pub fn post_exec_syscall(&self, t: &Task) {
            unimplemented!()
        }

        /// Change the program data break of this address space to
        /// |addr|. Only called during recording!
        pub fn brk(&self, t: &Task, addr: RemotePtr<u8>, prot: i32) {
            unimplemented!()
        }

        /// This can only be called during recording.
        pub fn current_brk() -> RemotePtr<u8> {
            unimplemented!()
        }

        /// Dump a representation of |this| to stderr in a format
        /// similar to /proc/[tid]/maps.
        /// @TODO impl Display
        pub fn dump(&self) {
            unimplemented!()
        }

        /// Return tid of the first task for this address space.
        pub fn leader_tid() -> pid_t {
            unimplemented!()
        }

        /// Return AddressSpaceUid for this address space.
        pub fn uid() -> AddressSpaceUid {
            unimplemented!()
        }

        pub fn session(&self) -> &Session {
            unimplemented!()
        }

        pub fn arch(&self) -> SupportedArch {
            unimplemented!()
        }

        /// Return the path this address space was exec()'d with.
        pub fn exe_image(&self) -> String {
            unimplemented!()
        }

        /// Assuming the last retired instruction has raised a SIGTRAP
        /// and might be a breakpoint trap instruction, return the type
        /// of breakpoint set at |ip() - sizeof(breakpoint_insn)|, if
        /// one exists.  Otherwise return TRAP_NONE.
        pub fn get_breakpoint_type_for_retired_insn(&self, ip: RemoteCodePtr) -> BreakpointType {
            unimplemented!()
        }

        /// Return the type of breakpoint that's been registered for
        /// |addr|.
        pub fn get_breakpoint_type_at_addr(addr: RemoteCodePtr) -> BreakpointType {
            unimplemented!()
        }

        /// Returns true when the breakpoint at |addr| is in private
        /// non-writeable memory. When this returns true, the breakpoint can't be
        /// overwritten by the tracee without an intervening mprotect or mmap
        /// syscall.
        pub fn is_breakpoint_in_private_read_only_memory(addr: RemoteCodePtr) -> bool {
            unimplemented!()
        }

        /// Return true if there's a breakpoint instruction at |ip|. This might
        /// be an explicit instruction, even if there's no breakpoint set via our API.
        pub fn is_breakpoint_instruction(t: &Task, ip: RemoteCodePtr) -> bool {
            unimplemented!()
        }

        /// The buffer |dest| of length |length| represents the contents of tracee
        /// memory at |addr|. Replace the bytes in |dest| that have been overwritten
        /// by breakpoints with the original data that was replaced by the breakpoints.
        pub fn replace_breakpoints_with_original_values(
            &self,
            dest: &mut [u8],
            addr: RemotePtr<u8>,
        ) {
            unimplemented!()
        }

        /// Map |num_bytes| into this address space at |addr|, with
        /// |prot| protection and |flags|.  The pages are (possibly
        /// initially) backed starting at |offset| of |res|. |fsname|, |device| and
        /// |inode| are values that will appear in the /proc/<pid>/maps entry.
        /// |mapped_file_stat| is a complete copy of the 'stat' data for the mapped
        /// file, or null if this isn't a file mapping or isn't during recording.
        /// |*recorded_map| is the mapping during recording, or null if the mapping
        /// during recording is known to be the same as the new map (e.g. because
        /// we are recording!).
        /// |local_addr| is the local address of the memory shared with the tracee,
        /// or null if it's not shared with the tracee. AddressSpace takes ownership
        /// of the shared memory and is responsible for unmapping it.
        pub fn map(
            t: &Task,
            addr: RemotePtr<u8>,
            num_bytes: usize,
            prot: i32,
            flags: i32,
            offset_bytes: i64,
            fsname: &str,
            device: dev_t,
            inode: ino_t,
            mapped_file_stat: Option<Box<libc::stat>>,
            record_map: Option<&KernelMapping>,
            emu_file: Option<EmuFileSharedPtr>,
            local_addr: *const u8,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) {
            unimplemented!()
        }

        /// Return the mapping and mapped resource for the byte at address 'addr'.
        pub fn mapping_of(&self, addr: RemotePtr<u8>) -> Option<&Mapping> {
            unimplemented!()
        }

        /// Detach local mapping and return it.
        pub fn detach_local_mapping(addr: RemotePtr<u8>) -> Option<*const u8> {
            unimplemented!()
        }

        /// Return a reference to the flags of the mapping at this address, allowing
        /// manipulation.
        pub fn mapping_flags_of(&mut self, addr: RemotePtr<u8>) -> Option<&mut u32> {
            unimplemented!()
        }

        /// Return true if there is some mapping for the byte at 'addr'.
        pub fn has_mapping(addr: RemotePtr<u8>) -> bool {
            unimplemented!()
        }

        /// If the given memory region is mapped into the local address space, obtain
        /// the local address from which the `size` bytes at `addr` can be accessed.
        pub fn local_mapping(&self, addr: RemotePtr<u8>, size: usize) -> &[u8] {
            unimplemented!()
        }

        /// Return true if the rd page is mapped at its expected address.
        pub fn has_rd_page(&self) -> bool {
            unimplemented!()
        }

        pub fn monitored_addrs(&self) -> &HashSet<RemotePtr<u8>> {
            unimplemented!()
        }

        /// Change the protection bits of [addr, addr + num_bytes) to
        /// |prot|.
        pub fn protect(&self, t: &Task, addr: RemotePtr<u8>, num_bytes: usize, prot: i32) {
            unimplemented!()
        }

        /// Fix up mprotect registers parameters to take account of PROT_GROWSDOWN.
        pub fn fixup_mprotect_growsdown_parameters(&self, t: &Task) {
            unimplemented!()
        }

        /// Move the mapping [old_addr, old_addr + old_num_bytes) to
        /// [new_addr, old_addr + new_num_bytes), preserving metadata.
        pub fn remap(
            &self,
            t: &Task,
            old_addr: RemotePtr<u8>,
            old_num_bytes: usize,
            new_addr: RemotePtr<u8>,
            new_num_bytes: usize,
        ) {
            unimplemented!()
        }

        /// Notify that data was written to this address space by rr or
        /// by the kernel.
        /// |flags| can contain values from Task::WriteFlags.
        pub fn notify_written(&self, addr: RemotePtr<u8>, num_bytes: usize, flags: u32) {
            unimplemented!()
        }

        /// Ensure a breakpoint of |type| is set at |addr|.
        pub fn add_breakpoint(&mut self, addr: RemoteCodePtr, type_: BreakpointType) {
            unimplemented!()
        }
        /// Remove a |type| reference to the breakpoint at |addr|.  If
        /// the removed reference was the last, the breakpoint is
        /// destroyed.
        pub fn remove_breakpoint(&mut self, addr: RemoteCodePtr, type_: BreakpointType) {
            unimplemented!()
        }
        /// Destroy all breakpoints in this VM, regardless of their
        /// reference counts.
        pub fn remove_all_breakpoints(&mut self) {
            unimplemented!()
        }

        /// Temporarily remove the breakpoint at |addr|.
        pub fn suspend_breakpoint_at(&self, addr: RemoteCodePtr) {
            unimplemented!()
        }

        /// Restore any temporarily removed breakpoint at |addr|.
        pub fn restore_breakpoint_at(&self, addr: RemoteCodePtr) {
            unimplemented!()
        }

        /// Manage watchpoints.  Analogous to breakpoint-managing
        /// methods above, except that watchpoints can be set for an
        /// address range.
        pub fn add_watchpoint(
            &self,
            addr: RemotePtr<u8>,
            num_bytes: usize,
            type_: WatchType,
        ) -> bool {
            unimplemented!()
        }
        pub fn remove_watchpoint(&self, addr: RemotePtr<u8>, num_bytes: usize, type_: WatchType) {
            unimplemented!()
        }
        pub fn remove_all_watchpoints(&self) {
            unimplemented!()
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
        pub fn has_any_watchpoint_changes(&self) {
            unimplemented!()
        }

        /// Return true if an EXEC watchpoint has fired at addr since the last
        /// consume_watchpoint_changes.
        pub fn has_exec_watchpoint_fired(&self, addr: RemoteCodePtr) {
            unimplemented!()
        }

        /// Return all changed watchpoints in |watches| and clear their changed flags.
        pub fn consume_watchpoint_changes(&self) -> Vec<WatchConfig> {
            unimplemented!()
        }

        pub fn set_shm_size(&self, addr: RemotePtr<u8>, bytes: usize) {
            unimplemented!()
        }

        /// Dies if no shm size is registered for the address.
        pub fn get_shm_size(&self, addr: RemotePtr<u8>) -> usize {
            unimplemented!()
        }
        pub fn remove_shm_size(&self, addr: RemotePtr<u8>) {
            unimplemented!()
        }

        /// Make [addr, addr + num_bytes) inaccessible within this
        /// address space.
        pub fn unmap(&self, t: &Task, addr: RemotePtr<u8>, snum_bytes: usize) {
            unimplemented!()
        }

        /// Notification of madvise call.
        pub fn advise(&self, t: &Task, addr: RemotePtr<u8>, snum_bytes: usize, advice: i32) {
            unimplemented!()
        }

        /// Return the vdso mapping of this.
        pub fn vdso(&self) -> KernelMapping {
            unimplemented!()
        }

        /// Verify that this cached address space matches what the
        /// kernel thinks it should be.
        pub fn verify(&self, t: &Task) {
            unimplemented!()
        }

        pub fn has_breakpoints(&self) -> bool {
            unimplemented!()
        }
        pub fn has_watchpoints(&self) -> bool {
            unimplemented!()
        }

        /// Encoding of the |int $3| instruction.
        pub const BREAKPOINT_INSN: u8 = 0xCC;

        pub fn mem_fd(&self) -> &ScopedFd {
            unimplemented!()
        }
        pub fn set_mem_fd(&mut self, fd: ScopedFd) {
            unimplemented!()
        }

        pub fn monkeypatcher(&self) -> &MonkeyPatcher {
            unimplemented!()
        }

        pub fn at_preload_init(&self, t: &Task) {
            unimplemented!()
        }

        /// The address of the syscall instruction from which traced syscalls made by
        /// the syscallbuf will originate.
        pub fn traced_syscall_ip(&self) -> RemoteCodePtr {
            unimplemented!()
        }

        /// The address of the syscall instruction from which privileged traced
        /// syscalls made by the syscallbuf will originate.
        pub fn privileged_traced_syscall_ip(&self) -> RemoteCodePtr {
            unimplemented!()
        }

        pub fn syscallbuf_enabled(&self) {
            unimplemented!()
        }

        /// We'll map a page of memory here into every exec'ed process for our own
        /// use.
        pub fn rd_page_start() -> RemotePtr<u8> {
            unimplemented!()
        }

        /// This might not be the length of an actual system page, but we allocate
        /// at least this much space.
        pub fn rd_page_size() -> u32 {
            4096
        }
        pub fn rr_page_end() -> RemotePtr<u8> {
            unimplemented!()
        }

        pub fn preload_thread_locals_start() -> RemotePtr<u8> {
            unimplemented!()
        }
        pub fn preload_thread_locals_size() -> u32 {
            unimplemented!()
        }

        pub fn rr_page_syscall_exit_point(
            traced: Traced,
            privileged: Privileged,
            enabled: Enabled,
        ) -> RemoteCodePtr {
            unimplemented!()
        }
        pub fn rr_page_syscall_entry_point(
            traced: Traced,
            privileged: Privileged,
            enabled: Enabled,
            arch: SupportedArch,
        ) -> RemoteCodePtr {
            unimplemented!()
        }

        pub fn rd_page_syscalls() -> Vec<SyscallType> {
            unimplemented!()
        }
        pub fn rd_page_syscall_from_exit_point(ip: RemoteCodePtr) -> SyscallType {
            unimplemented!()
        }
        pub fn rd_page_syscall_from_entry_point(ip: RemoteCodePtr) -> SyscallType {
            unimplemented!()
        }

        /// Return a pointer to 8 bytes of 0xFF
        pub fn rd_page_ff_bytes() -> RemotePtr<u8> {
            unimplemented!()
        }

        /// Locate a syscall instruction in t's VDSO.
        /// This gives us a way to execute remote syscalls without having to write
        /// a syscall instruction into executable tracee memory (which might not be
        /// possible with some kernels, e.g. PaX).
        pub fn find_syscall_instruction(t: &Task) -> RemoteCodePtr {
            unimplemented!()
        }

        /// Task |t| just forked from this address space. Apply dont_fork settings.
        pub fn did_fork_into(t: &Task) {
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
        pub fn save_auxv(t: &Task) {
            unimplemented!()
        }

        /// Reads the /proc/<pid>/maps entry for a specific address. Does no caching.
        /// If performed on a file in a btrfs file system, this may return the
        /// wrong device number! If you stick to anonymous or special file
        /// mappings, this should be OK.
        pub fn read_kernel_mapping(t: &Task, addr: RemotePtr<u8>) -> KernelMapping {
            unimplemented!()
        }

        /// Same as read_kernel_mapping, but reads rd's own memory map.
        pub fn read_local_kernel_mapping(addr: *const u8) -> KernelMapping {
            unimplemented!()
        }

        pub fn chaos_mode_min_stack_size() -> u32 {
            8 * 1024 * 1024
        }

        pub fn chaos_mode_find_free_memory(t: &RecordTask, len: usize) -> RemotePtr<u8> {
            unimplemented!()
        }
        pub fn find_free_memory(len: usize, after: Option<RemotePtr<u8>>) -> RemotePtr<u8> {
            unimplemented!()
        }

        pub fn properties(&self) -> &PropertyTable {
            unimplemented!()
        }

        /// The return value indicates whether we (re)created the preload_thread_locals
        /// area.
        pub fn post_vm_clone(t: &Task) {
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
        pub fn maybe_update_breakpoints(t: &Task, addr: RemotePtr<u8>, len: usize) {
            unimplemented!()
        }

        /// Call this to ensure that the mappings in `range` during replay has the same length
        /// is collapsed to a single mapping. The caller guarantees that all the
        /// mappings in the range can be coalesced (because they corresponded to a single
        /// mapping during recording).
        /// The end of the range might be in the middle of a mapping.
        /// The start of the range might also be in the middle of a mapping.
        pub fn ensure_replay_matches_single_recorded_mapping(t: &Task, range: MemoryRange) {
            unimplemented!()
        }

        /// Print process maps.
        pub fn print_process_maps(t: &Task) {
            unimplemented!()
        }

        pub fn add_stap_semaphore_range(t: &Task, range: MemoryRange) {
            unimplemented!()
        }
        pub fn remove_stap_semaphore_range(t: &Task, range: MemoryRange) {
            unimplemented!()
        }
        pub fn is_stap_semaphore(addr: RemotePtr<u16>) {
            unimplemented!()
        }
    }

    impl<'a> Deref for AddressSpace<'a> {
        type Target = TaskSet<'a>;
        fn deref(&self) -> &Self::Target {
            &self.task_set
        }
    }

    impl<'a> DerefMut for AddressSpace<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.task_set
        }
    }

    impl<'a> Drop for AddressSpace<'a> {
        fn drop(&mut self) {
            unimplemented!()
        }
    }
}

#[cfg(test)]
mod test {
    use super::address_space::AddressSpace;
    use crate::task_trait::TaskTrait;

    struct Task(u32);
    impl TaskTrait for Task {}

    #[test]
    fn basic_test() {
        let mut addr_space = AddressSpace::new();
        let t1 = Task(1);
        let t2 = Task(2);
        // @TODO
        // assert!(addr_space.insert_task(&t1));
        assert!(addr_space.has_task(&t1));
        assert!(!addr_space.insert_task(&t1));
        // @TODO
        // assert!(addr_space.insert_task(&t2));
        assert!(addr_space.has_task(&t2));
        assert!(addr_space.erase_task(&t1));
        assert!(!addr_space.erase_task(&t1));
        assert!(!addr_space.has_task(&t1));
    }
}
