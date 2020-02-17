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

pub enum Traced {
    Traced,
    Untraced,
}
pub enum Privileged {
    Privileged,
    Unpriviledged,
}
pub enum Enabled {
    RecordingOnly,
    ReplayOnly,
    RecordingAndReplay,
}

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
    use crate::remote_code_ptr::RemoteCodePtr;
    use crate::remote_ptr::RemotePtr;
    use crate::session::Session;
    use crate::task::Task;
    use crate::task_set::TaskSet;
    use crate::taskish_uid::AddressSpaceUid;
    use libc::{dev_t, ino_t, pid_t};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ops::Drop;
    use std::ops::{Deref, DerefMut};
    use std::rc::Rc;

    pub struct Mapping {}

    pub type MemoryMap = BTreeMap<MemoryRange, Mapping>;

    pub type AddressSpaceSharedPtr<'a> = Rc<RefCell<AddressSpace<'a>>>;

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
        assert!(addr_space.insert_task(&t1));
        assert!(addr_space.has_task(&t1));
        assert!(!addr_space.insert_task(&t1));
        assert!(addr_space.insert_task(&t2));
        assert!(addr_space.has_task(&t2));
        assert!(addr_space.erase_task(&t1));
        assert!(!addr_space.erase_task(&t1));
        assert!(!addr_space.has_task(&t1));
    }
}
