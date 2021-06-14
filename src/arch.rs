#![allow(non_camel_case_types)]

use crate::{
    kernel_abi::{
        x64, x86, CloneParameterOrdering, CloneTLSType, MmapCallingSemantics, Ptr,
        SelectCallingSemantics, SupportedArch,
    },
    remote_ptr::{RemotePtr, Void},
};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    mem::size_of,
    num::TryFromIntError,
    ops::Add,
};

/// This type will impl Architecture
#[derive(Default)]
pub struct X86Arch;

/// This type will impl Archiecture
#[derive(Default)]
pub struct X64Arch;

#[cfg(target_arch = "x86_64")]
pub type NativeArch = X64Arch;

#[cfg(target_arch = "x86")]
pub type NativeArch = X86Arch;

macro_rules! rd_arch_function {
    ($slf:expr, $func_name:ident, $arch:expr) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $slf.$func_name::<crate::arch::X86Arch>(),
            crate::kernel_abi::SupportedArch::X64 => $slf.$func_name::<crate::arch::X64Arch>(),
        }
    };
    ($slf:expr, $func_name:ident, $arch:expr, $($exp:tt)*) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $slf.$func_name::<crate::arch::X86Arch>($($exp)*),
            crate::kernel_abi::SupportedArch::X64 => $slf.$func_name::<crate::arch::X64Arch>($($exp)*),
        }
    };
}

macro_rules! rd_arch_function_selfless {
    ($func_name:ident, $arch:expr) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $func_name::<crate::arch::X86Arch>(),
            crate::kernel_abi::SupportedArch::X64 => $func_name::<crate::arch::X64Arch>(),
        }
    };
    ($func_name:ident, $arch:expr, $($exp:tt)*) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $func_name::<crate::arch::X86Arch>($($exp)*),
            crate::kernel_abi::SupportedArch::X64 => $func_name::<crate::arch::X64Arch>($($exp)*),
        }
    };
}

macro_rules! rd_arch_task_function_selfless {
    ($t:ident, $func_name:ident, $arch:expr) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $func_name::<crate::arch::X86Arch, $t>(),
            crate::kernel_abi::SupportedArch::X64 => $func_name::<crate::arch::X64Arch, $t>(),
        }
    };
    ($t:ident, $func_name:ident, $arch:expr, $($exp:tt)*) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $func_name::<crate::arch::X86Arch, $t>($($exp)*),
            crate::kernel_abi::SupportedArch::X64 => $func_name::<crate::arch::X64Arch, $t>($($exp)*),
        }
    };
}
// The const_assert_eq!() in these include files keep the syscalls and their values in sync.
include!(concat!(
    env!("OUT_DIR"),
    "/syscall_const_asserts_x86_generated.rs"
));
include!(concat!(
    env!("OUT_DIR"),
    "/syscall_const_asserts_x64_generated.rs"
));

// Invariant
const_assert_eq!(
    X64Arch::VALID_SYSCALL_COUNT + X64Arch::INVALID_SYSCALL_COUNT,
    X86Arch::VALID_SYSCALL_COUNT + X86Arch::INVALID_SYSCALL_COUNT
);

pub type off64_t = i64;
pub type loff_t = i64;
pub type rlim64_t = u64;
pub type ino64_t = u64;
pub type blkcnt64_t = i64;

pub trait Architecture: 'static + Default {
    const MMAP_SEMANTICS: MmapCallingSemantics;
    const CLONE_TLS_TYPE: CloneTLSType;
    const CLONE_PARAMETER_ORDERING: CloneParameterOrdering;
    const SELECT_SEMANTICS: SelectCallingSemantics;

    // This list from the `syscall_consts_trait_generated` generator
    // See `generators_for` in generate_syscalls.py
    //
    // This list is kept in sync by using const_asserts_eq! macros.
    const WAITPID: i32;
    const _BREAK: i32;
    const OLDSTAT: i32;
    const UMOUNT: i32;
    const STIME: i32;
    const OLDFSTAT: i32;
    const STTY: i32;
    const GTTY: i32;
    const NICE: i32;
    const FTIME: i32;
    const PROF: i32;
    const SIGNAL: i32;
    const LOCK: i32;
    const MPX: i32;
    const ULIMIT: i32;
    const OLDOLDUNAME: i32;
    const SIGACTION: i32;
    const SGETMASK: i32;
    const SSETMASK: i32;
    const SIGSUSPEND: i32;
    const SIGPENDING: i32;
    const OLDLSTAT: i32;
    const READDIR: i32;
    const PROFIL: i32;
    const SOCKETCALL: i32;
    const OLDUNAME: i32;
    const IDLE: i32;
    const VM86OLD: i32;
    const IPC: i32;
    const SIGRETURN: i32;
    const SIGPROCMASK: i32;
    const BDFLUSH: i32;
    const _LLSEEK: i32;
    const _NEWSELECT: i32;
    const VM86: i32;
    const UGETRLIMIT: i32;
    const MMAP2: i32;
    const TRUNCATE64: i32;
    const FTRUNCATE64: i32;
    const STAT64: i32;
    const LSTAT64: i32;
    const FSTAT64: i32;
    const LCHOWN32: i32;
    const GETUID32: i32;
    const GETGID32: i32;
    const GETEUID32: i32;
    const GETEGID32: i32;
    const SETREUID32: i32;
    const SETREGID32: i32;
    const GETGROUPS32: i32;
    const SETGROUPS32: i32;
    const FCHOWN32: i32;
    const SETRESUID32: i32;
    const GETRESUID32: i32;
    const SETRESGID32: i32;
    const GETRESGID32: i32;
    const CHOWN32: i32;
    const SETUID32: i32;
    const SETGID32: i32;
    const SETFSUID32: i32;
    const SETFSGID32: i32;
    const FCNTL64: i32;
    const SENDFILE64: i32;
    const STATFS64: i32;
    const FSTATFS64: i32;
    const FADVISE64_64: i32;
    const CLOCK_GETTIME64: i32;
    const CLOCK_SETTIME64: i32;
    const CLOCK_ADJTIME64: i32;
    const CLOCK_GETRES_TIME64: i32;
    const CLOCK_NANOSLEEP_TIME64: i32;
    const TIMER_GETTIME64: i32;
    const TIMER_SETTIME64: i32;
    const TIMERFD_GETTIME64: i32;
    const TIMERFD_SETTIME64: i32;
    const UTIMENSAT_TIME64: i32;
    const PSELECT6_TIME64: i32;
    const PPOLL_TIME64: i32;
    const IO_PGETEVENTS_TIME64: i32;
    const RECVMMSG_TIME64: i32;
    const MQ_TIMEDSEND_TIME64: i32;
    const MQ_TIMEDRECEIVE_TIME64: i32;
    const SEMTIMEDOP_TIME64: i32;
    const RT_SIGTIMEDWAIT_TIME64: i32;
    const FUTEX_TIME64: i32;
    const SCHED_RR_GET_INTERVAL_TIME64: i32;
    const READ: i32;
    const WRITE: i32;
    const OPEN: i32;
    const CLOSE: i32;
    const STAT: i32;
    const FSTAT: i32;
    const LSTAT: i32;
    const POLL: i32;
    const LSEEK: i32;
    const MMAP: i32;
    const MPROTECT: i32;
    const MUNMAP: i32;
    const BRK: i32;
    const RT_SIGACTION: i32;
    const RT_SIGPROCMASK: i32;
    const RT_SIGRETURN: i32;
    const IOCTL: i32;
    const PREAD64: i32;
    const PWRITE64: i32;
    const READV: i32;
    const WRITEV: i32;
    const ACCESS: i32;
    const PIPE: i32;
    const SELECT: i32;
    const SCHED_YIELD: i32;
    const MREMAP: i32;
    const MSYNC: i32;
    const MINCORE: i32;
    const MADVISE: i32;
    const SHMGET: i32;
    const SHMAT: i32;
    const SHMCTL: i32;
    const DUP: i32;
    const DUP2: i32;
    const PAUSE: i32;
    const NANOSLEEP: i32;
    const GETITIMER: i32;
    const ALARM: i32;
    const SETITIMER: i32;
    const GETPID: i32;
    const SENDFILE: i32;
    const SOCKET: i32;
    const CONNECT: i32;
    const ACCEPT: i32;
    const SENDTO: i32;
    const RECVFROM: i32;
    const SENDMSG: i32;
    const RECVMSG: i32;
    const SHUTDOWN: i32;
    const BIND: i32;
    const LISTEN: i32;
    const GETSOCKNAME: i32;
    const GETPEERNAME: i32;
    const SOCKETPAIR: i32;
    const SETSOCKOPT: i32;
    const GETSOCKOPT: i32;
    const CLONE: i32;
    const FORK: i32;
    const VFORK: i32;
    const EXECVE: i32;
    const EXIT: i32;
    const WAIT4: i32;
    const KILL: i32;
    const UNAME: i32;
    const SEMGET: i32;
    const SEMOP: i32;
    const SEMCTL: i32;
    const SHMDT: i32;
    const MSGGET: i32;
    const MSGSND: i32;
    const MSGRCV: i32;
    const MSGCTL: i32;
    const FCNTL: i32;
    const FLOCK: i32;
    const FSYNC: i32;
    const FDATASYNC: i32;
    const TRUNCATE: i32;
    const FTRUNCATE: i32;
    const GETDENTS: i32;
    const GETCWD: i32;
    const CHDIR: i32;
    const FCHDIR: i32;
    const RENAME: i32;
    const MKDIR: i32;
    const RMDIR: i32;
    const CREAT: i32;
    const LINK: i32;
    const UNLINK: i32;
    const SYMLINK: i32;
    const READLINK: i32;
    const CHMOD: i32;
    const FCHMOD: i32;
    const CHOWN: i32;
    const FCHOWN: i32;
    const LCHOWN: i32;
    const UMASK: i32;
    const GETTIMEOFDAY: i32;
    const GETRLIMIT: i32;
    const GETRUSAGE: i32;
    const SYSINFO: i32;
    const TIMES: i32;
    const PTRACE: i32;
    const GETUID: i32;
    const SYSLOG: i32;
    const GETGID: i32;
    const SETUID: i32;
    const SETGID: i32;
    const GETEUID: i32;
    const GETEGID: i32;
    const SETPGID: i32;
    const GETPPID: i32;
    const GETPGRP: i32;
    const SETSID: i32;
    const SETREUID: i32;
    const SETREGID: i32;
    const GETGROUPS: i32;
    const SETGROUPS: i32;
    const SETRESUID: i32;
    const GETRESUID: i32;
    const SETRESGID: i32;
    const GETRESGID: i32;
    const GETPGID: i32;
    const SETFSUID: i32;
    const SETFSGID: i32;
    const GETSID: i32;
    const CAPGET: i32;
    const CAPSET: i32;
    const RT_SIGPENDING: i32;
    const RT_SIGTIMEDWAIT: i32;
    const RT_SIGQUEUEINFO: i32;
    const RT_SIGSUSPEND: i32;
    const SIGALTSTACK: i32;
    const UTIME: i32;
    const MKNOD: i32;
    const USELIB: i32;
    const PERSONALITY: i32;
    const USTAT: i32;
    const STATFS: i32;
    const FSTATFS: i32;
    const SYSFS: i32;
    const GETPRIORITY: i32;
    const SETPRIORITY: i32;
    const SCHED_SETPARAM: i32;
    const SCHED_GETPARAM: i32;
    const SCHED_SETSCHEDULER: i32;
    const SCHED_GETSCHEDULER: i32;
    const SCHED_GET_PRIORITY_MAX: i32;
    const SCHED_GET_PRIORITY_MIN: i32;
    const SCHED_RR_GET_INTERVAL: i32;
    const MLOCK: i32;
    const MUNLOCK: i32;
    const MLOCKALL: i32;
    const MUNLOCKALL: i32;
    const VHANGUP: i32;
    const MODIFY_LDT: i32;
    const PIVOT_ROOT: i32;
    const _SYSCTL: i32;
    const PRCTL: i32;
    const ARCH_PRCTL: i32;
    const ADJTIMEX: i32;
    const SETRLIMIT: i32;
    const CHROOT: i32;
    const SYNC: i32;
    const ACCT: i32;
    const SETTIMEOFDAY: i32;
    const MOUNT: i32;
    const UMOUNT2: i32;
    const SWAPON: i32;
    const SWAPOFF: i32;
    const REBOOT: i32;
    const SETHOSTNAME: i32;
    const SETDOMAINNAME: i32;
    const IOPL: i32;
    const IOPERM: i32;
    const CREATE_MODULE: i32;
    const INIT_MODULE: i32;
    const DELETE_MODULE: i32;
    const GET_KERNEL_SYMS: i32;
    const QUERY_MODULE: i32;
    const QUOTACTL: i32;
    const NFSSERVCTL: i32;
    const GETPMSG: i32;
    const PUTPMSG: i32;
    const AFS_SYSCALL: i32;
    const TUXCALL: i32;
    const SECURITY: i32;
    const GETTID: i32;
    const READAHEAD: i32;
    const SETXATTR: i32;
    const LSETXATTR: i32;
    const FSETXATTR: i32;
    const GETXATTR: i32;
    const LGETXATTR: i32;
    const FGETXATTR: i32;
    const LISTXATTR: i32;
    const LLISTXATTR: i32;
    const FLISTXATTR: i32;
    const REMOVEXATTR: i32;
    const LREMOVEXATTR: i32;
    const FREMOVEXATTR: i32;
    const TKILL: i32;
    const TIME: i32;
    const FUTEX: i32;
    const SCHED_SETAFFINITY: i32;
    const SCHED_GETAFFINITY: i32;
    const SET_THREAD_AREA: i32;
    const IO_SETUP: i32;
    const IO_DESTROY: i32;
    const IO_GETEVENTS: i32;
    const IO_SUBMIT: i32;
    const IO_CANCEL: i32;
    const GET_THREAD_AREA: i32;
    const LOOKUP_DCOOKIE: i32;
    const EPOLL_CREATE: i32;
    const EPOLL_CTL_OLD: i32;
    const EPOLL_WAIT_OLD: i32;
    const REMAP_FILE_PAGES: i32;
    const GETDENTS64: i32;
    const SET_TID_ADDRESS: i32;
    const RESTART_SYSCALL: i32;
    const SEMTIMEDOP: i32;
    const FADVISE64: i32;
    const TIMER_CREATE: i32;
    const TIMER_SETTIME: i32;
    const TIMER_GETTIME: i32;
    const TIMER_GETOVERRUN: i32;
    const TIMER_DELETE: i32;
    const CLOCK_SETTIME: i32;
    const CLOCK_GETTIME: i32;
    const CLOCK_GETRES: i32;
    const CLOCK_NANOSLEEP: i32;
    const EXIT_GROUP: i32;
    const EPOLL_WAIT: i32;
    const EPOLL_CTL: i32;
    const TGKILL: i32;
    const UTIMES: i32;
    const VSERVER: i32;
    const MBIND: i32;
    const SET_MEMPOLICY: i32;
    const GET_MEMPOLICY: i32;
    const MQ_OPEN: i32;
    const MQ_UNLINK: i32;
    const MQ_TIMEDSEND: i32;
    const MQ_TIMEDRECEIVE: i32;
    const MQ_NOTIFY: i32;
    const MQ_GETSETATTR: i32;
    const KEXEC_LOAD: i32;
    const WAITID: i32;
    const ADD_KEY: i32;
    const REQUEST_KEY: i32;
    const KEYCTL: i32;
    const IOPRIO_SET: i32;
    const IOPRIO_GET: i32;
    const INOTIFY_INIT: i32;
    const INOTIFY_ADD_WATCH: i32;
    const INOTIFY_RM_WATCH: i32;
    const MIGRATE_PAGES: i32;
    const OPENAT: i32;
    const MKDIRAT: i32;
    const MKNODAT: i32;
    const FCHOWNAT: i32;
    const FUTIMESAT: i32;
    const FSTATAT64: i32;
    const UNLINKAT: i32;
    const RENAMEAT: i32;
    const LINKAT: i32;
    const SYMLINKAT: i32;
    const READLINKAT: i32;
    const FCHMODAT: i32;
    const FACCESSAT: i32;
    const PSELECT6: i32;
    const PPOLL: i32;
    const UNSHARE: i32;
    const SET_ROBUST_LIST: i32;
    const GET_ROBUST_LIST: i32;
    const SPLICE: i32;
    const TEE: i32;
    const SYNC_FILE_RANGE: i32;
    const VMSPLICE: i32;
    const MOVE_PAGES: i32;
    const UTIMENSAT: i32;
    const EPOLL_PWAIT: i32;
    const SIGNALFD: i32;
    const TIMERFD_CREATE: i32;
    const EVENTFD: i32;
    const FALLOCATE: i32;
    const TIMERFD_SETTIME: i32;
    const TIMERFD_GETTIME: i32;
    const ACCEPT4: i32;
    const SIGNALFD4: i32;
    const EVENTFD2: i32;
    const EPOLL_CREATE1: i32;
    const DUP3: i32;
    const PIPE2: i32;
    const INOTIFY_INIT1: i32;
    const PREADV: i32;
    const PWRITEV: i32;
    const RT_TGSIGQUEUEINFO: i32;
    const PERF_EVENT_OPEN: i32;
    const RECVMMSG: i32;
    const FANOTIFY_INIT: i32;
    const FANOTIFY_MARK: i32;
    const PRLIMIT64: i32;
    const NAME_TO_HANDLE_AT: i32;
    const OPEN_BY_HANDLE_AT: i32;
    const CLOCK_ADJTIME: i32;
    const SYNCFS: i32;
    const SENDMMSG: i32;
    const SETNS: i32;
    const GETCPU: i32;
    const PROCESS_VM_READV: i32;
    const PROCESS_VM_WRITEV: i32;
    const KCMP: i32;
    const FINIT_MODULE: i32;
    const SCHED_SETATTR: i32;
    const SCHED_GETATTR: i32;
    const RENAMEAT2: i32;
    const SECCOMP: i32;
    const GETRANDOM: i32;
    const MEMFD_CREATE: i32;
    const BPF: i32;
    const EXECVEAT: i32;
    const USERFAULTFD: i32;
    const MEMBARRIER: i32;
    const MLOCK2: i32;
    const COPY_FILE_RANGE: i32;
    const PREADV2: i32;
    const PWRITEV2: i32;
    const PKEY_MPROTECT: i32;
    const PKEY_ALLOC: i32;
    const PKEY_FREE: i32;
    const STATX: i32;
    const IO_PGETEVENTS: i32;
    const RSEQ: i32;
    const PIDFD_SEND_SIGNAL: i32;
    const IO_URING_SETUP: i32;
    const IO_URING_ENTER: i32;
    const IO_URING_REGISTER: i32;
    const OPEN_TREE: i32;
    const MOVE_MOUNT: i32;
    const FSOPEN: i32;
    const FSCONFIG: i32;
    const FSMOUNT: i32;
    const FSPICK: i32;
    const RDCALL_INIT_PRELOAD: i32;
    const RDCALL_INIT_BUFFERS: i32;
    const RDCALL_NOTIFY_SYSCALL_HOOK_EXIT: i32;
    const RDCALL_NOTIFY_CONTROL_MSG: i32;
    const RDCALL_RELOAD_AUXV: i32;
    const RDCALL_MPROTECT_RECORD: i32;
    const VALID_SYSCALL_COUNT: i32;
    const INVALID_SYSCALL_COUNT: i32;
    // End list from generate_syscalls.py. See above.

    type FPROG_PAD_ARR: Default + Copy + 'static;
    type STD_PAD_ARR: Default + Copy + 'static;
    type SIGINFO_PADDING_ARR: Default + Copy + 'static;

    type signed_short: Default + Copy + 'static;
    type unsigned_short: Default + Copy + 'static;
    type signed_word: Default + Copy + 'static;
    type ssize_t: Default + Copy + 'static;

    type syscall_slong_t: Default + Copy + 'static;
    type syscall_ulong_t: Default + Copy + 'static;
    type time_t: Default + Copy + 'static = Self::syscall_slong_t;
    type off_t: Default + Copy + 'static = Self::syscall_slong_t;
    type blkcnt_t: Default + Copy + 'static = Self::syscall_slong_t;
    type blksize_t: Default + Copy + 'static = Self::syscall_slong_t;
    type rlim_t: Default + Copy + 'static = Self::syscall_ulong_t;
    type fsblkcnt_t: Default + Copy + 'static = Self::syscall_ulong_t;
    type fsfilcnt_t: Default + Copy + 'static = Self::syscall_ulong_t;
    type ino_t: Default + Copy + 'static = Self::syscall_ulong_t;
    type nlink_t: Default + Copy + 'static = Self::syscall_ulong_t;
    type __kernel_ulong_t: Default + Copy + 'static = Self::unsigned_long;
    type __kernel_long_t: Default + Copy + 'static = Self::signed_long;
    type __kernel_time_t: Default + Copy + 'static = Self::__kernel_long_t;
    type __kernel_suseconds_t: Default + Copy + 'static = Self::__kernel_long_t;
    type clock_t: Default + Copy + 'static = Self::syscall_slong_t;

    type __statfs_word: Default + Copy + 'static;
    type sigchld_clock_t: Default + Copy + 'static;
    type size_t: Default + Copy + From<u8> + 'static;
    type signed_long: Default + Copy + From<i32> + TryFrom<usize, Error = TryFromIntError> + 'static;
    type unsigned_long: Default
        + Copy
        + From<u32>
        + TryFrom<usize, Error = TryFromIntError>
        + 'static;
    type iovec: Copy + Default + 'static;
    type msghdr: Copy + Default + 'static;
    type sockaddr_un: Copy + 'static;
    type unsigned_word: Copy
        + Default
        + Eq
        + Debug
        + PartialEq
        + Add<Self::unsigned_word, Output = Self::unsigned_word>
        + From<u8>
        + TryInto<usize, Error = TryFromIntError>
        + 'static;
    type user_regs_struct: Copy + 'static;
    type user_fpregs_struct: Copy + 'static;
    type user: Copy + 'static;
    type winsize: Copy + 'static;
    type stat: Copy + 'static;
    type utsname: Copy + 'static;
    type kernel_sigset_t: Default + Copy + 'static;
    type rlimit64: Default + Copy + 'static;
    type tms: Default + Copy + 'static;
    type rlimit: Default + Copy + 'static;
    type rusage: Default + Copy + 'static;
    type timeval: Default + Copy + 'static;
    type timezone: Default + Copy + 'static;
    type statfs: Default + Copy + 'static;
    type itimerval: Default + Copy + 'static;
    type sysinfo: Default + Copy + 'static;
    type timex: Default + Copy + 'static;
    type sched_param: Default + Copy + 'static;
    type stack_t: Default + Copy + 'static;
    type stat64: 'static;
    type itimerspec: Default + Copy + 'static;
    type timespec: Default + Copy + 'static;
    type statfs64: Default + Copy + 'static;
    type mq_attr: Default + Copy + 'static;
    type statx: Default + Copy + 'static;
    type legacy_uid_t: Default + Copy + 'static;
    type legacy_gid_t: Default + Copy + 'static;

    type _flock: Default + Copy + 'static;
    type flock64: Default + Copy + 'static;
    type f_owner_ex: Default + Copy + 'static;
    type user_desc: Default + Copy + 'static;

    type termios: Copy + 'static;
    type termio: Copy + 'static;
    type snd_ctl_card_info: Copy + 'static;
    type hci_dev_info: Copy + 'static;
    type hci_dev_list_req: Copy + 'static;
    type pollfd: Copy + 'static;
    type fd_set: Copy + 'static;
    type epoll_event: 'static;
    type dqblk: Copy + 'static;
    type dqinfo: Copy + 'static;
    type msqid64_ds: Copy + 'static;
    type msginfo: Copy + 'static;
    type ethtool_cmd: Copy + 'static;
    type ifbond: Copy + 'static;
    type dirent: Copy + 'static;
    type dirent64: Copy + 'static;
    type shmid64_ds: Copy + 'static;
    type shminfo64: Copy + 'static;
    type shm_info: Copy + 'static;
    type semid64_ds: Copy + 'static;
    type seminfo: Copy + 'static;

    fn as_rptr<T>(p: Ptr<Self::unsigned_word, T>) -> RemotePtr<T>;

    fn from_remote_ptr<T>(p: RemotePtr<T>) -> Ptr<Self::unsigned_word, T>;

    fn arch() -> SupportedArch;

    fn set_iovec(msgdata: &mut Self::iovec, iov_base: RemotePtr<Void>, iov_len: usize);

    fn as_signed_short(ss: i16) -> Self::signed_short;

    fn as_signed_long(ul: Self::unsigned_long) -> Self::signed_long;

    fn as_signed_long_truncated(l: i64) -> Self::signed_long;

    fn as_sigchld_clock_t_truncated(l: i64) -> Self::sigchld_clock_t;

    fn long_as_usize(sl: Self::signed_long) -> usize;

    fn long_as_isize(sl: Self::signed_long) -> isize;

    fn size_t_as_usize(s: Self::size_t) -> usize;

    fn usize_as_size_t(s: usize) -> Self::size_t;

    fn ssize_t_as_isize(ss: Self::ssize_t) -> isize;

    fn off_t_as_isize(o: Self::off_t) -> isize;

    fn ulong_as_usize(sl: Self::unsigned_long) -> usize;

    fn usize_as_signed_long(v: usize) -> Self::signed_long;

    fn usize_as_ulong(v: usize) -> Self::unsigned_long;

    fn as_unsigned_word(u: usize) -> Self::unsigned_word;

    fn get_iovec(msgdata: &Self::iovec) -> (RemotePtr<Void>, usize);

    fn set_msghdr(
        msg: &mut Self::msghdr,
        msg_control: RemotePtr<u8>,
        msg_controllen: usize,
        msg_iov: RemotePtr<Self::iovec>,
        msg_iovlen: usize,
    );
}

impl Architecture for X86Arch {
    const MMAP_SEMANTICS: MmapCallingSemantics = x86::MMAP_SEMANTICS;
    const CLONE_TLS_TYPE: CloneTLSType = x86::CLONE_TLS_TYPE;
    const CLONE_PARAMETER_ORDERING: CloneParameterOrdering = x86::CLONE_PARAMETER_ORDERING;
    const SELECT_SEMANTICS: SelectCallingSemantics = x86::SELECT_SEMANTICS;

    // This list from the `syscall_consts_trait_impl_x86_generated` generator
    // See `generators_for` in generate_syscalls.py
    //
    // This list is kept in sync by using const_asserts_eq! macros.
    const ACCEPT: i32 = -1;
    const SHMGET: i32 = -2;
    const SHMAT: i32 = -3;
    const SHMCTL: i32 = -4;
    const SEMGET: i32 = -5;
    const SEMOP: i32 = -6;
    const SEMCTL: i32 = -7;
    const SHMDT: i32 = -8;
    const MSGGET: i32 = -9;
    const MSGSND: i32 = -10;
    const MSGRCV: i32 = -11;
    const MSGCTL: i32 = -12;
    const SEMTIMEDOP: i32 = -13;
    const TUXCALL: i32 = -14;
    const SECURITY: i32 = -15;
    const EPOLL_CTL_OLD: i32 = -16;
    const EPOLL_WAIT_OLD: i32 = -17;
    const RESTART_SYSCALL: i32 = 0;
    const EXIT: i32 = 1;
    const FORK: i32 = 2;
    const READ: i32 = 3;
    const WRITE: i32 = 4;
    const OPEN: i32 = 5;
    const CLOSE: i32 = 6;
    const WAITPID: i32 = 7;
    const CREAT: i32 = 8;
    const LINK: i32 = 9;
    const UNLINK: i32 = 10;
    const EXECVE: i32 = 11;
    const CHDIR: i32 = 12;
    const TIME: i32 = 13;
    const MKNOD: i32 = 14;
    const CHMOD: i32 = 15;
    const LCHOWN: i32 = 16;
    const _BREAK: i32 = 17;
    const OLDSTAT: i32 = 18;
    const LSEEK: i32 = 19;
    const GETPID: i32 = 20;
    const MOUNT: i32 = 21;
    const UMOUNT: i32 = 22;
    const SETUID: i32 = 23;
    const GETUID: i32 = 24;
    const STIME: i32 = 25;
    const PTRACE: i32 = 26;
    const ALARM: i32 = 27;
    const OLDFSTAT: i32 = 28;
    const PAUSE: i32 = 29;
    const UTIME: i32 = 30;
    const STTY: i32 = 31;
    const GTTY: i32 = 32;
    const ACCESS: i32 = 33;
    const NICE: i32 = 34;
    const FTIME: i32 = 35;
    const SYNC: i32 = 36;
    const KILL: i32 = 37;
    const RENAME: i32 = 38;
    const MKDIR: i32 = 39;
    const RMDIR: i32 = 40;
    const DUP: i32 = 41;
    const PIPE: i32 = 42;
    const TIMES: i32 = 43;
    const PROF: i32 = 44;
    const BRK: i32 = 45;
    const SETGID: i32 = 46;
    const GETGID: i32 = 47;
    const SIGNAL: i32 = 48;
    const GETEUID: i32 = 49;
    const GETEGID: i32 = 50;
    const ACCT: i32 = 51;
    const UMOUNT2: i32 = 52;
    const LOCK: i32 = 53;
    const IOCTL: i32 = 54;
    const FCNTL: i32 = 55;
    const MPX: i32 = 56;
    const SETPGID: i32 = 57;
    const ULIMIT: i32 = 58;
    const OLDOLDUNAME: i32 = 59;
    const UMASK: i32 = 60;
    const CHROOT: i32 = 61;
    const USTAT: i32 = 62;
    const DUP2: i32 = 63;
    const GETPPID: i32 = 64;
    const GETPGRP: i32 = 65;
    const SETSID: i32 = 66;
    const SIGACTION: i32 = 67;
    const SGETMASK: i32 = 68;
    const SSETMASK: i32 = 69;
    const SETREUID: i32 = 70;
    const SETREGID: i32 = 71;
    const SIGSUSPEND: i32 = 72;
    const SIGPENDING: i32 = 73;
    const SETHOSTNAME: i32 = 74;
    const SETRLIMIT: i32 = 75;
    const GETRLIMIT: i32 = 76;
    const GETRUSAGE: i32 = 77;
    const GETTIMEOFDAY: i32 = 78;
    const SETTIMEOFDAY: i32 = 79;
    const GETGROUPS: i32 = 80;
    const SETGROUPS: i32 = 81;
    const SELECT: i32 = 82;
    const SYMLINK: i32 = 83;
    const OLDLSTAT: i32 = 84;
    const READLINK: i32 = 85;
    const USELIB: i32 = 86;
    const SWAPON: i32 = 87;
    const REBOOT: i32 = 88;
    const READDIR: i32 = 89;
    const MMAP: i32 = 90;
    const MUNMAP: i32 = 91;
    const TRUNCATE: i32 = 92;
    const FTRUNCATE: i32 = 93;
    const FCHMOD: i32 = 94;
    const FCHOWN: i32 = 95;
    const GETPRIORITY: i32 = 96;
    const SETPRIORITY: i32 = 97;
    const PROFIL: i32 = 98;
    const STATFS: i32 = 99;
    const FSTATFS: i32 = 100;
    const IOPERM: i32 = 101;
    const SOCKETCALL: i32 = 102;
    const SYSLOG: i32 = 103;
    const SETITIMER: i32 = 104;
    const GETITIMER: i32 = 105;
    const STAT: i32 = 106;
    const LSTAT: i32 = 107;
    const FSTAT: i32 = 108;
    const OLDUNAME: i32 = 109;
    const IOPL: i32 = 110;
    const VHANGUP: i32 = 111;
    const IDLE: i32 = 112;
    const VM86OLD: i32 = 113;
    const WAIT4: i32 = 114;
    const SWAPOFF: i32 = 115;
    const SYSINFO: i32 = 116;
    const IPC: i32 = 117;
    const FSYNC: i32 = 118;
    const SIGRETURN: i32 = 119;
    const CLONE: i32 = 120;
    const SETDOMAINNAME: i32 = 121;
    const UNAME: i32 = 122;
    const MODIFY_LDT: i32 = 123;
    const ADJTIMEX: i32 = 124;
    const MPROTECT: i32 = 125;
    const SIGPROCMASK: i32 = 126;
    const CREATE_MODULE: i32 = 127;
    const INIT_MODULE: i32 = 128;
    const DELETE_MODULE: i32 = 129;
    const GET_KERNEL_SYMS: i32 = 130;
    const QUOTACTL: i32 = 131;
    const GETPGID: i32 = 132;
    const FCHDIR: i32 = 133;
    const BDFLUSH: i32 = 134;
    const SYSFS: i32 = 135;
    const PERSONALITY: i32 = 136;
    const AFS_SYSCALL: i32 = 137;
    const SETFSUID: i32 = 138;
    const SETFSGID: i32 = 139;
    const _LLSEEK: i32 = 140;
    const GETDENTS: i32 = 141;
    const _NEWSELECT: i32 = 142;
    const FLOCK: i32 = 143;
    const MSYNC: i32 = 144;
    const READV: i32 = 145;
    const WRITEV: i32 = 146;
    const GETSID: i32 = 147;
    const FDATASYNC: i32 = 148;
    const _SYSCTL: i32 = 149;
    const MLOCK: i32 = 150;
    const MUNLOCK: i32 = 151;
    const MLOCKALL: i32 = 152;
    const MUNLOCKALL: i32 = 153;
    const SCHED_SETPARAM: i32 = 154;
    const SCHED_GETPARAM: i32 = 155;
    const SCHED_SETSCHEDULER: i32 = 156;
    const SCHED_GETSCHEDULER: i32 = 157;
    const SCHED_YIELD: i32 = 158;
    const SCHED_GET_PRIORITY_MAX: i32 = 159;
    const SCHED_GET_PRIORITY_MIN: i32 = 160;
    const SCHED_RR_GET_INTERVAL: i32 = 161;
    const NANOSLEEP: i32 = 162;
    const MREMAP: i32 = 163;
    const SETRESUID: i32 = 164;
    const GETRESUID: i32 = 165;
    const VM86: i32 = 166;
    const QUERY_MODULE: i32 = 167;
    const POLL: i32 = 168;
    const NFSSERVCTL: i32 = 169;
    const SETRESGID: i32 = 170;
    const GETRESGID: i32 = 171;
    const PRCTL: i32 = 172;
    const RT_SIGRETURN: i32 = 173;
    const RT_SIGACTION: i32 = 174;
    const RT_SIGPROCMASK: i32 = 175;
    const RT_SIGPENDING: i32 = 176;
    const RT_SIGTIMEDWAIT: i32 = 177;
    const RT_SIGQUEUEINFO: i32 = 178;
    const RT_SIGSUSPEND: i32 = 179;
    const PREAD64: i32 = 180;
    const PWRITE64: i32 = 181;
    const CHOWN: i32 = 182;
    const GETCWD: i32 = 183;
    const CAPGET: i32 = 184;
    const CAPSET: i32 = 185;
    const SIGALTSTACK: i32 = 186;
    const SENDFILE: i32 = 187;
    const GETPMSG: i32 = 188;
    const PUTPMSG: i32 = 189;
    const VFORK: i32 = 190;
    const UGETRLIMIT: i32 = 191;
    const MMAP2: i32 = 192;
    const TRUNCATE64: i32 = 193;
    const FTRUNCATE64: i32 = 194;
    const STAT64: i32 = 195;
    const LSTAT64: i32 = 196;
    const FSTAT64: i32 = 197;
    const LCHOWN32: i32 = 198;
    const GETUID32: i32 = 199;
    const GETGID32: i32 = 200;
    const GETEUID32: i32 = 201;
    const GETEGID32: i32 = 202;
    const SETREUID32: i32 = 203;
    const SETREGID32: i32 = 204;
    const GETGROUPS32: i32 = 205;
    const SETGROUPS32: i32 = 206;
    const FCHOWN32: i32 = 207;
    const SETRESUID32: i32 = 208;
    const GETRESUID32: i32 = 209;
    const SETRESGID32: i32 = 210;
    const GETRESGID32: i32 = 211;
    const CHOWN32: i32 = 212;
    const SETUID32: i32 = 213;
    const SETGID32: i32 = 214;
    const SETFSUID32: i32 = 215;
    const SETFSGID32: i32 = 216;
    const PIVOT_ROOT: i32 = 217;
    const MINCORE: i32 = 218;
    const MADVISE: i32 = 219;
    const GETDENTS64: i32 = 220;
    const FCNTL64: i32 = 221;
    const GETTID: i32 = 224;
    const READAHEAD: i32 = 225;
    const SETXATTR: i32 = 226;
    const LSETXATTR: i32 = 227;
    const FSETXATTR: i32 = 228;
    const GETXATTR: i32 = 229;
    const LGETXATTR: i32 = 230;
    const FGETXATTR: i32 = 231;
    const LISTXATTR: i32 = 232;
    const LLISTXATTR: i32 = 233;
    const FLISTXATTR: i32 = 234;
    const REMOVEXATTR: i32 = 235;
    const LREMOVEXATTR: i32 = 236;
    const FREMOVEXATTR: i32 = 237;
    const TKILL: i32 = 238;
    const SENDFILE64: i32 = 239;
    const FUTEX: i32 = 240;
    const SCHED_SETAFFINITY: i32 = 241;
    const SCHED_GETAFFINITY: i32 = 242;
    const SET_THREAD_AREA: i32 = 243;
    const GET_THREAD_AREA: i32 = 244;
    const IO_SETUP: i32 = 245;
    const IO_DESTROY: i32 = 246;
    const IO_GETEVENTS: i32 = 247;
    const IO_SUBMIT: i32 = 248;
    const IO_CANCEL: i32 = 249;
    const FADVISE64: i32 = 250;
    const EXIT_GROUP: i32 = 252;
    const LOOKUP_DCOOKIE: i32 = 253;
    const EPOLL_CREATE: i32 = 254;
    const EPOLL_CTL: i32 = 255;
    const EPOLL_WAIT: i32 = 256;
    const REMAP_FILE_PAGES: i32 = 257;
    const SET_TID_ADDRESS: i32 = 258;
    const TIMER_CREATE: i32 = 259;
    const TIMER_SETTIME: i32 = 260;
    const TIMER_GETTIME: i32 = 261;
    const TIMER_GETOVERRUN: i32 = 262;
    const TIMER_DELETE: i32 = 263;
    const CLOCK_SETTIME: i32 = 264;
    const CLOCK_GETTIME: i32 = 265;
    const CLOCK_GETRES: i32 = 266;
    const CLOCK_NANOSLEEP: i32 = 267;
    const STATFS64: i32 = 268;
    const FSTATFS64: i32 = 269;
    const TGKILL: i32 = 270;
    const UTIMES: i32 = 271;
    const FADVISE64_64: i32 = 272;
    const VSERVER: i32 = 273;
    const MBIND: i32 = 274;
    const GET_MEMPOLICY: i32 = 275;
    const SET_MEMPOLICY: i32 = 276;
    const MQ_OPEN: i32 = 277;
    const MQ_UNLINK: i32 = 278;
    const MQ_TIMEDSEND: i32 = 279;
    const MQ_TIMEDRECEIVE: i32 = 280;
    const MQ_NOTIFY: i32 = 281;
    const MQ_GETSETATTR: i32 = 282;
    const KEXEC_LOAD: i32 = 283;
    const WAITID: i32 = 284;
    const ADD_KEY: i32 = 286;
    const REQUEST_KEY: i32 = 287;
    const KEYCTL: i32 = 288;
    const IOPRIO_SET: i32 = 289;
    const IOPRIO_GET: i32 = 290;
    const INOTIFY_INIT: i32 = 291;
    const INOTIFY_ADD_WATCH: i32 = 292;
    const INOTIFY_RM_WATCH: i32 = 293;
    const MIGRATE_PAGES: i32 = 294;
    const OPENAT: i32 = 295;
    const MKDIRAT: i32 = 296;
    const MKNODAT: i32 = 297;
    const FCHOWNAT: i32 = 298;
    const FUTIMESAT: i32 = 299;
    const FSTATAT64: i32 = 300;
    const UNLINKAT: i32 = 301;
    const RENAMEAT: i32 = 302;
    const LINKAT: i32 = 303;
    const SYMLINKAT: i32 = 304;
    const READLINKAT: i32 = 305;
    const FCHMODAT: i32 = 306;
    const FACCESSAT: i32 = 307;
    const PSELECT6: i32 = 308;
    const PPOLL: i32 = 309;
    const UNSHARE: i32 = 310;
    const SET_ROBUST_LIST: i32 = 311;
    const GET_ROBUST_LIST: i32 = 312;
    const SPLICE: i32 = 313;
    const SYNC_FILE_RANGE: i32 = 314;
    const TEE: i32 = 315;
    const VMSPLICE: i32 = 316;
    const MOVE_PAGES: i32 = 317;
    const GETCPU: i32 = 318;
    const EPOLL_PWAIT: i32 = 319;
    const UTIMENSAT: i32 = 320;
    const SIGNALFD: i32 = 321;
    const TIMERFD_CREATE: i32 = 322;
    const EVENTFD: i32 = 323;
    const FALLOCATE: i32 = 324;
    const TIMERFD_SETTIME: i32 = 325;
    const TIMERFD_GETTIME: i32 = 326;
    const SIGNALFD4: i32 = 327;
    const EVENTFD2: i32 = 328;
    const EPOLL_CREATE1: i32 = 329;
    const DUP3: i32 = 330;
    const PIPE2: i32 = 331;
    const INOTIFY_INIT1: i32 = 332;
    const PREADV: i32 = 333;
    const PWRITEV: i32 = 334;
    const RT_TGSIGQUEUEINFO: i32 = 335;
    const PERF_EVENT_OPEN: i32 = 336;
    const RECVMMSG: i32 = 337;
    const FANOTIFY_INIT: i32 = 338;
    const FANOTIFY_MARK: i32 = 339;
    const PRLIMIT64: i32 = 340;
    const NAME_TO_HANDLE_AT: i32 = 341;
    const OPEN_BY_HANDLE_AT: i32 = 342;
    const CLOCK_ADJTIME: i32 = 343;
    const SYNCFS: i32 = 344;
    const SENDMMSG: i32 = 345;
    const SETNS: i32 = 346;
    const PROCESS_VM_READV: i32 = 347;
    const PROCESS_VM_WRITEV: i32 = 348;
    const KCMP: i32 = 349;
    const FINIT_MODULE: i32 = 350;
    const SCHED_SETATTR: i32 = 351;
    const SCHED_GETATTR: i32 = 352;
    const RENAMEAT2: i32 = 353;
    const SECCOMP: i32 = 354;
    const GETRANDOM: i32 = 355;
    const MEMFD_CREATE: i32 = 356;
    const BPF: i32 = 357;
    const EXECVEAT: i32 = 358;
    const SOCKET: i32 = 359;
    const SOCKETPAIR: i32 = 360;
    const BIND: i32 = 361;
    const CONNECT: i32 = 362;
    const LISTEN: i32 = 363;
    const ACCEPT4: i32 = 364;
    const GETSOCKOPT: i32 = 365;
    const SETSOCKOPT: i32 = 366;
    const GETSOCKNAME: i32 = 367;
    const GETPEERNAME: i32 = 368;
    const SENDTO: i32 = 369;
    const SENDMSG: i32 = 370;
    const RECVFROM: i32 = 371;
    const RECVMSG: i32 = 372;
    const SHUTDOWN: i32 = 373;
    const USERFAULTFD: i32 = 374;
    const MEMBARRIER: i32 = 375;
    const MLOCK2: i32 = 376;
    const COPY_FILE_RANGE: i32 = 377;
    const PREADV2: i32 = 378;
    const PWRITEV2: i32 = 379;
    const PKEY_MPROTECT: i32 = 380;
    const PKEY_ALLOC: i32 = 381;
    const PKEY_FREE: i32 = 382;
    const STATX: i32 = 383;
    const ARCH_PRCTL: i32 = 384;
    const IO_PGETEVENTS: i32 = 385;
    const RSEQ: i32 = 386;
    const CLOCK_GETTIME64: i32 = 403;
    const CLOCK_SETTIME64: i32 = 404;
    const CLOCK_ADJTIME64: i32 = 405;
    const CLOCK_GETRES_TIME64: i32 = 406;
    const CLOCK_NANOSLEEP_TIME64: i32 = 407;
    const TIMER_GETTIME64: i32 = 408;
    const TIMER_SETTIME64: i32 = 409;
    const TIMERFD_GETTIME64: i32 = 410;
    const TIMERFD_SETTIME64: i32 = 411;
    const UTIMENSAT_TIME64: i32 = 412;
    const PSELECT6_TIME64: i32 = 413;
    const PPOLL_TIME64: i32 = 414;
    const IO_PGETEVENTS_TIME64: i32 = 416;
    const RECVMMSG_TIME64: i32 = 417;
    const MQ_TIMEDSEND_TIME64: i32 = 418;
    const MQ_TIMEDRECEIVE_TIME64: i32 = 419;
    const SEMTIMEDOP_TIME64: i32 = 420;
    const RT_SIGTIMEDWAIT_TIME64: i32 = 421;
    const FUTEX_TIME64: i32 = 422;
    const SCHED_RR_GET_INTERVAL_TIME64: i32 = 423;
    const PIDFD_SEND_SIGNAL: i32 = 424;
    const IO_URING_SETUP: i32 = 425;
    const IO_URING_ENTER: i32 = 426;
    const IO_URING_REGISTER: i32 = 427;
    const OPEN_TREE: i32 = 428;
    const MOVE_MOUNT: i32 = 429;
    const FSOPEN: i32 = 430;
    const FSCONFIG: i32 = 431;
    const FSMOUNT: i32 = 432;
    const FSPICK: i32 = 433;
    const RDCALL_INIT_PRELOAD: i32 = 442;
    const RDCALL_INIT_BUFFERS: i32 = 443;
    const RDCALL_NOTIFY_SYSCALL_HOOK_EXIT: i32 = 444;
    const RDCALL_NOTIFY_CONTROL_MSG: i32 = 445;
    const RDCALL_RELOAD_AUXV: i32 = 446;
    const RDCALL_MPROTECT_RECORD: i32 = 447;
    const VALID_SYSCALL_COUNT: i32 = 419;
    const INVALID_SYSCALL_COUNT: i32 = 17;
    // End list from generate_syscalls.py. See above.

    type FPROG_PAD_ARR = [u8; size_of::<Ptr<Self::unsigned_word, Void>>() - size_of::<u16>()];
    type STD_PAD_ARR = [u8; size_of::<Self::unsigned_long>() - size_of::<i32>()];
    type SIGINFO_PADDING_ARR = [i32; x86::SIGINFO_PADDING];

    type signed_short = i16;
    type unsigned_short = u16;
    type signed_long = i32;
    type unsigned_long = u32;
    type signed_word = i32;
    type unsigned_word = u32;
    type ssize_t = i32;

    type syscall_slong_t = i32;
    type syscall_ulong_t = u32;
    type size_t = u32;
    type off_t = i32;
    type iovec = x86::iovec;
    type msghdr = x86::msghdr;
    type sockaddr_un = x86::sockaddr_un;
    type user_regs_struct = x86::user_regs_struct;
    type user_fpregs_struct = x86::user_fpregs_struct;
    type user = x86::user;
    type winsize = x86::winsize;

    type sigchld_clock_t = i32;
    type __statfs_word = u32;

    type stat = x86::stat;
    type utsname = x86::utsname;
    type kernel_sigset_t = x86::kernel_sigset_t;
    type rlimit64 = x86::rlimit64;
    type tms = x86::tms;
    type rlimit = x86::rlimit;
    type rusage = x86::rusage;
    type timeval = x86::timeval;
    type timezone = x86::timezone;
    type statfs = x86::statfs;
    type itimerval = x86::itimerval;
    type sysinfo = x86::sysinfo;
    type timex = x86::timex;
    type sched_param = x86::sched_param;
    type stack_t = x86::stack_t;
    type stat64 = x86::stat64;
    type itimerspec = x86::itimerspec;
    type timespec = x86::timespec;
    type statfs64 = x86::statfs64;
    type mq_attr = x86::mq_attr;
    type statx = x86::statx;
    type legacy_uid_t = x86::legacy_uid_t;
    type legacy_gid_t = x86::legacy_gid_t;

    type _flock = x86::_flock;
    type flock64 = x86::flock64;
    type f_owner_ex = x86::f_owner_ex;
    type user_desc = x86::user_desc;

    type termios = x86::termios;
    type termio = x86::termio;
    type snd_ctl_card_info = x86::snd_ctl_card_info;
    type hci_dev_info = x86::hci_dev_info;
    type hci_dev_list_req = x86::hci_dev_list_req;
    type pollfd = x86::pollfd;
    type fd_set = x86::fd_set;
    type epoll_event = x86::epoll_event;
    type dqblk = x86::dqblk;
    type dqinfo = x86::dqinfo;
    type msqid64_ds = x86::msqid64_ds;
    type msginfo = x86::msginfo;
    type ethtool_cmd = x86::ethtool_cmd;
    type ifbond = x86::ifbond;
    type dirent = x86::dirent;
    type dirent64 = x86::dirent64;
    type shmid64_ds = x86::shmid64_ds;
    type shminfo64 = x86::shminfo64;
    type shm_info = x86::shm_info;
    type semid64_ds = x86::semid64_ds;
    type seminfo = x86::seminfo;

    fn as_rptr<T>(p: Ptr<u32, T>) -> RemotePtr<T> {
        p.rptr()
    }

    fn from_remote_ptr<T>(p: RemotePtr<T>) -> Ptr<u32, T> {
        Ptr::<u32, T>::from_remote_ptr(p)
    }

    fn arch() -> SupportedArch {
        SupportedArch::X86
    }

    fn set_iovec(msgdata: &mut Self::iovec, iov_base: RemotePtr<u8>, iov_len: usize) {
        msgdata.iov_base = iov_base.into();
        msgdata.iov_len = iov_len.try_into().unwrap();
    }

    fn as_signed_short(ss: i16) -> Self::signed_short {
        ss as Self::signed_short
    }

    fn as_signed_long(ul: Self::unsigned_long) -> Self::signed_long {
        ul as Self::signed_long
    }

    fn as_signed_long_truncated(l: i64) -> Self::signed_long {
        l as Self::signed_long
    }

    fn as_sigchld_clock_t_truncated(l: i64) -> Self::sigchld_clock_t {
        l as Self::sigchld_clock_t
    }

    fn long_as_usize(sl: Self::signed_long) -> usize {
        sl as usize
    }

    fn ulong_as_usize(usl: Self::unsigned_long) -> usize {
        usl as usize
    }

    fn long_as_isize(sl: Self::signed_long) -> isize {
        sl as isize
    }

    fn size_t_as_usize(s: Self::size_t) -> usize {
        s as usize
    }

    fn usize_as_size_t(s: usize) -> Self::size_t {
        s as Self::size_t
    }

    fn ssize_t_as_isize(ss: Self::ssize_t) -> isize {
        ss as isize
    }

    fn off_t_as_isize(ss: Self::off_t) -> isize {
        ss as isize
    }

    fn as_unsigned_word(u: usize) -> Self::unsigned_word {
        u as Self::unsigned_word
    }

    fn get_iovec(msgdata: &Self::iovec) -> (RemotePtr<Void>, usize) {
        (msgdata.iov_base.rptr(), msgdata.iov_len as usize)
    }

    fn usize_as_signed_long(v: usize) -> Self::signed_long {
        v as Self::signed_long
    }

    fn usize_as_ulong(v: usize) -> Self::unsigned_long {
        v as Self::unsigned_long
    }

    fn set_msghdr(
        msg: &mut Self::msghdr,
        msg_control: RemotePtr<u8>,
        msg_controllen: usize,
        msg_iov: RemotePtr<Self::iovec>,
        msg_iovlen: usize,
    ) {
        msg.msg_control = msg_control.into();
        msg.msg_controllen = msg_controllen.try_into().unwrap();
        msg.msg_iov = msg_iov.into();
        msg.msg_iovlen = msg_iovlen.try_into().unwrap();
    }
}

impl Architecture for X64Arch {
    const MMAP_SEMANTICS: MmapCallingSemantics = x64::MMAP_SEMANTICS;
    const CLONE_TLS_TYPE: CloneTLSType = x64::CLONE_TLS_TYPE;
    const CLONE_PARAMETER_ORDERING: CloneParameterOrdering = x64::CLONE_PARAMETER_ORDERING;
    const SELECT_SEMANTICS: SelectCallingSemantics = x64::SELECT_SEMANTICS;

    // This list from the `syscall_consts_trait_impl_x64_generated` generator
    // See `generators_for` in generate_syscalls.py
    //
    // This list is kept in sync by using const_asserts_eq! macros.
    const WAITPID: i32 = -1;
    const _BREAK: i32 = -2;
    const OLDSTAT: i32 = -3;
    const UMOUNT: i32 = -4;
    const STIME: i32 = -5;
    const OLDFSTAT: i32 = -6;
    const STTY: i32 = -7;
    const GTTY: i32 = -8;
    const NICE: i32 = -9;
    const FTIME: i32 = -10;
    const PROF: i32 = -11;
    const SIGNAL: i32 = -12;
    const LOCK: i32 = -13;
    const MPX: i32 = -14;
    const ULIMIT: i32 = -15;
    const OLDOLDUNAME: i32 = -16;
    const SIGACTION: i32 = -17;
    const SGETMASK: i32 = -18;
    const SSETMASK: i32 = -19;
    const SIGSUSPEND: i32 = -20;
    const SIGPENDING: i32 = -21;
    const OLDLSTAT: i32 = -22;
    const READDIR: i32 = -23;
    const PROFIL: i32 = -24;
    const SOCKETCALL: i32 = -25;
    const OLDUNAME: i32 = -26;
    const IDLE: i32 = -27;
    const VM86OLD: i32 = -28;
    const IPC: i32 = -29;
    const SIGRETURN: i32 = -30;
    const SIGPROCMASK: i32 = -31;
    const BDFLUSH: i32 = -32;
    const _LLSEEK: i32 = -33;
    const _NEWSELECT: i32 = -34;
    const VM86: i32 = -35;
    const UGETRLIMIT: i32 = -36;
    const MMAP2: i32 = -37;
    const TRUNCATE64: i32 = -38;
    const FTRUNCATE64: i32 = -39;
    const STAT64: i32 = -40;
    const LSTAT64: i32 = -41;
    const FSTAT64: i32 = -42;
    const LCHOWN32: i32 = -43;
    const GETUID32: i32 = -44;
    const GETGID32: i32 = -45;
    const GETEUID32: i32 = -46;
    const GETEGID32: i32 = -47;
    const SETREUID32: i32 = -48;
    const SETREGID32: i32 = -49;
    const GETGROUPS32: i32 = -50;
    const SETGROUPS32: i32 = -51;
    const FCHOWN32: i32 = -52;
    const SETRESUID32: i32 = -53;
    const GETRESUID32: i32 = -54;
    const SETRESGID32: i32 = -55;
    const GETRESGID32: i32 = -56;
    const CHOWN32: i32 = -57;
    const SETUID32: i32 = -58;
    const SETGID32: i32 = -59;
    const SETFSUID32: i32 = -60;
    const SETFSGID32: i32 = -61;
    const FCNTL64: i32 = -62;
    const SENDFILE64: i32 = -63;
    const STATFS64: i32 = -64;
    const FSTATFS64: i32 = -65;
    const FADVISE64_64: i32 = -66;
    const CLOCK_GETTIME64: i32 = -67;
    const CLOCK_SETTIME64: i32 = -68;
    const CLOCK_ADJTIME64: i32 = -69;
    const CLOCK_GETRES_TIME64: i32 = -70;
    const CLOCK_NANOSLEEP_TIME64: i32 = -71;
    const TIMER_GETTIME64: i32 = -72;
    const TIMER_SETTIME64: i32 = -73;
    const TIMERFD_GETTIME64: i32 = -74;
    const TIMERFD_SETTIME64: i32 = -75;
    const UTIMENSAT_TIME64: i32 = -76;
    const PSELECT6_TIME64: i32 = -77;
    const PPOLL_TIME64: i32 = -78;
    const IO_PGETEVENTS_TIME64: i32 = -79;
    const RECVMMSG_TIME64: i32 = -80;
    const MQ_TIMEDSEND_TIME64: i32 = -81;
    const MQ_TIMEDRECEIVE_TIME64: i32 = -82;
    const SEMTIMEDOP_TIME64: i32 = -83;
    const RT_SIGTIMEDWAIT_TIME64: i32 = -84;
    const FUTEX_TIME64: i32 = -85;
    const SCHED_RR_GET_INTERVAL_TIME64: i32 = -86;
    const READ: i32 = 0;
    const WRITE: i32 = 1;
    const OPEN: i32 = 2;
    const CLOSE: i32 = 3;
    const STAT: i32 = 4;
    const FSTAT: i32 = 5;
    const LSTAT: i32 = 6;
    const POLL: i32 = 7;
    const LSEEK: i32 = 8;
    const MMAP: i32 = 9;
    const MPROTECT: i32 = 10;
    const MUNMAP: i32 = 11;
    const BRK: i32 = 12;
    const RT_SIGACTION: i32 = 13;
    const RT_SIGPROCMASK: i32 = 14;
    const RT_SIGRETURN: i32 = 15;
    const IOCTL: i32 = 16;
    const PREAD64: i32 = 17;
    const PWRITE64: i32 = 18;
    const READV: i32 = 19;
    const WRITEV: i32 = 20;
    const ACCESS: i32 = 21;
    const PIPE: i32 = 22;
    const SELECT: i32 = 23;
    const SCHED_YIELD: i32 = 24;
    const MREMAP: i32 = 25;
    const MSYNC: i32 = 26;
    const MINCORE: i32 = 27;
    const MADVISE: i32 = 28;
    const SHMGET: i32 = 29;
    const SHMAT: i32 = 30;
    const SHMCTL: i32 = 31;
    const DUP: i32 = 32;
    const DUP2: i32 = 33;
    const PAUSE: i32 = 34;
    const NANOSLEEP: i32 = 35;
    const GETITIMER: i32 = 36;
    const ALARM: i32 = 37;
    const SETITIMER: i32 = 38;
    const GETPID: i32 = 39;
    const SENDFILE: i32 = 40;
    const SOCKET: i32 = 41;
    const CONNECT: i32 = 42;
    const ACCEPT: i32 = 43;
    const SENDTO: i32 = 44;
    const RECVFROM: i32 = 45;
    const SENDMSG: i32 = 46;
    const RECVMSG: i32 = 47;
    const SHUTDOWN: i32 = 48;
    const BIND: i32 = 49;
    const LISTEN: i32 = 50;
    const GETSOCKNAME: i32 = 51;
    const GETPEERNAME: i32 = 52;
    const SOCKETPAIR: i32 = 53;
    const SETSOCKOPT: i32 = 54;
    const GETSOCKOPT: i32 = 55;
    const CLONE: i32 = 56;
    const FORK: i32 = 57;
    const VFORK: i32 = 58;
    const EXECVE: i32 = 59;
    const EXIT: i32 = 60;
    const WAIT4: i32 = 61;
    const KILL: i32 = 62;
    const UNAME: i32 = 63;
    const SEMGET: i32 = 64;
    const SEMOP: i32 = 65;
    const SEMCTL: i32 = 66;
    const SHMDT: i32 = 67;
    const MSGGET: i32 = 68;
    const MSGSND: i32 = 69;
    const MSGRCV: i32 = 70;
    const MSGCTL: i32 = 71;
    const FCNTL: i32 = 72;
    const FLOCK: i32 = 73;
    const FSYNC: i32 = 74;
    const FDATASYNC: i32 = 75;
    const TRUNCATE: i32 = 76;
    const FTRUNCATE: i32 = 77;
    const GETDENTS: i32 = 78;
    const GETCWD: i32 = 79;
    const CHDIR: i32 = 80;
    const FCHDIR: i32 = 81;
    const RENAME: i32 = 82;
    const MKDIR: i32 = 83;
    const RMDIR: i32 = 84;
    const CREAT: i32 = 85;
    const LINK: i32 = 86;
    const UNLINK: i32 = 87;
    const SYMLINK: i32 = 88;
    const READLINK: i32 = 89;
    const CHMOD: i32 = 90;
    const FCHMOD: i32 = 91;
    const CHOWN: i32 = 92;
    const FCHOWN: i32 = 93;
    const LCHOWN: i32 = 94;
    const UMASK: i32 = 95;
    const GETTIMEOFDAY: i32 = 96;
    const GETRLIMIT: i32 = 97;
    const GETRUSAGE: i32 = 98;
    const SYSINFO: i32 = 99;
    const TIMES: i32 = 100;
    const PTRACE: i32 = 101;
    const GETUID: i32 = 102;
    const SYSLOG: i32 = 103;
    const GETGID: i32 = 104;
    const SETUID: i32 = 105;
    const SETGID: i32 = 106;
    const GETEUID: i32 = 107;
    const GETEGID: i32 = 108;
    const SETPGID: i32 = 109;
    const GETPPID: i32 = 110;
    const GETPGRP: i32 = 111;
    const SETSID: i32 = 112;
    const SETREUID: i32 = 113;
    const SETREGID: i32 = 114;
    const GETGROUPS: i32 = 115;
    const SETGROUPS: i32 = 116;
    const SETRESUID: i32 = 117;
    const GETRESUID: i32 = 118;
    const SETRESGID: i32 = 119;
    const GETRESGID: i32 = 120;
    const GETPGID: i32 = 121;
    const SETFSUID: i32 = 122;
    const SETFSGID: i32 = 123;
    const GETSID: i32 = 124;
    const CAPGET: i32 = 125;
    const CAPSET: i32 = 126;
    const RT_SIGPENDING: i32 = 127;
    const RT_SIGTIMEDWAIT: i32 = 128;
    const RT_SIGQUEUEINFO: i32 = 129;
    const RT_SIGSUSPEND: i32 = 130;
    const SIGALTSTACK: i32 = 131;
    const UTIME: i32 = 132;
    const MKNOD: i32 = 133;
    const USELIB: i32 = 134;
    const PERSONALITY: i32 = 135;
    const USTAT: i32 = 136;
    const STATFS: i32 = 137;
    const FSTATFS: i32 = 138;
    const SYSFS: i32 = 139;
    const GETPRIORITY: i32 = 140;
    const SETPRIORITY: i32 = 141;
    const SCHED_SETPARAM: i32 = 142;
    const SCHED_GETPARAM: i32 = 143;
    const SCHED_SETSCHEDULER: i32 = 144;
    const SCHED_GETSCHEDULER: i32 = 145;
    const SCHED_GET_PRIORITY_MAX: i32 = 146;
    const SCHED_GET_PRIORITY_MIN: i32 = 147;
    const SCHED_RR_GET_INTERVAL: i32 = 148;
    const MLOCK: i32 = 149;
    const MUNLOCK: i32 = 150;
    const MLOCKALL: i32 = 151;
    const MUNLOCKALL: i32 = 152;
    const VHANGUP: i32 = 153;
    const MODIFY_LDT: i32 = 154;
    const PIVOT_ROOT: i32 = 155;
    const _SYSCTL: i32 = 156;
    const PRCTL: i32 = 157;
    const ARCH_PRCTL: i32 = 158;
    const ADJTIMEX: i32 = 159;
    const SETRLIMIT: i32 = 160;
    const CHROOT: i32 = 161;
    const SYNC: i32 = 162;
    const ACCT: i32 = 163;
    const SETTIMEOFDAY: i32 = 164;
    const MOUNT: i32 = 165;
    const UMOUNT2: i32 = 166;
    const SWAPON: i32 = 167;
    const SWAPOFF: i32 = 168;
    const REBOOT: i32 = 169;
    const SETHOSTNAME: i32 = 170;
    const SETDOMAINNAME: i32 = 171;
    const IOPL: i32 = 172;
    const IOPERM: i32 = 173;
    const CREATE_MODULE: i32 = 174;
    const INIT_MODULE: i32 = 175;
    const DELETE_MODULE: i32 = 176;
    const GET_KERNEL_SYMS: i32 = 177;
    const QUERY_MODULE: i32 = 178;
    const QUOTACTL: i32 = 179;
    const NFSSERVCTL: i32 = 180;
    const GETPMSG: i32 = 181;
    const PUTPMSG: i32 = 182;
    const AFS_SYSCALL: i32 = 183;
    const TUXCALL: i32 = 184;
    const SECURITY: i32 = 185;
    const GETTID: i32 = 186;
    const READAHEAD: i32 = 187;
    const SETXATTR: i32 = 188;
    const LSETXATTR: i32 = 189;
    const FSETXATTR: i32 = 190;
    const GETXATTR: i32 = 191;
    const LGETXATTR: i32 = 192;
    const FGETXATTR: i32 = 193;
    const LISTXATTR: i32 = 194;
    const LLISTXATTR: i32 = 195;
    const FLISTXATTR: i32 = 196;
    const REMOVEXATTR: i32 = 197;
    const LREMOVEXATTR: i32 = 198;
    const FREMOVEXATTR: i32 = 199;
    const TKILL: i32 = 200;
    const TIME: i32 = 201;
    const FUTEX: i32 = 202;
    const SCHED_SETAFFINITY: i32 = 203;
    const SCHED_GETAFFINITY: i32 = 204;
    const SET_THREAD_AREA: i32 = 205;
    const IO_SETUP: i32 = 206;
    const IO_DESTROY: i32 = 207;
    const IO_GETEVENTS: i32 = 208;
    const IO_SUBMIT: i32 = 209;
    const IO_CANCEL: i32 = 210;
    const GET_THREAD_AREA: i32 = 211;
    const LOOKUP_DCOOKIE: i32 = 212;
    const EPOLL_CREATE: i32 = 213;
    const EPOLL_CTL_OLD: i32 = 214;
    const EPOLL_WAIT_OLD: i32 = 215;
    const REMAP_FILE_PAGES: i32 = 216;
    const GETDENTS64: i32 = 217;
    const SET_TID_ADDRESS: i32 = 218;
    const RESTART_SYSCALL: i32 = 219;
    const SEMTIMEDOP: i32 = 220;
    const FADVISE64: i32 = 221;
    const TIMER_CREATE: i32 = 222;
    const TIMER_SETTIME: i32 = 223;
    const TIMER_GETTIME: i32 = 224;
    const TIMER_GETOVERRUN: i32 = 225;
    const TIMER_DELETE: i32 = 226;
    const CLOCK_SETTIME: i32 = 227;
    const CLOCK_GETTIME: i32 = 228;
    const CLOCK_GETRES: i32 = 229;
    const CLOCK_NANOSLEEP: i32 = 230;
    const EXIT_GROUP: i32 = 231;
    const EPOLL_WAIT: i32 = 232;
    const EPOLL_CTL: i32 = 233;
    const TGKILL: i32 = 234;
    const UTIMES: i32 = 235;
    const VSERVER: i32 = 236;
    const MBIND: i32 = 237;
    const SET_MEMPOLICY: i32 = 238;
    const GET_MEMPOLICY: i32 = 239;
    const MQ_OPEN: i32 = 240;
    const MQ_UNLINK: i32 = 241;
    const MQ_TIMEDSEND: i32 = 242;
    const MQ_TIMEDRECEIVE: i32 = 243;
    const MQ_NOTIFY: i32 = 244;
    const MQ_GETSETATTR: i32 = 245;
    const KEXEC_LOAD: i32 = 246;
    const WAITID: i32 = 247;
    const ADD_KEY: i32 = 248;
    const REQUEST_KEY: i32 = 249;
    const KEYCTL: i32 = 250;
    const IOPRIO_SET: i32 = 251;
    const IOPRIO_GET: i32 = 252;
    const INOTIFY_INIT: i32 = 253;
    const INOTIFY_ADD_WATCH: i32 = 254;
    const INOTIFY_RM_WATCH: i32 = 255;
    const MIGRATE_PAGES: i32 = 256;
    const OPENAT: i32 = 257;
    const MKDIRAT: i32 = 258;
    const MKNODAT: i32 = 259;
    const FCHOWNAT: i32 = 260;
    const FUTIMESAT: i32 = 261;
    const FSTATAT64: i32 = 262;
    const UNLINKAT: i32 = 263;
    const RENAMEAT: i32 = 264;
    const LINKAT: i32 = 265;
    const SYMLINKAT: i32 = 266;
    const READLINKAT: i32 = 267;
    const FCHMODAT: i32 = 268;
    const FACCESSAT: i32 = 269;
    const PSELECT6: i32 = 270;
    const PPOLL: i32 = 271;
    const UNSHARE: i32 = 272;
    const SET_ROBUST_LIST: i32 = 273;
    const GET_ROBUST_LIST: i32 = 274;
    const SPLICE: i32 = 275;
    const TEE: i32 = 276;
    const SYNC_FILE_RANGE: i32 = 277;
    const VMSPLICE: i32 = 278;
    const MOVE_PAGES: i32 = 279;
    const UTIMENSAT: i32 = 280;
    const EPOLL_PWAIT: i32 = 281;
    const SIGNALFD: i32 = 282;
    const TIMERFD_CREATE: i32 = 283;
    const EVENTFD: i32 = 284;
    const FALLOCATE: i32 = 285;
    const TIMERFD_SETTIME: i32 = 286;
    const TIMERFD_GETTIME: i32 = 287;
    const ACCEPT4: i32 = 288;
    const SIGNALFD4: i32 = 289;
    const EVENTFD2: i32 = 290;
    const EPOLL_CREATE1: i32 = 291;
    const DUP3: i32 = 292;
    const PIPE2: i32 = 293;
    const INOTIFY_INIT1: i32 = 294;
    const PREADV: i32 = 295;
    const PWRITEV: i32 = 296;
    const RT_TGSIGQUEUEINFO: i32 = 297;
    const PERF_EVENT_OPEN: i32 = 298;
    const RECVMMSG: i32 = 299;
    const FANOTIFY_INIT: i32 = 300;
    const FANOTIFY_MARK: i32 = 301;
    const PRLIMIT64: i32 = 302;
    const NAME_TO_HANDLE_AT: i32 = 303;
    const OPEN_BY_HANDLE_AT: i32 = 304;
    const CLOCK_ADJTIME: i32 = 305;
    const SYNCFS: i32 = 306;
    const SENDMMSG: i32 = 307;
    const SETNS: i32 = 308;
    const GETCPU: i32 = 309;
    const PROCESS_VM_READV: i32 = 310;
    const PROCESS_VM_WRITEV: i32 = 311;
    const KCMP: i32 = 312;
    const FINIT_MODULE: i32 = 313;
    const SCHED_SETATTR: i32 = 314;
    const SCHED_GETATTR: i32 = 315;
    const RENAMEAT2: i32 = 316;
    const SECCOMP: i32 = 317;
    const GETRANDOM: i32 = 318;
    const MEMFD_CREATE: i32 = 319;
    const BPF: i32 = 321;
    const EXECVEAT: i32 = 322;
    const USERFAULTFD: i32 = 323;
    const MEMBARRIER: i32 = 324;
    const MLOCK2: i32 = 325;
    const COPY_FILE_RANGE: i32 = 326;
    const PREADV2: i32 = 327;
    const PWRITEV2: i32 = 328;
    const PKEY_MPROTECT: i32 = 329;
    const PKEY_ALLOC: i32 = 330;
    const PKEY_FREE: i32 = 331;
    const STATX: i32 = 332;
    const IO_PGETEVENTS: i32 = 333;
    const RSEQ: i32 = 334;
    const PIDFD_SEND_SIGNAL: i32 = 424;
    const IO_URING_SETUP: i32 = 425;
    const IO_URING_ENTER: i32 = 426;
    const IO_URING_REGISTER: i32 = 427;
    const OPEN_TREE: i32 = 428;
    const MOVE_MOUNT: i32 = 429;
    const FSOPEN: i32 = 430;
    const FSCONFIG: i32 = 431;
    const FSMOUNT: i32 = 432;
    const FSPICK: i32 = 433;
    const RDCALL_INIT_PRELOAD: i32 = 442;
    const RDCALL_INIT_BUFFERS: i32 = 443;
    const RDCALL_NOTIFY_SYSCALL_HOOK_EXIT: i32 = 444;
    const RDCALL_NOTIFY_CONTROL_MSG: i32 = 445;
    const RDCALL_RELOAD_AUXV: i32 = 446;
    const RDCALL_MPROTECT_RECORD: i32 = 447;
    const VALID_SYSCALL_COUNT: i32 = 350;
    const INVALID_SYSCALL_COUNT: i32 = 86;
    // End list from generate_syscalls.py. See above.

    type FPROG_PAD_ARR = [u8; size_of::<Ptr<Self::unsigned_word, Void>>() - size_of::<u16>()];
    type STD_PAD_ARR = [u8; size_of::<Self::unsigned_long>() - size_of::<i32>()];
    type SIGINFO_PADDING_ARR = [i32; x64::SIGINFO_PADDING];

    type signed_short = i16;
    type unsigned_short = u16;
    type signed_long = i64;
    type unsigned_long = u64;
    type signed_word = i64;
    type unsigned_word = u64;
    type ssize_t = i64;

    type syscall_slong_t = i64;
    type syscall_ulong_t = u64;
    type size_t = u64;
    type off_t = i64;
    type iovec = x64::iovec;
    type msghdr = x64::msghdr;
    type sockaddr_un = x64::sockaddr_un;
    type user_regs_struct = x64::user_regs_struct;
    type user_fpregs_struct = x64::user_fpregs_struct;
    type user = x64::user;
    type winsize = x64::winsize;

    type sigchld_clock_t = i64;
    type __statfs_word = i64;

    type stat = x64::stat;
    type utsname = x64::utsname;
    type kernel_sigset_t = x64::kernel_sigset_t;
    type rlimit64 = x64::rlimit64;
    type tms = x64::tms;
    type rlimit = x64::rlimit;
    type rusage = x64::rusage;
    type timeval = x64::timeval;
    type timezone = x64::timezone;
    type statfs = x64::statfs;
    type itimerval = x64::itimerval;
    type sysinfo = x64::sysinfo;
    type timex = x64::timex;
    type sched_param = x64::sched_param;
    type stack_t = x64::stack_t;
    type stat64 = x64::stat64;
    type itimerspec = x64::itimerspec;
    type timespec = x64::timespec;
    type statfs64 = x64::statfs64;
    type mq_attr = x64::mq_attr;
    type statx = x64::statx;
    type legacy_uid_t = x64::legacy_uid_t;
    type legacy_gid_t = x64::legacy_gid_t;

    type _flock = x64::_flock;
    type flock64 = x64::flock64;
    type f_owner_ex = x64::f_owner_ex;
    type user_desc = x64::user_desc;

    type termios = x64::termios;
    type termio = x64::termio;
    type snd_ctl_card_info = x64::snd_ctl_card_info;
    type hci_dev_info = x64::hci_dev_info;
    type hci_dev_list_req = x64::hci_dev_list_req;
    type pollfd = x64::pollfd;
    type fd_set = x64::fd_set;
    type epoll_event = x64::epoll_event;
    type dqblk = x64::dqblk;
    type dqinfo = x64::dqinfo;
    type msqid64_ds = x64::msqid64_ds;
    type msginfo = x64::msginfo;
    type ethtool_cmd = x64::ethtool_cmd;
    type ifbond = x64::ifbond;
    type dirent = x64::dirent;
    type dirent64 = x64::dirent64;
    type shmid64_ds = x64::shmid64_ds;
    type shminfo64 = x64::shminfo64;
    type shm_info = x64::shm_info;
    type semid64_ds = x64::semid64_ds;
    type seminfo = x64::seminfo;

    fn as_rptr<T>(p: Ptr<u64, T>) -> RemotePtr<T> {
        p.rptr()
    }

    fn from_remote_ptr<T>(p: RemotePtr<T>) -> Ptr<u64, T> {
        Ptr::<u64, T>::from_remote_ptr(p)
    }

    fn arch() -> SupportedArch {
        SupportedArch::X64
    }

    fn set_iovec(msgdata: &mut Self::iovec, iov_base: RemotePtr<u8>, iov_len: usize) {
        msgdata.iov_base = iov_base.into();
        msgdata.iov_len = iov_len as _;
    }

    fn as_signed_short(ss: i16) -> Self::signed_short {
        ss as Self::signed_short
    }

    fn as_signed_long(ul: Self::unsigned_long) -> Self::signed_long {
        ul as Self::signed_long
    }

    fn as_signed_long_truncated(l: i64) -> Self::signed_long {
        l as Self::signed_long
    }

    fn as_sigchld_clock_t_truncated(l: i64) -> Self::sigchld_clock_t {
        l as Self::sigchld_clock_t
    }

    fn long_as_usize(sl: Self::signed_long) -> usize {
        sl as usize
    }

    fn ulong_as_usize(usl: Self::unsigned_long) -> usize {
        usl as usize
    }

    fn long_as_isize(sl: Self::signed_long) -> isize {
        sl as isize
    }

    fn size_t_as_usize(s: Self::size_t) -> usize {
        s as usize
    }

    fn usize_as_size_t(s: usize) -> Self::size_t {
        s as Self::size_t
    }

    fn ssize_t_as_isize(ss: Self::ssize_t) -> isize {
        ss as isize
    }

    fn off_t_as_isize(ss: Self::off_t) -> isize {
        ss as isize
    }

    fn as_unsigned_word(u: usize) -> Self::unsigned_word {
        u as Self::unsigned_word
    }

    fn get_iovec(msgdata: &Self::iovec) -> (RemotePtr<Void>, usize) {
        (msgdata.iov_base.rptr(), msgdata.iov_len as usize)
    }

    fn usize_as_signed_long(v: usize) -> Self::signed_long {
        v as Self::signed_long
    }

    fn usize_as_ulong(v: usize) -> Self::unsigned_long {
        v as Self::unsigned_long
    }

    fn set_msghdr(
        msg: &mut Self::msghdr,
        msg_control: RemotePtr<u8>,
        msg_controllen: usize,
        msg_iov: RemotePtr<Self::iovec>,
        msg_iovlen: usize,
    ) {
        msg.msg_control = msg_control.into();
        msg.msg_controllen = msg_controllen as _;
        msg.msg_iov = msg_iov.into();
        msg.msg_iovlen = msg_iovlen as _;
    }
}
