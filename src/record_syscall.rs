use crate::{
    arch::{loff_t, off64_t, Architecture, NativeArch},
    arch_structs::{
        self,
        __sysctl_args,
        accept4_args,
        accept_args,
        cmsg_align,
        cmsghdr,
        connect_args,
        getsockname_args,
        getsockopt_args,
        ifconf,
        ifreq,
        iovec,
        ipc_kludge_args,
        iwreq,
        kernel_sigaction,
        mmap_args,
        mmsghdr,
        msghdr,
        pselect6_arg6,
        recv_args,
        recvfrom_args,
        recvmmsg_args,
        recvmsg_args,
        select_args,
        sendmmsg_args,
        sendmsg_args,
        sg_io_hdr,
        siginfo_t,
        sock_fprog,
        socketpair_args,
        usbdevfs_ctrltransfer,
        usbdevfs_ioctl,
        usbdevfs_iso_packet_desc,
        usbdevfs_urb,
        v4l2_buffer,
    },
    auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem, MemParamsEnabled},
    bindings::{
        fcntl,
        kernel::{
            semid64_ds,
            seminfo,
            shmid64_ds,
            user_desc,
            vfs_cap_data,
            CAP_SYS_ADMIN,
            FIOASYNC,
            FIOCLEX,
            FIONBIO,
            FIONCLEX,
            GETALL,
            GETNCNT,
            GETPID,
            GETVAL,
            GETZCNT,
            IPC_64,
            IPC_INFO,
            IPC_RMID,
            IPC_SET,
            IPC_STAT,
            MSGCTL,
            MSGGET,
            MSGRCV,
            MSGSND,
            MSG_INFO,
            MSG_STAT,
            NT_FPREGSET,
            NT_PRSTATUS,
            NT_X86_XSTATE,
            SEMCTL,
            SEMGET,
            SEMOP,
            SEMTIMEDOP,
            SEM_INFO,
            SEM_STAT,
            SETALL,
            SETVAL,
            SG_GET_VERSION_NUM,
            SG_IO,
            SHMAT,
            SHMCTL,
            SHMDT,
            SHMGET,
            SHM_INFO,
            SHM_LOCK,
            SHM_STAT,
            SHM_UNLOCK,
            SIOCADDMULTI,
            SIOCADDRT,
            SIOCBONDINFOQUERY,
            SIOCBRADDBR,
            SIOCBRADDIF,
            SIOCBRDELBR,
            SIOCBRDELIF,
            SIOCDELMULTI,
            SIOCDELRT,
            SIOCETHTOOL,
            SIOCGIFADDR,
            SIOCGIFBRDADDR,
            SIOCGIFCONF,
            SIOCGIFDSTADDR,
            SIOCGIFFLAGS,
            SIOCGIFHWADDR,
            SIOCGIFINDEX,
            SIOCGIFMAP,
            SIOCGIFMETRIC,
            SIOCGIFMTU,
            SIOCGIFNAME,
            SIOCGIFNETMASK,
            SIOCGIFPFLAGS,
            SIOCGIFTXQLEN,
            SIOCGIWESSID,
            SIOCGIWFREQ,
            SIOCGIWMODE,
            SIOCGIWNAME,
            SIOCGIWRATE,
            SIOCGIWSENS,
            SIOCGSTAMP,
            SIOCGSTAMPNS,
            SIOCSIFADDR,
            SIOCSIFBRDADDR,
            SIOCSIFDSTADDR,
            SIOCSIFFLAGS,
            SIOCSIFHWADDR,
            SIOCSIFHWBROADCAST,
            SIOCSIFMAP,
            SIOCSIFMETRIC,
            SIOCSIFMTU,
            SIOCSIFNAME,
            SIOCSIFNETMASK,
            SIOCSIFPFLAGS,
            SIOCSIFTXQLEN,
            SUBCMDSHIFT,
            SYS_ACCEPT,
            SYS_ACCEPT4,
            SYS_BIND,
            SYS_CONNECT,
            SYS_GETPEERNAME,
            SYS_GETSOCKNAME,
            SYS_GETSOCKOPT,
            SYS_LISTEN,
            SYS_RECV,
            SYS_RECVFROM,
            SYS_RECVMMSG,
            SYS_RECVMSG,
            SYS_SEND,
            SYS_SENDMMSG,
            SYS_SENDMSG,
            SYS_SENDTO,
            SYS_SETSOCKOPT,
            SYS_SHUTDOWN,
            SYS_SOCKET,
            SYS_SOCKETPAIR,
            S_ISGID,
            S_ISUID,
            TCFLSH,
            TCGETA,
            TCGETS,
            TCSBRK,
            TCSBRKP,
            TCSETA,
            TCSETAF,
            TCSETAW,
            TCSETS,
            TCSETSF,
            TCSETSW,
            TCXONC,
            TIOCCBRK,
            TIOCCONS,
            TIOCEXCL,
            TIOCGETD,
            TIOCGLCKTRMIOS,
            TIOCGPGRP,
            TIOCGSID,
            TIOCGWINSZ,
            TIOCINQ,
            TIOCNOTTY,
            TIOCNXCL,
            TIOCOUTQ,
            TIOCPKT,
            TIOCSBRK,
            TIOCSCTTY,
            TIOCSETD,
            TIOCSLCKTRMIOS,
            TIOCSPGRP,
            TIOCSTI,
            TIOCSWINSZ,
            USBDEVFS_URB_TYPE_ISO,
            V4L2_MEMORY_MMAP,
            _IOC_READ,
            _IOC_SIZEMASK,
            _IOC_SIZESHIFT,
            _LINUX_CAPABILITY_U32S_1,
            _LINUX_CAPABILITY_U32S_2,
            _LINUX_CAPABILITY_U32S_3,
            _LINUX_CAPABILITY_VERSION_1,
            _LINUX_CAPABILITY_VERSION_2,
            _LINUX_CAPABILITY_VERSION_3,
            _SNDRV_CTL_IOCTL_CARD_INFO,
            _SNDRV_CTL_IOCTL_PVERSION,
            _VIDIOC_DQBUF,
            _VIDIOC_ENUMINPUT,
            _VIDIOC_ENUM_FMT,
            _VIDIOC_ENUM_FRAMEINTERVALS,
            _VIDIOC_ENUM_FRAMESIZES,
            _VIDIOC_G_CTRL,
            _VIDIOC_G_FMT,
            _VIDIOC_G_OUTPUT,
            _VIDIOC_G_PARM,
            _VIDIOC_QBUF,
            _VIDIOC_QUERYBUF,
            _VIDIOC_QUERYCAP,
            _VIDIOC_QUERYCTRL,
            _VIDIOC_REQBUFS,
            _VIDIOC_S_CTRL,
            _VIDIOC_S_FMT,
            _VIDIOC_S_PARM,
            _VIDIOC_TRY_FMT,
        },
        misc_for_ioctl::{
            _EVIOCGEFFECTS,
            _EVIOCGID,
            _EVIOCGKEYCODE,
            _EVIOCGKEY_0,
            _EVIOCGLED_0,
            _EVIOCGMASK,
            _EVIOCGMTSLOTS_0,
            _EVIOCGNAME_0,
            _EVIOCGPHYS_0,
            _EVIOCGPROP_0,
            _EVIOCGREP,
            _EVIOCGSND_0,
            _EVIOCGSW_0,
            _EVIOCGUNIQ_0,
            _EVIOCGVERSION,
            _FS_IOC_GETFLAGS,
            _FS_IOC_GETVERSION,
            _JSIOCGAXES,
            _JSIOCGAXMAP,
            _JSIOCGBTNMAP,
            _JSIOCGBUTTONS,
            _JSIOCGNAME_0,
            _JSIOCGVERSION,
            _VFAT_IOCTL_READDIR_BOTH,
        },
        packet::{PACKET_RX_RING, PACKET_TX_RING},
        perf_event::perf_event_attr,
        personality::{PER_LINUX, PER_LINUX32},
        prctl::{
            ARCH_GET_CPUID,
            ARCH_GET_FS,
            ARCH_GET_GS,
            ARCH_SET_CPUID,
            ARCH_SET_FS,
            ARCH_SET_GS,
            PR_CAPBSET_DROP,
            PR_CAPBSET_READ,
            PR_CAP_AMBIENT,
            PR_GET_CHILD_SUBREAPER,
            PR_GET_DUMPABLE,
            PR_GET_ENDIAN,
            PR_GET_FPEMU,
            PR_GET_FPEXC,
            PR_GET_KEEPCAPS,
            PR_GET_NAME,
            PR_GET_NO_NEW_PRIVS,
            PR_GET_PDEATHSIG,
            PR_GET_SECCOMP,
            PR_GET_SPECULATION_CTRL,
            PR_GET_TIMERSLACK,
            PR_GET_TSC,
            PR_GET_UNALIGN,
            PR_MCE_KILL,
            PR_MCE_KILL_GET,
            PR_SET_CHILD_SUBREAPER,
            PR_SET_DUMPABLE,
            PR_SET_KEEPCAPS,
            PR_SET_NAME,
            PR_SET_NO_NEW_PRIVS,
            PR_SET_PDEATHSIG,
            PR_SET_PTRACER,
            PR_SET_SECCOMP,
            PR_SET_SPECULATION_CTRL,
            PR_SET_TIMERSLACK,
            PR_SET_TSC,
            PR_TSC_ENABLE,
            PR_TSC_SIGSEGV,
        },
        ptrace::{
            PTRACE_ARCH_PRCTL,
            PTRACE_ATTACH,
            PTRACE_CONT,
            PTRACE_DETACH,
            PTRACE_EVENT_CLONE,
            PTRACE_EVENT_EXEC,
            PTRACE_EVENT_EXIT,
            PTRACE_EVENT_FORK,
            PTRACE_EVENT_VFORK,
            PTRACE_GETEVENTMSG,
            PTRACE_GETFPREGS,
            PTRACE_GETFPXREGS,
            PTRACE_GETREGS,
            PTRACE_GETREGSET,
            PTRACE_GETSIGINFO,
            PTRACE_GET_THREAD_AREA,
            PTRACE_KILL,
            PTRACE_O_TRACECLONE,
            PTRACE_O_TRACEEXEC,
            PTRACE_O_TRACEEXIT,
            PTRACE_O_TRACEFORK,
            PTRACE_O_TRACESYSGOOD,
            PTRACE_O_TRACEVFORK,
            PTRACE_PEEKDATA,
            PTRACE_PEEKTEXT,
            PTRACE_PEEKUSER,
            PTRACE_POKEDATA,
            PTRACE_POKETEXT,
            PTRACE_POKEUSER,
            PTRACE_SEIZE,
            PTRACE_SETFPREGS,
            PTRACE_SETFPXREGS,
            PTRACE_SETOPTIONS,
            PTRACE_SETREGS,
            PTRACE_SETREGSET,
            PTRACE_SET_THREAD_AREA,
            PTRACE_SINGLESTEP,
            PTRACE_SYSCALL,
            PTRACE_SYSEMU,
            PTRACE_SYSEMU_SINGLESTEP,
            PTRACE_TRACEME,
        },
        signal::{siginfo_t as siginfo_t_signal, SI_USER},
    },
    event::{
        Event,
        EventType,
        OpenedFd,
        SignalDeterministic,
        SignalEventData,
        Switchable,
        SyscallState,
    },
    extra_registers::Format,
    fd_table::FdTable,
    file_monitor::{
        self,
        base_file_monitor::BaseFileMonitor,
        mmapped_file_monitor::MmappedFileMonitor,
        proc_fd_dir_monitor::ProcFdDirMonitor,
        proc_mem_monitor::ProcMemMonitor,
        stdio_monitor::StdioMonitor,
        virtual_perf_counter_monitor::VirtualPerfCounterMonitor,
        FileMonitor,
        LazyOffset,
        Range,
    },
    kernel_abi::{
        common,
        is_at_syscall_instruction,
        is_clone_syscall,
        is_exit_group_syscall,
        is_exit_syscall,
        is_vfork_syscall,
        syscall_instruction_length,
        syscall_number_for_close,
        syscall_number_for_munmap,
        syscall_number_for_openat,
        syscall_number_for_pause,
        syscall_number_for_rt_sigprocmask,
        x64,
        x86,
        CloneTLSType,
        FcntlOperation,
        MmapCallingSemantics,
        Ptr,
        SelectCallingSemantics,
        SupportedArch,
    },
    kernel_metadata::{
        errno_name,
        is_sigreturn,
        ptrace_req_name,
        shm_flags_to_mmap_prot,
        syscall_name,
    },
    kernel_supplement::{
        sig_set_t,
        BPF_MAP_CREATE,
        BPF_MAP_DELETE_ELEM,
        BPF_MAP_UPDATE_ELEM,
        BPF_PROG_LOAD,
        BTRFS_IOC_CLONE_,
        BTRFS_IOC_CLONE_RANGE_,
        NUM_SIGNALS,
        PTRACE_OLDSETOPTIONS,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_SET_MODE_STRICT,
        SO_SET_REPLACE,
        _HCIGETDEVINFO,
        _HCIGETDEVLIST,
        _TIOCGEXCL,
        _TIOCGPKT,
        _TIOCGPTLCK,
        _TIOCGPTN,
        _TIOCGPTPEER,
        _TIOCSPTLCK,
        _TUNATTACHFILTER,
        _TUNDETACHFILTER,
        _TUNGETFEATURES,
        _TUNGETFILTER,
        _TUNGETIFF,
        _TUNGETSNDBUF,
        _TUNGETVNETBE,
        _TUNGETVNETHDRSZ,
        _TUNGETVNETLE,
        _TUNSETDEBUG,
        _TUNSETGROUP,
        _TUNSETIFF,
        _TUNSETIFINDEX,
        _TUNSETLINK,
        _TUNSETNOCSUM,
        _TUNSETOFFLOAD,
        _TUNSETOWNER,
        _TUNSETPERSIST,
        _TUNSETQUEUE,
        _TUNSETSNDBUF,
        _TUNSETTXFILTER,
        _TUNSETVNETBE,
        _TUNSETVNETHDRSZ,
        _TUNSETVNETLE,
        _USBDEVFS_ALLOC_STREAMS,
        _USBDEVFS_CLAIMINTERFACE,
        _USBDEVFS_CLEAR_HALT,
        _USBDEVFS_CONTROL,
        _USBDEVFS_DISCARDURB,
        _USBDEVFS_DISCONNECT_CLAIM,
        _USBDEVFS_FREE_STREAMS,
        _USBDEVFS_GETDRIVER,
        _USBDEVFS_GET_CAPABILITIES,
        _USBDEVFS_IOCTL,
        _USBDEVFS_REAPURB,
        _USBDEVFS_REAPURBNDELAY,
        _USBDEVFS_RELEASEINTERFACE,
        _USBDEVFS_RESET,
        _USBDEVFS_SETCONFIGURATION,
        _USBDEVFS_SETINTERFACE,
        _USBDEVFS_SUBMITURB,
    },
    log::{LogDebug, LogInfo, LogWarn},
    monitored_shared_memory::MonitoredSharedMemory,
    monkey_patcher::MmapMode,
    preload_interface::{
        syscallbuf_hdr,
        syscallbuf_record,
        SYS_rdcall_init_buffers,
        SYS_rdcall_init_preload,
        SYS_rdcall_notify_control_msg,
        SYS_rdcall_notify_syscall_hook_exit,
    },
    preload_interface_arch::rdcall_init_buffers_params,
    rd::RD_RESERVED_ROOT_DIR_FD,
    registers,
    registers::{with_converted_registers, Registers},
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    seccomp_filter_rewriter::SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO,
    session::{
        address_space::{
            address_space::AddressSpace,
            kernel_mapping::KernelMapping,
            read_kernel_mapping,
        },
        record_session::set_arch_siginfo,
        session_inner::SessionInner,
        task::{
            record_task::{EmulatedStopType, RecordTask, WaitType},
            task_common::{read_mem, read_val_mem, write_mem, write_val_mem},
            task_inner::{ResumeRequest, TicksRequest, WaitRequest, WriteFlags},
            Task,
            TaskSharedPtr,
            TaskSharedWeakPtr,
        },
    },
    sig,
    sig::Sig,
    trace::{
        trace_stream::TraceRemoteFd,
        trace_task_event::TraceTaskEvent,
        trace_writer::{MappingOrigin, RecordInTrace},
    },
    util::{
        ceil_page_size,
        clone_flags_to_task_flags,
        copy_file,
        create_temporary_file,
        extract_clone_parameters,
        has_effective_caps,
        is_proc_fd_dir,
        is_proc_mem_file,
        page_size,
        read_auxv,
        u8_slice_mut,
        word_at,
        word_size,
        write_all,
        CloneParameters,
    },
    wait_status::WaitStatus,
    weak_ptr_set::WeakPtrSet,
};
use arch_structs::{ipt_replace, setsockopt_args};
use file_monitor::FileMonitorType;
use libc::{
    cpu_set_t,
    getxattr,
    id_t,
    idtype_t,
    memcmp,
    pid_t,
    sockaddr_un,
    socklen_t,
    SYS_tgkill,
    ADDR_COMPAT_LAYOUT,
    ADDR_LIMIT_32BIT,
    ADDR_LIMIT_3GB,
    ADDR_NO_RANDOMIZE,
    AF_UNIX,
    AT_ENTRY,
    CLONE_PARENT,
    CLONE_THREAD,
    CLONE_UNTRACED,
    CLONE_VFORK,
    CLONE_VM,
    EACCES,
    EFAULT,
    EINVAL,
    EIO,
    ENODATA,
    ENODEV,
    ENOENT,
    ENOPROTOOPT,
    ENOSYS,
    ENOTBLK,
    ENOTSUP,
    ENOTTY,
    EPERM,
    ESRCH,
    FDPIC_FUNCPTRS,
    FUTEX_CMD_MASK,
    FUTEX_CMP_REQUEUE,
    FUTEX_CMP_REQUEUE_PI,
    FUTEX_LOCK_PI,
    FUTEX_TRYLOCK_PI,
    FUTEX_UNLOCK_PI,
    FUTEX_WAIT,
    FUTEX_WAIT_BITSET,
    FUTEX_WAIT_REQUEUE_PI,
    FUTEX_WAKE,
    FUTEX_WAKE_BITSET,
    FUTEX_WAKE_OP,
    GRND_NONBLOCK,
    IPPROTO_IP,
    IPPROTO_IPV6,
    KEYCTL_ASSUME_AUTHORITY,
    KEYCTL_CHOWN,
    KEYCTL_CLEAR,
    KEYCTL_DESCRIBE,
    KEYCTL_DH_COMPUTE,
    KEYCTL_GET_KEYRING_ID,
    KEYCTL_GET_SECURITY,
    KEYCTL_INSTANTIATE,
    KEYCTL_INSTANTIATE_IOV,
    KEYCTL_INVALIDATE,
    KEYCTL_JOIN_SESSION_KEYRING,
    KEYCTL_LINK,
    KEYCTL_NEGATE,
    KEYCTL_READ,
    KEYCTL_REJECT,
    KEYCTL_REVOKE,
    KEYCTL_SEARCH,
    KEYCTL_SESSION_TO_PARENT,
    KEYCTL_SETPERM,
    KEYCTL_SET_REQKEY_KEYRING,
    KEYCTL_SET_TIMEOUT,
    KEYCTL_UNLINK,
    KEYCTL_UPDATE,
    MADV_DODUMP,
    MADV_DOFORK,
    MADV_DONTDUMP,
    MADV_DONTFORK,
    MADV_DONTNEED,
    MADV_FREE,
    MADV_HUGEPAGE,
    MADV_HWPOISON,
    MADV_MERGEABLE,
    MADV_NOHUGEPAGE,
    MADV_NORMAL,
    MADV_RANDOM,
    MADV_REMOVE,
    MADV_SEQUENTIAL,
    MADV_SOFT_OFFLINE,
    MADV_UNMERGEABLE,
    MADV_WILLNEED,
    MAP_32BIT,
    MAP_FIXED,
    MAP_GROWSDOWN,
    MMAP_PAGE_ZERO,
    MSG_DONTWAIT,
    O_DIRECT,
    O_RDONLY,
    PRIO_PROCESS,
    P_ALL,
    P_PGID,
    P_PID,
    Q_GETFMT,
    Q_GETINFO,
    Q_GETQUOTA,
    Q_QUOTAOFF,
    Q_QUOTAON,
    Q_SETINFO,
    Q_SETQUOTA,
    Q_SYNC,
    READ_IMPLIES_EXEC,
    SCM_RIGHTS,
    SECCOMP_MODE_FILTER,
    SECCOMP_MODE_STRICT,
    SHORT_INODE,
    SIGCHLD,
    SIGKILL,
    SIGSTOP,
    SIG_BLOCK,
    SOL_PACKET,
    SOL_SOCKET,
    STDERR_FILENO,
    STDIN_FILENO,
    STDOUT_FILENO,
    STICKY_TIMEOUTS,
    S_IWUSR,
    UNAME26,
    WHOLE_SECONDS,
    WNOHANG,
    WNOWAIT,
    WUNTRACED,
};
use mem::size_of_val;
use nix::{
    errno::errno,
    fcntl::{open, OFlag},
    sys::{
        mman::{MapFlags, ProtFlags},
        stat::{self, stat, Mode, SFlag},
    },
    unistd::{getpid, ttyname, unlink},
};
use std::{
    cell::RefCell,
    cmp::{max, min},
    convert::{TryFrom, TryInto},
    env,
    ffi::{CStr, OsStr, OsString},
    fs::read_dir,
    intrinsics::{copy_nonoverlapping, transmute},
    mem::{self, size_of},
    os::{
        raw::c_uint,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::Path,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

extern "C" {
    fn ioctl_type(nr: c_uint) -> c_uint;
    fn ioctl_size(nr: c_uint) -> c_uint;
    fn ioctl_dir(nr: c_uint) -> c_uint;
    fn ioctl_nr(nr: c_uint) -> c_uint;
}

#[allow(non_camel_case_types)]
struct rdcall_params<Arch: Architecture> {
    result: Arch::unsigned_word,
    original_syscallno: Arch::unsigned_word,
}

/// Prepare `t` to enter its current syscall event.  Return Switchable::AllowSwitch if
/// a context-switch is allowed for `t`, Switchable::PreventSwitch if not.
pub fn rec_prepare_syscall(t: &mut RecordTask) -> Switchable {
    if t.syscall_state.is_none() {
        let mut new_ts = TaskSyscallState::new(t);
        new_ts.init(t);
        t.syscall_state = Some(Rc::new(RefCell::new(new_ts)));
    } else {
        t.syscall_state_unwrap().borrow_mut().init(t);
    }

    let s = rec_prepare_syscall_internal(t);
    let syscallno = t.ev().syscall_event().number;
    if is_sigreturn(syscallno, t.ev().syscall_event().arch()) {
        // There isn't going to be an exit event for this syscall, so remove
        // syscall_state now.
        t.syscall_state = None;
        return s;
    }

    t.syscall_state_unwrap().borrow_mut().done_preparing(t, s)
}

/// DIFF NOTE: Does not take separate TaskSyscallState param
/// as that can be gotten from t directly
fn rec_prepare_syscall_internal(t: &mut RecordTask) -> Switchable {
    let arch: SupportedArch = t.ev().syscall_event().arch();
    let regs = t.regs_ref().clone();
    with_converted_registers(&regs, arch, |converted_regs| {
        rd_arch_function_selfless!(rec_prepare_syscall_arch, arch, t, converted_regs)
    })
}

/// DIFF NOTE: Does not take separate TaskSyscallState param
/// as that can be gotten from t directly
fn rec_prepare_syscall_arch<Arch: Architecture>(
    t: &mut RecordTask,
    regs: &Registers,
) -> Switchable {
    let sys = t.ev().syscall_event().number;

    if t.regs_ref().original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO {
        // rd vetoed this syscall. Don't do any pre-processing.
        return Switchable::PreventSwitch;
    }

    let syscall_state_shr = t.syscall_state_unwrap();
    let mut syscall_state = syscall_state_shr.borrow_mut();
    syscall_state.syscall_entry_registers = regs.clone();

    if !t.desched_rec().is_null() {
        // `t` was descheduled while in a buffered syscall.  We normally don't
        // use scratch memory for the call, because the syscallbuf itself
        // is serving that purpose. More importantly, we *can't* set up
        // scratch for `t`, because it's already in the syscall. Instead, we will
        // record the syscallbuf memory in rec_process_syscall_arch.
        //
        // However there is one case where we use scratch memory: when
        // sys_read's block-cloning path is interrupted. In that case, record
        // the scratch memory.
        if sys == Arch::READ && regs.arg2() == t.scratch_ptr.as_usize() {
            syscall_state.reg_parameter_with_size(
                2,
                ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
                Some(ArgMode::InOutNoScratch),
                None,
            );
        }

        return Switchable::AllowSwitch;
    }

    if sys < 0 {
        // Invalid syscall. Don't let it accidentally match a
        // syscall number below that's for an undefined syscall.
        syscall_state.expect_errno = ENOSYS;
        return Switchable::PreventSwitch;
    }

    include!(concat!(
        env!("OUT_DIR"),
        "/syscall_record_case_generated.rs"
    ));

    if sys == Arch::IOCTL {
        return prepare_ioctl::<Arch>(t, &mut syscall_state);
    }

    if sys == Arch::EXECVE {
        let mut cmd_line = Vec::new();
        let mut argv = RemotePtr::<Arch::unsigned_word>::from(regs.arg2());
        loop {
            let p = read_val_mem(t, argv, None);
            if p == 0.into() {
                break;
            }
            let component = t.read_c_str(RemotePtr::new(p.try_into().unwrap()));
            cmd_line.push(OsString::from_vec(component.into_bytes()));
            argv += 1;
        }

        // Save the event. We can't record it here because the exec might fail.
        let raw_filename = t.read_c_str(RemotePtr::from(regs.arg1()));
        syscall_state.exec_saved_event = Some(Box::new(TraceTaskEvent::for_exec(
            t.tid,
            &OsString::from_vec(raw_filename.into_bytes()),
            &cmd_line,
        )));

        // This can trigger unstable exits of non-main threads, so we have to
        // allow them to be handled.
        return Switchable::AllowSwitch;
    }

    if sys == Arch::RT_SIGPROCMASK || sys == Arch::SIGPROCMASK {
        syscall_state.reg_parameter::<Arch::kernel_sigset_t>(3, None, None);
        syscall_state.reg_parameter::<Arch::kernel_sigset_t>(
            2,
            Some(ArgMode::In),
            Some(Box::new(protect_rd_sigs)),
        );

        return Switchable::PreventSwitch;
    }

    if sys == Arch::WRITE || sys == Arch::WRITEV {
        let fd = regs.arg1_signed() as i32;
        return t.fd_table().will_write(t, fd);
    }

    if sys == Arch::EXIT_GROUP {
        if t.thread_group().task_set().len() == 1 {
            prepare_exit(t, regs.arg1() as i32);
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::EXIT {
        prepare_exit(t, regs.arg1() as i32);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::ARCH_PRCTL {
        match regs.arg1_signed() as u32 {
            ARCH_SET_FS | ARCH_SET_GS => (),

            ARCH_GET_FS | ARCH_GET_GS => {
                syscall_state.reg_parameter::<Arch::unsigned_long>(2, None, None);
            }

            ARCH_SET_CPUID => {
                if SessionInner::has_cpuid_faulting() {
                    // Prevent the actual SET_CPUID call.
                    let mut r: Registers = t.regs_ref().clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    let val = t.regs_ref().arg2() as i32;
                    t.cpuid_mode = if val != 0 { 1 } else { 0 };
                    syscall_state.emulate_result(0);
                }
            }

            ARCH_GET_CPUID => {
                if SessionInner::has_cpuid_faulting() {
                    // Prevent the actual GET_CPUID call and return our emulated state.
                    let mut r: Registers = t.regs_ref().clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    syscall_state.emulate_result_signed(t.cpuid_mode as isize);
                }
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }

        return Switchable::PreventSwitch;
    }
    // int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned
    // long arg4, unsigned long arg5);
    if sys == Arch::PRCTL {
        // @TODO This is a arg1_signed() as i32 in rr
        match regs.arg1() as u32 {
            PR_GET_CHILD_SUBREAPER
            | PR_GET_ENDIAN
            | PR_GET_FPEMU
            | PR_GET_FPEXC
            | PR_GET_PDEATHSIG
            | PR_GET_UNALIGN => {
                syscall_state.reg_parameter::<i32>(2, None, None);
            }

            PR_GET_KEEPCAPS
            | PR_GET_NO_NEW_PRIVS
            | PR_GET_TIMERSLACK
            | PR_MCE_KILL
            | PR_MCE_KILL_GET
            | PR_SET_CHILD_SUBREAPER
            | PR_SET_KEEPCAPS
            | PR_SET_NAME
            | PR_SET_PDEATHSIG
            | PR_SET_TIMERSLACK
            | PR_CAP_AMBIENT
            | PR_CAPBSET_DROP
            | PR_CAPBSET_READ
            | PR_GET_SPECULATION_CTRL
            | PR_SET_SPECULATION_CTRL => (),

            PR_SET_DUMPABLE => {
                if regs.arg2() == 0 {
                    // Don't let processes make themselves undumpable. If a process
                    // becomes undumpable, calling perf_event_open on it fails.
                    let mut r: Registers = regs.clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    syscall_state.emulate_result(0);
                    t.thread_group_mut().dumpable = false;
                } else if regs.arg2() == 1 {
                    t.thread_group_mut().dumpable = true;
                }
            }

            PR_GET_DUMPABLE => {
                syscall_state.emulate_result(if t.thread_group().dumpable { 1 } else { 0 });
            }

            PR_GET_SECCOMP => {
                syscall_state.emulate_result(t.prctl_seccomp_status as usize);
            }

            PR_GET_TSC => {
                // Prevent the actual GET_TSC call and return our emulated state.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
                syscall_state.emulate_result(0);
                let child_addr =
                    syscall_state.reg_parameter::<i32>(2, Some(ArgMode::InOutNoScratch), None);
                let tsc_mode = t.tsc_mode;
                write_val_mem(t, child_addr, &tsc_mode, None);
            }

            PR_SET_TSC => {
                // Prevent the actual SET_TSC call.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
                let val = regs.arg2() as i32;
                if val != PR_TSC_ENABLE as i32 && val != PR_TSC_SIGSEGV as i32 {
                    syscall_state.emulate_result_signed(-EINVAL as isize);
                } else {
                    syscall_state.emulate_result(0);
                    t.tsc_mode = val;
                }
            }

            PR_GET_NAME => {
                syscall_state.reg_parameter_with_size(2, ParamSize::from(16), None, None);
            }

            PR_SET_NO_NEW_PRIVS => {
                // @TODO in rr there is a cast to unsigned long
                if regs.arg2() != 1 {
                    syscall_state.expect_errno = EINVAL;
                }
            }

            PR_SET_SECCOMP => {
                // Allow all known seccomp calls. We must allow the seccomp call
                // that rr triggers when spawning the initial tracee.
                match regs.arg2() as u32 {
                    SECCOMP_MODE_STRICT => (),
                    SECCOMP_MODE_FILTER => {
                        // If we're bootstrapping then this must be rr's own syscall
                        // filter, so just install it normally now.
                        if t.session().done_initial_exec() {
                            // Prevent the actual prctl call. We'll fix this up afterwards.
                            let mut r: Registers = regs.clone();
                            r.set_arg1_signed(-1);
                            t.set_regs(&r);
                        }
                    }
                    _ => {
                        syscall_state.expect_errno = EINVAL;
                    }
                }
            }

            PR_SET_PTRACER => {
                // Prevent any PR_SET_PTRACER call, but pretend it succeeded, since
                // we don't want any interference with our ptracing.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
                syscall_state.emulate_result(0);
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::BRK
        || sys == Arch::MUNMAP
        || sys == Arch::PROCESS_VM_READV
        || sys == Arch::PROCESS_VM_WRITEV
        || sys == SYS_rdcall_notify_syscall_hook_exit as i32
        || sys == Arch::MREMAP
        || sys == Arch::SHMAT
        || sys == Arch::SHMDT
    {
        return Switchable::PreventSwitch;
    }

    // futex parameters are in-out but they can't be moved to scratch
    // addresses.
    if sys == Arch::FUTEX_TIME64 || sys == Arch::FUTEX {
        let op = regs.arg2_signed() as i32;
        match op & FUTEX_CMD_MASK {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => return Switchable::AllowSwitch,

            FUTEX_CMP_REQUEUE | FUTEX_WAKE_OP => {
                syscall_state.reg_parameter::<i32>(5, Some(ArgMode::InOutNoScratch), None);
            }

            FUTEX_WAKE | FUTEX_WAKE_BITSET => (),

            FUTEX_LOCK_PI
            | FUTEX_UNLOCK_PI
            | FUTEX_TRYLOCK_PI
            | FUTEX_CMP_REQUEUE_PI
            | FUTEX_WAIT_REQUEUE_PI => {
                let mut r: Registers = regs.clone();
                r.set_arg2_signed(-1);
                t.set_regs(&r);
                syscall_state.emulate_result_signed(-ENOSYS as isize);
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::MMAP {
        match Arch::MMAP_SEMANTICS {
            MmapCallingSemantics::StructArguments => {
                let args = read_val_mem(t, RemotePtr::<mmap_args<Arch>>::from(regs.arg1()), None);
                let mmap_flags = args.flags;
                // XXX fix this
                ed_assert!(t, mmap_flags & MAP_GROWSDOWN == 0);
            }
            MmapCallingSemantics::RegisterArguments => {
                prepare_mmap_register_params(t);
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::MPROTECT {
        // Since we're stripping MAP_GROWSDOWN from kernel mmap calls, we need
        // to implement PROT_GROWSDOWN ourselves.
        t.vm_shr_ptr().fixup_mprotect_growsdown_parameters(t);
        return Switchable::PreventSwitch;
    }

    // Various syscalls that can block but don't otherwise have behavior we need
    // to record.
    if sys == Arch::FDATASYNC
        || sys == Arch::FSYNC
        || sys == Arch::MSGSND
        || sys == Arch::MSYNC
        || sys == Arch::OPEN
        || sys == Arch::OPENAT
        || sys == Arch::SEMOP
        || sys == Arch::SEMTIMEDOP_TIME64
        || sys == Arch::SEMTIMEDOP
        || sys == Arch::SYNC
        || sys == Arch::SYNC_FILE_RANGE
        || sys == Arch::SYNCFS
    {
        return Switchable::AllowSwitch;
    }

    if sys ==  Arch::PREAD64||
    /* ssize_t read(int fd, void *buf, size_t count); */
    sys == Arch::READ
    {
        let fd = regs.arg1() as i32;
        let mut result: usize = 0;
        let mut ranges = Vec::<file_monitor::Range>::new();
        ranges.push(file_monitor::Range::new(
            RemotePtr::from(regs.arg2()),
            regs.arg3(),
        ));
        let mut offset = LazyOffset::new(t, regs, sys);
        if offset
            .task()
            .fd_table_shr_ptr()
            .emulate_read(fd, &ranges, &mut offset, &mut result)
        {
            // Don't perform this syscall.
            let mut r: Registers = regs.clone();
            r.set_arg1_signed(-1);
            t.set_regs(&r);
            record_ranges(t, &ranges, result);
            syscall_state.emulate_result(result);

            return Switchable::PreventSwitch;
        }

        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
            None,
            None,
        );

        return Switchable::AllowSwitch;
    }

    if sys == SYS_rdcall_notify_control_msg as i32 || sys == SYS_rdcall_init_preload as i32 {
        syscall_state.emulate_result(0);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SIGACTION || sys == Arch::RT_SIGACTION {
        syscall_state.reg_parameter::<kernel_sigaction<Arch>>(
            2,
            Some(ArgMode::In),
            Some(Box::new(protect_rd_sigs_sa_mask)),
        );
        syscall_state.reg_parameter::<kernel_sigaction<Arch>>(3, Some(ArgMode::Out), None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::CLOSE {
        if t.fd_table().is_rd_fd(regs.arg1() as i32) {
            // Don't let processes close this fd. Abort with EBADF by setting
            // oldfd to -1, as if the fd is already closed.
            let mut r: Registers = regs.clone();
            r.set_arg1_signed(-1);
            t.set_regs(&r);
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::FCNTL || sys == Arch::FCNTL64 {
        let fd = regs.arg1() as i32;
        let mut result: usize = 0;
        if t.fd_table_shr_ptr().emulate_fcntl(fd, t, &mut result) {
            // Don't perform this syscall.
            let mut r: Registers = regs.clone();
            r.set_arg1_signed(-1);
            t.set_regs(&r);
            syscall_state.emulate_result(result);
            return Switchable::PreventSwitch;
        }

        let operation = unsafe { transmute(regs.arg2_signed() as i32) };
        match operation {
            FcntlOperation::DUPFD
            | FcntlOperation::DUPFD_CLOEXEC
            | FcntlOperation::GETFD
            | FcntlOperation::GETFL
            | FcntlOperation::SETFL
            | FcntlOperation::SETLK
            | FcntlOperation::SETLK64
            | FcntlOperation::OFD_SETLK
            | FcntlOperation::SETOWN
            | FcntlOperation::SETOWN_EX
            | FcntlOperation::GETSIG
            | FcntlOperation::SETSIG
            | FcntlOperation::SETPIPE_SZ
            | FcntlOperation::GETPIPE_SZ
            | FcntlOperation::ADD_SEALS
            | FcntlOperation::SET_RW_HINT
            | FcntlOperation::SET_FILE_RW_HINT => (),

            FcntlOperation::SETFD => {
                if t.fd_table().is_rd_fd(fd) {
                    // Don't let tracee set FD_CLOEXEC on this fd. Disable the syscall,
                    // but emulate a successful return.
                    let mut r: Registers = regs.clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    syscall_state.emulate_result(0);
                }
            }

            FcntlOperation::GETLK => {
                syscall_state.reg_parameter::<Arch::_flock>(3, Some(ArgMode::InOut), None);
            }

            FcntlOperation::OFD_GETLK | FcntlOperation::GETLK64 => {
                // flock and flock64 better be different on 32-bit architectures,
                // but on 64-bit architectures, it's OK if they're the same.
                // @TODO assertion here
                syscall_state.reg_parameter::<Arch::flock64>(3, Some(ArgMode::InOut), None);
            }

            FcntlOperation::GETOWN_EX => {
                syscall_state.reg_parameter::<Arch::f_owner_ex>(3, None, None);
            }

            FcntlOperation::SETLKW | FcntlOperation::SETLKW64 | FcntlOperation::OFD_SETLKW => {
                // SETLKW blocks, but doesn't write any
                // outparam data to the `struct flock`
                // argument, so no need for scratch.
                return Switchable::AllowSwitch;
            }

            FcntlOperation::GET_RW_HINT | FcntlOperation::GET_FILE_RW_HINT => {
                syscall_state.reg_parameter::<i64>(3, None, None);
            }

            _ => {
                // Unknown command should trigger EINVAL.
                syscall_state.expect_errno = EINVAL;
            }
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::DUP2 || sys == Arch::DUP3 {
        if t.fd_table().is_rd_fd(regs.arg2() as i32) {
            // Don't let processes dup over this fd. Abort with EBADF by setting
            // oldfd to -1.
            let mut r: Registers = regs.clone();
            r.set_arg1_signed(-1);
            t.set_regs(&r);
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::MMAP2 {
        prepare_mmap_register_params(t);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::GET_THREAD_AREA || sys == Arch::SET_THREAD_AREA {
        syscall_state.reg_parameter::<Arch::user_desc>(1, Some(ArgMode::InOut), None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SIGSUSPEND || sys == Arch::RT_SIGSUSPEND {
        t.invalidate_sigmask();
        return Switchable::AllowSwitch;
    }

    if sys == Arch::SIGRETURN || sys == Arch::RT_SIGRETURN {
        t.invalidate_sigmask();
        return Switchable::PreventSwitch;
    }

    if sys == Arch::ACCEPT || sys == Arch::ACCEPT4 {
        let addrlen_ptr =
            syscall_state.reg_parameter::<common::socklen_t>(3, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_initialized_mem(t, addrlen_ptr),
            None,
            None,
        );
        return Switchable::AllowSwitch;
    }

    if sys == Arch::GETCWD {
        syscall_state.reg_parameter_with_size(
            1,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg2()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::GETDENTS || sys == Arch::GETDENTS64 {
        syscall_state.reg_parameter_with_size(
            2,
            // @TODO Is the cast to u32 neccessary?
            ParamSize::from_syscall_result_with_size::<i32>(regs.arg3() as u32 as usize),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::READLINK {
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::READLINKAT {
        syscall_state.reg_parameter_with_size(
            3,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg4()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::IO_SETUP {
        // Prevent the io_setup from running and fake an ENOSYS return. We want
        // to discourage applications from using this API because the async
        // reads are writes by the kernel that can race with userspace execution.
        let mut r: Registers = regs.clone();
        r.set_arg2(0);
        t.set_regs(&r);
        syscall_state.emulate_result_signed(-ENOSYS as isize);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::MEMFD_CREATE {
        let name = t.read_c_str(regs.arg1().into());
        if is_blacklisted_memfd(&name) {
            log!(LogWarn, "Cowardly refusing to memfd_create {:?}", name);
            let mut r: Registers = regs.clone();
            r.set_arg1(0);
            t.set_regs(&r);
            syscall_state.emulate_result_signed(-ENOSYS as isize);
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::GETGROUPS {
        // We could record a little less data by restricting the recorded data
        // to the syscall result * sizeof(Arch::legacy_gid_t), but that would
        // require more infrastructure and it's not worth worrying about.
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(regs.arg1_signed() as u32 as usize * size_of::<Arch::legacy_gid_t>()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::GETGROUPS32 {
        // We could record a little less data by restricting the recorded data
        // to the syscall result * sizeof(Arch::gid_t), but that would
        // require more infrastructure and it's not worth worrying about.
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(regs.arg1_signed() as u32 as usize * size_of::<common::gid_t>()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::FORK || sys == Arch::VFORK || sys == Arch::CLONE {
        prepare_clone::<Arch>(t, &mut syscall_state);
        return Switchable::AllowSwitch;
    }

    // pid_t waitpid(pid_t pid, int *status, int options);
    // pid_t wait4(pid_t pid, int *status, int options, struct rusage
    // *rusage);
    //
    if sys == Arch::WAITPID || sys == Arch::WAIT4 {
        syscall_state.reg_parameter::<i32>(2, Some(ArgMode::InOut), None);
        if sys == Arch::WAIT4 {
            syscall_state.reg_parameter::<Arch::rusage>(4, None, None);
        }
        let pid: pid_t = regs.arg1_signed() as pid_t;
        if pid < -1 {
            t.in_wait_type = WaitType::WaitTypePgid;
            t.in_wait_pid = -pid;
        } else if pid == -1 {
            t.in_wait_type = WaitType::WaitTypeAny;
        } else if pid == 0 {
            t.in_wait_type = WaitType::WaitTypeSamePgid;
        } else {
            t.in_wait_type = WaitType::WaitTypePid;
            t.in_wait_pid = pid;
        }
        let options = regs.arg3() as i32;
        if maybe_emulate_wait(t, &mut syscall_state, options) {
            let mut r: Registers = regs.clone();
            // Set options to an invalid value to force syscall to fail
            r.set_arg3(0xffffffff);
            t.set_regs(&r);
            return Switchable::PreventSwitch;
        }
        maybe_pause_instead_of_waiting(t, options);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::WAITID {
        syscall_state.reg_parameter::<Arch::siginfo_t>(3, Some(ArgMode::InOut), None);
        // Kludge
        t.in_wait_pid = regs.arg2() as id_t as pid_t;
        match regs.arg1() as idtype_t {
            P_ALL => {
                t.in_wait_type = WaitType::WaitTypeAny;
            }
            P_PID => {
                t.in_wait_type = WaitType::WaitTypePid;
            }
            P_PGID => {
                t.in_wait_type = WaitType::WaitTypePgid;
            }
            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        let options: i32 = regs.arg4() as i32;
        if maybe_emulate_wait(t, &mut syscall_state, options) {
            let mut r: Registers = regs.clone();
            // Set options to an invalid value to force syscall to fail
            r.set_arg4(0xffffffff);
            t.set_regs(&r);
            return Switchable::PreventSwitch;
        }
        maybe_pause_instead_of_waiting(t, options);
        return Switchable::AllowSwitch;
    }

    // The following two syscalls enable context switching not for
    // liveness/correctness reasons, but rather because if we
    // didn't context-switch away, rr might end up busy-waiting
    // needlessly.  In addition, albeit far less likely, the
    // client program may have carefully optimized its own context
    // switching and we should take the hint.
    if sys == Arch::NANOSLEEP {
        syscall_state.reg_parameter::<Arch::timespec>(2, None, None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::CLOCK_NANOSLEEP {
        syscall_state.reg_parameter::<Arch::timespec>(4, None, None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::MADVISE {
        match regs.arg3() as i32 {
            MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTNEED
            | MADV_REMOVE | MADV_DONTFORK | MADV_DOFORK | MADV_SOFT_OFFLINE | MADV_HWPOISON
            | MADV_MERGEABLE | MADV_UNMERGEABLE | MADV_HUGEPAGE | MADV_NOHUGEPAGE
            | MADV_DONTDUMP | MADV_DODUMP => (),
            MADV_FREE => {
                // MADV_FREE introduces nondeterminism --- the kernel zeroes the
                // pages when under memory pressure. So we don't allow it.
                let mut r: Registers = regs.clone();
                r.set_arg3_signed(-1);
                t.set_regs(&r);
            }
            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SCHED_YIELD {
        t.session()
            .as_record()
            .unwrap()
            .scheduler()
            .schedule_one_round_robin(t);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::GETXATTR || sys == Arch::LGETXATTR || sys == Arch::FGETXATTR {
        syscall_state.reg_parameter_with_size(
            3,
            ParamSize::from_syscall_result_with_size::<isize>(regs.arg4()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::LISTXATTR || sys == Arch::LLISTXATTR || sys == Arch::FLISTXATTR {
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_syscall_result_with_size::<isize>(regs.arg3()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SCHED_GETATTR {
        syscall_state.reg_parameter_with_size(2, ParamSize::from(regs.arg3()), None, None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SCHED_SETAFFINITY {
        // Ignore all sched_setaffinity syscalls. They might interfere
        // with our own affinity settings.
        let mut r: Registers = regs.clone();
        // Set arg1 to an invalid PID to ensure this syscall is ignored.
        r.set_arg1_signed(-1);
        t.set_regs(&r);
        syscall_state.emulate_result(0);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SCHED_GETAFFINITY {
        syscall_state.reg_parameter_with_size(3, ParamSize::from(regs.arg2()), None, None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SECCOMP {
        match regs.arg1() as u32 {
            SECCOMP_SET_MODE_STRICT => (),
            SECCOMP_SET_MODE_FILTER => {
                // Prevent the actual seccomp call. We'll fix this up afterwards.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
            }
            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SETPRIORITY {
        // The syscall might fail due to insufficient
        // permissions (e.g. while trying to decrease the nice value
        // while not root).
        // We'll choose to honor the new value anyway since we'd like
        // to be able to test configurations where a child thread
        // has a lower nice value than its parent, which requires
        // lowering the child's nice value.
        if regs.arg1() as u32 == PRIO_PROCESS {
            let tid = regs.arg2_signed() as pid_t;
            let found_rc: TaskSharedPtr;
            let mut found_b;
            let maybe_target = if tid == t.rec_tid || tid == 0 {
                Some(t)
            } else {
                match t.session().find_task_from_rec_tid(tid) {
                    Some(found) => {
                        found_rc = found;
                        found_b = found_rc.borrow_mut();
                        Some(found_b.as_rec_mut_unwrap())
                    }
                    None => None,
                }
            };

            match maybe_target {
                Some(target) => {
                    log!(
                        LogDebug,
                        "Setting nice value for tid {} to {}",
                        target.tid,
                        regs.arg3()
                    );
                    target
                        .session()
                        .as_record()
                        .unwrap()
                        .scheduler()
                        .update_task_priority(target, regs.arg3_signed() as i32);
                }
                None => (),
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SPLICE {
        syscall_state.reg_parameter::<loff_t>(2, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter::<loff_t>(4, Some(ArgMode::InOut), None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::SENDFILE {
        syscall_state.reg_parameter::<Arch::off_t>(3, Some(ArgMode::InOut), None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::SENDFILE64 {
        syscall_state.reg_parameter::<off64_t>(3, Some(ArgMode::InOut), None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::GETRANDOM {
        syscall_state.reg_parameter_with_size(
            1,
            ParamSize::from_syscall_result_with_size::<i32>(regs.arg2()),
            None,
            None,
        );
        return if GRND_NONBLOCK as usize & regs.arg3() != 0 {
            Switchable::PreventSwitch
        } else {
            Switchable::AllowSwitch
        };
    }

    if sys == Arch::SYSFS {
        let option = regs.arg1() as i32;
        match option {
            1 | 3 => (),
            2 => {
                let remote_buf = RemotePtr::<u8>::from(regs.arg3());
                // Assume no filesystem type name is more than 1K
                let mut buf = Vec::<u8>::with_capacity(1024);
                buf.resize(1024, 0);
                match t.read_bytes_fallible(remote_buf, &mut buf) {
                    Ok(nread) if nread > 0 => {
                        syscall_state.reg_parameter_with_size(
                            3,
                            ParamSize::from(nread),
                            None,
                            None,
                        );
                    }
                    _ => (),
                }
            }
            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::COPY_FILE_RANGE {
        syscall_state.reg_parameter::<loff_t>(2, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter::<loff_t>(4, Some(ArgMode::InOut), None);
        let in_fd = regs.arg1_signed() as i32;
        let out_fd = regs.arg3_signed() as i32;
        ed_assert!(
            t,
            !t.fd_table().is_monitoring(in_fd),
            "copy_file_range for monitored fds not supported yet"
        );
        ed_assert!(
            t,
            !t.fd_table().is_monitoring(out_fd),
            "copy_file_range for monitored fds not supported yet"
        );
        return Switchable::AllowSwitch;
    }

    if sys == Arch::PAUSE {
        return Switchable::AllowSwitch;
    }

    if sys == SYS_rdcall_init_buffers as i32 {
        // This is purely for testing purposes. See signal_during_preload_init.
        if send_signal_during_init_buffers() {
            unsafe { libc::syscall(SYS_tgkill, t.tgid(), t.tid, SIGCHLD) };
        }
        syscall_state.reg_parameter::<rdcall_init_buffers_params<Arch>>(
            1,
            Some(ArgMode::InOut),
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::PPOLL_TIME64 || sys == Arch::PPOLL {
        // The raw syscall modifies this with the time remaining. The libc
        // does not expose this functionality however
        if sys == Arch::PPOLL {
            syscall_state.reg_parameter::<Arch::timespec>(3, Some(ArgMode::InOut), None);
        } else {
            syscall_state.reg_parameter::<x64::timespec>(3, Some(ArgMode::InOut), None);
        }
        syscall_state.reg_parameter::<Arch::kernel_sigset_t>(
            4,
            Some(ArgMode::In),
            Some(Box::new(protect_rd_sigs)),
        );
        t.invalidate_sigmask();

        // This needs to fall through to the next if
    }

    if sys == Arch::PPOLL_TIME64 || sys == Arch::PPOLL || sys == Arch::POLL {
        let nfds = regs.arg2();
        syscall_state.reg_parameter_with_size(
            1,
            ParamSize::from(size_of::<Arch::pollfd>() * nfds),
            Some(ArgMode::InOut),
            None,
        );

        return Switchable::AllowSwitch;
    }

    if sys == Arch::CONNECT {
        return maybe_blacklist_connect::<Arch>(t, regs.arg2().into(), regs.arg3() as socklen_t);
    }

    if sys == Arch::RECVFROM {
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
            None,
            None,
        );
        let addrlen_ptr =
            syscall_state.reg_parameter::<common::socklen_t>(6, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter_with_size(
            5,
            ParamSize::from_initialized_mem(t, addrlen_ptr),
            None,
            None,
        );
        return Switchable::AllowSwitch;
    }

    if sys == Arch::SENDTO {
        if regs.arg4() as i32 & MSG_DONTWAIT == 0 {
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SENDMSG {
        if regs.arg3() as i32 & MSG_DONTWAIT == 0 {
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SENDMMSG {
        let vlen = regs.arg3() as u32 as usize;
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(size_of::<mmsghdr<Arch>>() * vlen),
            Some(ArgMode::InOut),
            None,
        );
        if regs.arg4() as i32 & MSG_DONTWAIT == 0 {
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::PSELECT6_TIME64 || sys == Arch::PSELECT6 {
        syscall_state.reg_parameter::<Arch::fd_set>(2, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter::<Arch::fd_set>(3, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter::<Arch::fd_set>(4, Some(ArgMode::InOut), None);
        if sys == Arch::PSELECT6 {
            syscall_state.reg_parameter::<Arch::timespec>(5, Some(ArgMode::InOut), None);
        } else {
            syscall_state.reg_parameter::<x64::timespec>(5, Some(ArgMode::InOut), None);
        }
        let arg6p = syscall_state.reg_parameter::<pselect6_arg6<Arch>>(6, Some(ArgMode::In), None);
        let child_addr = RemotePtr::<Ptr<Arch::unsigned_word, Arch::kernel_sigset_t>>::cast(
            arg6p.as_rptr_u8() + offset_of!(pselect6_arg6<Arch>, ss),
        );
        syscall_state.mem_ptr_parameter_inferred::<Arch, Arch::kernel_sigset_t>(
            t,
            child_addr,
            Some(ArgMode::In),
            Some(Box::new(protect_rd_sigs)),
        );
        t.invalidate_sigmask();
        return Switchable::AllowSwitch;
    }

    if sys == Arch::SELECT || sys == Arch::_NEWSELECT {
        if sys == Arch::SELECT
            && Arch::SELECT_SEMANTICS == SelectCallingSemantics::SelectStructArguments
        {
            let argsp =
                syscall_state.reg_parameter::<select_args<Arch>>(1, Some(ArgMode::In), None);

            syscall_state.mem_ptr_parameter_inferred::<Arch, Arch::fd_set>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, select_args<Arch>, read_fds)),
                Some(ArgMode::InOut),
                None,
            );
            syscall_state.mem_ptr_parameter_inferred::<Arch, Arch::fd_set>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, select_args<Arch>, write_fds)),
                Some(ArgMode::InOut),
                None,
            );
            syscall_state.mem_ptr_parameter_inferred::<Arch, Arch::fd_set>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, select_args<Arch>, except_fds)),
                Some(ArgMode::InOut),
                None,
            );
            syscall_state.mem_ptr_parameter_inferred::<Arch, Arch::timeval>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, select_args<Arch>, timeout)),
                Some(ArgMode::InOut),
                None,
            );
        } else {
            syscall_state.reg_parameter::<Arch::fd_set>(2, Some(ArgMode::InOut), None);
            syscall_state.reg_parameter::<Arch::fd_set>(3, Some(ArgMode::InOut), None);
            syscall_state.reg_parameter::<Arch::fd_set>(4, Some(ArgMode::InOut), None);
            syscall_state.reg_parameter::<Arch::timeval>(5, Some(ArgMode::InOut), None);
        }
        return Switchable::AllowSwitch;
    }

    if sys == Arch::RECVMSG {
        let msgp = syscall_state.reg_parameter::<msghdr<Arch>>(2, Some(ArgMode::InOut), None);
        prepare_recvmsg::<Arch>(
            t,
            &mut syscall_state,
            msgp,
            ParamSize::from_syscall_result::<Arch::ssize_t>(),
        );
        if regs.arg3() as i32 & MSG_DONTWAIT == 0 {
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::RECVMMSG_TIME64 || sys == Arch::RECVMMSG {
        let vlen = regs.arg3() as u32 as usize;
        let mmsgp = RemotePtr::<mmsghdr<Arch>>::cast(syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(size_of::<mmsghdr<Arch>>() * vlen),
            Some(ArgMode::InOut),
            None,
        ));
        prepare_recvmmsg::<Arch>(t, &mut syscall_state, mmsgp, vlen);
        if regs.arg4() as i32 & MSG_DONTWAIT == 0 {
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    // int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
    if sys == Arch::EPOLL_WAIT {
        // DIFF NOTE: This is arg3_signed in rr
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(size_of::<Arch::epoll_event>() * regs.arg3()),
            None,
            None,
        );
        return Switchable::AllowSwitch;
    }

    if sys == Arch::EPOLL_PWAIT {
        // DIFF NOTE: This is arg3_signed() in rr
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(size_of::<Arch::epoll_event>() * regs.arg3()),
            None,
            None,
        );
        t.invalidate_sigmask();
        return Switchable::AllowSwitch;
    }

    if sys == Arch::CAPGET {
        let child_addr = syscall_state.reg_parameter::<arch_structs::__user_cap_header_struct>(
            1,
            Some(ArgMode::InOut),
            None,
        );
        let hdr = read_val_mem(t, child_addr, None);
        let struct_count: usize;
        match hdr.version {
            _LINUX_CAPABILITY_VERSION_1 => {
                struct_count = _LINUX_CAPABILITY_U32S_1 as usize;
            }
            _LINUX_CAPABILITY_VERSION_2 => {
                struct_count = _LINUX_CAPABILITY_U32S_2 as usize;
            }
            _LINUX_CAPABILITY_VERSION_3 => {
                struct_count = _LINUX_CAPABILITY_U32S_3 as usize;
            }
            _ => {
                struct_count = 0;
            }
        }
        if struct_count > 0 {
            syscall_state.reg_parameter_with_size(
                2,
                ParamSize::from(size_of::<arch_structs::__user_cap_data_struct>() * struct_count),
                Some(ArgMode::Out),
                None,
            );
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::MQ_TIMEDRECEIVE_TIME64 || sys == Arch::MQ_TIMEDRECEIVE {
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
            None,
            None,
        );
        syscall_state.reg_parameter::<u32>(4, None, None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::MODIFY_LDT {
        let func = regs.arg1() as i32;
        if func == 0 || func == 2 {
            syscall_state.reg_parameter_with_size(
                2,
                ParamSize::from_syscall_result_with_size::<i32>(regs.arg3()),
                None,
                None,
            );
        }
        // N.B. Unlike set_thread_area, the entry number is not written
        // for (func == 1 || func == 0x11)
        return Switchable::AllowSwitch;
    }

    if sys == Arch::NAME_TO_HANDLE_AT {
        syscall_state.reg_parameter_with_size(
            3,
            ParamSize::from(size_of::<fcntl::file_handle>() + fcntl::MAX_HANDLE_SZ as usize),
            None,
            None,
        );
        syscall_state.reg_parameter::<i32>(4, None, None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::MINCORE {
        syscall_state.reg_parameter_with_size(
            3,
            ParamSize::from((regs.arg2() + page_size() - 1) / page_size()),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::CLOCK_NANOSLEEP_TIME64 {
        syscall_state.reg_parameter::<x64::timespec>(4, None, None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::RT_SIGPENDING {
        syscall_state.reg_parameter_with_size(1, ParamSize::from(regs.arg2()), None, None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::RT_SIGTIMEDWAIT_TIME64 || sys == Arch::RT_SIGTIMEDWAIT {
        syscall_state.reg_parameter::<Arch::siginfo_t>(2, None, None);
        return Switchable::AllowSwitch;
    }

    if sys == Arch::GET_MEMPOLICY {
        syscall_state.reg_parameter::<i32>(1, None, None);
        let maxnode = t.regs_ref().arg3();
        let align_mask = 8 * size_of::<Arch::unsigned_long>() - 1;
        let aligned_maxnode = (maxnode + align_mask) & !align_mask;
        syscall_state.reg_parameter_with_size(2, ParamSize::from(aligned_maxnode / 8), None, None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SETSOCKOPT {
        let args = setsockopt_args::<Arch> {
            sockfd: Arch::usize_as_signed_long(regs.arg1()),
            level: Arch::usize_as_signed_long(regs.arg2()),
            optname: Arch::usize_as_signed_long(regs.arg3()),
            optval: Arch::from_remote_ptr(RemotePtr::from(regs.arg4())),
            optlen: Arch::usize_as_signed_long(regs.arg5()),
        };
        return prepare_setsockopt::<Arch>(t, &mut syscall_state, &args);
    }

    if sys == Arch::GETSOCKNAME || sys == Arch::GETPEERNAME {
        let addrlen_ptr =
            syscall_state.reg_parameter::<common::socklen_t>(3, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_initialized_mem(t, addrlen_ptr),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::GETSOCKOPT {
        let optlen_ptr =
            syscall_state.reg_parameter::<common::socklen_t>(5, Some(ArgMode::InOut), None);
        syscall_state.reg_parameter_with_size(
            4,
            ParamSize::from_initialized_mem(t, optlen_ptr),
            None,
            None,
        );
        return Switchable::PreventSwitch;
    }

    if sys == Arch::KEYCTL {
        match regs.arg1() as u32 {
            KEYCTL_GET_KEYRING_ID
            | KEYCTL_JOIN_SESSION_KEYRING
            | KEYCTL_UPDATE
            | KEYCTL_REVOKE
            | KEYCTL_CHOWN
            | KEYCTL_SETPERM
            | KEYCTL_CLEAR
            | KEYCTL_LINK
            | KEYCTL_UNLINK
            | KEYCTL_SEARCH
            | KEYCTL_INSTANTIATE
            | KEYCTL_INSTANTIATE_IOV
            | KEYCTL_NEGATE
            | KEYCTL_REJECT
            | KEYCTL_SET_REQKEY_KEYRING
            | KEYCTL_SET_TIMEOUT
            | KEYCTL_ASSUME_AUTHORITY
            | KEYCTL_SESSION_TO_PARENT
            | KEYCTL_INVALIDATE => (),

            KEYCTL_DESCRIBE | KEYCTL_READ | KEYCTL_GET_SECURITY | KEYCTL_DH_COMPUTE => {
                syscall_state.reg_parameter_with_size(
                    3,
                    ParamSize::from_syscall_result_with_size::<Arch::signed_long>(regs.arg4()),
                    None,
                    None,
                );
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::QUOTACTL {
        match (regs.arg1() >> SUBCMDSHIFT) as i32 {
            Q_GETQUOTA => {
                syscall_state.reg_parameter::<Arch::dqblk>(4, None, None);
            }
            Q_GETINFO => {
                syscall_state.reg_parameter::<Arch::dqinfo>(4, None, None);
            }
            Q_GETFMT => {
                syscall_state.reg_parameter::<i32>(4, None, None);
            }
            Q_SETQUOTA => {
                fatal!("Trying to set disk quota usage, this may interfere with rd recording");
            }

            Q_QUOTAON | Q_QUOTAOFF | Q_SETINFO | Q_SYNC => (),
            // Don't set expect_errno here because quotactl can fail with
            // various error codes before checking the command
            _ => (),
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::PERSONALITY {
        // DIFF NOTE: This cast to i32 is not present in rr
        let p = regs.arg1_signed() as i32;
        if p == -1 {
            // A special argument that only returns the existing personality.
            return Switchable::PreventSwitch;
        }

        match (p as u8) as u32 {
            // The default personality requires no handling.
            PER_LINUX32 | PER_LINUX => (),
            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }

        if t.session().as_record().unwrap().enable_chaos() {
            // XXX fix this to actually disable chaos mode ASLR?
            ed_assert_eq!(
                t,
                p & (ADDR_COMPAT_LAYOUT | ADDR_NO_RANDOMIZE | ADDR_LIMIT_32BIT | ADDR_LIMIT_3GB),
                0,
                "Personality value {:#x} not compatible with chaos mode addres-space randomization",
                p
            );
        }
        if (((p as u32 & 0xffffff00) as i32)
            & !(ADDR_COMPAT_LAYOUT
                | ADDR_NO_RANDOMIZE
                | ADDR_LIMIT_32BIT
                | ADDR_LIMIT_3GB
                | FDPIC_FUNCPTRS
                | MMAP_PAGE_ZERO
                | SHORT_INODE
                | STICKY_TIMEOUTS
                | UNAME26
                | WHOLE_SECONDS
                | READ_IMPLIES_EXEC))
            != 0
        {
            syscall_state.expect_errno = EINVAL;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::PTRACE {
        return prepare_ptrace::<Arch>(t, &mut syscall_state);
    }

    if sys == Arch::MSGCTL {
        return prepare_msgctl::<Arch>(&mut syscall_state, regs.arg2() as u32, 3);
    }

    if sys == Arch::MSGRCV {
        let msgsize = regs.arg3();
        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(size_of::<Arch::signed_long>() + msgsize),
            None,
            None,
        );

        return Switchable::AllowSwitch;
    }

    if sys == Arch::_SYSCTL {
        let argsp = syscall_state.reg_parameter::<__sysctl_args<Arch>>(1, Some(ArgMode::In), None);
        let oldlenp_buf_ptr = RemotePtr::<Ptr<Arch::unsigned_word, Arch::size_t>>::cast(
            remote_ptr_field!(argsp, __sysctl_args<Arch>, oldlenp),
        );
        let oldlenp = syscall_state.mem_ptr_parameter_inferred::<Arch, Arch::size_t>(
            t,
            oldlenp_buf_ptr,
            Some(ArgMode::InOut),
            None,
        );
        let oldval_buf_ptr =
            RemotePtr::<u8>::cast(remote_ptr_field!(argsp, __sysctl_args<Arch>, oldval));
        let param_size = ParamSize::from_initialized_mem(t, oldlenp);
        syscall_state.mem_ptr_parameter_with_size(t, oldval_buf_ptr, param_size, None, None);

        return Switchable::PreventSwitch;
    }

    if sys == Arch::SHMCTL {
        return prepare_shmctl::<Arch>(&mut syscall_state, regs.arg2() as u32, 3);
    }

    if sys == Arch::SOCKETCALL {
        return prepare_socketcall::<Arch>(t, &mut syscall_state);
    }

    if sys == Arch::PERF_EVENT_OPEN {
        let tid: pid_t = regs.arg2_signed() as pid_t;
        let target = t.session().find_task_from_rec_tid(tid);
        let cpu = regs.arg3_signed() as i32;
        let flags = regs.arg5();
        if target.is_some() && cpu == -1 && flags == 0 {
            let attr = read_val_mem(t, RemotePtr::<perf_event_attr>::from(regs.arg1()), None);
            if VirtualPerfCounterMonitor::should_virtualize(&attr) {
                let mut r = regs.clone();
                // Turn this into an inotify_init() syscall. This just gives us an
                // allocated fd. Syscalls using this fd will be emulated (except for
                // close()).
                r.set_original_syscallno(Arch::INOTIFY_INIT as isize);
                t.set_regs(&r);
            }
        }
        return Switchable::PreventSwitch;
    }

    // ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
    // ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
    if sys == Arch::READV || sys == Arch::PREADV {
        let fd = regs.arg1_signed() as i32;
        let iovcnt = regs.arg3() as u32 as usize;
        let iovecsp_void = syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from(size_of::<iovec<Arch>>() * iovcnt),
            Some(ArgMode::In),
            None,
        );
        let iovecsp = RemotePtr::<iovec<Arch>>::cast(iovecsp_void);
        let iovecs = read_mem(t, iovecsp, iovcnt, None);
        let mut result: usize = 0;
        let mut ranges = Vec::<Range>::new();
        for i in 0..iovcnt {
            ranges.push(Range::new(
                Arch::as_rptr(iovecs[i].iov_base),
                Arch::size_t_as_usize(iovecs[i].iov_len),
            ));
        }
        let mut offset = LazyOffset::new(t, regs, sys);
        if offset
            .task()
            .fd_table_shr_ptr()
            .emulate_read(fd, &ranges, &mut offset, &mut result)
        {
            // Don't perform this syscall.
            let mut r: Registers = regs.clone();
            r.set_arg1_signed(-1);
            t.set_regs(&r);
            record_ranges(t, &ranges, result);
            syscall_state.emulate_result(result);
            return Switchable::PreventSwitch;
        }
        let io_size = ParamSize::from_syscall_result::<Arch::ssize_t>();
        for i in 0..iovcnt {
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(iovecsp + i, iovec<Arch>, iov_base),
                ParamSize::from(io_size.limit_size(Arch::size_t_as_usize(iovecs[i].iov_len))),
                None,
                None,
            );
        }

        return Switchable::AllowSwitch;
    }

    if sys == Arch::BPF {
        return prepare_bpf::<Arch>(t, &mut syscall_state);
    }

    if sys == Arch::IPC {
        match regs.arg1() as u32 {
            MSGGET | SHMDT | SHMGET | SEMGET => (),

            MSGCTL => {
                let cmd = regs.arg3() as u32 & !IPC_64;
                return prepare_msgctl::<Arch>(&mut syscall_state, cmd, 5);
            }

            MSGSND | SEMOP | SEMTIMEDOP => {
                return Switchable::AllowSwitch;
            }

            MSGRCV => {
                let msgsize = regs.arg3();
                let kluge_args = syscall_state.reg_parameter::<ipc_kludge_args<Arch>>(
                    5,
                    Some(ArgMode::In),
                    None,
                );
                syscall_state.mem_ptr_parameter_with_size(
                    t,
                    remote_ptr_field!(kluge_args, ipc_kludge_args<Arch>, msgbuf),
                    ParamSize::from(size_of::<Arch::signed_long>() + msgsize),
                    None,
                    None,
                );
                return Switchable::AllowSwitch;
            }

            SHMAT => {
                // Insane legacy feature: ipc SHMAT returns its pointer via an
                // in-memory out parameter.
                syscall_state.reg_parameter::<Arch::unsigned_long>(4, None, None);
                return Switchable::PreventSwitch;
            }

            SHMCTL => {
                let cmd = regs.arg3() as u32 & !IPC_64;
                return prepare_shmctl::<Arch>(&mut syscall_state, cmd, 5);
            }

            SEMCTL => {
                let cmd = regs.arg4() as u32 & !IPC_64;
                return prepare_semctl::<Arch>(
                    t,
                    &mut syscall_state,
                    regs.arg2_signed() as i32,
                    cmd,
                    5,
                    SemctlDereference::Dereference,
                );
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SEMCTL {
        return prepare_semctl::<Arch>(
            t,
            &mut syscall_state,
            regs.arg1_signed() as i32,
            regs.arg3() as u32,
            4,
            SemctlDereference::UseDirectly,
        );
    }

    // Invalid syscalls return -ENOSYS. Assume any such
    // result means the syscall was completely ignored by the
    // kernel so it's OK for us to not do anything special.
    // Other results mean we probably need to understand this
    // syscall, but we don't.
    syscall_state.expect_errno = ENOSYS;
    Switchable::PreventSwitch
}

fn is_blacklisted_memfd(name: &CStr) -> bool {
    match name.to_str() {
        Ok(name_str) if name_str == "pulseaudio" => true,
        _ => false,
    }
}

fn maybe_blacklist_connect<Arch: Architecture>(
    t: &mut RecordTask,
    addr_ptr: RemotePtr<Void>,
    addrlen: socklen_t,
) -> Switchable {
    let mut addr: sockaddr_un = unsafe { mem::zeroed() };
    let len = min(size_of_val(&addr), addrlen as usize);
    // DIFF NOTE: In rr there is no check for error. Here we unwrap().
    t.read_bytes_fallible(addr_ptr, &mut u8_slice_mut(&mut addr)[0..len])
        .unwrap();
    // Ensure null termination;
    addr.sun_path[size_of_val(&addr.sun_path) - 1] = 0;
    if addr.sun_family as i32 == AF_UNIX {
        if let Some(file) = is_blacklisted_socket(&addr.sun_path) {
            log!(LogWarn, "Cowardly refusing to connect to {:?}", file);
            // Hijack the syscall.
            let mut r: Registers = t.regs_ref().clone();
            r.set_original_syscallno(Arch::GETTID as isize);
            t.set_regs(&r);
        }
    }

    Switchable::PreventSwitch
}

fn is_blacklisted_socket(filename_in: &[i8; 108]) -> Option<&str> {
    let filename: &[u8; 108] = unsafe { mem::transmute(filename_in) };
    // Blacklist the nscd socket because glibc communicates with the daemon over
    // shared memory rd can't handle.
    let nsd = b"/var/run/nscd/socket\0";
    if &filename[0..nsd.len()] == nsd {
        Some("/var/run/nscd/socket")
    } else {
        None
    }
}

fn maybe_emulate_wait(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    options: i32,
) -> bool {
    for child in &t.emulated_ptrace_tracees {
        let rt_childb = child.borrow();
        let rt_child = rt_childb.as_rec_unwrap();
        if t.is_waiting_for_ptrace(rt_child) && rt_child.emulated_stop_pending {
            syscall_state.emulate_wait_for_child = Some(Rc::downgrade(&child));
            return true;
        }
    }
    if options & WUNTRACED != 0 {
        for child_process in t.thread_group().children() {
            for child in child_process.borrow().task_set() {
                let rchildb = child.borrow();
                let rchild = rchildb.as_rec_unwrap();
                if rchild.emulated_stop_type == EmulatedStopType::GroupStop
                    && rchild.emulated_stop_pending
                    && t.is_waiting_for(rchild)
                {
                    syscall_state.emulate_wait_for_child = Some(Rc::downgrade(&child));
                    return true;
                }
            }
        }
    }

    false
}

fn protect_rd_sigs_sa_mask(
    t: &mut RecordTask,
    p: RemotePtr<Void>,
    maybe_save: Option<&mut [u8]>,
) -> bool {
    let arch = t.arch();
    rd_arch_function_selfless!(protect_rd_sigs_sa_mask_arch, arch, t, p, maybe_save)
}

fn protect_rd_sigs_sa_mask_arch<Arch: Architecture>(
    t: &mut RecordTask,
    p: RemotePtr<Void>,
    maybe_save: Option<&mut [u8]>,
) -> bool {
    let sap = RemotePtr::<kernel_sigaction<Arch>>::cast(p);
    if sap.is_null() {
        return false;
    }

    let mut sa = read_val_mem(t, sap, None);
    let mut new_sig_set = sa.sa_mask;
    // Don't let the tracee block TIME_SLICE_SIGNAL or
    // SYSCALLBUF_DESCHED_SIGNAL.
    new_sig_set &= !t.session().as_record().unwrap().rd_signal_mask();

    if sa.sa_mask == new_sig_set {
        return false;
    }

    match maybe_save {
        Some(save) => unsafe {
            copy_nonoverlapping(
                &raw const sa as *const u8,
                save.as_mut_ptr(),
                size_of::<kernel_sigaction<Arch>>(),
            );
        },
        None => (),
    }
    sa.sa_mask = new_sig_set;
    write_val_mem(t, sap, &sa, None);

    true
}

fn protect_rd_sigs(t: &mut RecordTask, p: RemotePtr<Void>, maybe_save: Option<&mut [u8]>) -> bool {
    let setp = RemotePtr::<sig_set_t>::cast(p);
    if setp.is_null() {
        return false;
    }

    let sig_set = read_val_mem(t, setp, None);
    let mut new_sig_set = sig_set;
    // Don't let the tracee block TIME_SLICE_SIGNAL or
    // SYSCALLBUF_DESCHED_SIGNAL.
    new_sig_set &= !t.session().as_record().unwrap().rd_signal_mask();

    if sig_set == new_sig_set {
        return false;
    }

    write_val_mem(t, setp, &new_sig_set, None);
    match maybe_save {
        Some(save) => unsafe {
            copy_nonoverlapping(
                &raw const sig_set as *const u8,
                save.as_mut_ptr(),
                size_of::<sig_set_t>(),
            );
        },
        None => (),
    }

    true
}

fn record_ranges(t: &mut RecordTask, ranges: &[file_monitor::Range], size: usize) {
    let mut s = size;
    for r in ranges {
        let bytes = min(s, r.length);
        if bytes > 0 {
            t.record_remote(r.data, bytes);
            s -= bytes;
        }
    }
}

fn prepare_mmap_register_params(t: &mut RecordTask) {
    let mut r: Registers = t.regs_ref().clone();
    if t.session().as_record().unwrap().enable_chaos()
        && (r.arg4_signed() & (MAP_FIXED as isize | MAP_32BIT as isize) == 0)
        && r.arg1() == 0
    {
        // No address hint was provided. Randomize the allocation address.
        let mut len: usize = r.arg2();
        if r.arg4_signed() & MAP_GROWSDOWN as isize != 0 {
            // Ensure stacks can grow to the minimum size we choose
            len = max(AddressSpace::chaos_mode_min_stack_size(), len);
        }
        let addr: RemotePtr<Void> = t.vm_shr_ptr().chaos_mode_find_free_memory(t, len);
        if !addr.is_null() {
            r.set_arg1(addr.as_usize() + len - r.arg2());
            // Note that we don't set MapFlags::MAP_FIXED here. If anything goes wrong (e.g.
            // we pick a hint address that actually can't be used on this system), the
            // kernel will pick a valid address instead.
        }
    }
    r.set_arg4_signed(r.arg4_signed() & !(MAP_GROWSDOWN as isize));
    t.set_regs(&r);
}

/// At thread exit time, undo the work that init_buffers() did.
///
/// Call this when the tracee has already entered SYS_exit/SYS_exit_group. The
/// tracee will be returned at a state in which it has entered (or
/// re-entered) SYS_exit/SYS_exit_group.
fn prepare_exit(t: &mut RecordTask, exit_code: i32) {
    // RecordSession is responsible for ensuring we don't get here with
    // pending signals.
    ed_assert!(t, !t.has_any_stashed_sig());

    t.stable_exit = true;
    t.exit_code = exit_code;
    t.session()
        .as_record()
        .unwrap()
        .scheduler()
        .in_stable_exit(t);

    let mut r: Registers = t.regs_ref().clone();
    let mut exit_regs: Registers = r.clone();
    ed_assert!(
        t,
        is_exit_syscall(
            exit_regs.original_syscallno() as i32,
            t.ev().syscall_event().arch()
        ) || is_exit_group_syscall(
            exit_regs.original_syscallno() as i32,
            t.ev().syscall_event().arch()
        ),
        "Tracee should have been at exit/exit_group, but instead at {}",
        t.ev().syscall_event().syscall_name()
    );

    // The first thing we need to do is to block all signals to prevent
    // a signal being delivered to the thread (since it's going to exit and
    // won't be able to handle any more signals).
    //
    // The tracee is at the entry to SYS_exit/SYS_exit_group, but hasn't started
    // the call yet.  We can't directly start injecting syscalls
    // because the tracee is still in the kernel.  And obviously,
    // if we finish the SYS_exit/SYS_exit_group syscall, the tracee isn't around
    // anymore.
    //
    // So hijack this SYS_exit call and rewrite it into a SYS_rt_sigprocmask.
    r.set_original_syscallno(syscall_number_for_rt_sigprocmask(t.arch()) as isize);
    r.set_arg1(SIG_BLOCK as usize);
    r.set_arg2(AddressSpace::rd_page_ff_bytes().as_usize());
    r.set_arg3(0);
    r.set_arg4(size_of::<sig_set_t>());
    t.set_regs(&r);
    // This exits the SYS_rt_sigprocmask.  Now the tracee is ready to do our
    // bidding.
    t.exit_syscall();
    check_signals_while_exiting(t);

    // Do the actual buffer and fd cleanup.
    t.destroy_buffers();

    check_signals_while_exiting(t);

    // Restore these regs to what they would have been just before
    // the tracee trapped at SYS_exit/SYS_exit_group.  When we've finished
    // cleanup, we'll restart the call.
    exit_regs.set_syscallno(exit_regs.original_syscallno());
    exit_regs.set_original_syscallno(-1);
    exit_regs.set_ip(exit_regs.ip() - syscall_instruction_length(t.arch()));
    let is_at_syscall_instruction = is_at_syscall_instruction(t, exit_regs.ip());
    ed_assert!(
        t,
        is_at_syscall_instruction,
        "Tracee should have entered through int $0x80."
    );
    // Restart the SYS_exit call.
    t.set_regs(&exit_regs);
    t.enter_syscall();
    check_signals_while_exiting(t);

    let emulated_ptracer = t.emulated_ptracer.as_ref().map(|w| w.upgrade().unwrap());
    match emulated_ptracer {
        Some(tracer_rc) => {
            if t.emulated_ptrace_options & PTRACE_O_TRACEEXIT != 0 {
                // Ensure that do_ptrace_exit_stop can run later.
                t.emulated_ptrace_queued_exit_stop = true;
                t.emulate_ptrace_stop(
                    WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT),
                    tracer_rc.borrow().as_rec_unwrap(),
                    None,
                    None,
                    None,
                );
            } else {
                do_ptrace_exit_stop(t, Some(tracer_rc.borrow().as_rec_unwrap()));
            }
        }
        None => {
            do_ptrace_exit_stop(t, None);
        }
    }
}

fn check_signals_while_exiting(t: &mut RecordTask) {
    let maybe_s = t.peek_stashed_sig_to_deliver();
    match maybe_s {
        Some(s) => {
            // An unblockable signal (SIGKILL, SIGSTOP) might be received
            // and stashed. Since these signals are unblockable they take
            // effect no matter what and we don't need to deliver them to an exiting
            // thread.
            let siginfo = unsafe { (*s).siginfo };
            let sig = siginfo.si_signo;
            ed_assert!(
                t,
                sig == SIGKILL || sig == SIGSTOP,
                "Got unexpected signal {} (should have been blocked)",
                siginfo
            );
        }
        None => (),
    }
}

/// DIFF NOTE: Takes the extra param `maybe_tracer` unlike rr.
fn do_ptrace_exit_stop(t: &mut RecordTask, maybe_tracer: Option<&RecordTask>) {
    // Notify ptracer of the exit if it's not going to receive it from the
    // kernel because it's not the parent. (The kernel has similar logic to
    // deliver two stops in this case.)
    t.emulated_ptrace_queued_exit_stop = false;
    match maybe_tracer {
        Some(tracer) if t.is_clone_child() || t.get_parent_pid() != tracer.real_tgid() => {
            // This is a bit wrong; this is an exit stop, not a signal/ptrace stop.
            t.emulate_ptrace_stop(
                WaitStatus::for_exit_code(t.exit_code),
                tracer,
                None,
                None,
                None,
            );
        }
        _ => (),
    }
}

pub fn rec_prepare_restart_syscall(t: &mut RecordTask) {
    rec_prepare_restart_syscall_internal(t);
    t.syscall_state = None;
}

pub fn rec_prepare_restart_syscall_internal(t: &mut RecordTask) {
    let arch = t.arch();
    rd_arch_function_selfless!(rec_prepare_restart_syscall_arch, arch, t);
}

fn rec_prepare_restart_syscall_arch<Arch: Architecture>(t: &mut RecordTask) {
    let sys: i32 = t.ev().syscall_event().number;
    if sys == Arch::NANOSLEEP || sys == Arch::CLOCK_NANOSLEEP || sys == Arch::CLOCK_NANOSLEEP_TIME64
    {
        // Hopefully uniquely among syscalls, nanosleep()/clock_nanosleep()
        // requires writing to its remaining-time outparam
        // *only if* the syscall fails with -EINTR.  When a
        // nanosleep() is interrupted by a signal, we don't
        // know a priori whether it's going to be eventually
        // restarted or not.  (Not easily, anyway.)  So we
        // don't know whether it will eventually return -EINTR
        // and would need the outparam written.  To resolve
        // that, we do what the kernel does, and update the
        // outparam at the -ERESTART_RESTART interruption
        // regardless.
        t.syscall_state_unwrap()
            .borrow_mut()
            .process_syscall_results(t);
    }
    if sys == Arch::PPOLL
        || sys == Arch::PPOLL_TIME64
        || sys == Arch::PSELECT6
        || sys == Arch::PSELECT6_TIME64
        || sys == Arch::SIGSUSPEND
        || sys == Arch::RT_SIGSUSPEND
    {
        t.invalidate_sigmask();
    }

    if sys == Arch::WAIT4 || sys == Arch::WAITID || sys == Arch::WAITPID {
        let mut r: Registers = t.regs_ref().clone();
        let original_syscallno = t
            .syscall_state_unwrap()
            .borrow()
            .syscall_entry_registers
            .original_syscallno();
        r.set_original_syscallno(original_syscallno);
        t.set_regs(&r);
        let arch = t.arch();
        t.canonicalize_regs(arch);
        t.in_wait_type = WaitType::WaitTypeNone;
    }
}

pub fn rec_process_syscall(t: &mut RecordTask) {
    let syscall_state_shr = t.syscall_state_unwrap();
    let mut syscall_state = syscall_state_shr.borrow_mut();
    let sys_ev_arch = t.ev().syscall_event().arch();
    let sys_ev_number = t.ev().syscall_event().number;
    if sys_ev_arch != t.arch() {
        static DID_WARN: AtomicBool = AtomicBool::new(false);
        if !DID_WARN.load(Ordering::SeqCst) {
            log!(
                LogWarn,
                "Cross architecture syscall detected. Support is best effort"
            );
            DID_WARN.store(true, Ordering::SeqCst);
        }
    }
    rec_process_syscall_internal(t, sys_ev_arch, &mut syscall_state);
    syscall_state.process_syscall_results(t);
    let regs = t.regs_ref().clone();
    t.on_syscall_exit(sys_ev_number, sys_ev_arch, &regs);
    t.syscall_state = None;

    MonitoredSharedMemory::check_all(t);
}

/// N.B.: `arch` is the the architecture of the syscall, which may be different
///         from the architecture of the call (e.g. x86_64 may invoke x86 syscalls)
pub fn rec_process_syscall_internal(
    t: &mut RecordTask,
    arch: SupportedArch,
    syscall_state: &mut TaskSyscallState,
) {
    rd_arch_function_selfless!(rec_process_syscall_arch, arch, t, syscall_state)
}

pub fn rec_process_syscall_arch<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
) {
    let sys: i32 = t.ev().syscall_event().number;

    if t.regs_ref().original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO {
        // rd vetoed this syscall. Don't do any post-processing.
        return;
    }

    log!(
        LogDebug,
        "{}: processing: {} -- time: {}",
        t.tid,
        t.ev(),
        t.trace_time()
    );

    let rec = t.desched_rec();
    if !rec.is_null() {
        // If the syscallbuf has already been unmapped, there's no need to record
        // the entry.
        if !t.syscallbuf_child.is_null() {
            let num_bytes = read_val_mem(
                t,
                RemotePtr::<u32>::cast(rec.as_rptr_u8() + offset_of!(syscallbuf_record, size)),
                None,
            ) as usize;
            t.record_remote(
                rec.as_rptr_u8() + offset_of!(syscallbuf_record, extra_data),
                num_bytes - size_of::<syscallbuf_record>(),
            );
        }
        return;
    }

    if syscall_state.expect_errno != 0 {
        if syscall_state.expect_errno == EINVAL
            && sys == Arch::IOCTL
            && t.regs_ref().syscall_result_signed() == -ENOTTY as isize
        {
            // Unsupported ioctl was called, but is not supported for this device,
            // so we can safely ignore it.
            return;
        }
        ed_assert_eq!(
            t,
            t.regs_ref().syscall_result_signed(),
            -syscall_state.expect_errno as isize,
            "Expected {} for '{}' but got result {} (errno {}) {}",
            errno_name(syscall_state.expect_errno),
            syscall_name(sys, Arch::arch()),
            t.regs_ref().syscall_result_signed(),
            errno_name((-t.regs_ref().syscall_result_signed()).try_into().unwrap()),
            extra_expected_errno_info::<Arch>(t, syscall_state)
        );
        return;
    }

    // Here we handle syscalls that need work that can only happen after the
    // syscall completes --- and that our TaskSyscallState infrastructure can't
    // handle.
    if sys == Arch::FORK || sys == Arch::VFORK || sys == Arch::CLONE {
        // On a 3.19.0-39-generic #44-Ubuntu kernel we have observed clone()
        // clearing the parity flag internally.
        let mut r: Registers = t.regs_ref().clone();
        r.set_flags(syscall_state.syscall_entry_registers.flags());
        t.set_regs(&r);
        return;
    }

    if sys == Arch::EXECVE {
        process_execve(t, syscall_state);
        let emulated_ptracer = t.emulated_ptracer.as_ref().map(|w| w.upgrade().unwrap());
        match emulated_ptracer {
            Some(tracer_rc) => {
                if t.emulated_ptrace_options & PTRACE_O_TRACEEXEC != 0 {
                    t.emulate_ptrace_stop(
                        WaitStatus::for_ptrace_event(PTRACE_EVENT_EXEC),
                        tracer_rc.borrow().as_rec_unwrap(),
                        None,
                        None,
                        None,
                    );
                } else if !t.emulated_ptrace_seized {
                    // Inject legacy SIGTRAP-after-exec
                    t.tgkill(sig::SIGTRAP);
                }
            }
            None => (),
        }
        return;
    }

    if sys == Arch::MREMAP {
        process_mremap(
            t,
            t.regs_ref().arg1().into(),
            t.regs_ref().arg2(),
            t.regs_ref().arg3(),
        );
        return;
    }

    if sys == Arch::SHMAT {
        let shmid = t.regs_ref().arg1_signed() as i32;
        let shm_flags = t.regs_ref().arg3_signed() as i32;
        let syscall_result: RemotePtr<Void> = t.regs_ref().syscall_result().into();
        process_shmat(t, shmid, shm_flags, syscall_result);
        return;
    }

    if sys == Arch::IPC {
        match t.regs_ref().arg1() as u32 {
            SHMAT => {
                // DIFF NOTE: Arch::unsigned_long in rr
                let child_addr = RemotePtr::<Arch::unsigned_word>::from(t.regs_ref().arg4());
                let out_ptr = read_val_mem(t, child_addr, None);
                let out_rptr = RemotePtr::<Void>::new(out_ptr.try_into().unwrap());
                process_shmat(
                    t,
                    t.regs_ref().arg2_signed() as i32,
                    t.regs_ref().arg3_signed() as i32,
                    out_rptr,
                );
            }
            _ => (),
        }
        return;
    }

    if sys == Arch::CLOCK_NANOSLEEP || sys == Arch::NANOSLEEP {
        // If the sleep completes, the kernel doesn't
        // write back to the remaining-time
        // argument.
        if t.regs_ref().syscall_result_signed() as i32 == 0 {
            syscall_state.write_back = WriteBack::NoWriteBack;
        }
        return;
    }

    if sys == Arch::PERF_EVENT_OPEN {
        if t.regs_ref().original_syscallno() == Arch::INOTIFY_INIT as isize {
            ed_assert!(t, !t.regs_ref().syscall_failed());
            let fd = t.regs_ref().syscall_result_signed() as i32;
            let mut r: Registers = t.regs_ref().clone();
            r.set_original_syscallno(syscall_state.syscall_entry_registers.original_syscallno());
            t.set_regs(&r);
            let child_addr = RemotePtr::<perf_event_attr>::from(t.regs_ref().arg1());
            let attr = read_val_mem(t, child_addr, None);
            let tid = t.regs_ref().arg2_signed() as pid_t;
            let monitor = if t.tid != tid {
                Box::new(VirtualPerfCounterMonitor::new(
                    t,
                    t.session()
                        .find_task_from_rec_tid(tid)
                        .unwrap()
                        .borrow()
                        .as_ref(),
                    &attr,
                ))
            } else {
                Box::new(VirtualPerfCounterMonitor::new(t, t, &attr))
            };
            t.fd_table_shr_ptr().add_monitor(t, fd, monitor);
        }
        return;
    }

    if sys == Arch::CONNECT {
        // Restore the registers that we may have altered.
        let mut r: Registers = t.regs_ref().clone();
        if r.original_syscallno() == Arch::GETTID as isize {
            // We hijacked this call to deal with blacklisted sockets
            r.set_original_syscallno(Arch::CONNECT as isize);
            r.set_syscall_result_signed(-EACCES as isize);
            t.set_regs(&r);
        }
        return;
    }

    if sys == SYS_rdcall_notify_control_msg as i32 {
        let child_addr = RemotePtr::<msghdr<Arch>>::from(t.regs_ref().arg1());
        let msg = read_val_mem(t, child_addr, None);
        check_scm_rights_fd::<Arch>(t, &msg);
        return;
    }

    if sys == Arch::RECVMSG {
        if !t.regs_ref().syscall_failed() {
            let child_addr = RemotePtr::<msghdr<Arch>>::from(t.regs_ref().arg2());
            let msg = read_val_mem(t, child_addr, None);
            check_scm_rights_fd::<Arch>(t, &msg);
        }
        return;
    }

    if sys == Arch::RECVMMSG_TIME64 || sys == Arch::RECVMMSG {
        if !t.regs_ref().syscall_failed() {
            let child_addr = RemotePtr::<mmsghdr<Arch>>::from(t.regs_ref().arg2());
            let msg_count = t.regs_ref().syscall_result_signed() as i32 as usize;
            let msgs = read_mem(t, child_addr, msg_count, None);
            for m in &msgs {
                check_scm_rights_fd::<Arch>(t, &m.msg_hdr);
            }
        }
        return;
    }

    if sys == Arch::SCHED_GETAFFINITY {
        let pid = t.regs_ref().arg1() as pid_t;
        if !t.regs_ref().syscall_failed() && (pid == 0 || pid == t.rec_tid) {
            if t.regs_ref().syscall_result() > size_of::<cpu_set_t>() {
                log!(
                    LogWarn,
                    "Don't understand kernel's sched_getaffinity result"
                );
            } else {
                let cpu_set = t
                    .session()
                    .as_record()
                    .unwrap()
                    .scheduler()
                    .pretend_affinity_mask();
                let siz = t.regs_ref().syscall_result();

                let buf =
                    unsafe { std::slice::from_raw_parts(&raw const cpu_set as *const u8, siz) };
                let child_addr = t.regs_ref().arg3().into();
                t.write_bytes_helper(child_addr, buf, None, WriteFlags::empty());
            }
        }
        return;
    }

    if sys == Arch::SETSOCKOPT {
        // restore possibly-modified regs
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        t.set_regs(&r);
        return;
    }

    if sys == Arch::SOCKETCALL {
        // restore possibly-modified regs
        let mut r: Registers = t.regs_ref().clone();
        if r.original_syscallno() == Arch::GETTID as isize {
            // `connect` was suppressed
            r.set_syscall_result_signed(-EACCES as isize);
        }
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        r.set_original_syscallno(syscall_state.syscall_entry_registers.original_syscallno());
        t.set_regs(&r);

        if !t.regs_ref().syscall_failed() {
            match t.regs_ref().arg1() as u32 {
                SYS_RECVMSG => {
                    let child_addr = RemotePtr::<recvmsg_args<Arch>>::from(t.regs_ref().arg2());
                    let args = read_val_mem(t, child_addr, None);
                    let msg = read_val_mem(t, Arch::as_rptr(args.msg), None);
                    check_scm_rights_fd::<Arch>(t, &msg);
                }
                SYS_RECVMMSG => {
                    let child_addr = RemotePtr::<recvmmsg_args<Arch>>::from(t.regs_ref().arg2());
                    let args = read_val_mem(t, child_addr, None);
                    let msg_count = t.regs_ref().syscall_result_signed() as u32 as usize;
                    let msgs = read_mem(t, Arch::as_rptr(args.msgvec), msg_count, None);
                    for m in msgs {
                        check_scm_rights_fd::<Arch>(t, &m.msg_hdr);
                    }
                }
                // @TODO Is this what we want?
                _ => (),
            }
        }
    }

    if sys == Arch::PROCESS_VM_READV {
        record_iovec_output::<Arch>(
            t,
            None,
            RemotePtr::<iovec<Arch>>::from(t.regs_ref().arg2()),
            t.regs_ref().arg3() as u32,
        );
        return;
    }

    if sys == Arch::PROCESS_VM_WRITEV {
        let tid = t.regs_ref().arg1() as i32;
        let task_rc: TaskSharedPtr;
        let mut taskb;
        let dest_task;
        let maybe_dest = if tid == t.tid {
            None
        } else {
            match t.session().find_task_from_rec_tid(tid) {
                None => return,
                Some(rc) => {
                    task_rc = rc;
                    taskb = task_rc.borrow_mut();
                    dest_task = taskb.as_rec_mut_unwrap();
                    Some(dest_task)
                }
            }
        };
        record_iovec_output::<Arch>(
            t,
            maybe_dest,
            RemotePtr::<iovec<Arch>>::from(t.regs_ref().arg4()),
            t.regs_ref().arg5() as u32,
        );
        return;
    }

    if sys == Arch::GETDENTS || sys == Arch::GETDENTS64 {
        let fd = t.regs_ref().arg1() as i32;
        t.fd_table_shr_ptr().filter_getdents(fd, t);
        return;
    }

    if sys == Arch::WAITPID || sys == Arch::WAIT4 || sys == Arch::WAITID {
        t.in_wait_type = WaitType::WaitTypeNone;
        // Restore possibly-modified registers
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        r.set_arg2(syscall_state.syscall_entry_registers.arg2());
        r.set_arg3(syscall_state.syscall_entry_registers.arg3());
        r.set_arg4(syscall_state.syscall_entry_registers.arg4());
        r.set_original_syscallno(syscall_state.syscall_entry_registers.original_syscallno());
        t.set_regs(&r);

        let maybe_tracee = &syscall_state.emulate_wait_for_child;
        match maybe_tracee {
            Some(tracee_weak) => {
                let tracee_rc = tracee_weak.upgrade().unwrap();
                let mut traceeb = tracee_rc.borrow_mut();
                let tracee = traceeb.as_rec_mut_unwrap();
                // Finish emulation of ptrace result or stop-signal
                let mut r: Registers = t.regs_ref().clone();
                r.set_syscall_result(tracee.tid as usize);
                t.set_regs(&r);
                if sys == Arch::WAITID {
                    let sip: RemotePtr<siginfo_t<Arch>> = r.arg3().into();
                    if !sip.is_null() {
                        let mut si: siginfo_t<Arch> = unsafe { mem::zeroed() };
                        si.si_signo = SIGCHLD;
                        tracee.set_siginfo_for_waited_task::<Arch>(&mut si);

                        write_val_mem(t, sip, &si, None);
                    }
                } else {
                    let statusp: RemotePtr<i32> = r.arg2().into();
                    if !statusp.is_null() {
                        write_val_mem(t, statusp, &tracee.emulated_stop_code.get(), None);
                    }
                }
                if sys == Arch::WAITID && (r.arg4() & WNOWAIT as usize != 0) {
                    // Leave the child in a waitable state
                } else {
                    if tracee.emulated_stop_code.exit_code().is_some() {
                        // If we stopped the tracee to deliver this notification,
                        // now allow it to continue to exit properly and notify its
                        // real parent.
                        ed_assert!(
                            t,
                            tracee.ev().is_syscall_event()
                                && SyscallState::ProcessingSyscall
                                    == tracee.ev().syscall_event().state
                                && tracee.stable_exit
                        );
                        // Continue the task since we didn't in enter_syscall
                        tracee.resume_execution(
                            ResumeRequest::ResumeSyscall,
                            WaitRequest::ResumeNonblocking,
                            TicksRequest::ResumeNoTicks,
                            None,
                        );
                    }

                    // @TODO Check this code again
                    if tracee
                        .emulated_ptracer
                        .as_ref()
                        .map_or(false, |w| w.ptr_eq(&t.weak_self))
                    {
                        tracee.emulated_stop_pending = false;
                    } else {
                        tracee.emulated_stop_pending = false;
                        for thread in tracee
                            .thread_group()
                            .task_set()
                            .iter_except(tracee.weak_self_ptr())
                        {
                            thread
                                .borrow_mut()
                                .as_rec_mut_unwrap()
                                .emulated_stop_pending = false;
                        }
                    }
                }
            }
            None => (),
        }
        return;
    }

    if sys == Arch::QUOTACTL {
        match (t.regs_ref().arg1() >> SUBCMDSHIFT) as i32 {
            Q_GETQUOTA | Q_GETINFO | Q_GETFMT | Q_SETQUOTA | Q_QUOTAON | Q_QUOTAOFF | Q_SETINFO
            | Q_SYNC => (),
            _ => {
                let ret = t.regs_ref().syscall_result_signed() as i32;
                ed_assert!(
                    t,
                    ret == -ENOENT || ret == -ENODEV || ret == -ENOTBLK || ret == -EINVAL,
                    " unknown quotactl({:#x})",
                    (t.regs_ref().arg1() >> SUBCMDSHIFT)
                );
            }
        }
        return;
    }

    if sys == Arch::SECCOMP {
        // Restore arg1 in case we modified it to disable the syscall
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        t.set_regs(&r);
        if t.regs_ref().arg1() == SECCOMP_SET_MODE_FILTER as usize {
            ed_assert!(
                t,
                t.session().done_initial_exec(),
                "no seccomp calls during spawn"
            );
            t.session()
                .as_record()
                .unwrap()
                .seccomp_filter_rewriter_mut()
                .install_patched_seccomp_filter(t);
        }
        return;
    }

    if sys == SYS_rdcall_init_buffers as i32 {
        t.init_buffers();
        return;
    }

    if sys == SYS_rdcall_init_preload as i32 {
        t.at_preload_init();
        return;
    }

    if sys == SYS_rdcall_notify_syscall_hook_exit as i32 {
        let child_addr = remote_ptr_field!(
            t.syscallbuf_child,
            syscallbuf_hdr,
            notify_on_syscall_hook_exit
        );
        write_val_mem(t, child_addr, &0u8, None);
        t.record_remote_for(child_addr);

        let mut r: Registers = t.regs_ref().clone();
        let params_ptr = r.sp() + size_of::<Arch::unsigned_word>();
        let params = read_val_mem(t, RemotePtr::<rdcall_params<Arch>>::cast(params_ptr), None);
        r.set_syscall_result(params.result.try_into().unwrap());
        r.set_original_syscallno(params.original_syscallno.try_into().unwrap() as isize);
        t.set_regs(&r);
        return;
    }

    if sys == Arch::PRCTL {
        // Restore arg1 in case we modified it to disable the syscall
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        t.set_regs(&r);
        if t.regs_ref().arg1() as u32 == PR_SET_SECCOMP {
            if t.session().done_initial_exec() {
                t.session()
                    .as_record()
                    .unwrap()
                    .seccomp_filter_rewriter_mut()
                    .install_patched_seccomp_filter(t);
            }
        }

        return;
    }

    if sys == Arch::ARCH_PRCTL {
        // Restore arg1 in case we modified it to disable the syscall
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        t.set_regs(&r);
        return;
    }

    if sys == Arch::CLOSE
        || sys == Arch::DUP2
        || sys == Arch::DUP3
        || sys == Arch::FCNTL
        || sys == Arch::FCNTL64
        || sys == Arch::FUTEX_TIME64
        || sys == Arch::FUTEX
        || sys == Arch::IOCTL
        || sys == Arch::IO_SETUP
        || sys == Arch::MADVISE
        || sys == Arch::MEMFD_CREATE
        || sys == Arch::PREAD64
        || sys == Arch::PREADV
        || sys == Arch::PTRACE
        || sys == Arch::READ
        || sys == Arch::READV
        || sys == Arch::SCHED_SETAFFINITY
        || sys == Arch::MPROTECT
    {
        // Restore the registers that we may have altered.
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        r.set_arg2(syscall_state.syscall_entry_registers.arg2());
        r.set_arg3(syscall_state.syscall_entry_registers.arg3());
        t.set_regs(&r);
        return;
    }

    if sys == Arch::BRK {
        let old_brk: RemotePtr<Void> = ceil_page_size(t.vm().current_brk());
        let new_brk: RemotePtr<Void> = ceil_page_size(t.regs_ref().syscall_result().into());
        let km: KernelMapping;
        if old_brk < new_brk {
            // Read the kernel's mapping. There doesn't seem to be any other way to
            // get the correct prot bits for heaps. Usually it's READ|WRITE but
            // there seem to be exceptions depending on system settings.
            let kernel_info: KernelMapping = AddressSpace::read_kernel_mapping(t, old_brk);
            ed_assert_eq!(t, kernel_info.device(), KernelMapping::NO_DEVICE);
            ed_assert_eq!(t, kernel_info.inode(), KernelMapping::NO_INODE);
            km = kernel_info.subrange(old_brk, new_brk);
        } else {
            // Write a dummy KernelMapping that indicates an unmap
            km = KernelMapping::new_with_opts(
                new_brk,
                old_brk,
                &OsString::new(),
                KernelMapping::NO_DEVICE,
                KernelMapping::NO_INODE,
                ProtFlags::empty(),
                MapFlags::empty(),
                0,
            );
        }
        let d = t
            .trace_writer_mut()
            .write_mapped_region(t, &km, &km.fake_stat(), &[], None, None);
        ed_assert_eq!(t, d, RecordInTrace::DontRecordInTrace);
        let addr = t.regs_ref().syscall_result().into();
        t.vm_shr_ptr().brk(t, addr, km.prot());
        return;
    }

    if sys == Arch::MMAP {
        match Arch::MMAP_SEMANTICS {
            MmapCallingSemantics::StructArguments => {
                let child_addr = RemotePtr::<mmap_args<Arch>>::from(t.regs_ref().arg1());
                let args = read_val_mem(t, child_addr, None);
                process_mmap(
                    t,
                    Arch::size_t_as_usize(args.len),
                    args.prot,
                    args.flags,
                    args.fd,
                    Arch::off_t_as_isize(args.offset) as usize / 4096,
                );
            }
            MmapCallingSemantics::RegisterArguments => {
                let mut r: Registers = t.regs_ref().clone();
                r.set_arg1(syscall_state.syscall_entry_registers.arg1());
                r.set_arg4(syscall_state.syscall_entry_registers.arg4());
                t.set_regs(&r);
                process_mmap(
                    t,
                    r.arg2(),
                    r.arg3_signed() as i32,
                    r.arg4_signed() as i32,
                    r.arg5_signed() as i32,
                    // NOTE: Assuming offset always positive
                    r.arg6() / 4096,
                );
            }
        }
        return;
    }

    if sys == Arch::MMAP2 {
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        r.set_arg4(syscall_state.syscall_entry_registers.arg4());
        t.set_regs(&r);
        process_mmap(
            t,
            r.arg2(),
            r.arg3_signed() as i32,
            r.arg4_signed() as i32,
            r.arg5_signed() as i32,
            // DIFF NOTE: In rr this is signed but offsets always greater than 0?
            r.arg6(),
        );
        return;
    }

    if sys == Arch::OPEN || sys == Arch::OPENAT {
        let mut r: Registers = t.regs_ref().clone();
        if r.syscall_failed() {
            let path = if sys == Arch::OPENAT {
                r.arg2()
            } else {
                r.arg1()
            };
            let cpathname = t.read_c_str(RemotePtr::<u8>::from(path));
            let pathname = OsString::from_vec(cpathname.into_bytes());
            if is_gcrypt_deny_file(&pathname) {
                fake_gcrypt_file(t, &mut r);
                t.set_regs(&r);
            }
        } else {
            let fd = r.syscall_result_signed() as i32;
            let flags = if sys == Arch::OPENAT {
                r.arg3() as i32
            } else {
                r.arg2() as i32
            };
            let pathname = handle_opened_file(t, fd, flags);
            let gcrypt = is_gcrypt_deny_file(&pathname);
            if gcrypt || is_blacklisted_filename(&pathname) {
                {
                    let mut remote = AutoRemoteSyscalls::new(t);
                    rd_infallible_syscall!(remote, syscall_number_for_close(remote.arch()), fd);
                }
                if gcrypt {
                    fake_gcrypt_file(t, &mut r);
                } else {
                    log!(LogWarn, "Cowardly refusing to open {:?}", pathname);
                    r.set_syscall_result_signed(-ENOENT as isize);
                }
                t.set_regs(&r);
            }
        }
        return;
    }
}

fn fake_gcrypt_file(t: &mut RecordTask, r: &mut Registers) {
    // We hijacked this call to deal with /etc/gcrypt/hwf.deny.
    let file = create_temporary_file(b"rd-gcrypt-hwf-deny-XXXXXX");

    if stat("/etc/gcrypt/hwf.deny").is_ok() {
        // Copy the contents into our temporary file
        let existing = ScopedFd::open_path("/etc/gcrypt/hwf.deny", OFlag::O_RDONLY);
        if !copy_file(file.fd.as_raw(), existing.as_raw()) {
            fatal!(
                "Can't copy file \"/etc/gcrypt/hwf.deny\" into temporary file {:?}",
                file.name
            );
        }
    }

    let disable_rdrand = b"\nintel-rdrand\n";
    write_all(file.fd.as_raw(), disable_rdrand);

    // Now open the file in the child.
    let child_fd: i32;
    {
        let sys = syscall_number_for_openat(t.arch());
        let mut remote = AutoRemoteSyscalls::new(t);
        let mut child_str = AutoRestoreMem::push_cstr(&mut remote, file.name.as_os_str());
        // skip leading '/' since we want the path to be relative to the root fd
        let child_addr = child_str.get().unwrap().as_usize() + 1;
        child_fd = rd_infallible_syscall!(
            child_str,
            sys,
            RD_RESERVED_ROOT_DIR_FD,
            child_addr,
            O_RDONLY
        ) as i32;
    }

    // Unlink it now that the child has opened it.
    // DIFF NOTE: rr does not ensure this happens. We do an unwrap().
    unlink(file.name.as_os_str()).unwrap();

    // And hand out our fake file.
    r.set_syscall_result_signed(child_fd as isize);
}

fn is_blacklisted_filename(filename_os: &OsStr) -> bool {
    let filename = filename_os.as_bytes();
    if filename.starts_with(b"/dev/dri/")
        || filename == b"/dev/nvidiactl"
        || filename == b"/usr/share/alsa/alsa.conf"
        || filename == b"/dev/nvidia-uvm"
    {
        return true;
    }
    let maybe_f = Path::new(filename_os).file_name();
    match maybe_f {
        Some(f_os) => {
            let f = f_os.as_bytes();
            f.starts_with(b"rr-test-blacklist-file_name")
                || f.starts_with(b"rd-test-blacklist-file_name")
                || f.starts_with(b"pulse-shm-")
        }
        None => false,
    }
}

fn is_gcrypt_deny_file(f: &OsStr) -> bool {
    f.as_bytes() == b"/etc/gcrypt/hwf.deny"
}

fn handle_opened_file(t: &mut RecordTask, fd: i32, flags: i32) -> OsString {
    let mut pathname = t.file_name_of_fd(fd);
    let st = t.stat_fd(fd);

    // This must be kept in sync with replay_syscall's handle_opened_files.
    let mut file_monitor: Option<Box<dyn FileMonitor>> = None;
    if is_mapped_shared(t, &st) && is_writable(t, fd) {
        log!(LogInfo, "Installing MmappedFileMonitor for {}", fd);
        file_monitor = Some(Box::new(MmappedFileMonitor::new(t, fd)));
    } else if is_rd_terminal(&pathname) {
        // This will let rd event annotations echo to the terminal. It will also
        // ensure writes to this fd are not syscall-buffered.
        log!(LogInfo, "Installing StdioMonitor for {}", fd);
        file_monitor = Some(Box::new(StdioMonitor::new(dev_tty_fd())));
        pathname = "terminal".into();
    } else if is_proc_mem_file(&pathname) {
        log!(LogInfo, "Installing ProcMemMonitor for {}", fd);
        file_monitor = Some(Box::new(ProcMemMonitor::new(t, &pathname)));
    } else if is_proc_fd_dir(&pathname) {
        log!(LogInfo, "Installing ProcFdDirMonitor for {}", fd);
        file_monitor = Some(Box::new(ProcFdDirMonitor::new(t, &pathname)));
    } else if flags & O_DIRECT != 0 {
        // O_DIRECT can impose unknown alignment requirements, in which case
        // syscallbuf records will not be properly aligned and will cause I/O
        // to fail. Disable syscall buffering for O_DIRECT files.
        log!(LogInfo, "Installing FileMonitor for O_DIRECT {}", fd);
        file_monitor = Some(Box::new(BaseFileMonitor::new()));
    }

    match file_monitor {
        Some(mon) => {
            // Write absolute file name
            {
                let syscall = t.ev_mut().syscall_event_mut();
                syscall.opened.push(OpenedFd {
                    path: pathname.clone(),
                    fd,
                    device: st.st_dev,
                    inode: st.st_ino,
                });
            }
            t.fd_table_shr_ptr().add_monitor(t, fd, mon);
        }
        None => (),
    }

    pathname
}

fn init_dev_tty_fd() -> i32 {
    open("/dev/tty", OFlag::O_WRONLY, Mode::empty()).unwrap()
}

fn dev_tty_fd() -> i32 {
    *DEV_TTY_FD
}

lazy_static! {
    static ref DEV_TTY_FD: i32 = init_dev_tty_fd();
}

fn is_rd_terminal(pathname: &OsStr) -> bool {
    if pathname.as_bytes() == b"/dev/tty" {
        // XXX the tracee's /dev/tty could refer to a tty other than
        // the recording tty, in which case output should not be
        // redirected. That's not too bad, replay will still work, just
        // with some spurious echoes.
        return true;
    }

    is_rd_fd_terminal(STDIN_FILENO, pathname)
        || is_rd_fd_terminal(STDOUT_FILENO, pathname)
        || is_rd_fd_terminal(STDERR_FILENO, pathname)
}

fn is_rd_fd_terminal(fd: i32, pathname: &OsStr) -> bool {
    match ttyname(fd) {
        Err(_) => false,
        Ok(name) => name == pathname,
    }
}

fn is_writable(t: &dyn Task, fd: i32) -> bool {
    let lst = t.lstat_fd(fd);
    (lst.st_mode & S_IWUSR) != 0
}

fn is_mapped_shared(t: &dyn Task, st: &libc::stat) -> bool {
    for vm in &t.session().vms() {
        for (_, m) in &vm.maps() {
            if m.map.flags().contains(MapFlags::MAP_SHARED) {
                match m.mapped_file_stat {
                    Some(mstat) if mstat.st_dev == st.st_dev && mstat.st_ino == st.st_ino => {
                        return true;
                    }
                    _ => (),
                }
            }
        }
    }

    false
}

fn process_mmap(
    t: &mut RecordTask,
    length: usize,
    prot_raw: i32,
    flags_raw: i32,
    fd: i32,
    // Ok to assume offset is always positive?
    offset_pages: usize,
) {
    let prot = ProtFlags::from_bits(prot_raw).unwrap();
    let flags = MapFlags::from_bits(flags_raw).unwrap();
    if t.regs_ref().syscall_failed() {
        // We purely emulate failed mmaps.
        return;
    }

    let size = ceil_page_size(length);
    let offset: u64 = offset_pages as u64 * 4096;
    let addr: RemotePtr<Void> = t.regs_ref().syscall_result().into();
    if flags.contains(MapFlags::MAP_ANONYMOUS) {
        let km: KernelMapping;
        if !flags.contains(MapFlags::MAP_SHARED) {
            // Anonymous mappings are by definition not backed by any file-like
            // object, and are initialized to zero, so there's no nondeterminism to
            // record.
            km = t.vm_shr_ptr().map(
                t,
                addr,
                size,
                prot,
                flags,
                0,
                &OsString::new(),
                KernelMapping::NO_DEVICE,
                KernelMapping::NO_INODE,
                None,
                None,
                None,
                None,
                None,
            );
        } else {
            ed_assert!(t, !flags.contains(MapFlags::MAP_GROWSDOWN));
            // Read the kernel's mapping. There doesn't seem to be any other way to
            // get the correct device/inode numbers. Fortunately anonymous shared
            // mappings are rare.
            let kernel_info = AddressSpace::read_kernel_mapping(t, addr);
            km = t.vm().map(
                t,
                addr,
                size,
                prot,
                flags,
                0,
                kernel_info.fsname(),
                kernel_info.device(),
                kernel_info.inode(),
                None,
                None,
                None,
                None,
                None,
            );
        }
        let d = t
            .trace_writer_mut()
            .write_mapped_region(t, &km, &km.fake_stat(), &[], None, None);
        ed_assert_eq!(t, d, RecordInTrace::DontRecordInTrace);
        return;
    }

    ed_assert!(t, fd >= 0, "Valid fd required for file mapping");
    ed_assert!(t, !flags.contains(MapFlags::MAP_GROWSDOWN));

    let mut effectively_anonymous: bool = false;
    let mut st = t.stat_fd(fd);
    let mut file_name = t.file_name_of_fd(fd);
    if file_name.as_bytes() == b"/dev/zero" {
        // mmapping /dev/zero is equivalent to MapFlags::MAP_ANONYMOUS, just more annoying.
        // grab the device/inode from the kernel mapping so that it will be unique.
        let kernel_synthetic_info: KernelMapping = AddressSpace::read_kernel_mapping(t, addr);
        st.st_dev = kernel_synthetic_info.device();
        st.st_ino = kernel_synthetic_info.inode();
        file_name = kernel_synthetic_info.fsname().to_owned();
        effectively_anonymous = true;
    }

    let km = t.vm_shr_ptr().map(
        t,
        addr,
        size,
        prot,
        flags,
        offset,
        &file_name,
        st.st_dev,
        st.st_ino,
        Some(st),
        None,
        None,
        None,
        None,
    );

    let mut adjusted_size = false;
    if st.st_size == 0 && !SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFREG) {
        // Some device files are mmappable but have zero size. Increasing the
        // size here is safe even if the mapped size is greater than the real size.
        st.st_size = (offset + size as u64).try_into().unwrap();
        adjusted_size = true;
    }

    let mut extra_fds: Vec<TraceRemoteFd> = Vec::new();
    let mut monitor_this_fd = false;
    if flags.contains(MapFlags::MAP_SHARED) && !effectively_anonymous {
        monitor_this_fd = monitor_fd_for_mapping(t, fd, &st, &mut extra_fds);
    }

    if t.trace_writer_mut().write_mapped_region(
        t,
        &km,
        &st,
        &extra_fds,
        Some(MappingOrigin::SyscallMapping),
        Some(!monitor_this_fd),
    ) == RecordInTrace::RecordInTrace
    {
        let end = st.st_size as u64 - km.file_offset_bytes();
        let nbytes = min(end, km.size() as u64);
        let nread = t
            .record_remote_fallible(addr, nbytes.try_into().unwrap())
            .unwrap();

        if !adjusted_size && nread as u64 != nbytes {
            // If we adjusted the size, we're not guaranteed that the bytes we're
            // reading are actually valid (it could actually have been a zero-sized
            // file).
            let st2 = t.stat_fd(fd);
            AddressSpace::dump_process_maps(t);
            // @TODO run df -h here to show to user
            ed_assert!(
                t,
                false,
                "Failed to read expected mapped data at {}; expected {} bytes, got {} bytes, \n\
              got file size {} before and {} after; is filesystem full?",
                km,
                nbytes,
                nread,
                st.st_size,
                st2.st_size
            );
        }
    }

    if flags.contains(MapFlags::MAP_SHARED) && !effectively_anonymous {
        // Setting up MmappedFileMonitor may trigger updates to syscallbuf_fds_disabled
        // in the tracee, recording memory records. Those should be recorded now, after the
        // memory region data itself. Needs to be consistent with replay_syscall.
        if monitor_this_fd {
            extra_fds.push(TraceRemoteFd { tid: t.tid, fd });
        }
        for f in &extra_fds {
            let rc_t;
            let mut tb;
            let tt: &mut dyn Task = if f.tid == t.tid {
                t
            } else {
                rc_t = t.session().find_task_from_rec_tid(f.tid).unwrap();
                tb = rc_t.borrow_mut();
                tb.as_mut()
            };

            if tt.fd_table().is_monitoring(f.fd) {
                let file_mon_shr_ptr = tt.fd_table().get_monitor(f.fd).unwrap();
                ed_assert_eq!(
                    tt,
                    file_mon_shr_ptr.borrow().file_monitor_type(),
                    FileMonitorType::Mmapped
                );
                file_mon_shr_ptr
                    .borrow_mut()
                    .as_mmapped_file_monitor_mut()
                    .unwrap()
                    .revive();
            } else {
                let mon = Box::new(MmappedFileMonitor::new(tt, f.fd));
                tt.fd_table_shr_ptr().add_monitor(tt, f.fd, mon);
            }
        }

        if prot.contains(ProtFlags::PROT_WRITE) {
            log!(LogDebug, "{:?} is SHARED|writable; that's not handled correctly yet. Optimistically hoping it's not \n\
                            written by programs outside the rr tracee tree.", file_name);
        }
    }

    // We don't want to patch MapFlags::MAP_SHARED files. In the best case we'd end crashing
    // at an assertion, in the worst case, we'd end up modifying the underlying
    // file.
    if !flags.contains(MapFlags::MAP_SHARED) {
        t.vm().monkeypatcher().unwrap().borrow().patch_after_mmap(
            t,
            addr,
            size,
            offset_pages,
            fd,
            MmapMode::MmapSyscall,
        );
    }

    if (prot & (ProtFlags::PROT_WRITE | ProtFlags::PROT_READ)) == ProtFlags::PROT_READ
        && flags.contains(MapFlags::MAP_SHARED)
        && !effectively_anonymous
    {
        let m = t.vm().mapping_of(addr).unwrap().clone();
        MonitoredSharedMemory::maybe_monitor(t, file_name.as_os_str(), m, fd, offset);
    }
}

fn monitor_fd_for_mapping(
    mapped_t: &mut dyn Task,
    mapped_fd: i32,
    file: &libc::stat,
    extra_fds: &mut Vec<TraceRemoteFd>,
) -> bool {
    let mut tables: WeakPtrSet<FdTable> = WeakPtrSet::new();
    let mut found_our_mapping = false;
    let mut our_mapping_writable = false;
    let mapped_table = Rc::downgrade(&mapped_t.fd_table_shr_ptr());
    let mapped_t_weak = mapped_t.weak_self_ptr();
    for (_, ts) in mapped_t.session().tasks().iter() {
        let tb;
        let t: &dyn Task = if mapped_t_weak.ptr_eq(&Rc::downgrade(ts)) {
            mapped_t
        } else {
            tb = ts.borrow();
            tb.as_ref()
        };
        if t.unstable.get() {
            // This task isn't a problem because it's exiting and won't write to its
            // fds. (Well in theory there could be a write in progress I suppose, but
            // let's ignore that for now :-().) Anyway, reading its /proc/.../fd will
            // probably fail.
            continue;
        }
        let table = Rc::downgrade(&t.fd_table_shr_ptr());
        if !tables.insert(table.clone()) {
            continue;
        }

        let dir_path = format!("/proc/{}/fd", t.tid);

        let dir = match read_dir(&dir_path) {
            Ok(dir) => dir,
            Err(e) => fatal!("Can't open fd dir {}: {:?}", dir_path, e),
        };

        for maybe_entry in dir {
            if maybe_entry.is_err() {
                continue;
            }
            let entry = maybe_entry.unwrap();
            match entry.file_type() {
                Ok(file_type) if !file_type.is_dir() => (),
                _ => continue,
            }
            let fd: i32 = match entry.file_name().to_str() {
                Some(s) => match s.parse::<i32>() {
                    Ok(fd) if fd >= 0 => fd,
                    _ => continue,
                },
                None => continue,
            };
            let fd_stat = t.stat_fd(fd);
            if fd_stat.st_dev != file.st_dev || fd_stat.st_ino != file.st_ino {
                // Not our file
                continue;
            }
            let writable = is_writable(t, fd);
            if table.ptr_eq(&mapped_table) && fd == mapped_fd {
                // This is what we're using to do the mmap. Don't put it in extra_fds.
                found_our_mapping = true;
                our_mapping_writable = writable;
                continue;
            }
            if !writable {
                // Ignore non-writable fds since they can't modify memory
                continue;
            }
            extra_fds.push(TraceRemoteFd { tid: t.tid, fd });
        }
    }
    ed_assert!(mapped_t, found_our_mapping, "Can't find fd for mapped file");
    our_mapping_writable
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ScratchAddrType {
    FixedAddress,
    DynamicAddress,
}

fn process_execve(t: &mut RecordTask, syscall_state: &mut TaskSyscallState) {
    if t.regs_ref().syscall_failed() {
        return;
    }

    t.post_exec_syscall();
    t.ev_mut().syscall_event_mut().exec_fds_to_close =
        t.fd_table_shr_ptr().fds_to_close_after_exec(t);

    check_privileged_exe(t);

    let rd_page_mapping: KernelMapping = t
        .vm()
        .mapping_of(AddressSpace::rd_page_start())
        .unwrap()
        .map
        .clone();

    let mut mode = t.trace_writer_mut().write_mapped_region(
        t,
        &rd_page_mapping,
        &rd_page_mapping.fake_stat(),
        &[],
        Some(MappingOrigin::RdBufferMapping),
        None,
    );
    ed_assert_eq!(t, mode, RecordInTrace::DontRecordInTrace);

    let preload_thread_locals_mapping: KernelMapping = t
        .vm()
        .mapping_of(AddressSpace::preload_thread_locals_start())
        .unwrap()
        .map
        .clone();

    mode = t.trace_writer_mut().write_mapped_region(
        t,
        &preload_thread_locals_mapping,
        &preload_thread_locals_mapping.fake_stat(),
        &[],
        Some(MappingOrigin::RdBufferMapping),
        None,
    );
    ed_assert_eq!(t, mode, RecordInTrace::DontRecordInTrace);

    let mut maybe_vvar: Option<KernelMapping> = None;

    // get the remote executable entry point
    // with the pointer, we find out which mapping is the executable
    let exe_entry: RemotePtr<Void> = get_exe_entry(t);
    ed_assert!(t, !exe_entry.is_null(), "AT_ENTRY not found");

    // Write out stack mappings first since during replay we need to set up the
    // stack before any files get mapped.
    let mut stacks: Vec<KernelMapping> = Vec::new();
    for (_, m) in &t.vm().maps() {
        let km = m.map.clone();
        // if true, this mapping is our executable
        if km.start() <= exe_entry && exe_entry < km.end() {
            ed_assert!(
                t,
                km.prot().contains(ProtFlags::PROT_EXEC),
                "Entry point not in executable code?"
            );
            syscall_state
                .exec_saved_event
                .as_mut()
                .unwrap()
                .exec_variant_mut()
                .set_exe_base(km.start());
        }

        if km.is_stack() {
            stacks.push(km);
        } else if km.is_vvar() {
            maybe_vvar = Some(km);
        }
    }
    ed_assert!(
        t,
        !syscall_state
            .exec_saved_event
            .as_ref()
            .unwrap()
            .exec_variant()
            .exe_base()
            .is_null()
    );

    t.trace_writer_mut()
        .write_task_event(syscall_state.exec_saved_event.as_ref().unwrap());

    {
        let mut remote =
            AutoRemoteSyscalls::new_with_mem_params(t, MemParamsEnabled::DisableMemoryParams);

        match maybe_vvar {
            Some(vvar) => {
                // We're not going to map [vvar] during replay --- that wouldn't
                // make sense, since it contains data from the kernel that isn't correct
                // for replay, and we patch out the vdso syscalls that would use it.
                // Unmapping it now makes recording look more like replay.
                // Also note that under 4.0.7-300.fc22.x86_64 (at least) /proc/<pid>/mem
                // can't read the contents of [vvar].
                let munmap_no: i32 = syscall_number_for_munmap(remote.arch());
                rd_infallible_syscall!(remote, munmap_no, vvar.start().as_usize(), vvar.size());
                remote
                    .task()
                    .vm_shr_ptr()
                    .unmap(remote.task(), vvar.start(), vvar.size());
            }
            None => (),
        }

        for km in &stacks {
            mode = remote
                .task()
                .as_rec_unwrap()
                .trace_writer_mut()
                .write_mapped_region(
                    remote.task().as_rec_unwrap(),
                    km,
                    &km.fake_stat(),
                    &[],
                    Some(MappingOrigin::ExecMapping),
                    None,
                );
            ed_assert_eq!(remote.task(), mode, RecordInTrace::RecordInTrace);
            let buf = read_mem(remote.task_mut(), km.start(), km.size(), None);
            remote.task().as_rec_unwrap().trace_writer_mut().write_raw(
                remote.task().rec_tid,
                &buf,
                km.start(),
            );

            // Remove MAP_GROWSDOWN from stacks by remapping the memory and
            // writing the contents back.
            let flags = (km.flags() & !MapFlags::MAP_GROWSDOWN) | MapFlags::MAP_ANONYMOUS;
            let munmap_no: i32 = syscall_number_for_munmap(remote.arch());
            rd_infallible_syscall!(remote, munmap_no, km.start().as_usize(), km.size());
            if !remote
                .task()
                .vm()
                .mapping_of(km.start() - page_size())
                .is_some()
            {
                // Unmap an extra page at the start; this seems to be necessary
                // to properly wipe out the growsdown mapping. Doing it as a separate
                // munmap call also seems to be necessary.
                rd_infallible_syscall!(
                    remote,
                    munmap_no,
                    km.start().as_usize() - page_size(),
                    page_size()
                );
            }
            remote.infallible_mmap_syscall(Some(km.start()), km.size(), km.prot(), flags, -1, 0);
            write_mem(remote.task_mut(), km.start(), &buf, None);
        }
    }

    // The kernel may zero part of the last page in each data mapping according
    // to ELF BSS metadata. So we record the last page of each data mapping in
    // the trace.
    let mut pages_to_record: Vec<RemotePtr<Void>> = Vec::new();

    for (_, m) in &t.vm_shr_ptr().maps() {
        let km = m.map.clone();
        if km.start() == AddressSpace::rd_page_start()
            || km.start() == AddressSpace::preload_thread_locals_start()
        {
            continue;
        }
        if km.is_stack() || km.is_vsyscall() {
            // [stack] has already been handled.
            // [vsyscall] can't be read via /proc/<pid>/mem, *should*
            // be the same across all execs, and can't be munmapped so we can't fix
            // it even if it does vary. Plus no-one should be using it anymore.
            continue;
        }
        let maybe_stat = stat::stat(km.fsname());
        let st = match maybe_stat {
            Err(_) => {
                let mut fake_st = km.fake_stat();
                // Size is not real. Don't confuse the logic below
                fake_st.st_size = 0;
                fake_st
            }
            Ok(st) => st,
        };

        if t.trace_writer_mut().write_mapped_region(
            t,
            &km,
            &st,
            &[],
            Some(MappingOrigin::ExecMapping),
            None,
        ) == RecordInTrace::RecordInTrace
        {
            if st.st_size > 0 {
                let end = st.st_size as u64 - km.file_offset_bytes();
                t.record_remote(km.start(), min(end.try_into().unwrap(), km.size()));
            } else {
                // st_size is not valid. Some device files are mmappable but have zero
                // size. We also take this path if there's no file at all (vdso etc).
                t.record_remote(km.start(), km.size());
            }
        } else {
            // See https://github.com/rr-debugger/rr/issues/1568; in some cases
            // after exec we have memory areas that are rwx. These areas have
            // a trailing page that may be partially zeroed by the kernel. Record the
            // trailing page of every mapping just to be simple and safe.
            pages_to_record.push(km.end() - page_size());
        }
    }

    for p in pages_to_record {
        t.record_remote(p, page_size());
    }

    // Patch LD_PRELOAD and VDSO after saving the mappings. Replay will apply
    // patches to the saved mappings.
    t.vm_shr_ptr()
        .monkeypatcher()
        .unwrap()
        .borrow_mut()
        .patch_after_exec(t);

    init_scratch_memory(t, Some(ScratchAddrType::FixedAddress));
}
/// Pointer used when running in WINE. Memory below this address is
/// unmapped by WINE immediately after exec, so start the scratch buffer
/// here.
const FIXED_SCRATCH_PTR: usize = 0x68000000;

fn init_scratch_memory(t: &mut RecordTask, maybe_addr_type: Option<ScratchAddrType>) {
    let addr_type = maybe_addr_type.unwrap_or(ScratchAddrType::DynamicAddress);
    let scratch_size = 512 * page_size();
    // The PROT_EXEC looks scary, and it is, but it's to prevent
    // this region from being coalesced with another anonymous
    // segment mapped just after this one.  If we named this
    // segment, we could remove this hack.
    let prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC;
    let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
    {
        // initialize the scratchpad for blocking system calls
        let mut remote = AutoRemoteSyscalls::new(t);

        if addr_type == ScratchAddrType::DynamicAddress {
            remote.task_mut().scratch_ptr =
                remote.infallible_mmap_syscall(None, scratch_size, prot, flags, -1, 0);
        } else {
            remote.task_mut().scratch_ptr = remote.infallible_mmap_syscall(
                Some(RemotePtr::from(FIXED_SCRATCH_PTR)),
                scratch_size,
                prot,
                flags | MapFlags::MAP_FIXED,
                -1,
                0,
            );
        }
        remote.task_mut().scratch_size = scratch_size;
    }

    t.setup_preload_thread_locals();

    // record this mmap for the replay
    let mut r: Registers = t.regs_ref().clone();
    let saved_result = r.syscall_result();
    r.set_syscall_result(t.scratch_ptr.as_usize());
    t.set_regs(&r);

    let km = t.vm_shr_ptr().map(
        t,
        t.scratch_ptr,
        scratch_size,
        prot,
        flags,
        0,
        &OsString::new(),
        KernelMapping::NO_DEVICE,
        KernelMapping::NO_INODE,
        None,
        None,
        None,
        None,
        None,
    );
    let stat: libc::stat = unsafe { mem::zeroed() };
    let record_in_trace = t
        .trace_writer_mut()
        .write_mapped_region(t, &km, &stat, &[], None, None);

    ed_assert_eq!(t, record_in_trace, RecordInTrace::DontRecordInTrace);

    r.set_syscall_result(saved_result);
    t.set_regs(&r);
}

fn check_privileged_exe(t: &mut RecordTask) {
    // Check if the executable we just execed has setuid bits or file capabilities
    // If so (and rd doesn't have CAP_SYS_ADMIN, which would have let us avoid,
    // no_new privs), they may have been ignored, due to our no_new_privs setting
    // in the tracee. That's most likely not what the user intended (and setuid
    // applications may not handle not being root particularly gracefully - after
    // all under usual circumstances, it would be an exec-time error). Give a loud
    // warning to tell the user what happened, but continue anyway.
    static DID_WARN: AtomicBool = AtomicBool::new(false);
    if !in_same_mount_namespace_as(t) {
        // We could try to enter the mount namespace and perform the below check
        // there, but don't bother. We know we must have privileges over the mount
        // namespaces (either because it's an unprivileged user namespace, in which
        // case we have full privileges, or because at some point one of our
        // tracees had to have CAP_SYS_ADMIN/CAP_SETUID to create the mount
        // namespace - as a result we must have at least as much privilege).
        // Nevertheless, we still need to stop the hpc counters, since
        // the executable may be privileged with respect to its namespace.
        t.hpc.stop();
    } else if is_privileged_executable(t, t.vm().exe_image()) {
        if has_effective_caps(1 << CAP_SYS_ADMIN) {
            // perf_events may have decided to stop counting for security reasons.
            // To be safe, close all perf counters now, to force re-opening the
            // perf file descriptors the next time we resume the task.
            t.hpc.stop();
        } else {
            // Only issue the warning once. If it's a problem, the user will likely
            // find out soon enough. If not, no need to keep bothering them.
            if !DID_WARN.load(Ordering::SeqCst) {
                eprintln!(
                    "[WARNING] rd: Executed file with setuid or file capabilities set.\n\
                        Capabilities did not take effect. Errors may follow.\n\
                        To record this execution faithfully, re-run rd as:\n\n\
                           sudo -EP rd record --setuid-sudo\n\n"
                );
                DID_WARN.store(true, Ordering::SeqCst);
            }
        }
    }
}

fn get_exe_entry(t: &mut RecordTask) -> RemotePtr<Void> {
    let v = read_auxv(t);
    let mut i: usize = 0;
    let wsize: usize = word_size(t.arch());
    while (i + 1) * wsize * 2 <= v.len() {
        if word_at(&v[i * 2 * wsize..i * 2 * wsize + wsize]) == AT_ENTRY {
            // @TODO Instead of try_into() should this just be `as usize` ?
            return RemotePtr::new(
                word_at(&v[(i * 2 + 1) * wsize..(i * 2 + 1) * wsize + wsize])
                    .try_into()
                    .unwrap(),
            );
        }
        i += 1;
    }

    RemotePtr::null()
}

type AfterSyscallAction = Box<dyn Fn(&mut RecordTask) -> ()>;
type ArgMutator = Box<dyn Fn(&mut RecordTask, RemotePtr<Void>, Option<&mut [u8]>) -> bool>;

/// When tasks enter syscalls that may block and so must be
/// prepared for a context-switch, and the syscall params
/// include (in)outparams that point to buffers, we need to
/// redirect those arguments to scratch memory.  This allows rd
/// to serialize execution of what may be multiple blocked
/// syscalls completing "simultaneously" (from rd's
/// perspective).  After the syscall exits, we restore the data
/// saved in scratch memory to the original buffers.
///
/// Then during replay, we simply restore the saved data to the
/// tracee's passed-in buffer args and continue on.
///
/// This is implemented by having rec_prepare_syscall_arch set up
/// a record in param_list for syscall in-memory  parameter (whether
/// "in" or "out"). Then done_preparing is called, which does the actual
/// scratch setup. process_syscall_results is called when the syscall is
/// done, to write back scratch results to the real parameters and
/// clean everything up.
///
/// ... a fly in this ointment is may-block buffered syscalls.
/// If a task blocks in one of those, it will look like it just
/// entered a syscall that needs a scratch buffer.  However,
/// it's too late at that point to fudge the syscall args,
/// because processing of the syscall has already begun in the
/// kernel.  But that's OK: the syscallbuf code has already
/// swapped out the original buffer-pointers for pointers into
/// the syscallbuf (which acts as its own scratch memory).  We
/// just have to worry about setting things up properly for
/// replay.
///
/// The descheduled syscall will "abort" its commit into the
/// syscallbuf, so the outparam data won't actually be saved
/// there (and thus, won't be restored during replay).  During
/// replay, we have to restore them like we restore the
/// non-buffered-syscall scratch data. This is done by recording
/// the relevant syscallbuf record data in rec_process_syscall_arch.
///
/// DIFF NOTE: The struct is pub
pub struct TaskSyscallState {
    /// NOTE: The task is passed explicity as a parameter in TaskSyscallState methods
    /// This is there only to verify that the correct task was passed in
    /// We can't use TaskUid as that can change during an exec
    weak_task: TaskSharedWeakPtr,

    param_list: Vec<MemoryParam>,
    /// Tracks the position in t's scratch_ptr buffer where we should allocate
    /// the next scratch area.
    scratch: RemotePtr<Void>,

    after_syscall_actions: Vec<AfterSyscallAction>,

    /// DIFF NOTE: Made into an Option<>
    exec_saved_event: Option<Box<TraceTaskEvent>>,
    /// DIFF NOTE: Made into an Option<>
    emulate_wait_for_child: Option<TaskSharedWeakPtr>,

    /// Saved syscall-entry registers, used by code paths that modify the
    /// registers temporarily.
    syscall_entry_registers: Registers,

    /// When nonzero, syscall is expected to return the given errno and we should
    /// die if it does not. This is set when we detect an error condition during
    /// syscall-enter preparation.
    expect_errno: i32,

    /// When should_emulate_result is true, syscall result should be adjusted to
    /// be emulated_result.
    should_emulate_result: bool,
    /// DIFF NOTE: In rr this is a u64
    emulated_result: usize,

    /// Records whether the syscall is switchable. Only valid when
    /// preparation_done is true.
    switchable: Switchable,

    /// Whether we should write back the syscall results from scratch. Only
    /// valid when preparation_done is true.
    write_back: WriteBack,

    /// When true, this syscall has already been prepared and should not
    /// be set up again.
    preparation_done: bool,

    /// When true, the scratch area is enabled, otherwise we're letting
    /// syscall outputs be written directly to their destinations.
    /// Only valid when preparation_done is true.
    scratch_enabled: bool,

    /// Miscellaneous saved data that can be used by particular syscalls
    saved_data: Vec<u8>,
}

impl TaskSyscallState {
    // DIFF NOTE: Unlike rr, you need to specify `t` (but as a tuid) right from the beginning
    pub fn new(task: &dyn Task) -> Self {
        Self {
            weak_task: task.weak_self_ptr(),
            param_list: Default::default(),
            scratch: Default::default(),
            after_syscall_actions: Default::default(),
            exec_saved_event: Default::default(),
            emulate_wait_for_child: Default::default(),
            syscall_entry_registers: Default::default(),
            expect_errno: 0,
            should_emulate_result: false,
            emulated_result: 0,
            // Arbitrarily chosen
            switchable: Switchable::PreventSwitch,
            // Arbitrarily chosen
            write_back: WriteBack::NoWriteBack,
            preparation_done: false,
            scratch_enabled: false,
            saved_data: Default::default(),
        }
    }

    pub fn init(&mut self, t: &RecordTask) {
        assert!(self.weak_task.ptr_eq(&t.weak_self));

        if self.preparation_done {
            return;
        }

        self.scratch = t.scratch_ptr;
    }

    /// Identify a syscall memory parameter whose address is in register 'arg'
    /// with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    fn reg_parameter<T>(
        &mut self,
        arg: usize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.reg_parameter_with_size(
            arg,
            ParamSize::from(size_of::<T>()),
            maybe_mode,
            maybe_mutator,
        ))
    }

    /// Identify a syscall memory parameter whose address is in register 'arg'
    /// with size 'size'.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    fn reg_parameter_with_size(
        &mut self,
        arg: usize,
        param_size: ParamSize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<Void> {
        let mode = maybe_mode.unwrap_or(ArgMode::Out);
        if self.preparation_done {
            return RemotePtr::null();
        }

        let mut param = MemoryParam::default();
        let dest = RemotePtr::from(self.syscall_entry_registers.arg(arg));
        if dest.is_null() {
            return RemotePtr::null();
        }

        param.dest = dest;
        param.num_bytes = param_size;
        param.mode = mode;
        param.maybe_mutator = maybe_mutator;
        assert!(param.maybe_mutator.is_none() || mode == ArgMode::In);

        if mode != ArgMode::InOutNoScratch {
            param.scratch = self.scratch;
            self.scratch += param.num_bytes.incoming_size;
            align_scratch(&mut self.scratch, None);
            param.ptr_in_reg = arg;
        }

        self.param_list.push(param);

        dest
    }

    /// Identify a syscall memory parameter whose address is in memory at
    /// location 'addr_of_buf_ptr' with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    /// addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
    /// call.
    ///
    /// DIFF NOTE: Takes `t` as param
    fn mem_ptr_parameter<T>(
        &mut self,
        t: &mut RecordTask,
        addr_of_buf_ptr: RemotePtr<Void>,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.mem_ptr_parameter_with_size(
            t,
            addr_of_buf_ptr,
            ParamSize::from(size_of::<T>()),
            maybe_mode,
            maybe_mutator,
        ))
    }

    /// Identify a syscall memory parameter whose address is in memory at
    /// location 'addr_of_buf_ptr' with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    /// addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
    /// call.
    ///
    /// DIFF NOTE: Takes `t` as param
    fn mem_ptr_parameter_inferred<Arch: Architecture, T>(
        &mut self,
        t: &mut RecordTask,
        addr_of_buf_ptr: RemotePtr<Ptr<Arch::unsigned_word, T>>,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.mem_ptr_parameter_with_size(
            t,
            RemotePtr::<Void>::cast(addr_of_buf_ptr),
            ParamSize::from(size_of::<T>()),
            maybe_mode,
            maybe_mutator,
        ))
    }

    /// Identify a syscall memory parameter whose address is in memory at
    /// location 'addr_of_buf_ptr' with size 'size'.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    /// addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
    /// call.
    ///
    /// DIFF NOTE: Takes `t` as param
    fn mem_ptr_parameter_with_size(
        &mut self,
        t: &mut RecordTask,
        addr_of_buf_ptr: RemotePtr<Void>,
        param_size: ParamSize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<Void> {
        assert!(self.weak_task.ptr_eq(&t.weak_self));

        let mode = maybe_mode.unwrap_or(ArgMode::Out);
        if self.preparation_done || addr_of_buf_ptr.is_null() {
            return RemotePtr::null();
        }

        let mut param = MemoryParam::default();
        let dest = get_remote_ptr(t, addr_of_buf_ptr);
        if dest.is_null() {
            return RemotePtr::null();
        }

        param.dest = dest;
        param.num_bytes = param_size;
        param.mode = mode;
        param.maybe_mutator = maybe_mutator;
        ed_assert!(t, param.maybe_mutator.is_none() || mode == ArgMode::In);
        if mode != ArgMode::InOutNoScratch {
            param.scratch = self.scratch;
            self.scratch += param.num_bytes.incoming_size;
            align_scratch(&mut self.scratch, None);
            param.ptr_in_memory = addr_of_buf_ptr;
        }
        self.param_list.push(param);

        dest
    }

    fn after_syscall_action(&mut self, action: AfterSyscallAction) {
        self.after_syscall_actions.push(action)
    }

    fn emulate_result(&mut self, result: usize) {
        assert!(!self.preparation_done);
        assert!(!self.should_emulate_result);
        self.should_emulate_result = true;
        self.emulated_result = result;
    }

    /// DIFF NOTE: This method is not there in rr
    fn emulate_result_signed(&mut self, result: isize) {
        assert!(!self.preparation_done);
        assert!(!self.should_emulate_result);
        self.should_emulate_result = true;
        self.emulated_result = result as usize;
    }

    /// Internal method that takes 'ptr', an address within some memory parameter,
    /// and relocates it to the parameter's location in scratch memory.
    fn relocate_pointer_to_scratch(&self, ptr: RemotePtr<Void>) -> RemotePtr<Void> {
        let mut num_relocations: usize = 0;
        let mut result = RemotePtr::<Void>::null();
        for param in &self.param_list {
            if param.dest <= ptr && ptr < param.dest + param.num_bytes.incoming_size {
                result = param.scratch + (ptr - param.dest);
                num_relocations += 1;
            }
        }
        debug_assert!(
            num_relocations > 0,
            "Pointer in non-scratch memory being updated to point to scratch?"
        );

        debug_assert!(
            num_relocations <= 1,
            "Overlapping buffers containing relocated pointer?"
        );

        result
    }

    /// Internal method that takes the index of a MemoryParam and a vector
    /// containing the actual sizes assigned to each param < i, and
    /// computes the actual size to use for parameter param_index.
    ///
    /// DIFF NOTE: Takes t as param
    fn eval_param_size(
        &self,
        t: &mut RecordTask,
        i: usize,
        actual_sizes: &mut Vec<usize>,
    ) -> usize {
        assert_eq!(actual_sizes.len(), i);
        assert!(self.weak_task.ptr_eq(&t.weak_self));

        let mut already_consumed: usize = 0;
        for j in 0usize..i {
            if self.param_list[j]
                .num_bytes
                .is_same_source(&self.param_list[i].num_bytes)
            {
                already_consumed += actual_sizes[j];
            }
        }

        let size: usize = self.param_list[i].num_bytes.eval(t, already_consumed);

        actual_sizes.push(size);

        size
    }

    /// Called when all memory parameters have been identified. If 'sw' is
    /// Switchable::AllowSwitch, sets up scratch memory and updates registers etc as
    /// necessary.
    /// If scratch can't be used for some reason, returns Switchable::PreventSwitch,
    /// otherwise returns 'sw'.
    ///
    /// DIFF NOTE: Takes t as param
    fn done_preparing(&mut self, t: &mut RecordTask, mut sw: Switchable) -> Switchable {
        assert!(self.weak_task.ptr_eq(&t.weak_self));

        if self.preparation_done {
            return self.switchable;
        }

        sw = self.done_preparing_internal(t, sw);
        ed_assert_eq!(t, sw, self.switchable);

        // Step 3: Execute mutators. This must run even if the scratch steps do not.
        for param in &mut self.param_list {
            if param.maybe_mutator.is_some() {
                // Mutated parameters must be IN. If we have scratch space, we don't need
                // to save anything.
                let mut saved_data_loc: Option<&mut [u8]> = None;
                if !self.scratch_enabled {
                    let prev_size = self.saved_data.len();
                    self.saved_data
                        .resize(prev_size + param.num_bytes.incoming_size, 0);
                    saved_data_loc = Some(
                        &mut self.saved_data[prev_size..prev_size + param.num_bytes.incoming_size],
                    );
                }
                if !param.maybe_mutator.as_ref().unwrap()(
                    t,
                    if self.scratch_enabled {
                        param.scratch
                    } else {
                        param.dest
                    },
                    saved_data_loc,
                ) {
                    // Nothing was modified, no need to clean up when we unwind.
                    param.maybe_mutator = None;
                    if !self.scratch_enabled {
                        self.saved_data
                            .resize(self.saved_data.len() - param.num_bytes.incoming_size, 0);
                    }
                }
            }
        }

        self.switchable
    }

    /// DIFF NOTE: Takes t as param
    fn done_preparing_internal(&mut self, t: &mut RecordTask, sw: Switchable) -> Switchable {
        ed_assert!(t, !self.preparation_done);

        self.preparation_done = true;
        self.write_back = WriteBack::WriteBack;
        self.switchable = sw;

        if t.scratch_ptr.is_null() {
            return self.switchable;
        }

        ed_assert!(t, self.scratch >= t.scratch_ptr);

        if sw == Switchable::AllowSwitch && self.scratch > t.scratch_ptr + t.usable_scratch_size() {
            log!(LogWarn,
         "`{}' needed a scratch buffer of size {}, but only {} was available.  Disabling context switching: deadlock may follow.",
             t.ev().syscall_event().syscall_name(),
        self.scratch.as_usize() - t.scratch_ptr.as_usize(),
        t.usable_scratch_size());

            self.switchable = Switchable::PreventSwitch;
        }
        if self.switchable == Switchable::PreventSwitch || self.param_list.is_empty() {
            return self.switchable;
        }

        self.scratch_enabled = true;

        // Step 1: Copy all IN/IN_OUT parameters to their scratch areas
        for param in &self.param_list {
            if param.mode == ArgMode::InOut || param.mode == ArgMode::In {
                // Initialize scratch buffer with input data
                let buf = read_mem(t, param.dest, param.num_bytes.incoming_size, None);
                write_mem(t, param.scratch, &buf, None);
            }
        }
        // Step 2: Update pointers in registers/memory to point to scratch areas
        {
            let mut r: Registers = t.regs_ref().clone();
            let mut to_adjust = Vec::<(usize, RemotePtr<Void>)>::new();
            for (i, param) in self.param_list.iter().enumerate() {
                if param.ptr_in_reg != 0 {
                    r.set_arg(param.ptr_in_reg, param.scratch.as_usize());
                }
                if !param.ptr_in_memory.is_null() {
                    // Pointers being relocated must themselves be in scratch memory.
                    // We don't want to modify non-scratch memory. Find the pointer's
                    // location
                    // in scratch memory.
                    let p = self.relocate_pointer_to_scratch(param.ptr_in_memory);
                    // Update pointer to point to scratch.
                    // Note that this can only happen after step 1 is complete and all
                    // parameter data has been copied to scratch memory.
                    set_remote_ptr(t, p, param.scratch);
                }
                // If the number of bytes to record is coming from a memory location,
                // update that location to scratch.
                if !param.num_bytes.mem_ptr.is_null() {
                    to_adjust.push((i, self.relocate_pointer_to_scratch(param.num_bytes.mem_ptr)));
                }
            }

            for (i, rptr) in to_adjust {
                self.param_list[i].num_bytes.mem_ptr = rptr;
            }

            t.set_regs(&r);
        }

        self.switchable
    }

    /// Called when a syscall exits to copy results from scratch memory to their
    /// original destinations, update registers, etc.
    ///
    /// DIFF NOTE: Takes t as param
    fn process_syscall_results(&mut self, t: &mut RecordTask) {
        assert!(self.weak_task.ptr_eq(&t.weak_self));
        ed_assert!(t, self.preparation_done);

        // XXX what's the best way to handle failed syscalls? Currently we just
        // record everything as if it succeeded. That handles failed syscalls that
        // wrote partial results, but doesn't handle syscalls that failed with
        // EFAULT.
        let mut actual_sizes: Vec<usize> = Vec::new();
        if self.scratch_enabled {
            let scratch_num_bytes: usize = self.scratch - t.scratch_ptr;
            let child_addr = RemotePtr::<u8>::cast(t.scratch_ptr);
            let data = read_mem(t, child_addr, scratch_num_bytes, None);
            let mut r: Registers = t.regs_ref().clone();
            // Step 1: compute actual sizes of all buffers and copy outputs
            // from scratch back to their origin
            for (i, param) in self.param_list.iter().enumerate() {
                let size: usize = self.eval_param_size(t, i, &mut actual_sizes);
                if self.write_back == WriteBack::WriteBack
                    && (param.mode == ArgMode::InOut || param.mode == ArgMode::Out)
                {
                    let offset = param.scratch.as_usize() - t.scratch_ptr.as_usize();
                    let d = &data[offset..offset + size];
                    write_mem(t, param.dest, d, None);
                }
            }

            let mut memory_cleaned_up: bool = false;
            // Step 2: restore modified in-memory pointers and registers
            for param in &self.param_list {
                if param.ptr_in_reg > 0 {
                    r.set_arg(param.ptr_in_reg, param.dest.as_usize());
                }
                if !param.ptr_in_memory.is_null() {
                    memory_cleaned_up = true;
                    set_remote_ptr(t, param.ptr_in_memory, param.dest);
                }
            }
            if self.write_back == WriteBack::WriteBack {
                // Step 3: record all output memory areas
                for (i, param) in self.param_list.iter().enumerate() {
                    let size: usize = actual_sizes[i];
                    if param.mode == ArgMode::InOutNoScratch {
                        t.record_remote(param.dest, size);
                    } else if param.mode == ArgMode::InOut || param.mode == ArgMode::Out {
                        // If pointers in memory were fixed up in step 2, then record
                        // from tracee memory to ensure we record such fixes. Otherwise we
                        // can record from our local data.
                        // XXX This optimization can be improved if necessary...
                        if memory_cleaned_up {
                            t.record_remote(param.dest, size);
                        } else {
                            let offset = param.scratch.as_usize() - t.scratch_ptr.as_usize();
                            let d = &data[offset..offset + size];
                            t.record_local(param.dest, d);
                        }
                    }
                }
            }
            t.set_regs(&r);
        } else {
            // Step 1: restore all mutated memory
            for param in &self.param_list {
                if param.maybe_mutator.is_some() {
                    let size: usize = param.num_bytes.incoming_size;
                    ed_assert!(t, self.saved_data.len() >= size);
                    write_mem(t, param.dest, &self.saved_data[0..size], None);
                    self.saved_data.drain(0..size);
                }
            }

            ed_assert!(t, self.saved_data.is_empty());
            // Step 2: record all output memory areas
            for (i, param) in self.param_list.iter().enumerate() {
                let size: usize = self.eval_param_size(t, i, &mut actual_sizes);
                t.record_remote(param.dest, size);
            }
        }

        if self.should_emulate_result {
            let mut r: Registers = t.regs_ref().clone();
            r.set_syscall_result(self.emulated_result);
            t.set_regs(&r);
        }

        for action in &self.after_syscall_actions {
            action(t);
        }
    }

    /// Called when a syscall has been completely aborted to undo any changes we
    /// made.
    ///
    /// DIFF NOTE: Takes t as param
    pub fn abort_syscall_results(&mut self, t: &mut RecordTask) {
        assert!(self.weak_task.ptr_eq(&t.weak_self));
        ed_assert!(t, self.preparation_done);

        if self.scratch_enabled {
            let mut r: Registers = t.regs_ref().clone();
            // restore modified in-memory pointers and registers
            for param in &self.param_list {
                if param.ptr_in_reg != 0 {
                    r.set_arg(param.ptr_in_reg, param.dest.as_usize());
                }
                if !param.ptr_in_memory.is_null() {
                    set_remote_ptr(t, param.ptr_in_memory, param.dest);
                }
            }
            t.set_regs(&r);
        } else {
            for param in &self.param_list {
                if param.maybe_mutator.is_some() {
                    let size: usize = param.num_bytes.incoming_size;
                    ed_assert!(t, self.saved_data.len() >= size);
                    write_mem(t, param.dest, &self.saved_data[0..size], None);
                    self.saved_data.drain(0..size);
                }
            }
        }
    }
}

/// Upon successful syscall completion, each RestoreAndRecordScratch record
/// in param_list consumes num_bytes from the t->scratch_ptr
/// buffer, copying the data to remote_dest and recording the data at
/// remote_dest. If ptr_in_reg is greater than zero, updates the task's
/// ptr_in_reg register with 'remote_dest'. If ptr_in_memory is non-null,
/// updates the ptr_in_memory location with the value 'remote_dest'.
#[derive(Default)]
struct MemoryParam {
    dest: RemotePtr<Void>,
    scratch: RemotePtr<Void>,
    num_bytes: ParamSize,
    ptr_in_memory: RemotePtr<Void>,
    /// DIFF NOTE: This is an i32 in rr
    ptr_in_reg: usize,
    mode: ArgMode,
    maybe_mutator: Option<ArgMutator>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum WriteBack {
    WriteBack,
    NoWriteBack,
}

/// Specifies how to determine the size of a syscall memory
/// parameter. There is usually an incoming size determined before the syscall
/// executes (which we need in order to allocate scratch memory), combined
/// with an optional final size taken from the syscall result or a specific
/// memory location after the syscall has executed. The minimum of the incoming
/// and final sizes is used, if both are present.
#[derive(Copy, Clone)]
struct ParamSize {
    incoming_size: usize,
    /// If non-null, the size is limited by the value at this location after
    /// the syscall.
    mem_ptr: RemotePtr<Void>,
    /// Size of the value at mem_ptr or in the syscall result register.
    read_size: usize,
    /// If true, the size is limited by the value of the syscall result.
    from_syscall: bool,
}

impl Default for ParamSize {
    fn default() -> Self {
        Self {
            incoming_size: i32::MAX as usize,
            mem_ptr: Default::default(),
            read_size: 0,
            from_syscall: false,
        }
    }
}

impl From<usize> for ParamSize {
    fn from(siz: usize) -> Self {
        ParamSize {
            incoming_size: min(i32::MAX as usize, siz),
            mem_ptr: 0usize.into(),
            read_size: 0,
            from_syscall: false,
        }
    }
}

impl ParamSize {
    /// p points to a tracee location that is already initialized with a
    /// "maximum buffer size" passed in by the tracee, and which will be filled
    /// in with the size of the data by the kernel when the syscall exits.
    fn from_initialized_mem<T>(t: &mut dyn Task, p: RemotePtr<T>) -> ParamSize {
        let mut r = ParamSize::from(if p.is_null() {
            0
        } else {
            match size_of::<T>() {
                4 => read_val_mem(t, RemotePtr::<u32>::cast(p), None) as usize,
                8 => read_val_mem(t, RemotePtr::<u64>::cast(p), None)
                    .try_into()
                    .unwrap(),
                _ => {
                    ed_assert!(t, false, "Unknown read_size");
                    0
                }
            }
        });
        r.mem_ptr = RemotePtr::cast(p);
        r.read_size = size_of::<T>();

        r
    }

    /// p points to a tracee location which will be filled in with the size of
    /// the data by the kernel when the syscall exits, but the location
    /// is uninitialized before the syscall.
    fn from_mem<T>(p: RemotePtr<T>) -> ParamSize {
        let mut r = ParamSize::default();
        r.mem_ptr = RemotePtr::cast(p);
        r.read_size = size_of::<T>();

        r
    }

    /// When the syscall exits, the syscall result will be of type T and contain
    /// the size of the data. 'incoming_size', if present, is a bound on the size
    /// of the data.
    fn from_syscall_result<T>() -> ParamSize {
        let mut r = ParamSize::default();
        r.from_syscall = true;
        r.read_size = size_of::<T>();
        r
    }

    fn from_syscall_result_with_size<T>(incoming_size: usize) -> ParamSize {
        let mut r = ParamSize::from(incoming_size);
        r.from_syscall = true;
        r.read_size = size_of::<T>();
        r
    }

    /// Indicate that the size will be at most 'max'.
    fn limit_size(&self, max: usize) -> ParamSize {
        let mut r = self.clone();
        r.incoming_size = min(r.incoming_size, max);

        r
    }

    fn eval(&self, t: &mut dyn Task, already_consumed: usize) -> usize {
        let mut s: usize = self.incoming_size;
        if !self.mem_ptr.is_null() {
            let mem_size: usize;
            match self.read_size {
                4 => {
                    mem_size = read_val_mem(t, RemotePtr::<u32>::cast(self.mem_ptr), None) as usize
                }
                8 => {
                    mem_size = read_val_mem(t, RemotePtr::<u64>::cast(self.mem_ptr), None)
                        .try_into()
                        .unwrap();
                }
                _ => {
                    ed_assert!(t, false, "Unknown read_size");
                    return 0;
                }
            }

            ed_assert!(t, already_consumed <= mem_size);
            s = min(s, mem_size - already_consumed);
        }

        if self.from_syscall {
            let mut syscall_size: usize =
                max(0isize, t.regs_ref().syscall_result_signed()) as usize;
            syscall_size = match self.read_size {
                // @TODO Is this what we want?
                4 => syscall_size as u32 as usize,
                // @TODO Is this what we want?
                8 => syscall_size as u64 as usize,
                _ => {
                    ed_assert!(t, false, "Unknown read_size");
                    return 0;
                }
            };

            ed_assert!(t, already_consumed <= syscall_size);
            s = min(s, syscall_size - already_consumed);
        }

        s
    }

    /// Return true if 'other' takes its dynamic size from the same source as
    /// this.
    /// When multiple syscall memory parameters take their dynamic size from the
    /// same source, the source size is distributed among them, with the first
    /// registered parameter taking up to its max_size bytes, followed by the next,
    /// etc. This lets us efficiently record iovec buffers.
    fn is_same_source(&self, other: &ParamSize) -> bool {
        ((!self.mem_ptr.is_null() && other.mem_ptr == self.mem_ptr)
            || (self.from_syscall && other.from_syscall))
            && (self.read_size == other.read_size)
    }
}

/// Modes used to register syscall memory parameter with TaskSyscallState.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum ArgMode {
    /// Syscall memory parameter is an in-parameter only.
    /// This is only important when we want to move the buffer to scratch memory
    /// so we can modify it without making the modifications potentially visible
    /// to user code. Otherwise, such parameters can be ignored.
    In,
    /// Syscall memory parameter is out-parameter only.
    Out,
    /// Syscall memory parameter is an in-out parameter.
    InOut,
    /// Syscall memory parameter is an in-out parameter but we must not use
    /// scratch (e.g. for futexes, we must use the actual memory word).
    InOutNoScratch,
}

impl Default for ArgMode {
    fn default() -> Self {
        Self::Out
    }
}

fn set_remote_ptr_arch<Arch: Architecture>(
    t: &mut dyn Task,
    addr: RemotePtr<Void>,
    value: RemotePtr<Void>,
) {
    let typed_addr = RemotePtr::<Arch::unsigned_word>::cast(addr);
    write_val_mem(
        t,
        typed_addr,
        &Arch::as_unsigned_word(value.as_usize()),
        None,
    );
}

fn set_remote_ptr(t: &mut dyn Task, addr: RemotePtr<Void>, value: RemotePtr<Void>) {
    let arch = t.arch();
    rd_arch_function_selfless!(set_remote_ptr_arch, arch, t, addr, value);
}

fn get_remote_ptr_arch<Arch: Architecture>(
    t: &mut dyn Task,
    addr: RemotePtr<Void>,
) -> RemotePtr<Void> {
    let typed_addr = RemotePtr::<Arch::unsigned_word>::cast(addr);
    let old = read_val_mem(t, typed_addr, None);
    RemotePtr::from(old.try_into().unwrap())
}

fn get_remote_ptr(t: &mut dyn Task, addr: RemotePtr<Void>) -> RemotePtr<Void> {
    let arch = t.arch();
    rd_arch_function_selfless!(get_remote_ptr_arch, arch, t, addr)
}

fn align_scratch(scratch: &mut RemotePtr<Void>, maybe_amount: Option<usize>) {
    let amount = maybe_amount.unwrap_or(8);
    *scratch = RemotePtr::from((scratch.as_usize() + amount - 1) & !(amount - 1));
}

fn extra_expected_errno_info<Arch: Architecture>(
    t: &RecordTask,
    syscall_state: &mut TaskSyscallState,
) -> String {
    match syscall_state.expect_errno {
        ENOSYS => return format!("; execution of syscall unsupported by rd"),
        EINVAL => {
            let sys = t.regs_ref().original_syscallno() as i32;
            if sys == Arch::IOCTL {
                let request = t.regs_ref().arg2() as u32;
                let type_ = unsafe { ioctl_type(request) };
                let nr = unsafe { ioctl_nr(request) };
                let dir = unsafe { ioctl_dir(request) };
                let size = unsafe { ioctl_size(request) };
                return format!(
                    "; Unknown ioctl({:x}): type:{:x} nr:{:x} dir:{:x} size:{:x} addr:{:x}",
                    request,
                    type_,
                    nr,
                    dir,
                    size,
                    t.regs_ref().arg3()
                );
            }
            if sys == Arch::FCNTL || sys == Arch::FCNTL64 {
                return format!("; unknown fcntl({:x})", t.regs_ref().arg2_signed() as i32);
            }
            if sys == Arch::PRCTL {
                return format!("; unknown prctl({:x})", t.regs_ref().arg1_signed() as i32);
            }
            if sys == Arch::ARCH_PRCTL {
                return format!(
                    "; unknown arch_prctl({:x})",
                    t.regs_ref().arg1_signed() as i32
                );
            }
            if sys == Arch::KEYCTL {
                return format!("; unknown keyctl({:x})", t.regs_ref().arg1_signed() as i32);
            }
            if sys == Arch::SOCKETCALL {
                return format!(
                    "; unknown socketcall({:x})",
                    t.regs_ref().arg1_signed() as i32
                );
            }
            if sys == Arch::IPC {
                return format!("; unknown ipc({:x})", t.regs_ref().arg1_signed() as i32);
            }
            if sys == Arch::FUTEX_TIME64 || sys == Arch::FUTEX {
                return format!(
                    "; unknown futex({:x})",
                    t.regs_ref().arg2_signed() as i32 & FUTEX_CMD_MASK
                );
            }
            if sys == Arch::WAITID {
                return format!("; unknown waitid({:x})", t.regs_ref().arg1() as idtype_t);
            }
            if sys == Arch::SECCOMP {
                return format!("; unknown seccomp({:x})", t.regs_ref().arg1() as u32);
            }
            if sys == Arch::MADVISE {
                return format!("; unknown madvise({:x})", t.regs_ref().arg3() as i32);
            }
        }
        EIO => {
            let sys = t.regs_ref().original_syscallno() as i32;
            if sys == Arch::PTRACE {
                return format!(
                    "; unsupported ptrace({:x}) [{}]",
                    t.regs_ref().arg1(),
                    ptrace_req_name(t.regs_ref().arg1() as u32)
                );
            }
        }
        _ => (),
    }

    return String::new();
}

const IOCTL_MASK_SIZE_TUNSETIFF: u32 = ioctl_mask_size(_TUNSETIFF);
const IOCTL_MASK_SIZE_TUNSETNOCSUM: u32 = ioctl_mask_size(_TUNSETNOCSUM);
const IOCTL_MASK_SIZE_TUNSETDEBUG: u32 = ioctl_mask_size(_TUNSETDEBUG);
const IOCTL_MASK_SIZE_TUNSETPERSIST: u32 = ioctl_mask_size(_TUNSETPERSIST);
const IOCTL_MASK_SIZE_TUNSETOWNER: u32 = ioctl_mask_size(_TUNSETOWNER);
const IOCTL_MASK_SIZE_TUNSETLINK: u32 = ioctl_mask_size(_TUNSETLINK);
const IOCTL_MASK_SIZE_TUNSETGROUP: u32 = ioctl_mask_size(_TUNSETGROUP);
const IOCTL_MASK_SIZE_TUNSETOFFLOAD: u32 = ioctl_mask_size(_TUNSETOFFLOAD);
const IOCTL_MASK_SIZE_TUNSETTXFILTER: u32 = ioctl_mask_size(_TUNSETTXFILTER);
const IOCTL_MASK_SIZE_TUNSETSNDBUF: u32 = ioctl_mask_size(_TUNSETSNDBUF);
const IOCTL_MASK_SIZE_TUNATTACHFILTER: u32 = ioctl_mask_size(_TUNATTACHFILTER);
const IOCTL_MASK_SIZE_TUNDETACHFILTER: u32 = ioctl_mask_size(_TUNDETACHFILTER);
const IOCTL_MASK_SIZE_TUNSETVNETHDRSZ: u32 = ioctl_mask_size(_TUNSETVNETHDRSZ);
const IOCTL_MASK_SIZE_TUNSETQUEUE: u32 = ioctl_mask_size(_TUNSETQUEUE);
const IOCTL_MASK_SIZE_TUNSETIFINDEX: u32 = ioctl_mask_size(_TUNSETIFINDEX);
const IOCTL_MASK_SIZE_TUNSETVNETLE: u32 = ioctl_mask_size(_TUNSETVNETLE);
const IOCTL_MASK_SIZE_TUNSETVNETBE: u32 = ioctl_mask_size(_TUNSETVNETBE);
const IOCTL_MASK_SIZE_TUNGETFEATURES: u32 = ioctl_mask_size(_TUNGETFEATURES);
const IOCTL_MASK_SIZE_TUNGETSNDBUF: u32 = ioctl_mask_size(_TUNGETSNDBUF);
const IOCTL_MASK_SIZE_TUNGETVNETHDRSZ: u32 = ioctl_mask_size(_TUNGETVNETHDRSZ);
const IOCTL_MASK_SIZE_TUNGETVNETLE: u32 = ioctl_mask_size(_TUNGETVNETLE);
const IOCTL_MASK_SIZE_TUNGETVNETBE: u32 = ioctl_mask_size(_TUNGETVNETBE);
const IOCTL_MASK_SIZE_TUNGETIFF: u32 = ioctl_mask_size(_TUNGETIFF);
const IOCTL_MASK_SIZE_TUNGETFILTER: u32 = ioctl_mask_size(_TUNGETFILTER);

const IOCTL_MASK_SIZE_BTRFS_IOC_CLONE: u32 = ioctl_mask_size(BTRFS_IOC_CLONE_);
const IOCTL_MASK_SIZE_BTRFS_IOC_CLONE_RANGE: u32 = ioctl_mask_size(BTRFS_IOC_CLONE_RANGE_);

const IOCTL_MASK_SIZE_USBDEVFS_DISCARDURB: u32 = ioctl_mask_size(_USBDEVFS_DISCARDURB);
const IOCTL_MASK_SIZE_USBDEVFS_RESET: u32 = ioctl_mask_size(_USBDEVFS_RESET);
const IOCTL_MASK_SIZE_USBDEVFS_GETDRIVER: u32 = ioctl_mask_size(_USBDEVFS_GETDRIVER);
const IOCTL_MASK_SIZE_USBDEVFS_REAPURB: u32 = ioctl_mask_size(_USBDEVFS_REAPURB);
const IOCTL_MASK_SIZE_USBDEVFS_REAPURBNDELAY: u32 = ioctl_mask_size(_USBDEVFS_REAPURBNDELAY);
const IOCTL_MASK_SIZE_USBDEVFS_ALLOC_STREAMS: u32 = ioctl_mask_size(_USBDEVFS_ALLOC_STREAMS);
const IOCTL_MASK_SIZE_USBDEVFS_CLAIMINTERFACE: u32 = ioctl_mask_size(_USBDEVFS_CLAIMINTERFACE);
const IOCTL_MASK_SIZE_USBDEVFS_CLEAR_HALT: u32 = ioctl_mask_size(_USBDEVFS_CLEAR_HALT);
const IOCTL_MASK_SIZE_USBDEVFS_DISCONNECT_CLAIM: u32 = ioctl_mask_size(_USBDEVFS_DISCONNECT_CLAIM);
const IOCTL_MASK_SIZE_USBDEVFS_FREE_STREAMS: u32 = ioctl_mask_size(_USBDEVFS_FREE_STREAMS);
const IOCTL_MASK_SIZE_USBDEVFS_RELEASEINTERFACE: u32 = ioctl_mask_size(_USBDEVFS_RELEASEINTERFACE);
const IOCTL_MASK_SIZE_USBDEVFS_SETCONFIGURATION: u32 = ioctl_mask_size(_USBDEVFS_SETCONFIGURATION);
const IOCTL_MASK_SIZE_USBDEVFS_SETINTERFACE: u32 = ioctl_mask_size(_USBDEVFS_SETINTERFACE);
const IOCTL_MASK_SIZE_USBDEVFS_SUBMITURB: u32 = ioctl_mask_size(_USBDEVFS_SUBMITURB);
const IOCTL_MASK_SIZE_USBDEVFS_IOCTL: u32 = ioctl_mask_size(_USBDEVFS_IOCTL);
const IOCTL_MASK_SIZE_USBDEVFS_CONTROL: u32 = ioctl_mask_size(_USBDEVFS_CONTROL);
const IOCTL_MASK_SIZE_USBDEVFS_GET_CAPABILITIES: u32 = ioctl_mask_size(_USBDEVFS_GET_CAPABILITIES);

const IOCTL_MASK_SIZE_TIOCGPTN: u32 = ioctl_mask_size(_TIOCGPTN);
const IOCTL_MASK_SIZE_TIOCGPKT: u32 = ioctl_mask_size(_TIOCGPKT);
const IOCTL_MASK_SIZE_TIOCGPTLCK: u32 = ioctl_mask_size(_TIOCGPTLCK);
const IOCTL_MASK_SIZE_TIOCGEXCL: u32 = ioctl_mask_size(_TIOCGEXCL);
const IOCTL_MASK_SIZE_TIOCSPTLCK: u32 = ioctl_mask_size(_TIOCSPTLCK);
const IOCTL_MASK_SIZE_TIOCGPTPEER: u32 = ioctl_mask_size(_TIOCGPTPEER);

const IOCTL_MASK_SIZE_VIDIOC_QUERYCAP: u32 = ioctl_mask_size(_VIDIOC_QUERYCAP);
const IOCTL_MASK_SIZE_VIDIOC_ENUM_FMT: u32 = ioctl_mask_size(_VIDIOC_ENUM_FMT);
const IOCTL_MASK_SIZE_VIDIOC_ENUM_FRAMESIZES: u32 = ioctl_mask_size(_VIDIOC_ENUM_FRAMESIZES);
const IOCTL_MASK_SIZE_VIDIOC_ENUM_FRAMEINTERVALS: u32 =
    ioctl_mask_size(_VIDIOC_ENUM_FRAMEINTERVALS);
const IOCTL_MASK_SIZE_VIDIOC_ENUMINPUT: u32 = ioctl_mask_size(_VIDIOC_ENUMINPUT);
const IOCTL_MASK_SIZE_VIDIOC_G_FMT: u32 = ioctl_mask_size(_VIDIOC_G_FMT);
const IOCTL_MASK_SIZE_VIDIOC_S_FMT: u32 = ioctl_mask_size(_VIDIOC_S_FMT);
const IOCTL_MASK_SIZE_VIDIOC_TRY_FMT: u32 = ioctl_mask_size(_VIDIOC_TRY_FMT);
const IOCTL_MASK_SIZE_VIDIOC_G_PARM: u32 = ioctl_mask_size(_VIDIOC_G_PARM);
const IOCTL_MASK_SIZE_VIDIOC_S_PARM: u32 = ioctl_mask_size(_VIDIOC_S_PARM);
const IOCTL_MASK_SIZE_VIDIOC_REQBUFS: u32 = ioctl_mask_size(_VIDIOC_REQBUFS);
const IOCTL_MASK_SIZE_VIDIOC_QUERYBUF: u32 = ioctl_mask_size(_VIDIOC_QUERYBUF);
const IOCTL_MASK_SIZE_VIDIOC_QUERYCTRL: u32 = ioctl_mask_size(_VIDIOC_QUERYCTRL);
const IOCTL_MASK_SIZE_VIDIOC_QBUF: u32 = ioctl_mask_size(_VIDIOC_QBUF);
const IOCTL_MASK_SIZE_VIDIOC_G_CTRL: u32 = ioctl_mask_size(_VIDIOC_G_CTRL);
const IOCTL_MASK_SIZE_VIDIOC_G_OUTPUT: u32 = ioctl_mask_size(_VIDIOC_G_OUTPUT);
const IOCTL_MASK_SIZE_VIDIOC_S_CTRL: u32 = ioctl_mask_size(_VIDIOC_S_CTRL);
const IOCTL_MASK_SIZE_VIDIOC_DQBUF: u32 = ioctl_mask_size(_VIDIOC_DQBUF);

const IOCTL_MASK_SIZE_VFAT_IOCTL_READDIR_BOTH: u32 = ioctl_mask_size(_VFAT_IOCTL_READDIR_BOTH);
const IOCTL_MASK_SIZE_FS_IOC_GETVERSION: u32 = ioctl_mask_size(_FS_IOC_GETVERSION);
const IOCTL_MASK_SIZE_FS_IOC_GETFLAGS: u32 = ioctl_mask_size(_FS_IOC_GETFLAGS);
const IOCTL_MASK_SIZE_EVIOCGVERSION: u32 = ioctl_mask_size(_EVIOCGVERSION);
const IOCTL_MASK_SIZE_EVIOCGID: u32 = ioctl_mask_size(_EVIOCGID);
const IOCTL_MASK_SIZE_EVIOCGREP: u32 = ioctl_mask_size(_EVIOCGREP);
const IOCTL_MASK_SIZE_EVIOCGKEYCODE: u32 = ioctl_mask_size(_EVIOCGKEYCODE);
const IOCTL_MASK_SIZE_EVIOCGNAME_0: u32 = ioctl_mask_size(_EVIOCGNAME_0);
const IOCTL_MASK_SIZE_EVIOCGPHYS_0: u32 = ioctl_mask_size(_EVIOCGPHYS_0);
const IOCTL_MASK_SIZE_EVIOCGUNIQ_0: u32 = ioctl_mask_size(_EVIOCGUNIQ_0);
const IOCTL_MASK_SIZE_EVIOCGPROP_0: u32 = ioctl_mask_size(_EVIOCGPROP_0);
const IOCTL_MASK_SIZE_EVIOCGMTSLOTS_0: u32 = ioctl_mask_size(_EVIOCGMTSLOTS_0);
const IOCTL_MASK_SIZE_EVIOCGKEY_0: u32 = ioctl_mask_size(_EVIOCGKEY_0);
const IOCTL_MASK_SIZE_EVIOCGLED_0: u32 = ioctl_mask_size(_EVIOCGLED_0);
const IOCTL_MASK_SIZE_EVIOCGSND_0: u32 = ioctl_mask_size(_EVIOCGSND_0);
const IOCTL_MASK_SIZE_EVIOCGSW_0: u32 = ioctl_mask_size(_EVIOCGSW_0);
const IOCTL_MASK_SIZE_EVIOCGEFFECTS: u32 = ioctl_mask_size(_EVIOCGEFFECTS);
const IOCTL_MASK_SIZE_EVIOCGMASK: u32 = ioctl_mask_size(_EVIOCGMASK);
const IOCTL_MASK_SIZE_JSIOCGVERSION: u32 = ioctl_mask_size(_JSIOCGVERSION);
const IOCTL_MASK_SIZE_JSIOCGAXES: u32 = ioctl_mask_size(_JSIOCGAXES);
const IOCTL_MASK_SIZE_JSIOCGBUTTONS: u32 = ioctl_mask_size(_JSIOCGBUTTONS);
const IOCTL_MASK_SIZE_JSIOCGAXMAP: u32 = ioctl_mask_size(_JSIOCGAXMAP);
const IOCTL_MASK_SIZE_JSIOCGBTNMAP: u32 = ioctl_mask_size(_JSIOCGBTNMAP);
const IOCTL_MASK_SIZE_JSIOCGNAME_0: u32 = ioctl_mask_size(_JSIOCGNAME_0);

fn prepare_ioctl<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
) -> Switchable {
    let fd = t.regs_ref().arg1() as i32;
    let mut result: usize = 0;
    if t.fd_table_shr_ptr().emulate_ioctl(fd, t, &mut result) {
        // Don't perform this syscall.
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1_signed(-1);
        t.set_regs(&r);
        syscall_state.emulate_result(result);
        return Switchable::PreventSwitch;
    }

    let request = t.regs_ref().arg2() as u32;
    let type_: u32 = unsafe { ioctl_type(request) };
    let nr: u32 = unsafe { ioctl_nr(request) };
    let dir: u32 = unsafe { ioctl_dir(request) };
    let size: u32 = unsafe { ioctl_size(request) };

    log!(
        LogDebug,
        "handling ioctl({:#x}): type:{:#x} nr:{:#x} dir:{:#x} size:{}",
        request,
        type_,
        nr,
        dir,
        size
    );

    ed_assert!(
        t,
        !t.is_desched_event_syscall(),
        "Failed to skip past desched ioctl()"
    );

    // Some ioctl()s are irregular and don't follow the _IOC()
    // conventions.  Special case them here.
    match request {
        SIOCETHTOOL => {
            let ifrp = syscall_state.reg_parameter::<ifreq<Arch>>(3, Some(ArgMode::In), None);

            let addr_of_buf_ptr: RemotePtr<u8> = remote_ptr_field!(ifrp, ifreq<Arch>, ifr_ifru);
            syscall_state.mem_ptr_parameter::<Arch::ethtool_cmd>(t, addr_of_buf_ptr, None, None);
            syscall_state.after_syscall_action(Box::new(record_page_below_stack_ptr));
            return Switchable::PreventSwitch;
        }

        SIOCGIFCONF => {
            let ifconfp =
                syscall_state.reg_parameter::<ifconf<Arch>>(3, Some(ArgMode::InOut), None);
            let addr_of_buf_ptr = remote_ptr_field!(ifconfp, ifconf<Arch>, ifc_ifcu);
            let param_size = ParamSize::from_initialized_mem(
                t,
                RemotePtr::<i32>::cast(remote_ptr_field!(ifconfp, ifconf<Arch>, ifc_len)),
            );
            syscall_state.mem_ptr_parameter_with_size(t, addr_of_buf_ptr, param_size, None, None);
            syscall_state.after_syscall_action(Box::new(record_page_below_stack_ptr));
            return Switchable::PreventSwitch;
        }

        // Privileged ioctls
        SIOCSIFADDR | SIOCSIFDSTADDR | SIOCSIFBRDADDR | SIOCSIFHWADDR | SIOCSIFFLAGS
        | SIOCSIFPFLAGS | SIOCSIFTXQLEN | SIOCSIFMTU | SIOCSIFNAME | SIOCSIFNETMASK
        | SIOCSIFMETRIC | SIOCSIFHWBROADCAST | SIOCSIFMAP | SIOCADDMULTI | SIOCDELMULTI => {
            return Switchable::PreventSwitch;
        }

        // Bridge ioctls
        SIOCBRADDBR | SIOCBRDELBR | SIOCBRADDIF | SIOCBRDELIF => {
            return Switchable::PreventSwitch;
        }

        // Routing iocts
        SIOCADDRT | SIOCDELRT => {
            return Switchable::PreventSwitch;
        }

        SIOCBONDINFOQUERY => {
            let ifrp = syscall_state.reg_parameter::<ifreq<Arch>>(3, Some(ArgMode::In), None);
            let addr_of_buf_ptr = remote_ptr_field!(ifrp, ifreq<Arch>, ifr_ifru);
            syscall_state.mem_ptr_parameter::<Arch::ifbond>(t, addr_of_buf_ptr, None, None);
            syscall_state.after_syscall_action(Box::new(record_page_below_stack_ptr));
            return Switchable::PreventSwitch;
        }

        SIOCGIFADDR | SIOCGIFDSTADDR | SIOCGIFBRDADDR | SIOCGIFHWADDR | SIOCGIFFLAGS
        | SIOCGIFPFLAGS | SIOCGIFTXQLEN | SIOCGIFINDEX | SIOCGIFMTU | SIOCGIFNAME
        | SIOCGIFNETMASK | SIOCGIFMETRIC | SIOCGIFMAP => {
            syscall_state.reg_parameter::<Arch::ifreq>(3, None, None);
            syscall_state.after_syscall_action(Box::new(record_page_below_stack_ptr));
            return Switchable::PreventSwitch;
        }

        // These haven't been observed to write beyond
        // tracees' stacks, but we record a stack page here
        // just in the behavior is driver-dependent.
        SIOCGIWFREQ | SIOCGIWMODE | SIOCGIWNAME | SIOCGIWRATE | SIOCGIWSENS => {
            syscall_state.reg_parameter::<Arch::iwreq>(3, None, None);
            syscall_state.after_syscall_action(Box::new(record_page_below_stack_ptr));
            return Switchable::PreventSwitch;
        }

        SIOCGIWESSID => {
            let argsp = syscall_state.reg_parameter::<iwreq<Arch>>(3, Some(ArgMode::InOut), None);
            let args = read_val_mem(t, argsp, None);
            let ptr = unsafe { args.u.essid.pointer };
            syscall_state.mem_ptr_parameter_with_size(
                t,
                Arch::as_rptr(ptr),
                ParamSize::from(unsafe { args.u.essid.length } as usize),
                None,
                None,
            );
            syscall_state.after_syscall_action(Box::new(record_page_below_stack_ptr));
            return Switchable::PreventSwitch;
        }

        SIOCGSTAMP => {
            syscall_state.reg_parameter::<Arch::timeval>(3, None, None);
            return Switchable::PreventSwitch;
        }

        SIOCGSTAMPNS => {
            syscall_state.reg_parameter::<Arch::timespec>(3, None, None);
            return Switchable::PreventSwitch;
        }

        TCGETS | TIOCGLCKTRMIOS => {
            syscall_state.reg_parameter::<Arch::termios>(3, None, None);
            return Switchable::PreventSwitch;
        }

        TCGETA => {
            syscall_state.reg_parameter::<Arch::termio>(3, None, None);
            return Switchable::PreventSwitch;
        }

        TIOCINQ | TIOCOUTQ | TIOCGETD => {
            syscall_state.reg_parameter::<i32>(3, None, None);
            return Switchable::PreventSwitch;
        }

        TIOCGWINSZ => {
            syscall_state.reg_parameter::<Arch::winsize>(3, None, None);
            return Switchable::PreventSwitch;
        }

        TIOCGPGRP | TIOCGSID => {
            syscall_state.reg_parameter::<common::pid_t>(3, None, None);
            return Switchable::PreventSwitch;
        }

        _SNDRV_CTL_IOCTL_PVERSION => {
            syscall_state.reg_parameter::<i32>(3, None, None);
            return Switchable::PreventSwitch;
        }

        _SNDRV_CTL_IOCTL_CARD_INFO => {
            syscall_state.reg_parameter::<Arch::snd_ctl_card_info>(3, None, None);
            return Switchable::PreventSwitch;
        }

        _HCIGETDEVINFO => {
            syscall_state.reg_parameter::<Arch::hci_dev_info>(3, None, None);
            return Switchable::PreventSwitch;
        }

        _HCIGETDEVLIST => {
            syscall_state.reg_parameter::<Arch::hci_dev_list_req>(3, None, None);
            return Switchable::PreventSwitch;
        }

        SG_GET_VERSION_NUM => {
            syscall_state.reg_parameter::<i32>(3, None, None);
            return Switchable::PreventSwitch;
        }

        SG_IO => {
            let argsp =
                syscall_state.reg_parameter::<sg_io_hdr<Arch>>(3, Some(ArgMode::InOut), None);
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, sg_io_hdr<Arch>, dxferp),
                ParamSize::from(args.dxfer_len as usize),
                None,
                None,
            );
            // cmdp: The user memory pointed to is only read (not written to).

            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, sg_io_hdr<Arch>, sbp),
                ParamSize::from(args.mx_sb_len as usize),
                None,
                None,
            );
            // usr_ptr: This value is not acted upon by the sg driver.

            return Switchable::PreventSwitch;
        }

        _ => (),
    }

    // In ioctl language, "_IOC_READ" means "outparam".  Both
    // READ and WRITE can be set for inout params.
    // USBDEVFS ioctls seem to be mostly backwards in their interpretation of the
    // read/write bits :-(.
    //
    if _IOC_READ & dir == 0 {
        match ioctl_mask_size(request) {
            // Order by value
            // Older ioctls don't use IOC macros at all, so don't mask size for them
            // No test for TIOCCONS because if run as root it would do bad things
            TCSETS
            | TCSETSW
            | TCSETSF
            | TCSETA
            | TCSETAW
            | TCSETAF
            | TIOCSLCKTRMIOS
            | TCSBRK
            | TCSBRKP
            | TIOCSBRK
            | TIOCCBRK
            | TCXONC
            | TCFLSH
            | TIOCEXCL
            | TIOCNXCL
            | TIOCSCTTY
            | TIOCNOTTY
            | TIOCSPGRP
            | TIOCSTI
            | TIOCSWINSZ
            | TIOCCONS
            | TIOCPKT
            | FIONBIO
            | FIOASYNC
            | TIOCSETD
            | IOCTL_MASK_SIZE_TIOCSPTLCK
            | IOCTL_MASK_SIZE_TIOCGPTPEER
            | FIOCLEX
            | FIONCLEX
            | IOCTL_MASK_SIZE_BTRFS_IOC_CLONE
            | IOCTL_MASK_SIZE_BTRFS_IOC_CLONE_RANGE
            | IOCTL_MASK_SIZE_USBDEVFS_DISCARDURB
            | IOCTL_MASK_SIZE_USBDEVFS_RESET
            | IOCTL_MASK_SIZE_TUNSETNOCSUM
            | IOCTL_MASK_SIZE_TUNSETDEBUG
            | IOCTL_MASK_SIZE_TUNSETPERSIST
            | IOCTL_MASK_SIZE_TUNSETOWNER
            | IOCTL_MASK_SIZE_TUNSETLINK
            | IOCTL_MASK_SIZE_TUNSETGROUP
            | IOCTL_MASK_SIZE_TUNSETOFFLOAD
            | IOCTL_MASK_SIZE_TUNSETTXFILTER
            | IOCTL_MASK_SIZE_TUNSETSNDBUF
            | IOCTL_MASK_SIZE_TUNATTACHFILTER
            | IOCTL_MASK_SIZE_TUNDETACHFILTER
            | IOCTL_MASK_SIZE_TUNSETVNETHDRSZ
            | IOCTL_MASK_SIZE_TUNSETQUEUE
            | IOCTL_MASK_SIZE_TUNSETIFINDEX
            | IOCTL_MASK_SIZE_TUNSETVNETLE
            | IOCTL_MASK_SIZE_TUNSETVNETBE => {
                return Switchable::PreventSwitch;
            }
            IOCTL_MASK_SIZE_USBDEVFS_GETDRIVER => {
                // Reads and writes its parameter despite not having the _IOC_READ bit.
                syscall_state.reg_parameter_with_size(
                    3,
                    ParamSize::from(size as usize),
                    None,
                    None,
                );
                return Switchable::PreventSwitch;
            }
            IOCTL_MASK_SIZE_USBDEVFS_REAPURB | IOCTL_MASK_SIZE_USBDEVFS_REAPURBNDELAY => {
                syscall_state.reg_parameter_with_size(
                    3,
                    ParamSize::from(size as usize),
                    None,
                    None,
                );
                syscall_state.after_syscall_action(Box::new(record_usbdevfs_reaped_urb::<Arch>));
                return Switchable::AllowSwitch;
            }
            IOCTL_MASK_SIZE_TUNSETIFF => {
                // Reads and writes its parameter despite not having the _IOC_READ
                // bit...
                // And the parameter is an ifreq, not an int as in the ioctl definition!
                syscall_state.reg_parameter::<Arch::ifreq>(3, None, None);
                return Switchable::PreventSwitch;
            }
            _ => (),
        }

        match type_ {
            // TIO*
            // SIO*
            // SIO* wireless interface ioctls
            // These ioctls are known to be irregular and don't usually have the
            // correct `dir` bits. They must be handled above
            0x54 | 0x89 | 0x8B => {
                syscall_state.expect_errno = EINVAL;
                return Switchable::PreventSwitch;
            }
            _ => (),
        }

        // If the kernel isn't going to write any data back to
        // us, we hope and pray that the result of the ioctl
        // (observable to the tracee) is deterministic.
        // We're also assuming it doesn't block.
        // This is risky! Many ioctls use irregular ioctl codes
        // that do not have the _IOC_READ bit set but actually do write to
        // user-space!
        log!(LogDebug, "  (presumed ignorable ioctl, nothing to do)");
        return Switchable::PreventSwitch;
    }

    // There are lots of ioctl values for EVIOCGBIT
    if type_ == b'E' as u32 && nr >= 0x20 && nr <= 0x7f {
        syscall_state.reg_parameter_with_size(3, ParamSize::from(size as usize), None, None);
        return Switchable::PreventSwitch;
    }

    // The following are thought to be "regular" ioctls, the
    // processing of which is only known to (observably) write to
    // the bytes in the structure passed to the kernel.  So all we
    // need is to record |size| bytes.
    // Since the size may vary across architectures we mask it out here to check
    // only the type + number.
    match ioctl_mask_size(request) {
        IOCTL_MASK_SIZE_VIDIOC_QUERYCAP
        | IOCTL_MASK_SIZE_VIDIOC_ENUM_FMT
        | IOCTL_MASK_SIZE_VIDIOC_ENUM_FRAMESIZES
        | IOCTL_MASK_SIZE_VIDIOC_ENUM_FRAMEINTERVALS
        | IOCTL_MASK_SIZE_VIDIOC_ENUMINPUT
        | IOCTL_MASK_SIZE_VIDIOC_G_FMT
        | IOCTL_MASK_SIZE_VIDIOC_S_FMT
        | IOCTL_MASK_SIZE_VIDIOC_TRY_FMT
        | IOCTL_MASK_SIZE_VIDIOC_G_PARM
        | IOCTL_MASK_SIZE_VIDIOC_S_PARM
        | IOCTL_MASK_SIZE_VIDIOC_REQBUFS
        | IOCTL_MASK_SIZE_VIDIOC_QUERYBUF
        | IOCTL_MASK_SIZE_VIDIOC_QUERYCTRL
        | IOCTL_MASK_SIZE_VIDIOC_QBUF
        | IOCTL_MASK_SIZE_VIDIOC_G_CTRL
        | IOCTL_MASK_SIZE_VIDIOC_G_OUTPUT
        | IOCTL_MASK_SIZE_VIDIOC_S_CTRL
        | IOCTL_MASK_SIZE_VFAT_IOCTL_READDIR_BOTH => {
            syscall_state.reg_parameter_with_size(
                3,
                ParamSize::from(size as usize),
                Some(ArgMode::InOut),
                None,
            );
            return Switchable::PreventSwitch;
        }

        // FS_IOC_GETVERSION has the same number as VIDIOCGCAP (but different size)
        // but the same treatment works for both.
        // EVIOCGKEYCODE also covers EVIOCGKEYCODE_V2
        // This gets a list of js_corr structures whose length we don't know without
        // querying the device ourselves.
        // IOCTL_MASK_SIZE(JSIOCGCORR)|
        IOCTL_MASK_SIZE_TIOCGPTN
        | IOCTL_MASK_SIZE_TIOCGPKT
        | IOCTL_MASK_SIZE_TIOCGPTLCK
        | IOCTL_MASK_SIZE_TIOCGEXCL
        | IOCTL_MASK_SIZE_USBDEVFS_GET_CAPABILITIES
        | IOCTL_MASK_SIZE_FS_IOC_GETVERSION
        | IOCTL_MASK_SIZE_FS_IOC_GETFLAGS
        | IOCTL_MASK_SIZE_TUNGETFEATURES
        | IOCTL_MASK_SIZE_TUNGETSNDBUF
        | IOCTL_MASK_SIZE_TUNGETVNETHDRSZ
        | IOCTL_MASK_SIZE_TUNGETVNETLE
        | IOCTL_MASK_SIZE_TUNGETVNETBE
        | IOCTL_MASK_SIZE_EVIOCGVERSION
        | IOCTL_MASK_SIZE_EVIOCGID
        | IOCTL_MASK_SIZE_EVIOCGREP
        | IOCTL_MASK_SIZE_EVIOCGKEYCODE
        | IOCTL_MASK_SIZE_EVIOCGNAME_0
        | IOCTL_MASK_SIZE_EVIOCGPHYS_0
        | IOCTL_MASK_SIZE_EVIOCGUNIQ_0
        | IOCTL_MASK_SIZE_EVIOCGPROP_0
        | IOCTL_MASK_SIZE_EVIOCGMTSLOTS_0
        | IOCTL_MASK_SIZE_EVIOCGKEY_0
        | IOCTL_MASK_SIZE_EVIOCGLED_0
        | IOCTL_MASK_SIZE_EVIOCGSND_0
        | IOCTL_MASK_SIZE_EVIOCGSW_0
        | IOCTL_MASK_SIZE_EVIOCGEFFECTS
        | IOCTL_MASK_SIZE_EVIOCGMASK
        | IOCTL_MASK_SIZE_JSIOCGVERSION
        | IOCTL_MASK_SIZE_JSIOCGAXES
        | IOCTL_MASK_SIZE_JSIOCGBUTTONS
        | IOCTL_MASK_SIZE_JSIOCGAXMAP
        | IOCTL_MASK_SIZE_JSIOCGBTNMAP
        | IOCTL_MASK_SIZE_JSIOCGNAME_0 => {
            syscall_state.reg_parameter_with_size(3, ParamSize::from(size as usize), None, None);
            return Switchable::PreventSwitch;
        }
        IOCTL_MASK_SIZE_USBDEVFS_ALLOC_STREAMS
        | IOCTL_MASK_SIZE_USBDEVFS_CLAIMINTERFACE
        | IOCTL_MASK_SIZE_USBDEVFS_CLEAR_HALT
        | IOCTL_MASK_SIZE_USBDEVFS_DISCONNECT_CLAIM
        | IOCTL_MASK_SIZE_USBDEVFS_FREE_STREAMS
        | IOCTL_MASK_SIZE_USBDEVFS_RELEASEINTERFACE
        | IOCTL_MASK_SIZE_USBDEVFS_SETCONFIGURATION
        | IOCTL_MASK_SIZE_USBDEVFS_SETINTERFACE
        | IOCTL_MASK_SIZE_USBDEVFS_SUBMITURB => {
            // Doesn't actually seem to write to userspace
            return Switchable::PreventSwitch;
        }
        IOCTL_MASK_SIZE_TUNGETIFF => {
            // The ioctl definition says "unsigned int" but it's actually a
            // struct ifreq!
            syscall_state.reg_parameter::<ifreq<Arch>>(3, None, None);
            return Switchable::PreventSwitch;
        }
        IOCTL_MASK_SIZE_TUNGETFILTER => {
            // The ioctl definition says "struct sock_fprog" but there is no kernel
            // compat code so a 32-bit task on a 64-bit kernel needs to use the
            // 64-bit type.
            if size_of::<usize>() == 8 {
                // 64-bit rd build. We must be on a 64-bit kernel so use the 64-bit
                // sock_fprog type.
                syscall_state.reg_parameter::<sock_fprog<NativeArch>>(3, None, None);
            } else {
                fatal!("TUNGETFILTER not supported on 32-bit since its behavior depends on 32-bit vs 64-bit kernel");
            }
            return Switchable::PreventSwitch;
        }
        IOCTL_MASK_SIZE_USBDEVFS_IOCTL => {
            let argsp =
                syscall_state.reg_parameter::<usbdevfs_ioctl<Arch>>(3, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, usbdevfs_ioctl<Arch>, data),
                ParamSize::from(unsafe { ioctl_size(args.ioctl_code as u32) } as usize),
                None,
                None,
            );
            return Switchable::PreventSwitch;
        }
        IOCTL_MASK_SIZE_USBDEVFS_CONTROL => {
            let argsp = syscall_state.reg_parameter::<usbdevfs_ctrltransfer<Arch>>(
                3,
                Some(ArgMode::In),
                None,
            );
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, usbdevfs_ctrltransfer<Arch>, data),
                ParamSize::from(args.wLength as usize),
                None,
                None,
            );
            return Switchable::PreventSwitch;
        }
        _ => (),
    }

    // These ioctls are mostly regular but require additional recording.
    match ioctl_mask_size(request) {
        IOCTL_MASK_SIZE_VIDIOC_DQBUF => {
            if size as usize == size_of::<v4l2_buffer<Arch>>() {
                syscall_state.reg_parameter_with_size(
                    3,
                    ParamSize::from(size as usize),
                    Some(ArgMode::InOut),
                    None,
                );
                syscall_state.after_syscall_action(Box::new(record_v4l2_buffer_contents::<Arch>));
                // VIDIOC_DQBUF can block. It can't if the fd was opened O_NONBLOCK,
                // but we don't try to determine that.
                // Note that we're exposed to potential race conditions here because
                // VIDIOC_DQBUF (blocking or not) assumes the driver has filled
                // the mmapped data region at some point since the buffer was queued
                // with VIDIOC_QBUF, and we don't/can't know exactly when that
                // happened. Replay could fail if this thread or another thread reads
                // the contents of mmapped contents queued with the driver.
                return Switchable::AllowSwitch;
            }
        }
        _ => (),
    }

    syscall_state.expect_errno = EINVAL;
    Switchable::PreventSwitch
}

const fn ioctl_mask_size(req: u32) -> u32 {
    req & !(_IOC_SIZEMASK << _IOC_SIZESHIFT)
}

fn record_page_below_stack_ptr(t: &mut RecordTask) {
    // Record.the page above the top of `t`'s stack.  The SIOC* ioctls
    // have been observed to write beyond the end of tracees' stacks, as
    // if they had allocated scratch space for themselves.  All we can do
    // for now is try to record the scratch data.
    let child_addr = t.regs_ref().sp() - page_size();
    t.record_remote(child_addr, page_size());
}

fn prepare_clone<Arch: Architecture>(t: &mut RecordTask, syscall_state: &mut TaskSyscallState) {
    // DIFF NOTE: rr uses a usize here
    let flags: i32;
    let mut params: CloneParameters = Default::default();
    let mut r: Registers = t.regs_ref().clone();
    let original_syscall = r.original_syscallno() as i32;
    let ptrace_event;
    let mut maybe_termination_signal = Some(sig::SIGCHLD);

    if is_clone_syscall(original_syscall, r.arch()) {
        params = extract_clone_parameters(t);
        flags = r.arg1() as i32;
        r.set_arg1((flags & !CLONE_UNTRACED) as usize);
        t.set_regs(&r);
        maybe_termination_signal = Sig::try_from(flags & 0xff).ok();
        if flags & CLONE_VFORK != 0 {
            ptrace_event = PTRACE_EVENT_VFORK;
        } else if maybe_termination_signal == Some(sig::SIGCHLD) {
            ptrace_event = PTRACE_EVENT_FORK;
        } else {
            ptrace_event = PTRACE_EVENT_CLONE;
        }
    } else if is_vfork_syscall(original_syscall, r.arch()) {
        ptrace_event = PTRACE_EVENT_VFORK;
        flags = CLONE_VM | CLONE_VFORK | SIGCHLD;
    } else {
        ptrace_event = PTRACE_EVENT_FORK;
        flags = SIGCHLD;
    }

    loop {
        t.resume_execution(
            ResumeRequest::ResumeSyscall,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeNoTicks,
            None,
        );
        // XXX handle stray signals?
        if t.maybe_ptrace_event().is_ptrace_event() {
            break;
        }
        ed_assert!(t, !t.maybe_stop_sig().is_sig());
        ed_assert!(t, t.regs_ref().syscall_result_signed() < 0);
        if !t.regs_ref().syscall_may_restart() {
            log!(
                LogDebug,
                "clone failed, returning {}",
                errno_name(-t.regs_ref().syscall_result_signed() as i32)
            );
            syscall_state.emulate_result(t.regs_ref().syscall_result());
            // clone failed and we're existing the syscall with an error. Reenter
            // the syscall so that we're in the same state as the normal execution
            // path.
            t.ev_mut().syscall_event_mut().failed_during_preparation = true;
            // Restore register we might have changed
            r.set_arg1(syscall_state.syscall_entry_registers.arg1());
            r.set_syscallno(Arch::GETTID as isize);
            r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
            t.set_regs(&r);
            t.enter_syscall();
            r.set_ip(t.regs_ref().ip());
            r.set_original_syscallno(original_syscall as isize);
            t.set_regs(&r);
            let arch = t.arch();
            t.canonicalize_regs(arch);
            return;
        }
        // Reenter the syscall. If we try to return an ERESTART* error using the
        // code path above, our set_syscallno(SYS_gettid) fails to take effect and
        // we actually do the clone, and things get horribly confused.
        r.set_syscallno(r.original_syscallno());
        r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
        t.set_regs(&r);
        t.enter_syscall();
    }

    ed_assert_eq!(t, t.maybe_ptrace_event(), ptrace_event);

    // Ideally we'd just use t.get_ptrace_eventmsg_pid() here, but
    // kernels failed to translate that value from other pid namespaces to
    // our pid namespace until June 2014:
    // https://github.com/torvalds/linux/commit/4e52365f279564cef0ddd41db5237f0471381093
    let new_tid: pid_t;
    if flags & CLONE_THREAD != 0 {
        new_tid = t.find_newborn_thread();
    } else {
        new_tid = t.find_newborn_process(if flags & CLONE_PARENT != 0 {
            t.get_parent_pid()
        } else {
            t.real_tgid()
        });
    }
    let new_task_shr_ptr = t.session().clone_task(
        t,
        clone_flags_to_task_flags(flags),
        params.stack,
        params.tls,
        params.ctid,
        new_tid,
        None,
    );
    let mut new_task_b = new_task_shr_ptr.borrow_mut();
    let new_task = new_task_b.as_rec_mut_unwrap();

    // Restore modified registers in cloned task
    let mut new_r: Registers = new_task.regs_ref().clone();
    new_r.set_original_syscallno(syscall_state.syscall_entry_registers.original_syscallno());
    new_r.set_arg1(syscall_state.syscall_entry_registers.arg1());
    let arch = new_task.arch();
    new_task.set_regs(&new_r);
    new_task.canonicalize_regs(arch);
    new_task.set_termination_signal(maybe_termination_signal);

    // record child id here
    if is_clone_syscall(original_syscall, r.arch()) {
        let child_params: CloneParameters = extract_clone_parameters(new_task);
        t.record_remote_even_if_null_for(params.ptid);

        if Arch::CLONE_TLS_TYPE == CloneTLSType::UserDescPointer {
            t.record_remote_even_if_null_for(RemotePtr::<Arch::user_desc>::cast(params.tls));
            new_task.record_remote_even_if_null_for(RemotePtr::<Arch::user_desc>::cast(params.tls));
        } else {
            debug_assert_eq!(Arch::CLONE_TLS_TYPE, CloneTLSType::PthreadStructurePointer);
        }
        new_task.record_remote_even_if_null_for(child_params.ptid);
        new_task.record_remote_even_if_null_for(child_params.ctid);
    }
    t.trace_writer_mut()
        .write_task_event(&TraceTaskEvent::for_clone(
            new_task.tid,
            t.tid,
            new_task.own_namespace_rec_tid,
            flags,
        ));

    init_scratch_memory(new_task, None);

    if t.emulated_ptrace_options & ptrace_option_for_event(ptrace_event) != 0
        && (flags & CLONE_UNTRACED == 0)
    {
        // There MUST be a ptracer present. Hence the unwrap().
        let emulated_ptracer = t.emulated_ptracer.as_ref().unwrap().upgrade().unwrap();
        new_task.set_emulated_ptracer(
            Some(emulated_ptracer.borrow_mut().as_rec_mut_unwrap()),
            None,
        );
        new_task.emulated_ptrace_seized = t.emulated_ptrace_seized;
        new_task.emulated_ptrace_options = t.emulated_ptrace_options;
        t.emulated_ptrace_event_msg = new_task.rec_tid as usize;
        t.emulate_ptrace_stop(
            WaitStatus::for_ptrace_event(ptrace_event),
            emulated_ptracer.borrow().as_rec_unwrap(),
            None,
            None,
            Some(new_task),
        );
        // ptrace(2) man page says that SIGSTOP is used here, but it's really
        // SIGTRAP (in 4.4.4-301.fc23.x86_64 anyway).
        new_task.apply_group_stop(sig::SIGTRAP, Some(t));
    }

    // Restore our register modifications now, so that the emulated ptracer will
    // see the original registers without our modifications if it inspects them
    // in the ptrace event.
    r = t.regs_ref().clone();
    r.set_arg1(syscall_state.syscall_entry_registers.arg1());
    r.set_original_syscallno(syscall_state.syscall_entry_registers.original_syscallno());
    t.set_regs(&r);
    let arch = t.arch();
    t.canonicalize_regs(arch);

    // We're in a PTRACE_EVENT_FORK/VFORK/CLONE so the next PTRACE_SYSCALL for
    // `t` will go to the exit of the syscall, as expected.
}

fn ptrace_option_for_event(ptrace_event: u32) -> u32 {
    match ptrace_event {
        PTRACE_EVENT_FORK => PTRACE_O_TRACEFORK,
        PTRACE_EVENT_CLONE => PTRACE_O_TRACECLONE,
        PTRACE_EVENT_VFORK => PTRACE_O_TRACEVFORK,
        _ => {
            fatal!("Unsupported ptrace event {}", ptrace_event);
        }
    }
}

fn maybe_pause_instead_of_waiting(t: &mut RecordTask, options: i32) {
    if t.in_wait_type != WaitType::WaitTypePid || (options & WNOHANG != 0) {
        return;
    }

    let maybe_child: Option<TaskSharedPtr> = t.session().find_task_from_rec_tid(t.in_wait_pid);
    match maybe_child {
        Some(child_rc) => {
            let mut childb = child_rc.borrow_mut();
            let child = childb.as_rec_mut_unwrap();
            if !t.is_waiting_for_ptrace(child) || t.is_waiting_for(child) {
                return;
            }
        }
        _ => return,
    }
    // OK, `t` is waiting for a ptrace child by tid, but since `t` is not really
    // ptracing child, entering a real wait syscall will not actually wait for
    // the child, so the kernel may error out with ECHILD (non-ptracers can't
    // wait on specific threads of another process, or for non-child processes).
    // To avoid this problem, we'll replace the wait syscall with a pause()
    // syscall.
    // It would be nice if we didn't have to do this, but can't see a better
    // way.
    let mut r: Registers = t.regs_ref().clone();
    r.set_original_syscallno(syscall_number_for_pause(t.arch()) as isize);
    t.set_regs(&r);
}

fn process_mremap(
    t: &mut RecordTask,
    old_addr: RemotePtr<Void>,
    old_length: usize,
    new_length: usize,
) {
    if t.regs_ref().syscall_failed() {
        // We purely emulate failed mremaps.
        return;
    }

    let old_size: usize = ceil_page_size(old_length);
    let new_size: usize = ceil_page_size(new_length);
    let new_addr: RemotePtr<Void> = t.regs_ref().syscall_result().into();

    t.vm().remap(t, old_addr, old_size, new_addr, new_size);
    let m = t.vm().mapping_of(new_addr).unwrap().clone();
    let mut km = m.map.subrange(new_addr, new_addr + min(new_size, old_size));
    let mut st = match m.mapped_file_stat {
        Some(st) => st,
        None => km.fake_stat(),
    };

    // Make sure that the trace records the mapping at the new location, even
    // if the mapping didn't grow.
    let r = t.trace_writer_mut().write_mapped_region(
        t,
        &km,
        &st,
        &[],
        Some(MappingOrigin::RemapMapping),
        None,
    );
    ed_assert_eq!(t, r, RecordInTrace::DontRecordInTrace);
    if old_size >= new_size {
        return;
    }

    // Now record the new part of the mapping.
    km = m.map.subrange(new_addr + old_size, new_addr + new_size);
    if st.st_size == 0 {
        // Some device files are mmappable but have zero size. Increasing the
        // size here is safe even if the mapped size is greater than the real size.
        st.st_size = (m.map.file_offset_bytes() + new_size as u64)
            .try_into()
            .unwrap();
    }

    if t.trace_writer_mut()
        .write_mapped_region(t, &km, &st, &[], None, None)
        == RecordInTrace::RecordInTrace
    {
        let end = if km.file_offset_bytes() > st.st_size as u64 {
            0
        } else {
            st.st_size as u64 - km.file_offset_bytes()
        };
        // Allow failure; the underlying file may have true zero size, in which
        // case this may try to record unmapped memory.
        t.record_remote_fallible(km.start(), min(end.try_into().unwrap(), km.size()))
            .unwrap_or(0);
    }

    // If the original mapping was monitored, we'll continue monitoring it
    // automatically.
}

fn send_signal_during_init_buffers() -> bool {
    env::var_os("RD_INIT_BUFFERS_SEND_SIGNAL").is_some()
}

fn prepare_recvmsg<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    msgp: RemotePtr<msghdr<Arch>>,
    io_size: ParamSize,
) {
    let namelen_ptr = RemotePtr::<common::socklen_t>::cast(
        msgp.as_rptr_u8() + offset_of!(msghdr<Arch>, msg_namelen),
    );
    let param_size = ParamSize::from_initialized_mem(t, namelen_ptr);
    syscall_state.mem_ptr_parameter_with_size(
        t,
        msgp.as_rptr_u8() + offset_of!(msghdr<Arch>, msg_name),
        param_size,
        None,
        None,
    );

    let msg = read_val_mem(t, msgp, None);
    let iovecsp_void: RemotePtr<Void> = syscall_state.mem_ptr_parameter_with_size(
        t,
        msgp.as_rptr_u8() + offset_of!(msghdr<Arch>, msg_iov),
        ParamSize::from(size_of::<iovec<Arch>>() * Arch::size_t_as_usize(msg.msg_iovlen)),
        Some(ArgMode::In),
        None,
    );
    let iovecsp = RemotePtr::<iovec<Arch>>::cast(iovecsp_void);
    let iovecs = read_mem(t, iovecsp, Arch::size_t_as_usize(msg.msg_iovlen), None);
    for i in 0..Arch::size_t_as_usize(msg.msg_iovlen) {
        syscall_state.mem_ptr_parameter_with_size(
            t,
            (iovecsp + i).as_rptr_u8() + offset_of!(iovec<Arch>, iov_base),
            io_size.limit_size(Arch::size_t_as_usize(iovecs[i].iov_len)),
            None,
            None,
        );
    }

    let controllen_ptr = RemotePtr::<Arch::size_t>::cast(
        msgp.as_rptr_u8() + offset_of!(msghdr<Arch>, msg_controllen),
    );
    let param_size = ParamSize::from_initialized_mem(t, controllen_ptr);
    syscall_state.mem_ptr_parameter_with_size(
        t,
        msgp.as_rptr_u8() + offset_of!(msghdr<Arch>, msg_control),
        param_size,
        None,
        None,
    );
}

fn prepare_recvmmsg<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    mmsgp: RemotePtr<mmsghdr<Arch>>,
    vlen: usize,
) {
    for i in 0..vlen {
        let msgp: RemotePtr<mmsghdr<Arch>> = mmsgp + i;
        prepare_recvmsg::<Arch>(
            t,
            syscall_state,
            RemotePtr::<msghdr<Arch>>::cast(msgp.as_rptr_u8() + offset_of!(mmsghdr<Arch>, msg_hdr)),
            ParamSize::from_mem(RemotePtr::<u32>::cast(
                msgp.as_rptr_u8() + offset_of!(mmsghdr<Arch>, msg_len),
            )),
        );
    }
}

fn check_scm_rights_fd<Arch: Architecture>(t: &mut RecordTask, msg: &msghdr<Arch>) {
    if Arch::size_t_as_usize(msg.msg_controllen) < size_of::<cmsghdr<Arch>>() {
        return;
    }
    let data: Vec<u8> = read_mem(
        t,
        Arch::as_rptr(msg.msg_control).as_rptr_u8(),
        Arch::size_t_as_usize(msg.msg_controllen),
        None,
    );
    let mut index: usize = 0;
    loop {
        let cmsg: cmsghdr<Arch> =
            unsafe { mem::transmute_copy(data.as_ptr().add(index).as_ref().unwrap()) };
        let cmsg_len = Arch::size_t_as_usize(cmsg.cmsg_len);
        if cmsg_len < size_of_val(&cmsg) || index + cmsg_align::<Arch>(cmsg_len) > data.len() {
            break;
        }
        if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
            let fd_count = (cmsg_len - size_of_val(&cmsg)) / size_of::<i32>();
            let base = &data[index + size_of_val(&cmsg)..];
            for i in 0..fd_count {
                let fd = i32::from_le_bytes(
                    base[i * size_of::<i32>()..(i + 1) * size_of::<i32>()]
                        .try_into()
                        .unwrap(),
                );
                handle_opened_file(t, fd, 0);
            }
        }
        index += cmsg_align::<Arch>(cmsg_len);
        if index + size_of_val(&cmsg) > data.len() {
            break;
        }
    }
}

fn block_sock_opt(level: i32, optname: u32, syscall_state: &mut TaskSyscallState) -> bool {
    match level {
        SOL_PACKET => match optname {
            PACKET_RX_RING | PACKET_TX_RING => {
                syscall_state.emulate_result_signed(-ENOPROTOOPT as isize);
                return true;
            }
            _ => (),
        },
        _ => (),
    }

    false
}

fn prepare_setsockopt<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    args: &setsockopt_args<Arch>,
) -> Switchable {
    let level = Arch::long_as_usize(args.level) as i32;
    let optname = Arch::long_as_usize(args.optname) as u32;
    if block_sock_opt(level, optname, syscall_state) {
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1_signed(-1);
        t.set_regs(&r);
    } else {
        match level {
            IPPROTO_IP | IPPROTO_IPV6 => match optname {
                SO_SET_REPLACE => {
                    if Arch::long_as_usize(args.optlen) < size_of::<ipt_replace<Arch>>() {
                        return Switchable::PreventSwitch;
                    }
                    let repl_ptr = RemotePtr::<ipt_replace<Arch>>::cast(Arch::as_rptr(args.optval));
                    let param_size = ParamSize::from(
                        read_val_mem(
                            t,
                            RemotePtr::<u32>::cast(remote_ptr_field!(
                                repl_ptr,
                                ipt_replace<Arch>,
                                num_counters
                            )),
                            None,
                        ) as usize
                            * size_of::<arch_structs::xt_counters>(),
                    );
                    syscall_state.mem_ptr_parameter_with_size(
                        t,
                        remote_ptr_field!(repl_ptr, ipt_replace<Arch>, counters),
                        param_size,
                        None,
                        None,
                    );
                }
                _ => (),
            },
            _ => (),
        }
    }

    Switchable::PreventSwitch
}

fn verify_ptrace_target(
    tracer: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    pid: pid_t,
) -> Option<TaskSharedPtr> {
    if tracer.rec_tid != pid {
        match tracer.session().find_task_from_rec_tid(pid) {
            Some(rc_tracee) => {
                {
                    let mut rc_traceeb = rc_tracee.borrow_mut();
                    let tracee = rc_traceeb.as_rec_mut_unwrap();
                    if tracee
                        .emulated_ptracer
                        .as_ref()
                        .map_or(true, |ep| !ep.ptr_eq(&tracer.weak_self))
                        || tracee.emulated_stop_type == EmulatedStopType::NotStopped
                    {
                        syscall_state.emulate_result_signed(-ESRCH as isize);
                        return None;
                    }
                }

                return Some(rc_tracee);
            }
            None => (),
        }
    }

    syscall_state.emulate_result_signed(-ESRCH as isize);

    None
}

fn path_inode_number(path: &OsStr) -> u64 {
    // DIFF NOTE: Only in debug mode in rr is a successful result ensured via a debug_assert.
    // Here the unwrap() happens regardless of debug/release.
    let st = stat(path).unwrap();

    st.st_ino
}

fn is_same_namespace(name: &str, tid1: pid_t, tid2: pid_t) -> bool {
    let path1 = format!("/proc/{}/ns/{}", tid1, name);
    let path2 = format!("/proc/{}/ns/{}", tid2, name);

    path_inode_number(OsStr::new(&path1)) == path_inode_number(OsStr::new(&path2))
}

fn widen_buffer_unsigned(buf: &[u8]) -> u64 {
    match buf.len() {
        1 => u8::from_le_bytes(buf.try_into().unwrap()) as u64,
        2 => u16::from_le_bytes(buf.try_into().unwrap()) as u64,
        4 => u32::from_le_bytes(buf.try_into().unwrap()) as u64,
        8 => u64::from_le_bytes(buf.try_into().unwrap()) as u64,
        s => {
            assert!(false, "Unsupported register size: {}", s);
            unreachable!();
        }
    }
}

fn widen_buffer_signed(buf: &[u8]) -> i64 {
    match buf.len() {
        1 => i8::from_le_bytes(buf.try_into().unwrap()) as i64,
        2 => i16::from_le_bytes(buf.try_into().unwrap()) as i64,
        4 => i32::from_le_bytes(buf.try_into().unwrap()) as i64,
        8 => i64::from_le_bytes(buf.try_into().unwrap()) as i64,
        s => {
            assert!(false, "Unsupported register size: {}", s);
            unreachable!();
        }
    }
}

/// DIFF NOTE: Has an extra param `tracer`
fn prepare_ptrace_cont(
    tracee: &mut RecordTask,
    maybe_sig: Option<Sig>,
    command: u32,
    tracer: &RecordTask,
) {
    match maybe_sig {
        Some(sig) => {
            let si = tracee.take_ptrace_signal_siginfo(sig);
            log!(LogDebug, "Doing ptrace resume with signal {}", sig);
            // Treat signal as nondeterministic; it won't happen just by
            // replaying the tracee.
            let disposition =
                tracee.sig_resolved_disposition(sig, SignalDeterministic::NondeterministicSig);
            tracee.push_event(Event::new_signal_event(
                EventType::EvSignal,
                SignalEventData::new(&si, SignalDeterministic::NondeterministicSig, disposition),
            ));
        }
        None => (),
    }

    tracee.emulated_stop_type = EmulatedStopType::NotStopped;
    tracee.emulated_stop_pending = false;
    tracee.emulated_stop_code = WaitStatus::default();
    tracee.emulated_ptrace_cont_command = command;

    if tracee.ev().is_syscall_event()
        && SyscallState::ProcessingSyscall == tracee.ev().syscall_event().state
    {
        // Continue the task since we didn't in enter_syscall
        tracee.resume_execution(
            ResumeRequest::ResumeSyscall,
            WaitRequest::ResumeNonblocking,
            TicksRequest::ResumeNoTicks,
            None,
        );
    }

    if tracee.emulated_ptrace_queued_exit_stop {
        do_ptrace_exit_stop(tracee, Some(tracer));
    }
}

fn ptrace_get_reg_set<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    regs: &[u8],
) {
    let piov = syscall_state.reg_parameter::<iovec<Arch>>(4, Some(ArgMode::InOut), None);
    let mut iov = read_val_mem(t, piov, None);
    iov.iov_len = Arch::usize_as_size_t(min(Arch::size_t_as_usize(iov.iov_len), regs.len()));
    write_val_mem(t, piov, &iov, None);
    let child_addr = remote_ptr_field!(piov, iovec<Arch>, iov_base);
    let data = syscall_state.mem_ptr_parameter_with_size(
        t,
        child_addr,
        ParamSize::from(Arch::size_t_as_usize(iov.iov_len)),
        None,
        None,
    );
    t.write_bytes_helper(
        data,
        &regs[0..Arch::size_t_as_usize(iov.iov_len)],
        None,
        WriteFlags::empty(),
    );
    syscall_state.emulate_result(0);
}

fn ptrace_verify_set_reg_set<Arch: Architecture>(
    t: &mut RecordTask,
    min_size: usize,
    syscall_state: &mut TaskSyscallState,
) {
    let child_addr = RemotePtr::<iovec<Arch>>::from(t.regs_ref().arg4());
    let iov = read_val_mem(t, child_addr, None);
    if Arch::size_t_as_usize(iov.iov_len) < min_size {
        syscall_state.emulate_result_signed(-EIO as isize);
    } else {
        syscall_state.emulate_result(0);
    }
}

fn verify_ptrace_options(t: &mut RecordTask, syscall_state: &mut TaskSyscallState) -> bool {
    // We "support" PTRACE_O_SYSGOOD because we don't support PTRACE_SYSCALL yet
    let supported_ptrace_options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEEXIT
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC;

    if t.regs_ref().arg4() as u32 & !supported_ptrace_options != 0 {
        log!(
            LogDebug,
            "Unsupported ptrace options {:#x}",
            t.regs_ref().arg4()
        );
        syscall_state.emulate_result_signed(-EINVAL as isize);
        return false;
    }

    true
}

fn prepare_ptrace_attach(
    t: &RecordTask,
    pid: pid_t,
    syscall_state: &mut TaskSyscallState,
) -> Option<TaskSharedPtr> {
    let maybe_tracee: Option<TaskSharedPtr> = get_ptrace_partner(t, pid);
    match maybe_tracee {
        None => {
            syscall_state.emulate_result_signed(-ESRCH as isize);
            return None;
        }
        Some(tracee) if !check_ptracer_compatible(t, tracee.borrow().as_rec_unwrap()) => {
            syscall_state.emulate_result_signed(-EPERM as isize);
            return None;
        }
        Some(tracee) => Some(tracee),
    }
}

fn check_ptracer_compatible(tracer: &RecordTask, tracee: &RecordTask) -> bool {
    // Don't allow a 32-bit process to trace a 64-bit process. That doesn't
    // make much sense (manipulating registers gets crazy), and would be hard to
    // support.
    if tracee.emulated_ptracer.is_some()
        || tracee.tgid() == tracer.tgid()
        || (tracer.arch() == SupportedArch::X86 && tracee.arch() == SupportedArch::X64)
    {
        return false;
    }

    true
}

fn get_ptrace_partner(t: &RecordTask, pid: pid_t) -> Option<TaskSharedPtr> {
    // To simplify things, require that a ptracer be in the same pid
    // namespace as rd itself. I.e., tracee tasks sandboxed in a pid
    // namespace can't use ptrace. This is normally a requirement of
    // sandboxes anyway.
    // This could be supported, but would require some work to translate
    // rd's pids to/from the ptracer's pid namespace.
    ed_assert!(t, is_same_namespace("pid", t.tid, getpid().as_raw()));
    // NOTE for the case when find_task_from_rec_tid() returns `None`:
    //   XXX This prevents a tracee from attaching to a process which isn't
    //   under rd's control. We could support this but it would complicate
    //   things.
    t.session().find_task_from_rec_tid(pid)
}

fn prepare_ptrace_traceme(
    t: &RecordTask,
    syscall_state: &mut TaskSyscallState,
) -> Option<TaskSharedPtr> {
    let maybe_tracer = get_ptrace_partner(t, t.get_parent_pid());
    match maybe_tracer {
        None => {
            syscall_state.emulate_result_signed(-ESRCH as isize);
            None
        }
        Some(tracer) if !check_ptracer_compatible(tracer.borrow().as_rec_unwrap(), t) => {
            syscall_state.emulate_result_signed(-EPERM as isize);
            None
        }
        Some(tracer) => Some(tracer),
    }
}

fn ptrace_attach_to_already_stopped_task(t: &mut RecordTask, tracer: &mut RecordTask) {
    ed_assert_eq!(t, t.emulated_stop_type, EmulatedStopType::GroupStop);
    // tracee is already stopped because of a group-stop signal.
    // Sending a SIGSTOP won't work, but we don't need to.
    t.force_emulate_ptrace_stop(WaitStatus::for_stop_sig(sig::SIGSTOP), tracer, None);
    let mut si = siginfo_t_signal::default();
    si.si_signo = SIGSTOP;
    si.si_code = SI_USER;
    t.save_ptrace_signal_siginfo(&si);
}

fn prepare_ptrace<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
) -> Switchable {
    let pid = t.regs_ref().arg2_signed() as pid_t;
    let mut emulate = true;
    let command: u32 = t.regs_ref().arg1() as u32;
    match command {
        PTRACE_ATTACH => {
            let maybe_tracee = prepare_ptrace_attach(t, pid, syscall_state);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    tracee.set_emulated_ptracer(Some(t), None);
                    tracee.emulated_ptrace_seized = false;
                    tracee.emulated_ptrace_options = 0;
                    syscall_state.emulate_result(0);
                    if tracee.emulated_stop_type == EmulatedStopType::NotStopped {
                        // Send SIGSTOP to this specific thread. Otherwise the kernel might
                        // deliver SIGSTOP to some other thread of the process, and we won't
                        // generate any ptrace event if that thread isn't being ptraced.
                        tracee.tgkill(sig::SIGSTOP);
                    } else {
                        ptrace_attach_to_already_stopped_task(tracee, t);
                    }
                }
                None => (),
            }
        }
        PTRACE_TRACEME => {
            let maybe_tracer = prepare_ptrace_traceme(t, syscall_state);
            match maybe_tracer {
                Some(tracer_rc) => {
                    let mut tracerb = tracer_rc.borrow_mut();
                    let tracer = tracerb.as_rec_mut_unwrap();
                    t.set_emulated_ptracer(Some(tracer), None);
                    t.emulated_ptrace_seized = false;
                    t.emulated_ptrace_options = 0;
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_SEIZE => {
            let maybe_tracee = prepare_ptrace_attach(t, pid, syscall_state);
            match maybe_tracee {
                Some(tracee_rc) => {
                    if t.regs_ref().arg3() != 0 {
                        syscall_state.emulate_result_signed(-EIO as isize);
                    } else {
                        if verify_ptrace_options(t, syscall_state) {
                            let mut traceeb = tracee_rc.borrow_mut();
                            let tracee = traceeb.as_rec_mut_unwrap();
                            tracee.set_emulated_ptracer(Some(t), None);
                            tracee.emulated_ptrace_seized = true;
                            tracee.emulated_ptrace_options = t.regs_ref().arg4() as u32;
                            if tracee.emulated_stop_type == EmulatedStopType::GroupStop {
                                ptrace_attach_to_already_stopped_task(tracee, t);
                            }
                            syscall_state.emulate_result(0);
                        }
                    }
                }
                None => (),
            }
        }
        PTRACE_OLDSETOPTIONS | PTRACE_SETOPTIONS => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    if verify_ptrace_options(t, syscall_state) {
                        tracee.emulated_ptrace_options = t.regs_ref().arg4() as u32;
                        syscall_state.emulate_result(0);
                    }
                }
                None => (),
            }
        }
        PTRACE_GETEVENTMSG => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    let datap = syscall_state.reg_parameter::<Arch::unsigned_long>(4, None, None);
                    write_val_mem(
                        t,
                        datap,
                        &Arch::usize_as_ulong(tracee.emulated_ptrace_event_msg),
                        None,
                    );
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_GETSIGINFO => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    let datap = syscall_state.reg_parameter::<siginfo_t<Arch>>(4, None, None);
                    let mut dest: siginfo_t<Arch> = unsafe { mem::zeroed() };
                    set_arch_siginfo(tracee.get_saved_ptrace_siginfo(), &mut dest);
                    write_val_mem(t, datap, &dest, None);
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_GETREGS => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            let data = syscall_state.reg_parameter::<Arch::user_regs_struct>(4, None, None);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    let regs: Vec<u8> = tracee.regs_ref().get_ptrace_for_arch(Arch::arch());
                    ed_assert_eq!(t, regs.len(), data.referent_size());
                    t.write_bytes_helper(
                        RemotePtr::<u8>::cast(data),
                        &regs,
                        None,
                        WriteFlags::empty(),
                    );
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_GETFPREGS => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    let data =
                        syscall_state.reg_parameter::<Arch::user_fpregs_struct>(4, None, None);
                    let regs: Vec<u8> =
                        tracee.extra_regs_ref().get_user_fpregs_struct(Arch::arch());
                    ed_assert_eq!(t, regs.len(), data.referent_size());
                    t.write_bytes_helper(
                        RemotePtr::<u8>::cast(data),
                        &regs,
                        None,
                        WriteFlags::empty(),
                    );
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_GETFPXREGS => {
            if Arch::arch() != SupportedArch::X86 {
                // GETFPXREGS is x86-32 only
                syscall_state.expect_errno = EIO;
            } else {
                let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                match maybe_tracee {
                    Some(tracee_rc) => {
                        let mut traceeb = tracee_rc.borrow_mut();
                        let tracee = traceeb.as_rec_mut_unwrap();
                        let data =
                            syscall_state.reg_parameter::<x86::user_fpxregs_struct>(4, None, None);
                        let regs = tracee.extra_regs_ref().get_user_fpxregs_struct();
                        write_val_mem(t, data, &regs, None);
                        syscall_state.emulate_result(0);
                    }
                    None => (),
                }
            }
        }
        PTRACE_GETREGSET => match t.regs_ref().arg3() as u32 {
            NT_PRSTATUS => {
                let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                match maybe_tracee {
                    Some(tracee_rc) => {
                        let mut traceeb = tracee_rc.borrow_mut();
                        let tracee = traceeb.as_rec_mut_unwrap();
                        let regs = tracee.regs_ref().get_ptrace_for_arch(Arch::arch());
                        ptrace_get_reg_set::<Arch>(t, syscall_state, &regs);
                    }
                    None => (),
                }
            }
            NT_FPREGSET => {
                let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                match maybe_tracee {
                    Some(tracee_rc) => {
                        let mut traceeb = tracee_rc.borrow_mut();
                        let tracee = traceeb.as_rec_mut_unwrap();
                        let regs = tracee.extra_regs_ref().get_user_fpregs_struct(Arch::arch());
                        ptrace_get_reg_set::<Arch>(t, syscall_state, &regs);
                    }
                    None => (),
                }
            }
            NT_X86_XSTATE => {
                let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                match maybe_tracee {
                    Some(tracee_rc) => {
                        let mut traceeb = tracee_rc.borrow_mut();
                        let tracee = traceeb.as_rec_mut_unwrap();
                        match tracee.extra_regs_ref().format() {
                            Format::XSave => ptrace_get_reg_set::<Arch>(
                                t,
                                syscall_state,
                                tracee.extra_regs_ref().data_bytes(),
                            ),
                            _ => syscall_state.emulate_result_signed(-EINVAL as isize),
                        }
                    }
                    None => (),
                }
            }
            _ => {
                syscall_state.expect_errno = EINVAL;
                emulate = false;
            }
        },
        PTRACE_SETREGS => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            if maybe_tracee.is_some() {
                // The actual register effects are performed by
                // Task::on_syscall_exit_arch
                syscall_state.emulate_result(0);
            }
        }
        PTRACE_SETFPREGS => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            if maybe_tracee.is_some() {
                // The actual register effects are performed by
                // Task::on_syscall_exit_arch
                syscall_state.emulate_result(0);
            }
        }
        PTRACE_SETFPXREGS => {
            if Arch::arch() != SupportedArch::X86 {
                // SETFPXREGS is x86-32 only
                syscall_state.expect_errno = EIO;
            } else {
                let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                if maybe_tracee.is_some() {
                    // The actual register effects are performed by
                    // Task::on_syscall_exit_arch
                    syscall_state.emulate_result(0);
                }
            }
        }
        PTRACE_SETREGSET => {
            // The actual register effects are performed by
            // Task::on_syscall_exit_arch
            match t.regs_ref().arg3() as u32 {
                NT_PRSTATUS => {
                    let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                    if maybe_tracee.is_some() {
                        ptrace_verify_set_reg_set::<Arch>(
                            t,
                            size_of::<Arch::user_regs_struct>(),
                            syscall_state,
                        );
                    }
                }
                NT_FPREGSET => {
                    let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                    if maybe_tracee.is_some() {
                        ptrace_verify_set_reg_set::<Arch>(
                            t,
                            size_of::<Arch::user_fpregs_struct>(),
                            syscall_state,
                        );
                    }
                }
                NT_X86_XSTATE => {
                    let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
                    match maybe_tracee {
                        Some(tracee_rc) => {
                            let format = tracee_rc.borrow_mut().extra_regs_ref().format();
                            match format {
                                Format::XSave => {
                                    ptrace_verify_set_reg_set::<Arch>(
                                        t,
                                        tracee_rc.borrow_mut().extra_regs_ref().data_size(),
                                        syscall_state,
                                    );
                                }
                                _ => {
                                    syscall_state.emulate_result_signed(-EINVAL as isize);
                                }
                            }
                        }
                        None => (),
                    }
                }
                _ => {
                    syscall_state.expect_errno = EINVAL;
                    emulate = false;
                }
            }
        }
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    // The actual syscall returns the data via the 'data' out-parameter.
                    // The behavior of returning the data as the system call result is
                    // provided by the glibc wrapper.
                    let datap = syscall_state.reg_parameter::<Arch::unsigned_word>(4, None, None);
                    let addr = RemotePtr::<Arch::unsigned_word>::from(t.regs_ref().arg3());
                    let mut ok = true;
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    let v = read_val_mem(tracee, addr, Some(&mut ok));
                    if ok {
                        write_val_mem(t, datap, &v, None);
                        syscall_state.emulate_result(0);
                    } else {
                        syscall_state.emulate_result_signed(-EIO as isize);
                    }
                }
                None => (),
            }
        }
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    let addr = RemotePtr::<Arch::unsigned_word>::from(t.regs_ref().arg3());
                    let data = Arch::as_unsigned_word(t.regs_ref().arg4());
                    let mut ok = true;
                    write_val_mem(tracee, addr, &data, Some(&mut ok));
                    if ok {
                        // Since we're recording data that might not be for `t`, we have to
                        // handle this specially during replay.
                        tracee.record_local_for(addr, &data);
                        syscall_state.emulate_result(0);
                    } else {
                        syscall_state.emulate_result_signed(-EIO as isize);
                    }
                }
                None => (),
            }
        }
        PTRACE_PEEKUSER => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let tracee = tracee_rc.borrow();
                    // The actual syscall returns the data via the 'data' out-parameter.
                    // The behavior of returning the data as the system call result is
                    // provided by the glibc wrapper.
                    let addr = t.regs_ref().arg3();
                    let mut data: Arch::unsigned_word = 0u8.into();
                    if (addr & (size_of_val(&data) - 1) != 0) || addr >= size_of::<Arch::user>() {
                        syscall_state.emulate_result_signed(-EIO as isize);
                    } else {
                        let datap =
                            syscall_state.reg_parameter::<Arch::unsigned_word>(4, None, None);
                        if addr < size_of::<Arch::user_regs_struct>() {
                            let mut buf = [0u8; registers::MAX_REG_SIZE_BYTES];
                            let res = tracee
                                .regs_ref()
                                .read_register_by_user_offset(&mut buf, addr);
                            match res {
                                Some(size) => {
                                    // For unclear reasons, all 32-bit user_regs_struct members are
                                    // signed while all 64-bit user_regs_struct members are unsigned.
                                    match Arch::arch() {
                                        SupportedArch::X86 => {
                                            data = Arch::as_unsigned_word(widen_buffer_signed(
                                                &buf[0..size],
                                            )
                                                as usize);
                                        }
                                        SupportedArch::X64 => {
                                            data = Arch::as_unsigned_word(widen_buffer_unsigned(
                                                &buf[0..size],
                                            )
                                                as usize);
                                        }
                                    }
                                }
                                None => {
                                    data = 0u8.into();
                                }
                            }
                        } else {
                            match Arch::arch() {
                                SupportedArch::X86
                                    if addr >= offset_of!(x86::user, u_debugreg)
                                        && addr
                                            < offset_of!(x86::user, u_debugreg)
                                                + 8 * size_of_val(&data) =>
                                {
                                    let regno = (addr - offset_of!(x86::user, u_debugreg))
                                        / size_of_val(&data);
                                    data = Arch::as_unsigned_word(tracee.get_debug_reg(regno));
                                }
                                SupportedArch::X64
                                    if addr >= offset_of!(x64::user, u_debugreg)
                                        && addr
                                            < offset_of!(x64::user, u_debugreg)
                                                + 8 * size_of_val(&data) =>
                                {
                                    let regno = (addr - offset_of!(x64::user, u_debugreg))
                                        / size_of_val(&data);
                                    data = Arch::as_unsigned_word(tracee.get_debug_reg(regno));
                                }
                                _ => {
                                    data = 0u8.into();
                                }
                            }
                        }

                        write_val_mem(t, datap, &data, None);
                        syscall_state.emulate_result(0);
                    }
                }
                None => (),
            }
        }
        PTRACE_POKEUSER => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(_tracee_rc) => {
                    // The actual syscall returns the data via the 'data' out-parameter.
                    // The behavior of returning the data as the system call result is
                    // provided by the glibc wrapper.
                    let addr = t.regs_ref().arg3();
                    if addr & (size_of::<Arch::unsigned_word>() - 1) != 0
                        || addr >= size_of::<Arch::user>()
                    {
                        syscall_state.emulate_result_signed(-EIO as isize);
                    } else {
                        syscall_state.emulate_result(0);
                    }
                }
                None => (),
            }
        }
        PTRACE_SYSCALL
        | PTRACE_SINGLESTEP
        | PTRACE_SYSEMU
        | PTRACE_SYSEMU_SINGLESTEP
        | PTRACE_CONT => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            // If the tracer wants to observe syscall entries, we can't use the
            // syscallbuf, because the tracer may want to change syscall numbers
            // which the syscallbuf code is not prepared to handle. Aditionally,
            // we also lock the syscallbuf for PTRACE_SINGLESTEP, since we usually
            // try to avoid delivering signals (e.g. PTRACE_SINGLESTEP's SIGTRAP)
            // inside syscallbuf code. However, if the syscallbuf if locked, doing
            // so should be safe.
            match maybe_tracee {
                Some(tracee_rc) => {
                    if t.regs_ref().arg4() as u32 >= NUM_SIGNALS as u32 {
                        // Invalid signals in ptrace resume cause EIO
                        syscall_state.emulate_result_signed(-EIO as isize);
                    } else {
                        let mut traceeb = tracee_rc.borrow_mut();
                        let tracee = traceeb.as_rec_mut_unwrap();
                        tracee.set_syscallbuf_locked(command != PTRACE_CONT);
                        prepare_ptrace_cont(
                            tracee,
                            Sig::try_from(t.regs_ref().arg4() as i32).ok(),
                            command,
                            t,
                        );
                        syscall_state.emulate_result(0);
                    }
                }
                None => (),
            }
        }
        PTRACE_DETACH => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    tracee.set_syscallbuf_locked(false);
                    tracee.emulated_ptrace_options = 0;
                    tracee.emulated_ptrace_cont_command = 0;
                    tracee.emulated_stop_pending = false;
                    tracee.emulated_ptrace_queued_exit_stop = false;
                    prepare_ptrace_cont(
                        tracee,
                        Sig::try_from(t.regs_ref().arg4() as i32).ok(),
                        0,
                        t,
                    );
                    tracee.set_emulated_ptracer(None, Some(t));
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_KILL => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    // The tracee could already be dead, in which case sending it a signal
                    // would move it out of the exit stop, preventing us from doing our
                    // clean up work.
                    tracee.try_wait();
                    tracee.kill_if_alive();
                    syscall_state.emulate_result(0);
                }
                None => (),
            }
        }
        PTRACE_GET_THREAD_AREA | PTRACE_SET_THREAD_AREA => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                Some(tracee_rc) => {
                    let mut tracee = tracee_rc.borrow_mut();
                    if tracee.arch() != SupportedArch::X86 {
                        // This syscall should fail if the tracee is not x86
                        syscall_state.expect_errno = EIO;
                        emulate = false;
                    } else {
                        let remote_addr = RemotePtr::<user_desc>::from(t.regs_ref().arg4());
                        let mut ok = true;
                        let mut desc = user_desc::default();
                        // Do the ptrace request ourselves
                        if command == PTRACE_GET_THREAD_AREA {
                            let ret = -tracee
                                .emulate_get_thread_area(t.regs_ref().arg3() as u32, &mut desc);
                            if ret == 0 {
                                write_val_mem(t, remote_addr, &desc, Some(&mut ok));
                                if !ok {
                                    syscall_state.emulate_result_signed(-EFAULT as isize);
                                } else {
                                    t.record_local_for(remote_addr, &desc);
                                    syscall_state.emulate_result_signed(0);
                                }
                            } else {
                                syscall_state.emulate_result_signed(ret as isize);
                            }
                        } else {
                            desc = read_val_mem(t, remote_addr, Some(&mut ok));
                            if !ok {
                                syscall_state.emulate_result_signed(-EFAULT as isize);
                            } else {
                                syscall_state.emulate_result_signed(
                                    -tracee
                                        .emulate_set_thread_area(t.regs_ref().arg3() as u32, desc)
                                        as isize,
                                );
                            }
                        }
                    }
                }
                None => (),
            }
        }
        PTRACE_ARCH_PRCTL => {
            let maybe_tracee = verify_ptrace_target(t, syscall_state, pid);
            match maybe_tracee {
                None => (),
                Some(tracee_rc) => {
                    let mut traceeb = tracee_rc.borrow_mut();
                    let tracee = traceeb.as_rec_mut_unwrap();
                    if tracee.arch() != SupportedArch::X64 {
                        // This syscall should fail if the tracee is not
                        // x86_64
                        syscall_state.expect_errno = EIO;
                        emulate = false;
                    } else {
                        let code = t.regs_ref().arg4() as u32;
                        match code {
                            ARCH_GET_FS | ARCH_GET_GS => {
                                let mut ok = true;
                                let addr = RemotePtr::<u64>::from(t.regs_ref().arg3());
                                let data = if code == ARCH_GET_FS {
                                    tracee.regs_ref().fs_base()
                                } else {
                                    tracee.regs_ref().gs_base()
                                };
                                write_val_mem(t, addr, &data, Some(&mut ok));
                                if ok {
                                    t.record_local_for(addr, &data);
                                    syscall_state.emulate_result(0);
                                } else {
                                    syscall_state.emulate_result_signed(-EIO as isize);
                                }
                            }
                            ARCH_SET_FS | ARCH_SET_GS => {
                                syscall_state.emulate_result(0);
                            }
                            _ => {
                                syscall_state.emulate_result_signed(-EINVAL as isize);
                            }
                        }
                    }
                }
            }
        }
        _ => {
            syscall_state.expect_errno = EIO;
            emulate = false;
        }
    }
    if emulate {
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1_signed(-1);
        t.set_regs(&r);
    }

    Switchable::PreventSwitch
}

/// if `maybe_dest` is `None` then this is interpreted to mean that `dest` is `t` also
fn record_iovec_output<Arch: Architecture>(
    t: &mut RecordTask,
    maybe_dest: Option<&mut RecordTask>,
    piov: RemotePtr<iovec<Arch>>,
    iov_cnt: u32,
) {
    // Ignore the syscall result, the kernel may have written more data than that.
    // See https://bugzilla.kernel.org/show_bug.cgi?id=113541
    let iovs = read_mem(t, piov, iov_cnt as usize, None);
    let dest = match maybe_dest {
        Some(dest) => dest,
        None => t,
    };
    for iov in &iovs {
        dest.record_remote_writable(
            Arch::as_rptr(iov.iov_base),
            Arch::size_t_as_usize(iov.iov_len),
        );
    }
}

fn prepare_msgctl<Arch: Architecture>(
    syscall_state: &mut TaskSyscallState,
    cmd: u32,
    ptr_reg: usize,
) -> Switchable {
    match cmd {
        IPC_STAT | MSG_STAT => {
            syscall_state.reg_parameter::<Arch::msqid64_ds>(ptr_reg, None, None);
        }
        IPC_INFO | MSG_INFO => {
            syscall_state.reg_parameter::<Arch::msginfo>(ptr_reg, None, None);
        }
        IPC_SET | IPC_RMID => (),
        _ => {
            syscall_state.expect_errno = EINVAL;
        }
    }

    Switchable::PreventSwitch
}

fn prepare_shmctl<Arch: Architecture>(
    syscall_state: &mut TaskSyscallState,
    cmd: u32,
    ptr_reg: usize,
) -> Switchable {
    match cmd {
        IPC_SET | IPC_RMID | SHM_LOCK | SHM_UNLOCK => (),

        IPC_STAT | SHM_STAT => {
            syscall_state.reg_parameter::<Arch::shmid64_ds>(ptr_reg, None, None);
        }

        IPC_INFO => {
            syscall_state.reg_parameter::<Arch::shminfo64>(ptr_reg, None, None);
        }

        SHM_INFO => {
            syscall_state.reg_parameter::<Arch::shm_info>(ptr_reg, None, None);
        }

        _ => {
            syscall_state.expect_errno = EINVAL;
        }
    }

    Switchable::PreventSwitch
}

fn prepare_socketcall<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
) -> Switchable {
    // int socketcall(int call, unsigned long *args) {
    //   long a[6];
    //   copy_from_user(a,args);
    //   sys_recv(a0, (void __user *)a1, a[2], a[3]);
    // }
    //
    // (from http://lxr.linux.no/#linux+v3.6.3/net/socket.c#L2354)
    match t.regs_ref().arg1() as u32 {
        // int socket(int domain, int type, int protocol);
        // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        // int listen(int sockfd, int backlog)
        // int shutdown(int socket, int how)
        SYS_SOCKET | SYS_BIND | SYS_LISTEN | SYS_SHUTDOWN => (),

        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        SYS_CONNECT => {
            let argsp =
                syscall_state.reg_parameter::<connect_args<Arch>>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            return maybe_blacklist_connect::<Arch>(t, Arch::as_rptr(args.addr), args.addrlen);
        }

        // ssize_t send(int sockfd, const void *buf, usize len, int flags)
        // ssize_t sendto(int sockfd, const void *buf, usize len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
        SYS_SEND | SYS_SENDTO => {
            // These can block when socket buffers are full.
            return Switchable::AllowSwitch;
        }

        // int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
        SYS_SETSOCKOPT => {
            let argsp =
                syscall_state.reg_parameter::<setsockopt_args<Arch>>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            return prepare_setsockopt::<Arch>(t, syscall_state, &args);
        }

        // int getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t* optlen);
        SYS_GETSOCKOPT => {
            let argsp =
                syscall_state.reg_parameter::<getsockopt_args<Arch>>(2, Some(ArgMode::In), None);
            let optlen_ptr = syscall_state.mem_ptr_parameter_inferred::<Arch, common::socklen_t>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, getsockopt_args<Arch>, optlen)),
                Some(ArgMode::InOut),
                None,
            );
            let param_size = ParamSize::from_initialized_mem(t, optlen_ptr);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, getsockopt_args<Arch>, optval),
                param_size,
                None,
                None,
            );
        }

        // int socketpair(int domain, int type, int protocol, int sv[2]);
        //
        // values returned in sv
        SYS_SOCKETPAIR => {
            let argsp =
                syscall_state.reg_parameter::<socketpair_args<Arch>>(2, Some(ArgMode::In), None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, socketpair_args<Arch>, sv),
                ParamSize::from(size_of::<i32>() * 2),
                None,
                None,
            );
        }

        // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        SYS_GETPEERNAME | SYS_GETSOCKNAME => {
            let argsp =
                syscall_state.reg_parameter::<getsockname_args<Arch>>(2, Some(ArgMode::In), None);
            let addrlen_ptr = syscall_state.mem_ptr_parameter_inferred::<Arch, common::socklen_t>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, getsockname_args<Arch>, addrlen)),
                Some(ArgMode::InOut),
                None,
            );
            let param_size = ParamSize::from_initialized_mem(t, addrlen_ptr);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, getsockname_args<Arch>, addr),
                param_size,
                None,
                None,
            );
        }

        // ssize_t recv([int sockfd, void *buf, usize len, int flags])
        SYS_RECV => {
            let argsp = syscall_state.reg_parameter::<recv_args<Arch>>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, recv_args<Arch>, buf),
                ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(Arch::size_t_as_usize(
                    args.len,
                )),
                None,
                None,
            );
            return Switchable::AllowSwitch;
        }

        // int accept([int sockfd, struct sockaddr *addr, socklen_t *addrlen])
        SYS_ACCEPT => {
            let argsp =
                syscall_state.reg_parameter::<accept_args<Arch>>(2, Some(ArgMode::In), None);
            let addrlen_ptr = syscall_state.mem_ptr_parameter_inferred::<Arch, common::socklen_t>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, accept_args<Arch>, addrlen)),
                Some(ArgMode::InOut),
                None,
            );
            let param_size = ParamSize::from_initialized_mem(t, addrlen_ptr);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, accept_args<Arch>, addr),
                param_size,
                None,
                None,
            );

            return Switchable::AllowSwitch;
        }

        // int accept4([int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags])
        SYS_ACCEPT4 => {
            let argsp =
                syscall_state.reg_parameter::<accept4_args<Arch>>(2, Some(ArgMode::In), None);
            let addrlen_ptr = syscall_state.mem_ptr_parameter_inferred::<Arch, common::socklen_t>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, accept4_args<Arch>, addrlen)),
                Some(ArgMode::InOut),
                None,
            );
            let param_size = ParamSize::from_initialized_mem(t, addrlen_ptr);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, accept4_args<Arch>, addr),
                param_size,
                None,
                None,
            );
            return Switchable::AllowSwitch;
        }

        SYS_RECVFROM => {
            let argsp =
                syscall_state.reg_parameter::<recvfrom_args<Arch>>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, recvfrom_args<Arch>, buf),
                ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(Arch::size_t_as_usize(
                    args.len,
                )),
                None,
                None,
            );
            let addrlen_ptr = syscall_state.mem_ptr_parameter_inferred::<Arch, common::socklen_t>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, recvfrom_args<Arch>, addrlen)),
                Some(ArgMode::InOut),
                None,
            );
            let param_size = ParamSize::from_initialized_mem(t, addrlen_ptr);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, recvfrom_args<Arch>, src_addr),
                param_size,
                None,
                None,
            );
            return Switchable::AllowSwitch;
        }

        SYS_RECVMSG => {
            let argsp =
                syscall_state.reg_parameter::<recvmsg_args<Arch>>(2, Some(ArgMode::In), None);
            let msgp = syscall_state.mem_ptr_parameter_inferred::<Arch, msghdr<Arch>>(
                t,
                RemotePtr::cast(remote_ptr_field!(argsp, recvmsg_args<Arch>, msg)),
                Some(ArgMode::InOut),
                None,
            );
            prepare_recvmsg::<Arch>(
                t,
                syscall_state,
                msgp,
                ParamSize::from_syscall_result::<Arch::ssize_t>(),
            );

            let args = read_val_mem(t, argsp, None);
            if args.flags & MSG_DONTWAIT == 0 {
                return Switchable::AllowSwitch;
            }
        }

        SYS_RECVMMSG => {
            let argsp =
                syscall_state.reg_parameter::<recvmmsg_args<Arch>>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            let mmsgp_void: RemotePtr<Void> = syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, recvmmsg_args<Arch>, msgvec),
                ParamSize::from(size_of::<mmsghdr<Arch>>() * args.vlen as usize),
                Some(ArgMode::InOut),
                None,
            );
            let mmsgp = RemotePtr::<mmsghdr<Arch>>::cast(mmsgp_void);
            prepare_recvmmsg::<Arch>(t, syscall_state, mmsgp, args.vlen as usize);
            if args.flags as i32 & MSG_DONTWAIT == 0 {
                return Switchable::AllowSwitch;
            }
        }

        // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
        SYS_SENDMSG => {
            let argsp = RemotePtr::<sendmsg_args<Arch>>::from(t.regs_ref().arg2());
            let args = read_val_mem(t, argsp, None);
            if args.flags & MSG_DONTWAIT == 0 {
                return Switchable::AllowSwitch;
            }
        }

        SYS_SENDMMSG => {
            let argsp =
                syscall_state.reg_parameter::<sendmmsg_args<Arch>>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, sendmmsg_args<Arch>, msgvec),
                ParamSize::from(size_of::<mmsghdr<Arch>>() * args.vlen as usize),
                Some(ArgMode::InOut),
                None,
            );
            if args.flags as i32 & MSG_DONTWAIT == 0 {
                return Switchable::AllowSwitch;
            }
        }

        _ => {
            syscall_state.expect_errno = EINVAL;
        }
    }

    Switchable::PreventSwitch
}

fn is_privileged_executable(t: &RecordTask, path: &OsStr) -> bool {
    let mut actual = vfs_cap_data::default();
    let mut path_with_nul = Vec::new();
    path_with_nul.extend_from_slice(path.as_bytes());
    path_with_nul.push(b'\0');
    let empty = vfs_cap_data::default();
    let s = b"security.capability\0";
    if -1
        != unsafe {
            getxattr(
                path_with_nul.as_ptr() as _,
                s.as_ptr() as _,
                &raw mut actual as _,
                size_of::<vfs_cap_data>(),
            )
        }
    {
        let res = unsafe {
            memcmp(
                &raw const actual as _,
                &raw const empty as _,
                size_of_val(&actual.data),
            )
        };
        res != 0
    } else {
        ed_assert!(t, errno() == ENODATA || errno() == ENOTSUP);

        let maybe_buf = stat(path);
        match maybe_buf {
            Ok(buf) if buf.st_mode & (S_ISUID | S_ISGID) != 0 => true,
            _ => false,
        }
    }
}

fn in_same_mount_namespace_as(t: &RecordTask) -> bool {
    let proc_ns_mount = format!("/proc/{}/ns/mnt", t.tid);
    let my_buf = stat("/proc/self/ns/mnt").unwrap();
    let their_buf = stat(proc_ns_mount.as_str()).unwrap();
    my_buf.st_ino == their_buf.st_ino
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum SemctlDereference {
    Dereference,
    UseDirectly,
}

#[repr(C)]
#[derive(Copy, Clone)]
union _semun {
    val: i32,
    buf: *mut semid64_ds,
    array: *mut i16,
    __buf: *mut seminfo,
}

fn prepare_semctl<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
    semid: i32,
    cmd: u32,
    ptr_reg: usize,
    dref: SemctlDereference,
) -> Switchable {
    match cmd {
        IPC_SET | IPC_RMID | GETNCNT | GETPID | GETVAL | GETZCNT | SETALL | SETVAL => (),

        IPC_STAT | SEM_STAT => {
            if dref == SemctlDereference::Dereference {
                let addr = RemotePtr::cast(
                    syscall_state.reg_parameter::<Arch::unsigned_long>(ptr_reg, None, None),
                );
                syscall_state.mem_ptr_parameter::<Arch::semid64_ds>(t, addr, None, None);
            } else {
                syscall_state.reg_parameter::<Arch::semid64_ds>(ptr_reg, None, None);
            }
        }

        IPC_INFO | SEM_INFO => {
            if dref == SemctlDereference::Dereference {
                let addr = RemotePtr::cast(
                    syscall_state.reg_parameter::<Arch::unsigned_long>(ptr_reg, None, None),
                );
                syscall_state.mem_ptr_parameter::<Arch::seminfo>(t, addr, None, None);
            } else {
                syscall_state.reg_parameter::<Arch::seminfo>(ptr_reg, None, None);
            }
        }

        GETALL => {
            let mut ds = semid64_ds::default();
            let mut un_arg: _semun = unsafe { mem::zeroed() };
            un_arg.buf = &raw mut ds;
            let ret: i32 = _semctl(semid, 0, IPC_STAT, un_arg);
            // @TODO msan_unpoison
            ed_assert_eq!(t, ret, 0);

            let sz: usize = ds.sem_nsems.try_into().unwrap();
            let size = ParamSize::from(size_of::<i16>() * sz);
            if dref == SemctlDereference::Dereference {
                let addr = RemotePtr::cast(
                    syscall_state.reg_parameter::<Arch::unsigned_long>(ptr_reg, None, None),
                );
                syscall_state.mem_ptr_parameter_with_size(t, addr, size, None, None);
            } else {
                syscall_state.reg_parameter_with_size(ptr_reg, size, None, None);
            }
        }

        _ => {
            syscall_state.expect_errno = EINVAL;
        }
    }

    Switchable::PreventSwitch
}

fn _semctl(semid: i32, semnum: i32, mut cmd: u32, un_arg: _semun) -> i32 {
    if size_of::<usize>() == 4 {
        cmd |= IPC_64;
    }

    // @TODO omitting the ifdef in rr
    unsafe { libc::syscall(libc::SYS_semctl, semid, semnum, cmd, un_arg) as i32 }
}

fn _shmctl(shmid: i32, mut cmd: u32, buf: &mut shmid64_ds) -> i32 {
    if size_of::<usize>() == 4 {
        cmd |= IPC_64;
    }

    // @TODO omitting the ifdef in rr
    unsafe { libc::syscall(libc::SYS_shmctl, shmid, cmd, buf) as i32 }
}

fn process_shmat(t: &mut RecordTask, shmid: i32, shm_flags: i32, addr: RemotePtr<Void>) {
    if t.regs_ref().syscall_failed() {
        // We purely emulate failed shmats.
        return;
    }

    let mut ds = shmid64_ds::default();
    let ret = _shmctl(shmid, IPC_STAT, &mut ds);
    // @TODO msan_unpoison;
    ed_assert_eq!(
        t,
        ret,
        0,
        "shmid should be readable by rd since rd has the same UID as tracees"
    );
    let size = ceil_page_size(ds.shm_segsz.try_into().unwrap());

    let prot = shm_flags_to_mmap_prot(shm_flags);
    let flags = MapFlags::MAP_SHARED;

    // Read the kernel's mapping for the shm segment. There doesn't seem to be
    // any other way to get the correct device number. (The inode number seems to
    // be the shm key.) This should be OK since SysV shmem is not used very much
    // and reading /proc/<pid>/maps should be reasonably cheap.
    let kernel_info: KernelMapping = read_kernel_mapping(t.tid, addr);
    let km: KernelMapping = t.vm_shr_ptr().map(
        t,
        addr,
        size,
        prot,
        flags,
        0,
        kernel_info.fsname(),
        kernel_info.device(),
        kernel_info.inode(),
        None,
        None,
        None,
        None,
        None,
    );
    t.vm().set_shm_size(km.start(), km.size());
    let disposition =
        t.trace_writer_mut()
            .write_mapped_region(t, &km, &km.fake_stat(), &[], None, None);
    ed_assert_eq!(t, disposition, RecordInTrace::RecordInTrace);
    t.record_remote(addr, size);

    log!(
        LogDebug,
        "Optimistically hoping that SysV segment is not used outside of tracees"
    );
}

/// A change has been made to file 'fd' in task t. If the file has been mmapped
/// somewhere in t's address space, record the changes.
/// We check for matching files by comparing file names. This may not be
/// reliable but hopefully it's good enough for the cases where we need this.
/// This doesn't currently handle shared mappings very well. A file mapped
/// shared in multiple locations will be recorded once per location.
/// This doesn't handle mappings of the file into other address spaces.
fn record_file_change(t: &mut RecordTask, fd: i32, offset: u64, length: u64) {
    let file_name = t.file_name_of_fd(fd);

    for (_, m) in &t.vm_shr_ptr().maps() {
        if m.map.fsname() == file_name {
            let start = max(offset, m.map.file_offset_bytes());
            let end = min(
                offset + length,
                m.map.file_offset_bytes() + m.map.size() as u64,
            );
            if start < end {
                t.record_remote(
                    m.map.start() + (start - m.map.file_offset_bytes()) as usize,
                    (end - start) as usize,
                );
            }
        }
    }
}

fn record_v4l2_buffer_contents<Arch: Architecture>(t: &mut RecordTask) {
    let bufp: RemotePtr<v4l2_buffer<Arch>> = t.regs_ref().arg3().into();
    let buf = read_val_mem(t, bufp, None);

    match buf.memory {
        V4L2_MEMORY_MMAP => {
            record_file_change(
                t,
                t.regs_ref().arg1_signed() as i32,
                unsafe { buf.m.offset as u64 },
                buf.length as u64,
            );
            return;
        }
        _ => {
            ed_assert!(t, false, "Unhandled V4L2 memory type {}", buf.memory);
        }
    }
}

fn record_usbdevfs_reaped_urb<Arch: Architecture>(t: &mut RecordTask) {
    if t.regs_ref().syscall_failed() {
        return;
    }

    let pp: RemotePtr<Arch::unsigned_word> = t.regs_ref().arg3().into();
    let p: RemotePtr<usbdevfs_urb<Arch>> =
        RemotePtr::new(read_val_mem(t, pp, None).try_into().unwrap());
    t.record_remote_for(p);
    let urb = read_val_mem(t, p, None);
    let mut length: usize;
    if urb.type_ as u32 == USBDEVFS_URB_TYPE_ISO {
        let iso_frame_descs_ptr: RemotePtr<usbdevfs_iso_packet_desc> =
            RemotePtr::cast(remote_ptr_field!(p, usbdevfs_urb<Arch>, iso_frame_desc));
        let iso_frame_descs: Vec<usbdevfs_iso_packet_desc> = read_mem(
            t,
            iso_frame_descs_ptr,
            unsafe { urb.usbdevfs_urb_u.number_of_packets } as usize,
            None,
        );
        length = 0;
        for f in &iso_frame_descs {
            length += f.length as usize;
        }
        t.record_local_for_slice(iso_frame_descs_ptr, &iso_frame_descs);
    } else {
        length = urb.buffer_length as usize;
    }
    // It's tempting to use actual_length here but in some cases the kernel
    // writes back more data than that.
    t.record_remote(Arch::as_rptr(urb.buffer), length);
}

fn prepare_bpf<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut TaskSyscallState,
) -> Switchable {
    let cmd = t.regs_ref().arg1() as u32;
    match cmd {
        BPF_MAP_CREATE | BPF_MAP_UPDATE_ELEM | BPF_MAP_DELETE_ELEM => {
            return Switchable::PreventSwitch;
        }
        BPF_PROG_LOAD => {
            let argsp =
                syscall_state.reg_parameter::<arch_structs::bpf_attr>(2, Some(ArgMode::In), None);
            let args = read_val_mem(t, argsp, None);
            syscall_state.mem_ptr_parameter_with_size(
                t,
                remote_ptr_field!(argsp, arch_structs::bpf_attr_u3, log_buf),
                ParamSize::from(unsafe { args.bpf_attr_u3.log_size } as usize),
                None,
                None,
            );
            return Switchable::PreventSwitch;
        }
        // These are hard to support because we have to track the key_size/value_size :-(
        // BPF_MAP_LOOKUP_ELEM
        // BPF_MAP_GET_NEXT_KEY
        _ => {
            syscall_state.expect_errno = EINVAL;
            return Switchable::PreventSwitch;
        }
    }
}
