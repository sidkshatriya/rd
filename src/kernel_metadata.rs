use crate::kernel_abi;
use crate::kernel_abi::SupportedArch;

pub fn syscall_name(syscall: i32, arch: SupportedArch) -> String {
    rr_arch_function!(syscallname_arch, arch, syscall)
}

pub fn signal_name(sig: i32) -> String {
    /* strsignal() would be nice to use here, but it provides TMI. */
    if 32 <= sig && sig <= 64 {
        return format!("SIGRT{}", sig);
    }

    match sig {
        libc::SIGHUP => "SIGHUP".into(),
        libc::SIGINT => "SIGINT".into(),
        libc::SIGQUIT => "SIGQUIT".into(),
        libc::SIGILL => "SIGILL".into(),
        libc::SIGTRAP => "SIGTRAP".into(),
        libc::SIGABRT => "SIGABRT".into(), // libc::SIGIOT,
        libc::SIGBUS => "SIGBUS".into(),
        libc::SIGFPE => "SIGFPE".into(),
        libc::SIGKILL => "SIGKILL".into(),
        libc::SIGUSR1 => "SIGUSR1".into(),
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGUSR2 => "SIGUSR2".into(),
        libc::SIGPIPE => "SIGPIPE".into(),
        libc::SIGALRM => "SIGALRM".into(),
        libc::SIGTERM => "SIGTERM".into(),
        libc::SIGSTKFLT => "SIGSTKFLT".into(), /*libc::SIGCLD".into(),*/
        libc::SIGCHLD => "SIGCHLD".into(),
        libc::SIGCONT => "SIGCONT".into(),
        libc::SIGSTOP => "SIGSTOP".into(),
        libc::SIGTSTP => "SIGTSTP".into(),
        libc::SIGTTIN => "SIGTTIN".into(),
        libc::SIGTTOU => "SIGTTOU".into(),
        libc::SIGURG => "SIGURG".into(),
        libc::SIGXCPU => "SIGXCPU".into(),
        libc::SIGXFSZ => "SIGXFSZ".into(),
        libc::SIGVTALRM => "SIGVTALRM".into(),
        libc::SIGPROF => "SIGPROF".into(),
        libc::SIGWINCH => "SIGWINCH".into(), // libc::SIGPOLL
        libc::SIGIO => "SIGIO".into(),
        libc::SIGPWR => "SIGPWR".into(),
        libc::SIGSYS => "SIGSYS".into(),
        /* Special-case this so we don't need to sprintf in this common case.
         * This case is common because we often pass signal_name(sig) to assertions
         * when sig is 0.
         */
        0 => "signal(0)".into(),
        _ => format!("signal({}))", sig)
    }
}

pub fn ptrace_event_name(event: i32) -> String {
    match event {
        libc::PTRACE_EVENT_FORK => "PTRACE_EVENT_FORK".into(),
        libc::PTRACE_EVENT_VFORK => "PTRACE_EVENT_VFORK".into(),
        libc::PTRACE_EVENT_CLONE => "PTRACE_EVENT_CLONE".into(),
        libc::PTRACE_EVENT_EXEC => "PTRACE_EVENT_EXEC".into(),
        libc::PTRACE_EVENT_VFORK_DONE => "PTRACE_EVENT_VFORK_DONE".into(),
        libc::PTRACE_EVENT_EXIT => "PTRACE_EVENT_EXIT".into(),
        // @TODO.
        /* XXX Ubuntu 12.04 defines a "PTRACE_EVENT_STOP", but that
         * has the same value as the newer EVENT_SECCOMP, so we'll
         * ignore STOP. */
        // libc::PTRACE_EVENT_SECCOMP_OBSOLETE => "PTRACE_EVENT_SECCOMP_OBSOLETE".into(),
        libc::PTRACE_EVENT_SECCOMP => "PTRACE_EVENT_SECCOMP".into(),
        // @TODO.
        // libc::PTRACE_EVENT_STOP => "PTRACE_EVENT_STOP".into(),
        /* Special-case this.
         * This case is common because we often pass ptrace_event_name(event) to
         * assertions when event is 0.
         */
        0 => "PTRACE_EVENT(0)".into(),
        _ => format!("PTRACE_EVENT({})", event),
    }
}

pub fn ptrace_req_name(request: u32) -> String {
    match request {
        libc::PTRACE_TRACEME => "PTRACE_TRACEME".into(),
        libc::PTRACE_PEEKTEXT => "PTRACE_PEEKTEXT".into(),
        libc::PTRACE_PEEKDATA => "PTRACE_PEEKDATA".into(),
        libc::PTRACE_PEEKUSER => "PTRACE_PEEKUSER".into(),
        libc::PTRACE_POKETEXT => "PTRACE_POKETEXT".into(),
        libc::PTRACE_POKEDATA => "PTRACE_POKEDATA".into(),
        libc::PTRACE_POKEUSER => "PTRACE_POKEUSER".into(),
        libc::PTRACE_CONT => "PTRACE_CONT".into(),
        libc::PTRACE_KILL => "PTRACE_KILL".into(),
        libc::PTRACE_SINGLESTEP => "PTRACE_SINGLESTEP".into(),
        libc::PTRACE_GETREGS => "PTRACE_GETREGS".into(),
        libc::PTRACE_SETREGS => "PTRACE_SETREGS".into(),
        libc::PTRACE_GETFPREGS => "PTRACE_GETFPREGS".into(),
        libc::PTRACE_SETFPREGS => "PTRACE_SETFPREGS".into(),
        libc::PTRACE_ATTACH => "PTRACE_ATTACH".into(),
        libc::PTRACE_DETACH => "PTRACE_DETACH".into(),
        libc::PTRACE_GETFPXREGS => "PTRACE_GETFPXREGS".into(),
        libc::PTRACE_SETFPXREGS => "PTRACE_SETFPXREGS".into(),
        libc::PTRACE_SYSCALL => "PTRACE_SYSCALL".into(),
        libc::PTRACE_SETOPTIONS => "PTRACE_SETOPTIONS".into(),
        libc::PTRACE_GETEVENTMSG => "PTRACE_GETEVENTMSG".into(),
        libc::PTRACE_GETSIGINFO => "PTRACE_GETSIGINFO".into(),
        libc::PTRACE_SETSIGINFO => "PTRACE_SETSIGINFO".into(),
        libc::PTRACE_GETREGSET => "PTRACE_GETREGSET".into(),
        libc::PTRACE_SETREGSET => "PTRACE_SETREGSET".into(),
        libc::PTRACE_SEIZE => "PTRACE_SEIZE".into(),
        libc::PTRACE_INTERRUPT => "PTRACE_INTERRUPT".into(),
        libc::PTRACE_LISTEN => "PTRACE_LISTEN".into(),
        // @TODO.
        // These aren't part of the official ptrace-request enum.
        // libc::PTRACE_SYSEMU => "PTRACE_SYSEMU".into(),
        // libc::PTRACE_SYSEMU_SINGLESTEP => "PTRACE_SYSEMU_SINGLESTEP".into(),
        _ => format!("PTRACE_REQUEST({})", request),
    }
}

pub fn errno_name(err: i32) -> String {
    match err {
        0 => "SUCCESS".into(),
        libc::EPERM => "EPERM".into(),
        libc::ENOENT => "ENOENT".into(),
        libc::ESRCH => "ESRCH".into(),
        libc::EINTR => "EINTR".into(),
        libc::EIO => "EIO".into(),
        libc::ENXIO => "ENXIO".into(),
        libc::E2BIG => "E2BIG".into(),
        libc::ENOEXEC => "ENOEXEC".into(),
        libc::EBADF => "EBADF".into(),
        libc::ECHILD => "ECHILD".into(),
        libc::EAGAIN => "EAGAIN".into(),
        libc::ENOMEM => "ENOMEM".into(),
        libc::EACCES => "EACCES".into(),
        libc::EFAULT => "EFAULT".into(),
        libc::ENOTBLK => "ENOTBLK".into(),
        libc::EBUSY => "EBUSY".into(),
        libc::EEXIST => "EEXIST".into(),
        libc::EXDEV => "EXDEV".into(),
        libc::ENODEV => "ENODEV".into(),
        libc::ENOTDIR => "ENOTDIR".into(),
        libc::EISDIR => "EISDIR".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::ENFILE => "ENFILE".into(),
        libc::EMFILE => "EMFILE".into(),
        libc::ENOTTY => "ENOTTY".into(),
        libc::ETXTBSY => "ETXTBSY".into(),
        libc::EFBIG => "EFBIG".into(),
        libc::ENOSPC => "ENOSPC".into(),
        libc::ESPIPE => "ESPIPE".into(),
        libc::EROFS => "EROFS".into(),
        libc::EMLINK => "EMLINK".into(),
        libc::EPIPE => "EPIPE".into(),
        libc::EDOM => "EDOM".into(),
        libc::ERANGE => "ERANGE".into(),
        libc::EDEADLK => "EDEADLK".into(),
        libc::ENAMETOOLONG => "ENAMETOOLONG".into(),
        libc::ENOLCK => "ENOLCK".into(),
        libc::ENOSYS => "ENOSYS".into(),
        libc::ENOTEMPTY => "ENOTEMPTY".into(),
        libc::ELOOP => "ELOOP".into(),
        libc::ENOMSG => "ENOMSG".into(),
        libc::EIDRM => "EIDRM".into(),
        libc::ECHRNG => "ECHRNG".into(),
        libc::EL2NSYNC => "EL2NSYNC".into(),
        libc::EL3HLT => "EL3HLT".into(),
        libc::EL3RST => "EL3RST".into(),
        libc::ELNRNG => "ELNRNG".into(),
        libc::EUNATCH => "EUNATCH".into(),
        libc::ENOCSI => "ENOCSI".into(),
        libc::EL2HLT => "EL2HLT".into(),
        libc::EBADE => "EBADE".into(),
        libc::EBADR => "EBADR".into(),
        libc::EXFULL => "EXFULL".into(),
        libc::ENOANO => "ENOANO".into(),
        libc::EBADRQC => "EBADRQC".into(),
        libc::EBADSLT => "EBADSLT".into(),
        libc::EBFONT => "EBFONT".into(),
        libc::ENOSTR => "ENOSTR".into(),
        libc::ENODATA => "ENODATA".into(),
        libc::ETIME => "ETIME".into(),
        libc::ENOSR => "ENOSR".into(),
        libc::ENONET => "ENONET".into(),
        libc::ENOPKG => "ENOPKG".into(),
        libc::EREMOTE => "EREMOTE".into(),
        libc::ENOLINK => "ENOLINK".into(),
        libc::EADV => "EADV".into(),
        libc::ESRMNT => "ESRMNT".into(),
        libc::ECOMM => "ECOMM".into(),
        libc::EPROTO => "EPROTO".into(),
        libc::EMULTIHOP => "EMULTIHOP".into(),
        libc::EDOTDOT => "EDOTDOT".into(),
        libc::EBADMSG => "EBADMSG".into(),
        libc::EOVERFLOW => "EOVERFLOW".into(),
        libc::ENOTUNIQ => "ENOTUNIQ".into(),
        libc::EBADFD => "EBADFD".into(),
        libc::EREMCHG => "EREMCHG".into(),
        libc::ELIBACC => "ELIBACC".into(),
        libc::ELIBBAD => "ELIBBAD".into(),
        libc::ELIBSCN => "ELIBSCN".into(),
        libc::ELIBMAX => "ELIBMAX".into(),
        libc::ELIBEXEC => "ELIBEXEC".into(),
        libc::EILSEQ => "EILSEQ".into(),
        libc::ERESTART => "ERESTART".into(),
        libc::ESTRPIPE => "ESTRPIPE".into(),
        libc::EUSERS => "EUSERS".into(),
        libc::ENOTSOCK => "ENOTSOCK".into(),
        libc::EDESTADDRREQ => "EDESTADDRREQ".into(),
        libc::EMSGSIZE => "EMSGSIZE".into(),
        libc::EPROTOTYPE => "EPROTOTYPE".into(),
        libc::ENOPROTOOPT => "ENOPROTOOPT".into(),
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT".into(),
        libc::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT".into(),
        libc::EOPNOTSUPP => "EOPNOTSUPP".into(),
        libc::EPFNOSUPPORT => "EPFNOSUPPORT".into(),
        libc::EAFNOSUPPORT => "EAFNOSUPPORT".into(),
        libc::EADDRINUSE => "EADDRINUSE".into(),
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL".into(),
        libc::ENETDOWN => "ENETDOWN".into(),
        libc::ENETUNREACH => "ENETUNREACH".into(),
        libc::ENETRESET => "ENETRESET".into(),
        libc::ECONNABORTED => "ECONNABORTED".into(),
        libc::ECONNRESET => "ECONNRESET".into(),
        libc::ENOBUFS => "ENOBUFS".into(),
        libc::EISCONN => "EISCONN".into(),
        libc::ENOTCONN => "ENOTCONN".into(),
        libc::ESHUTDOWN => "ESHUTDOWN".into(),
        libc::ETOOMANYREFS => "ETOOMANYREFS".into(),
        libc::ETIMEDOUT => "ETIMEDOUT".into(),
        libc::ECONNREFUSED => "ECONNREFUSED".into(),
        libc::EHOSTDOWN => "EHOSTDOWN".into(),
        libc::EHOSTUNREACH => "EHOSTUNREACH".into(),
        libc::EALREADY => "EALREADY".into(),
        libc::EINPROGRESS => "EINPROGRESS".into(),
        libc::ESTALE => "ESTALE".into(),
        libc::EUCLEAN => "EUCLEAN".into(),
        libc::ENOTNAM => "ENOTNAM".into(),
        libc::ENAVAIL => "ENAVAIL".into(),
        libc::EISNAM => "EISNAM".into(),
        libc::EREMOTEIO => "EREMOTEIO".into(),
        libc::EDQUOT => "EDQUOT".into(),
        libc::ENOMEDIUM => "ENOMEDIUM".into(),
        libc::EMEDIUMTYPE => "EMEDIUMTYPE".into(),
        libc::ECANCELED => "ECANCELED".into(),
        libc::ENOKEY => "ENOKEY".into(),
        libc::EKEYEXPIRED => "EKEYEXPIRED".into(),
        libc::EKEYREVOKED => "EKEYREVOKED".into(),
        libc::EKEYREJECTED => "EKEYREJECTED".into(),
        libc::EOWNERDEAD => "EOWNERDEAD".into(),
        libc::ENOTRECOVERABLE => "ENOTRECOVERABLE".into(),
        libc::ERFKILL => "ERFKILL".into(),
        libc::EHWPOISON => "EHWPOISON".into(),
        _ => format!("errno({})", err),
    }
}

fn is_sigreturn(syscallno: i32, arch: SupportedArch) -> bool {
    kernel_abi::is_sigreturn_syscall(syscallno, arch)
        || kernel_abi::is_rt_sigreturn_syscall(syscallno, arch)
}

macro_rules! case {
    ($match_var:expr, $mod_name:ident, $($case_name:ident),+) => {{
        use crate::$mod_name;
        match $match_var {
            $($mod_name::$case_name => return stringify!($case_name).into(),)+
            _ => ()
        }
    }};
}

fn sicode_name(code: i32, sig: i32) -> String {
    case!(
        code, signal, SI_USER, SI_KERNEL, SI_QUEUE, SI_TIMER, SI_MESGQ, SI_ASYNCIO, SI_SIGIO,
        SI_TKILL, SI_ASYNCNL
    );

    match sig {
        libc::SIGSEGV => case!(code as u32, signal, SEGV_MAPERR, SEGV_ACCERR),
        libc::SIGTRAP => case!(code as u32, signal, TRAP_BRKPT, TRAP_TRACE),
        libc::SIGILL => case!(
            code as u32,
            signal,
            ILL_ILLOPC,
            ILL_ILLOPN,
            ILL_ILLADR,
            ILL_ILLTRP,
            ILL_PRVOPC,
            ILL_PRVREG,
            ILL_COPROC,
            ILL_BADSTK
        ),
        libc::SIGFPE => case!(
            code as u32,
            signal,
            FPE_INTDIV,
            FPE_INTOVF,
            FPE_FLTDIV,
            FPE_FLTOVF,
            FPE_FLTUND,
            FPE_FLTRES,
            FPE_FLTINV,
            FPE_FLTSUB
        ),
        libc::SIGBUS => case!(
            code as u32,
            signal,
            BUS_ADRALN,
            BUS_ADRERR,
            BUS_OBJERR,
            BUS_MCEERR_AR,
            BUS_MCEERR_AO
        ),
        libc::SIGCHLD => case!(
            code as u32,
            signal,
            CLD_EXITED,
            CLD_KILLED,
            CLD_DUMPED,
            CLD_TRAPPED,
            CLD_STOPPED,
            CLD_CONTINUED
        ),
        libc::SIGPOLL => case!(
            code as u32,
            signal,
            POLL_IN,
            POLL_OUT,
            POLL_MSG,
            POLL_ERR,
            POLL_PRI,
            POLL_HUP
        ),
        _ => (),
    }
    format!("sicode({})", code)
}
