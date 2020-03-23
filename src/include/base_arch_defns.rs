use std::mem::size_of;

pub type time_t = syscall_slong_t;
pub type off_t = syscall_slong_t;
pub type blkcnt_t = syscall_slong_t;
pub type blksize_t = syscall_slong_t;
pub type rlim_t = syscall_ulong_t;
pub type fsblkcnt_t = syscall_ulong_t;
pub type fsfilcnt_t = syscall_ulong_t;
pub type ino_t = syscall_ulong_t;
pub type nlink_t = syscall_ulong_t;

pub type off64_t = int64_t;
pub type loff_t = int64_t;
pub type rlim64_t = uint64_t;
pub type ino64_t = uint64_t;
pub type blkcnt64_t = int64_t;

pub type clock_t = syscall_slong_t;
pub type __kernel_key_t = signed_int;
pub type __kernel_uid32_t = signed_int;
pub type __kernel_gid32_t = signed_int;
pub type __kernel_mode_t = unsigned_int;
pub type __kernel_ulong_t = unsigned_long;
pub type __kernel_long_t = signed_long;
pub type __kernel_time_t = __kernel_long_t;
pub type __kernel_suseconds_t = __kernel_long_t;
pub type __kernel_pid_t = signed_int;
pub type __kernel_loff_t = int64_t;

pub const STD_PAD: usize = size_of::<unsigned_long>() - size_of::<int>();
pub const KERNEL_SIGSET_SIZE: usize = 64 / (8 * size_of::<unsigned_long>());
pub const SIGSET_SIZE: usize = 1024 / (8 * size_of::<unsigned_long>());
pub const MAX_FDS: usize = 1024;
pub const FD_SET_NUM: usize = MAX_FDS / (8 * size_of::<unsigned_long>());
pub const SYSINFO_F_SIZE: usize = 20 - 2 * size_of::<__kernel_ulong_t>() - size_of::<uint32_t>();

#[repr(C)]
#[derive(Copy, Clone)]
pub union sigval_t {
    pub sival_int: signed_int,
    pub sival_ptr: ptr<u8>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sockaddr {
    pub sa_family: unsigned_short,
    pub sa_data: [u8; 14],
}
//RR_VERIFY_TYPE(sockaddr);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_un {
    pub sun_family: unsigned_short,
    pub sun_path: [u8; 108],
}
//RR_VERIFY_TYPE(sockaddr_un);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timeval {
    pub tv_sec: __kernel_time_t,
    pub tv_usec: __kernel_suseconds_t,
}
//RR_VERIFY_TYPE(timeval);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timespec {
    pub tv_sec: __kernel_time_t,
    pub tv_nsec: syscall_slong_t,
}
//RR_VERIFY_TYPE(timespec);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct pollfd {
    pub fd: signed_int,
    pub events: signed_short,
    pub revents: signed_short,
}
//RR_VERIFY_TYPE(pollfd);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iovec {
    pub iov_base: ptr<u8>,
    pub iov_len: size_t,
}
//RR_VERIFY_TYPE(iovec);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct msghdr {
    pub msg_name: ptr<u8>,
    pub msg_namelen: socklen_t,
    pub _padding: [u8; STD_PAD],

    pub msg_iov: ptr<iovec>,
    pub msg_iovlen: size_t,

    pub msg_control: ptr<u8>,
    pub msg_controllen: size_t,

    pub msg_flags: signed_int,
}
//RR_VERIFY_TYPE(msghdr);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct cmsghdr {
    pub cmsg_len: size_t,
    pub cmsg_level: int,
    pub cmsg_type: int,
}
//RR_VERIFY_TYPE(cmsghdr);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct mmsghdr {
    pub msg_hdr: msghdr,
    pub msg_len: unsigned_int,
}
//RR_VERIFY_TYPE(mmsghdr);

#[repr(C)]
pub union epoll_data {
    pub ptr_: ptr<u8>,
    pub fd: i32,
    pub data_u32: u32,
    pub data_u64: u64,
}

/// @TODO The align check does not seem to work in x86.
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct epoll_event {
    pub events: u32,
    pub data: epoll_data,
}

/// x86-64 is the only architecture to pack this structure, and it does
/// so to make the x86 and x86-64 definitions identical.  So even if
/// we're compiling on an x86-64 host that will support recording
/// 32-bit and 64-bit programs, this is the correct way to declare
/// epoll_event for both kinds of recordees.
/// See <linux/eventpoll.h>.
#[repr(C, packed)]
#[cfg(target_arch = "x86_64")]
pub struct epoll_event {
    pub events: u32,
    pub data: epoll_data,
}
//RR_VERIFY_TYPE(epoll_event);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct rusage {
    pub ru_utime: timeval,
    pub ru_stime: timeval,
    pub ru_maxrss: signed_long,
    pub ru_ixrss: signed_long,
    pub ru_idrss: signed_long,
    pub ru_isrss: signed_long,
    pub ru_minflt: signed_long,
    pub ru_majflt: signed_long,
    pub ru_nswap: signed_long,
    pub ru_inblock: signed_long,
    pub ru_oublock: signed_long,
    pub ru_msgnsd: signed_long,
    pub ru_msgrcv: signed_long,
    pub ru_nsignals: signed_long,
    pub ru_nvcsw: signed_long,
    pub ru_nivcsw: signed_long,
}
//RR_VERIFY_TYPE(rusage);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct siginfo_kill {
    si_pid_: pid_t,
    si_uid_: uid_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct siginfo_timer {
    pub si_tid_: signed_int,
    pub si_overrun_: signed_int,
    pub si_sigval_: sigval_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct siginfo_rt {
    pub si_pid_: pid_t,
    pub si_uid_: uid_t,
    pub si_sigval_: sigval_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct siginfo_sigchld {
    pub si_pid_: pid_t,
    pub si_uid_: uid_t,
    pub si_status_: signed_int,
    pub si_utime_: sigchld_clock_t,
    pub si_stime_: sigchld_clock_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct siginfo_sigfault {
    pub si_addr_: ptr<u8>,
    pub si_addr_lsb_: signed_short,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct siginfo_sigpoll {
    pub si_band_: signed_long,
    pub si_fd_: signed_int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct siginfo_sigsys {
    pub _call_addr: ptr<u8>,
    pub _syscall: signed_int,
    pub _arch: unsigned_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union siginfo_sifields {
    pub padding: [i32; SIGINFO_PADDING],
    pub _kill: siginfo_kill,
    pub _timer: siginfo_timer,
    pub _rt: siginfo_rt,
    pub _sigchld: siginfo_sigchld,
    pub _sigfault: siginfo_sigfault,
    pub _sigpoll: siginfo_sigpoll,
    pub _sigsys: siginfo_sigsys,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct siginfo_t {
    pub si_signo: signed_int,
    pub si_errno: signed_int,
    pub si_code: signed_int,
    pub _sifields: siginfo_sifields,
}
//RR_VERIFY_TYPE_EXPLICIT(siginfo_t, ::siginfo_t);

pub type cc_t = u8;
pub type speed_t = unsigned_int;
pub type tcflag_t = unsigned_int;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub _padding: [u8; 3],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}
//RR_VERIFY_TYPE(termios);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct termio {
    pub c_iflag: unsigned_short,
    pub c_oflag: unsigned_short,
    pub c_cflag: unsigned_short,
    pub c_lflag: unsigned_short,
    pub c_line: u8,
    pub c_cc: [u8; 8],
}
//RR_VERIFY_TYPE(termio);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct winsize {
    pub ws_row: unsigned_short,
    pub ws_col: unsigned_short,
    pub ws_xpixel: unsigned_short,
    pub ws_ypixel: unsigned_short,
}
//RR_VERIFY_TYPE(winsize);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ipc64_perm {
    pub key: __kernel_key_t,
    pub uid: __kernel_uid32_t,
    pub gid: __kernel_gid32_t,
    pub cuid: __kernel_uid32_t,
    pub cgid: __kernel_gid32_t,
    pub mode: __kernel_mode_t,
    pub seq: unsigned_short,
    pub __pad2: unsigned_short,
    pub __pad3: [u8; STD_PAD],
    pub unused1: __kernel_ulong_t,
    pub unused2: __kernel_ulong_t,
}
//RR_VERIFY_TYPE(ipc64_perm);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct msqid64_ds {
    pub msg_perm: ipc64_perm,
    /// These msg*time fields are really __kernel_time_t plus
    /// appropriate padding.  We don't touch the fields, though.
    ///
    /// We do, however, suffix them with _only_little_endian to
    /// urge anybody who does touch them to make sure the right
    /// thing is done for big-endian systems.
    pub msg_stime_only_little_endian: uint64_t,
    pub msg_rtime_only_little_endian: uint64_t,
    pub msg_ctime_only_little_endian: uint64_t,
    pub msg_cbytes: __kernel_ulong_t,
    pub msg_qnum: __kernel_ulong_t,
    pub msg_qbytes: __kernel_ulong_t,
    pub msg_lspid: __kernel_pid_t,
    pub msg_lrpid: __kernel_pid_t,
    pub unused1: __kernel_ulong_t,
    pub unused2: __kernel_ulong_t,
}
//RR_VERIFY_TYPE(msqid64_ds);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct msginfo {
    pub msgpool: signed_int,
    pub msgmap: signed_int,
    pub msgmax: signed_int,
    pub msgmnb: signed_int,
    pub msgmni: signed_int,
    pub msgssz: signed_int,
    pub msgtql: signed_int,
    pub msgseg: unsigned_short,
}
//RR_VERIFY_TYPE(msginfo);

/// Don't align for the 64-bit values on 32-bit x86
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct shmid64_ds {
    pub shm_perm: ipc64_perm,
    pub shm_segsz: size_t,
    pub shm_atime_only_little_endian: uint64_t,
    pub shm_dtime_only_little_endian: uint64_t,
    pub shm_ctime_only_little_endian: uint64_t,
    pub shm_cpid: __kernel_pid_t,
    pub shm_lpid: __kernel_pid_t,
    pub shm_nattch: __kernel_ulong_t,
    pub unused4: __kernel_ulong_t,
    pub unused5: __kernel_ulong_t,
}
//RR_VERIFY_TYPE(shmid64_ds);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct shminfo64 {
    pub shmmax: __kernel_ulong_t,
    pub shmmin: __kernel_ulong_t,
    pub shmmni: __kernel_ulong_t,
    pub shmseg: __kernel_ulong_t,
    pub shmall: __kernel_ulong_t,
    pub unused1: __kernel_ulong_t,
    pub unused2: __kernel_ulong_t,
    pub unused3: __kernel_ulong_t,
    pub unused4: __kernel_ulong_t,
}
//RR_VERIFY_TYPE(shminfo64);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct shm_info {
    pub used_ids: int,
    pub __pad: [u8; STD_PAD],
    pub shm_tot: __kernel_ulong_t,
    pub shm_rss: __kernel_ulong_t,
    pub shm_swp: __kernel_ulong_t,
    pub swap_attempts: __kernel_ulong_t,
    pub swap_successes: __kernel_ulong_t,
}
//RR_VERIFY_TYPE(shm_info);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct semid64_ds {
    pub sem_perm: ipc64_perm,
    pub sem_otime: __kernel_time_t,
    pub __unused1: __kernel_ulong_t,
    pub sem_ctime: __kernel_time_t,
    pub __unused2: __kernel_ulong_t,
    pub sem_nsems: __kernel_ulong_t,
    pub __unused3: __kernel_ulong_t,
    pub __unused4: __kernel_ulong_t,
}
//RR_VERIFY_TYPE(semid64_ds);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct seminfo {
    pub semmap: int,
    pub semmni: int,
    pub semmns: int,
    pub semmnu: int,
    pub semmsl: int,
    pub semopm: int,
    pub semume: int,
    pub semusz: int,
    pub semvmx: int,
    pub semaem: int,
}
//RR_VERIFY_TYPE(seminfo);

/// The clone(2) syscall has four (!) different calling conventions,
/// depending on what architecture it's being compiled for.  We describe
/// the orderings for x86oids here.
enum CloneParameterOrdering {
    FlagsStackParentTLSChild,
    FlagsStackParentChildTLS,
}

/// Despite the clone(2) manpage describing the clone syscall as taking a
/// pointer to `struct user_desc*`, the actual kernel interface treats the
/// TLS value as a opaque cookie, which architectures are then free to do
/// whatever they like with.  See for instance the definition of TLS_VALUE
/// in nptl/sysdeps/pthread/createthread.c in the glibc source.  We need to
/// describe what the architecture uses so we can record things accurately.
enum CloneTLSType {
    /// `struct user_desc*`
    UserDescPointer,
    /// This is the default choice for TLS_VALUE in the glibc source.
    PthreadStructurePointer,
}

// @TODO user_desc struct.
//RR_VERIFY_TYPE(user_desc);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct __user_cap_header_struct {
    pub version: __u32,
    pub pid: int,
}
//RR_VERIFY_TYPE(__user_cap_header_struct);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct __user_cap_data_struct {
    pub effective: __u32,
    pub permitted: __u32,
    pub inheritable: __u32,
}
//RR_VERIFY_TYPE(__user_cap_data_struct);

// This structure uses fixed-size fields, but the padding rules
// for 32-bit vs. 64-bit architectures dictate that it be
// defined in full.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct dqblk {
    pub dqb_bhardlimit: uint64_t,
    pub dqb_bsoftlimit: uint64_t,
    pub dqb_curspace: uint64_t,
    pub dqb_ihardlimit: uint64_t,
    pub dqb_isoftlimit: uint64_t,
    pub dqb_curinodes: uint64_t,
    pub dqb_btime: uint64_t,
    pub dqb_itime: uint64_t,
    pub dqb_valid: uint32_t,
}
//RR_VERIFY_TYPE(dqblk);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct dqinfo {
    pub dqi_bgrace: uint64_t,
    pub dqi_igrace: uint64_t,
    pub dqi_flags: uint32_t,
    pub dqi_valid: uint32_t,
}
//RR_VERIFY_TYPE(dqinfo);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ifmap {
    pub mem_start: unsigned_long,
    pub mem_end: unsigned_long,
    pub base_addr: unsigned_short,
    pub irq: u8,
    pub dma: u8,
    pub port: u8,
}
//RR_VERIFY_TYPE(ifmap);

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifs_ifsu {
    pub raw_hdlc: ptr<u8>,
    pub cisco: ptr<u8>,
    pub fr: ptr<u8>,
    pub fr_pvc: ptr<u8>,
    pub fr_pvc_info: ptr<u8>,
    pub sync: ptr<u8>,
    pub tel: ptr<u8>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct if_settings {
    pub type_: unsigned_int,
    pub size: unsigned_int,
    pub ifs_ifsu: ifs_ifsu,
}

//RR_VERIFY_TYPE(if_settings);
#[repr(C)]
#[derive(Copy, Clone)]
pub union ifr_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: signed_short,
    pub ifru_ivalue: signed_int,
    pub ifru_mtu: signed_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [u8; 16],
    pub ifru_newname: [u8; 16],
    pub ifru_data: ptr<u8>,
    pub ifru_settings: if_settings,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifr_ifrn {
    pub ifrn_name: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifr_ifrn: ifr_ifrn,
    pub ifr_ifru: ifr_ifru,
}
//RR_VERIFY_TYPE(ifreq);

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifc_ifcu {
    pub ifcu_buf: ptr<char>,
    pub ifcu_req: ptr<ifreq>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifconf {
    pub ifc_len: signed_int,
    pub __pad: [u8; STD_PAD],
    pub ifc_ifcu: ifc_ifcu,
}
//RR_VERIFY_TYPE(ifconf);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_param {
    pub value: int32_t,
    pub fixed: uint8_t,
    pub disabled: uint8_t,
    pub flags: uint16_t,
}
//RR_VERIFY_TYPE(iw_param);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_point {
    pub pointer: ptr<u8>,
    pub length: uint16_t,
    pub flags: uint16_t,
}
//RR_VERIFY_TYPE(iw_point);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_freq {
    pub m: int32_t,
    pub e: int16_t,
    pub i: uint8_t,
    pub flags: uint8_t,
}
//RR_VERIFY_TYPE(iw_freq);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_quality {
    pub qual: uint8_t,
    pub level: uint8_t,
    pub noise: uint8_t,
    pub updated: uint8_t,
}
//RR_VERIFY_TYPE(iw_quality);

#[repr(C)]
#[derive(Copy, Clone)]
pub union iwreq_data {
    pub name: [u8; 16],
    pub essid: iw_point,
    pub nwid: iw_param,
    pub freq: iw_freq,
    pub sens: iw_param,
    pub bitrate: iw_param,
    pub txpower: iw_param,
    pub rts: iw_param,
    pub frag: iw_param,
    pub mode: uint32_t,
    pub retry: iw_param,
    pub encoding: iw_point,
    pub power: iw_param,
    pub qual: iw_quality,
    pub ap_addr: sockaddr,
    pub addr: sockaddr,
    pub param: iw_param,
    pub data: iw_point,
}
//RR_VERIFY_TYPE(iwreq_data);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iwreq {
    pub ifr_ifrn: ifr_ifrn,
    pub u: iwreq_data,
}
//RR_VERIFY_TYPE(iwreq);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ethtool_cmd {
    pub cmd: uint32_t,
    pub supported: uint32_t,
    pub advertising: uint32_t,
    pub speed: uint16_t,
    pub duplex: uint8_t,
    pub port: uint8_t,
    pub phy_address: uint8_t,
    pub transceiver: uint8_t,
    pub autoneg: uint8_t,
    pub mdio_support: uint8_t,
    pub maxtxpkt: uint32_t,
    pub maxrxpkt: uint32_t,
    pub speed_hi: uint16_t,
    pub eth_tp_mdix: uint8_t,
    pub eth_tp_mdix_ctrl: uint8_t,
    pub lp_advertising: uint32_t,
    pub reserved: [uint32_t; 2],
}
//RR_VERIFY_TYPE(ethtool_cmd);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct _flock {
    pub l_type: signed_short,
    pub l_whence: signed_short,
    pub __pad: [u8; STD_PAD],
    pub l_start: off_t,
    pub l_len: off_t,
    pub l_pid: pid_t,
}
//RR_VERIFY_TYPE_EXPLICIT(struct ::flock, _flock);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct flock64 {
    pub l_type: signed_short,
    pub l_whence: signed_short,
    // @TODO compare with the rr version for padding
    pub __pad: [u8; STD_PAD],
    pub l_start: uint64_t,
    pub l_len: uint64_t,
    pub l_pid: pid_t,
}
//RR_VERIFY_TYPE(flock64);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct f_owner_ex {
    pub type_: signed_int,
    pub pid: __kernel_pid_t,
}
//RR_VERIFY_TYPE(f_owner_ex);

// Define various structures that package up syscall arguments.
// The types of their members are part of the ABI, and defining
// them here makes their definitions more concise.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct accept_args {
    pub sockfd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub addr: ptr<sockaddr>,
    pub addrlen: ptr<socklen_t>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct accept4_args {
    pub sockfd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub addr: ptr<sockaddr>,
    pub addrlen: ptr<socklen_t>,
    pub flags: signed_long,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct getsockname_args {
    pub sockfd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub addr: ptr<sockaddr>,
    pub addrlen: ptr<socklen_t>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct getsockopt_args {
    pub sockfd: signed_int,
    pub level: signed_int,
    pub optname: signed_int,
    pub __pad: [u8; STD_PAD],
    pub optval: ptr<u8>,
    pub optlen: ptr<socklen_t>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct setsockopt_args {
    pub sockfd: signed_long,
    pub level: signed_long,
    pub optname: signed_long,
    pub optval: ptr<u8>,
    pub optlen: signed_long,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct connect_args {
    pub sockfd: signed_long,
    pub addr: ptr<u8>,
    pub addrlen: socklen_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct recv_args {
    pub sockfd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub buf: ptr<u8>,
    pub len: size_t,
    pub flags: signed_int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct recvfrom_args {
    pub sockfd: signed_long,
    pub buf: ptr<u8>,
    pub len: size_t,
    pub flags: signed_long,
    pub src_addr: ptr<sockaddr>,
    pub addrlen: ptr<socklen_t>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct recvmsg_args {
    pub fd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub msg: ptr<msghdr>,
    pub flags: signed_int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct recvmmsg_args {
    pub sockfd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub msgvec: ptr<mmsghdr>,
    pub vlen: unsigned_int,
    pub flags: unsigned_int,
    pub timeout: ptr<timespec>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sendmsg_args {
    pub fd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub msg: ptr<msghdr>,
    pub flags: signed_int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sendmmsg_args {
    pub sockfd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub msgvec: ptr<mmsghdr>,
    pub vlen: unsigned_int,
    pub flags: unsigned_int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct socketpair_args {
    pub domain: signed_int,
    pub type_: signed_int,
    pub protocol: signed_int,
    pub __pad: [u8; STD_PAD],
    pub sv: ptr<signed_int>, // int sv[2]
}

// All architectures have an mmap syscall, but it has architecture-specific
// calling semantics. We describe those here, and specializations need to
// indicate which semantics they use.
enum MmapCallingSemantics {
    /// x86-ish, packaged into mmap_args, below
    StructArguments,
    /// arguments passed in registers, the offset
    /// is assumed to be in bytes, not in pages.
    RegisterArguments,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct mmap_args {
    pub addr: ptr<u8>,
    pub len: size_t,
    pub prot: signed_int,
    pub flags: signed_int,
    pub fd: signed_int,
    pub __pad: [u8; STD_PAD],
    pub offset: off_t,
}

// All architectures have a select syscall, but like mmap, there are two
// different calling styles: one that packages the args into a structure,
// and one that handles the args in registers.  (Architectures using the
// first style, like the x86, sometimes support the register-args version
// as a separate syscall.)
//
// (Yes, we'd like to call these StructArguments and RegisterArguments, but
// that would conflict with MmapCallingSemantics, above.)
enum SelectCallingSemantics {
    SelectStructArguments,
    SelectRegisterArguments,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct fd_set {
    pub fds_bits: [unsigned_long; FD_SET_NUM],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct select_args {
    pub n_fds: signed_int,
    pub __pad: [u8; STD_PAD],
    pub read_fds: ptr<fd_set>,
    pub write_fds: ptr<fd_set>,
    pub except_fds: ptr<fd_set>,
    pub timeout: ptr<timeval>,
}

///  Some ipc calls require 7 params, so two of them are stashed into
///  one of these structs and a pointer to this is passed instead.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ipc_kludge_args {
    pub msgbuf: ptr<u8>,
    pub msgtype: signed_long,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct __sysctl_args {
    pub name: ptr<signed_int>,
    pub nlen: signed_int,
    pub __pad: [u8; STD_PAD],
    pub oldval: ptr<u8>,
    pub oldlenp: ptr<size_t>,
    pub newval: ptr<u8>,
    pub newlen: ptr<size_t>,
    pub __rr_unused: [unsigned_long; 4],
}
//RR_VERIFY_TYPE(__sysctl_args);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct kernel_sigset_t {
    pub __val: [unsigned_long; KERNEL_SIGSET_SIZE],
}

// libc reserves some space in the user facing structures for future
// extensibility.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sigset_t {
    pub __val: [unsigned_long; SIGSET_SIZE],
}
//RR_VERIFY_TYPE(sigset_t);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct pselect6_arg6 {
    pub ss: ptr<kernel_sigset_t>,
    pub ss_len: size_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct kernel_sigaction {
    pub k_sa_handler: ptr<u8>,
    pub sa_flags: unsigned_long,
    pub sa_restorer: ptr<u8>,
    pub sa_mask: kernel_sigset_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct tms {
    pub tms_utime: clock_t,
    pub tms_stime: clock_t,
    pub tms_cutime: clock_t,
    pub tms_cstime: clock_t,
}
//RR_VERIFY_TYPE(tms);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}
//RR_VERIFY_TYPE(rlimit);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct rlimit64 {
    pub rlim_cur: rlim64_t,
    pub rlim_max: rlim64_t,
}
//RR_VERIFY_TYPE(rlimit64);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timezone {
    pub tz_minuteswest: int,
    pub tz_dsttime: int,
}
//RR_VERIFY_TYPE_EXPLICIT(struct ::timezone, timezone);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct f_fsid {
    pub __val: [int; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct statfs {
    pub f_type: __statfs_word,
    pub f_bsize: __statfs_word,
    pub f_blocks: __statfs_word,
    pub f_bfree: __statfs_word,
    pub f_bavail: __statfs_word,
    pub f_files: __statfs_word,
    pub f_ffree: __statfs_word,
    pub f_fsid: f_fsid,
    pub f_namelen: __statfs_word,
    pub f_frsize: __statfs_word,
    pub f_flags: __statfs_word,
    pub f_spare: [__statfs_word; 4],
}
//RR_VERIFY_TYPE_EXPLICIT(struct ::statfs, statfs);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct statfs64 {
    pub f_type: __statfs_word,
    pub f_bsize: __statfs_word,
    pub f_blocks: uint64_t,
    pub f_bfree: uint64_t,
    pub f_bavail: uint64_t,
    pub f_files: uint64_t,
    pub f_ffree: uint64_t,
    pub f_fsid: f_fsid,
    pub f_namelen: __statfs_word,
    pub f_frsize: __statfs_word,
    pub f_flags: __statfs_word,
    pub f_spare: [__statfs_word; 4],
}
//RR_VERIFY_TYPE_EXPLICIT(struct ::statfs64, statfs64);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct itimerval {
    pub it_interval: timeval,
    pub it_value: timeval,
}
//RR_VERIFY_TYPE(itimerval);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct itimerspec {
    pub it_interval: timespec,
    pub it_value: timespec,
}
//RR_VERIFY_TYPE(itimerspec);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sigaltstack {
    pub ss_sp: ptr<u8>,
    pub ss_flags: int,
    pub __pad: [u8; STD_PAD],
    pub ss_size: size_t,
}

pub type stack_t = sigaltstack;
//RR_VERIFY_TYPE(stack_t);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sysinfo {
    pub uptime: __kernel_long_t,
    pub loads: [__kernel_ulong_t; 3],
    pub totalram: __kernel_ulong_t,
    pub freeram: __kernel_ulong_t,
    pub sharedram: __kernel_ulong_t,
    pub bufferram: __kernel_ulong_t,
    pub totalswap: __kernel_ulong_t,
    pub freeswap: __kernel_ulong_t,
    pub procs: uint16_t,
    pub pad: uint16_t,
    pub __pad: [u8; STD_PAD],
    pub totalhigh: __kernel_ulong_t,
    pub freehigh: __kernel_ulong_t,
    pub mem_unit: uint32_t,
    pub _f: [u8; SYSINFO_F_SIZE],
}
//RR_VERIFY_TYPE_EXPLICIT(struct pub ::sysinfo, sysinfo);

pub const UTSNAME_LENGTH: usize = 65;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct utsname {
    pub sysname: [u8; UTSNAME_LENGTH],
    pub nodename: [u8; UTSNAME_LENGTH],
    pub release: [u8; UTSNAME_LENGTH],
    pub version: [u8; UTSNAME_LENGTH],
    pub machine: [u8; UTSNAME_LENGTH],
    pub domainname: [u8; UTSNAME_LENGTH],
}
//RR_VERIFY_TYPE(utsname);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sched_param {
    pub __sched_priority: int,
}
//RR_VERIFY_TYPE(sched_param);

pub const fn cmsg_data_offset() -> usize {
    cmsg_align(size_of::<cmsghdr>())
}

pub const fn cmsg_align(len: usize) -> usize {
    (len + size_of::<size_t>() - 1) & !(size_of::<size_t>() - 1)
}

pub const fn cmsg_space(len: usize) -> usize {
    cmsg_align(size_of::<cmsghdr>()) + cmsg_align(len)
}

pub const fn cmsg_len(len: usize) -> usize {
    cmsg_align(size_of::<cmsghdr>()) + len
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct v4l2_timecode {
    pub type_: uint32_t,
    pub flags: uint32_t,
    pub frames: uint8_t,
    pub seconds: uint8_t,
    pub minutes: uint8_t,
    pub hours: uint8_t,
    pub userbits: [uint8_t; 4],
}
//RR_VERIFY_TYPE(v4l2_timecode);

#[repr(C)]
#[derive(Copy, Clone)]
pub union v4l2_buffer_m {
    pub offset: uint32_t,
    pub userptr: unsigned_long,
    pub planes: ptr<u8>,
    pub fd: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct v4l2_buffer {
    pub index: uint32_t,
    pub type_: uint32_t,
    pub bytesused: uint32_t,
    pub flags: uint32_t,
    pub field: uint32_t,
    pub __pad: [u8; STD_PAD],
    pub timestamp: timeval,
    pub timecode: v4l2_timecode,
    pub sequence: uint32_t,
    pub memory: uint32_t,
    pub m: v4l2_buffer_m,
    pub length: uint32_t,
    pub reserved2: uint32_t,
    pub reserved: uint32_t,
}
//RR_VERIFY_TYPE(v4l2_buffer);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sock_filter {
    pub code: uint16_t,
    pub jt: uint8_t,
    pub jf: uint8_t,
    pub k: uint32_t,
}
//RR_VERIFY_TYPE(sock_filter);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sock_fprog {
    pub len: uint16_t,
    pub _padding: [u8; STD_PAD],
    pub filter: ptr<sock_filter>,
}
//RR_VERIFY_TYPE(sock_fprog);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct robust_list {
    pub next: ptr<robust_list>,
}
//RR_VERIFY_TYPE(robust_list);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct robust_list_head {
    pub list: robust_list,
    pub futex_offset: signed_long,
    pub list_op_pending: ptr<robust_list>,
}
//RR_VERIFY_TYPE(robust_list_head);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct snd_ctl_card_info {
    pub card: int,
    pub pad: int,
    pub id: [u8; 16],
    pub driver: [u8; 16],
    pub name: [u8; 32],
    pub longname: [u8; 80],
    pub reserved_: [u8; 16],
    pub mixername: [u8; 80],
    pub components: [u8; 128],
}
//RR_VERIFY_TYPE(snd_ctl_card_info);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct usbdevfs_iso_packet_desc {
    pub length: unsigned_int,
    pub actual_length: unsigned_int,
    pub status: unsigned_int,
}
//RR_VERIFY_TYPE(usbdevfs_iso_packet_desc);

#[repr(C)]
#[derive(Copy, Clone)]
pub union usbdevfs_urb_u {
    pub number_of_packets: int,
    pub stream_id: unsigned_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_urb {
    pub type_: u8,
    pub endpoint: u8,
    pub status: int,
    pub flags: unsigned_int,
    pub buffer: ptr<u8>,
    pub buffer_length: int,
    pub actual_length: int,
    pub start_frame: int,
    pub usbdevfs_urb_u: usbdevfs_urb_u,
    pub error_count: int,
    pub signr: unsigned_int,
    pub usercontext: ptr<u8>,
    pub iso_frame_desc: [usbdevfs_iso_packet_desc; 0],
}
//RR_VERIFY_TYPE(usbdevfs_urb);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct usbdevfs_ioctl {
    pub ifno: int,
    pub ioctl_code: int,
    pub data: ptr<u8>,
}
//RR_VERIFY_TYPE(usbdevfs_ioctl);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct usbdevfs_ctrltransfer {
    pub bRequestType: uint8_t,
    pub bRequest: uint8_t,
    pub wValue: uint16_t,
    pub wIndex: uint16_t,
    pub wLength: uint16_t,
    pub timeout: uint32_t,
    pub data: ptr<u8>,
}
//RR_VERIFY_TYPE(usbdevfs_ctrltransfer);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dirent {
    pub d_ino: ino_t,
    pub d_off: off_t,
    pub d_reclen: uint16_t,
    //    pub d_type : uint8_t,
    pub d_name: [uint8_t; 256],
}
//RR_VERIFY_TYPE(dirent);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dirent64 {
    pub d_ino: ino64_t,
    pub d_off: off64_t,
    pub d_reclen: uint16_t,
    pub d_type: uint8_t,
    pub d_name: [uint8_t; 256],
}
//RR_VERIFY_TYPE(dirent64);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct mq_attr {
    pub mq_flags: signed_long,
    pub mq_maxmsg: signed_long,
    pub mq_msgsize: signed_long,
    pub mq_curmsgs: signed_long,
    pub __reserved: [signed_long; 4],
}
//RR_VERIFY_TYPE(mq_attr);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct xt_counters {
    pub pcnt: uint64_t,
    pub bcnt: uint64_t,
}
//RR_VERIFY_TYPE(xt_counters);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ipt_replace {
    pub name: [uint8_t; 32],
    pub valid_hook: uint32_t,
    pub num_entries: uint32_t,
    pub size: uint32_t,
    pub hook_entry: [uint32_t; 5],
    pub underflow: [uint32_t; 5],
    pub num_counters: uint32_t,
    pub counters: ptr<xt_counters>,
    // Plus hangoff here
}
// The corresponding header requires -fpermissive, which we don't pass. Skip
// this check.
//RR_VERIFY_TYPE(ipt_replace);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct cap_header {
    pub version: uint32_t,
    pub pid: int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct cap_data {
    pub effective: uint32_t,
    pub permitted: uint32_t,
    pub inheritable: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hci_dev_req {
    pub dev_id: uint16_t,
    pub dev_opt: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hci_dev_list_req {
    pub dev_num: uint16_t,
    pub dev_req: [hci_dev_req; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct bdaddr_t {
    b: [uint8_t; 6],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hci_dev_stats {
    pub err_rx: uint32_t,
    pub err_tx: uint32_t,
    pub cmd_tx: uint32_t,
    pub evt_rx: uint32_t,
    pub acl_tx: uint32_t,
    pub acl_rx: uint32_t,
    pub sco_tx: uint32_t,
    pub sco_rx: uint32_t,
    pub byte_rx: uint32_t,
    pub byte_tx: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hci_dev_info {
    pub dev_id: uint16_t,
    pub name: [u8; 8],

    pub bdaddr: bdaddr_t,

    pub flags: uint32_t,
    pub type_: uint8_t,

    pub features: [uint8_t; 8],

    pub pkt_type: uint32_t,
    pub link_policy: uint32_t,
    pub link_mode: uint32_t,

    pub acl_mtu: uint16_t,
    pub acl_pkts: uint16_t,
    pub sco_mtu: uint16_t,
    pub sco_pkts: uint16_t,

    pub stat: hci_dev_stats,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ifbond {
    pub bond_mode: int32_t,
    pub num_slaves: int32_t,
    pub miimon: int32_t,
}
//RR_VERIFY_TYPE(ifbond);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timex {
    pub modes: unsigned_int,
    pub offset: __kernel_long_t,
    pub freq: __kernel_long_t,
    pub maxerror: __kernel_long_t,
    pub esterror: __kernel_long_t,
    pub status: int,
    pub constant: __kernel_long_t,
    pub precision: __kernel_long_t,
    pub tolerance: __kernel_long_t,
    pub time: timeval,
    pub tick: __kernel_long_t,
    pub ppsfreq: __kernel_long_t,
    pub jitter: __kernel_long_t,
    pub shift: int,
    pub stabil: __kernel_long_t,
    pub jitcnt: __kernel_long_t,
    pub calcnt: __kernel_long_t,
    pub errcnt: __kernel_long_t,
    pub stbcnt: __kernel_long_t,
    pub tai: int,

    // Further padding bytes to allow for future expansion.
    pub i_1: u32,
    pub i_2: u32,
    pub i_3: u32,
    pub i_4: u32,
    pub i_5: u32,
    pub i_6: u32,
    pub i_7: u32,
    pub i_8: u32,
    pub i_9: u32,
    pub i_10: u32,
    pub i_11: u32,
}

//RR_VERIFY_TYPE(timex);

pub struct statx_timestamp {
    pub tv_sec: int64_t,
    pub tv_nsec: uint32_t,
    pub __reserved: int32_t,
}
// statx_timestamp not yet widely available in system headers
//RR_VERIFY_TYPE(statx_timestamp);

pub struct statx {
    pub stx_mask: uint32_t,
    pub stx_blksize: uint32_t,
    pub stx_attributes: uint64_t,
    pub stx_nlink: uint32_t,
    pub stx_uid: uint32_t,
    pub stx_gid: uint32_t,
    pub stx_mode: uint16_t,
    pub __spare0: uint16_t,
    pub stx_ino: uint64_t,
    pub stx_size: uint64_t,
    pub stx_blocks: uint64_t,
    pub stx_attributes_mask: uint64_t,
    pub stx_atime: statx_timestamp,
    pub stx_btime: statx_timestamp,
    pub stx_ctime: statx_timestamp,
    pub stx_mtime: statx_timestamp,
    pub stx_rdev_major: uint32_t,
    pub stx_rdev_minor: uint32_t,
    pub stx_dev_major: uint32_t,
    pub stx_dev_minor: uint32_t,
    pub __spare2: [uint64_t; 14],
}
// statx not yet widely available in system headers
//RR_VERIFY_TYPE(statx);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sg_io_hdr {
    pub interface_id: int,
    pub dxfer_direction: int,
    pub cmd_len: u8,
    pub mx_sb_len: u8,
    pub iovec_count: unsigned_short,
    pub dxfer_len: unsigned_int,
    pub dxferp: ptr<u8>,
    pub cmdp: ptr<u8>,
    pub sbp: ptr<u8>,
    pub timeout: unsigned_int,
    pub flags: unsigned_int,
    pub pack_id: int,
    pub usr_ptr: ptr<u8>,
    pub status: u8,
    pub masked_status: u8,
    pub msg_status: u8,
    pub sb_len_wr: u8,
    pub host_status: unsigned_short,
    pub driver_status: unsigned_short,
    pub resid: int,
    pub duration: unsigned_int,
    pub info: unsigned_int,
}
//RR_VERIFY_TYPE(sg_io_hdr);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct bpf_attr_u1 {
    pub map_type: __u32,
    pub key_size: __u32,
    pub value_size: __u32,
    pub max_entries: __u32,
    pub map_flags: __u32,
    pub inner_map_fd: __u32,
    pub numa_node: __u32,
    pub map_name: [u8; 16],
    pub map_ifindex: __u32,
    pub btf_fd: __u32,
    pub btf_key_type_id: __u32,
    pub btf_value_type_id: __u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr_u2_u1 {
    pub value: ptr64<u8>,
    pub next_key: ptr64<u8>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr_u2 {
    pub map_fd: __u32,
    pub key: ptr64<u8>,
    pub bpf_attr_u2_u1: bpf_attr_u2_u1,
    pub flags: __u64,
}

#[repr(C, align(8))]
#[derive(Copy, Clone, Default)]
pub struct aligned_u64 {
    pub __val: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct bpf_attr_u3 {
    pub prog_type: __u32,
    pub insn_cnt: __u32,
    pub insns: ptr64<u8>,
    pub license: ptr64<u8>,
    pub log_level: __u32,
    pub log_size: __u32,
    pub log_buf: ptr64<char>,
    pub kern_version: __u32,
    pub prog_flags: __u32,
    pub prog_name: [u8; 16],
    pub prog_ifindex: __u32,
    pub expected_attach_type: __u32,
    pub prog_btf_fd: __u32,
    pub func_info_rec_size: __u32,
    pub func_info: aligned_u64,
    pub func_info_cnt: __u32,
    pub line_info_rec_size: __u32,
    pub line_info: aligned_u64,
    pub line_info_cnt: __u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr {
    pub bpf_attr_u1: bpf_attr_u1,
    pub bpf_attr_u2: bpf_attr_u2,
    pub bpf_attr_u3: bpf_attr_u3,
}
