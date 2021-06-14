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

pub const STD_PAD: usize = size_of::<unsigned_long>() - size_of::<int>();
pub const KERNEL_SIGSET_SIZE: usize = 64 / (8 * size_of::<unsigned_long>());
pub const SIGSET_SIZE: usize = 1024 / (8 * size_of::<unsigned_long>());
pub const MAX_FDS: usize = 1024;
pub const FD_SET_NUM: usize = MAX_FDS / (8 * size_of::<unsigned_long>());
pub const SYSINFO_F_SIZE: usize = 20 - 2 * size_of::<__kernel_ulong_t>() - size_of::<uint32_t>();

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_un {
    pub sun_family: unsigned_short,
    pub sun_path: [u8; 108],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timeval {
    pub tv_sec: __kernel_time_t,
    pub tv_usec: __kernel_suseconds_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timespec {
    pub tv_sec: __kernel_time_t,
    pub tv_nsec: syscall_slong_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct pollfd {
    pub fd: signed_int,
    pub events: signed_short,
    pub revents: signed_short,
}

#[repr(C)]
pub union epoll_data {
    pub ptr_: ptr<u8>,
    pub fd: i32,
    pub data_u32: u32,
    pub data_u64: u64,
}

/// @TODO Check this in x86
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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct winsize {
    pub ws_row: unsigned_short,
    pub ws_col: unsigned_short,
    pub ws_xpixel: unsigned_short,
    pub ws_ypixel: unsigned_short,
}

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct user_desc {
    pub entry_number: unsigned_int,
    pub base_addr: unsigned_int,
    pub limit: unsigned_int,
    /// There are bitfields here
    /// Just made it an unsigned int
    pub data: unsigned_int,
}

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct dqinfo {
    pub dqi_bgrace: uint64_t,
    pub dqi_igrace: uint64_t,
    pub dqi_flags: uint32_t,
    pub dqi_valid: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_param {
    pub value: int32_t,
    pub fixed: uint8_t,
    pub disabled: uint8_t,
    pub flags: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_point {
    pub pointer: ptr<u8>,
    pub length: uint16_t,
    pub flags: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iw_quality {
    pub qual: uint8_t,
    pub level: uint8_t,
    pub noise: uint8_t,
    pub updated: uint8_t,
}

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct f_owner_ex {
    pub type_: signed_int,
    pub pid: __kernel_pid_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct fd_set {
    pub fds_bits: [unsigned_long; FD_SET_NUM],
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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct tms {
    pub tms_utime: clock_t,
    pub tms_stime: clock_t,
    pub tms_cutime: clock_t,
    pub tms_cstime: clock_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct rlimit64 {
    pub rlim_cur: rlim64_t,
    pub rlim_max: rlim64_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct timezone {
    pub tz_minuteswest: int,
    pub tz_dsttime: int,
}

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct itimerval {
    pub it_interval: timeval,
    pub it_value: timeval,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct itimerspec {
    pub it_interval: timespec,
    pub it_value: timespec,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sigaltstack {
    pub ss_sp: ptr<u8>,
    pub ss_flags: int,
    pub __pad: [u8; STD_PAD],
    pub ss_size: size_t,
}

pub type stack_t = sigaltstack;

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sched_param {
    pub __sched_priority: int,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sock_filter {
    pub code: uint16_t,
    pub jt: uint8_t,
    pub jf: uint8_t,
    pub k: uint32_t,
}

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dirent {
    pub d_ino: ino_t,
    pub d_off: off_t,
    pub d_reclen: uint16_t,
    pub d_type: uint8_t,
    pub d_name: [uint8_t; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dirent64 {
    pub d_ino: ino64_t,
    pub d_off: off64_t,
    pub d_reclen: uint16_t,
    pub d_type: uint8_t,
    pub d_name: [uint8_t; 256],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct mq_attr {
    pub mq_flags: signed_long,
    pub mq_maxmsg: signed_long,
    pub mq_msgsize: signed_long,
    pub mq_curmsgs: signed_long,
    pub __reserved: [signed_long; 4],
}

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct statx_timestamp {
    pub tv_sec: int64_t,
    pub tv_nsec: uint32_t,
    pub __reserved: int32_t,
}
// statx_timestamp not yet widely available in system headers

#[repr(C)]
#[derive(Copy, Clone, Default)]
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

#[repr(C, align(8))]
#[derive(Copy, Clone, Default)]
pub struct aligned_u64 {
    pub __val: u64,
}
