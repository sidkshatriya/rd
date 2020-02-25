/// rd tracees can write data to this special fd that they want
/// verified across record/replay.  When it's written in recording, rr
/// saves the data.  During replay, the data are checked against the
/// recorded data.
///
/// Tracees using this interface should take care that the buffers
/// storing the data are either not racy, or are synchronized by the
/// tracee.
///
/// To simplify things, we make this a valid fd opened to /dev/null during
/// recording.
///
/// Tracees may close this fd, or dup() something over it, etc. If that happens,
/// it will lose its magical properties.
pub const RD_MAGIC_SAVE_DATA_FD: i32 = 999;

/// rd uses this fd to ensure the tracee has access to the original root
/// directory after a chroot(). Tracee close()es of this fd will be silently
/// ignored, and tracee dup()s to this fd will fail with EBADF.
/// This is set up during both recording and replay.
pub const RD_RESERVED_ROOT_DIR_FD: i32 = 1000;

/// Tracees use this fd to send other fds to rr.
/// This is only set up during recording.
/// Only the outermost rd uses this. Inner rd replays will use a different fd.
pub const RD_RESERVED_SOCKET_FD: i32 = 1001;

/// The preferred fd that rd uses to control tracee desched. Some software
/// (e.g. the chromium IPC code) wants to have the first few fds all to itself,
/// so we need to stay above some floor. Tracee close()es of the fd that is
/// actually assigned will be silently ignored, and tracee dup()s to that fd will
/// fail with EBADF.
pub const RD_DESCHED_EVENT_FLOOR_FD: i32 = 100;
