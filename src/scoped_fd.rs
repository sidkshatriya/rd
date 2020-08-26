use nix::{
    fcntl::{open, OFlag},
    sys::stat::Mode,
    unistd::close,
    NixPath,
};
use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    os::unix::io::RawFd,
    rc::Rc,
};

pub type ScopedFdSharedPtr = Rc<RefCell<ScopedFd>>;

// We DON'T want this to be Copy or Clone because of the Drop.
pub struct ScopedFd {
    fd: RawFd,
}

impl Default for ScopedFd {
    fn default() -> Self {
        Self::new()
    }
}

impl ScopedFd {
    pub fn new() -> Self {
        ScopedFd { fd: -1 }
    }

    pub fn from_raw(fd: RawFd) -> Self {
        ScopedFd { fd }
    }

    pub fn open_path<P: ?Sized + NixPath>(path: &P, oflag: OFlag) -> Self {
        let rawfd = open(path, oflag, Mode::empty()).unwrap_or(-1);
        ScopedFd { fd: rawfd }
    }

    pub fn open_path_with_mode<P: ?Sized + NixPath>(path: &P, oflag: OFlag, mode: Mode) -> Self {
        let rawfd = open(path, oflag, mode).unwrap_or(-1);
        ScopedFd { fd: rawfd }
    }

    pub fn close(&mut self) {
        if self.fd >= 0 {
            // We swallow any error on close
            close(self.fd).unwrap_or(());
        }

        self.fd = -1;
    }

    pub fn is_open(&self) -> bool {
        self.fd >= 0
    }

    pub fn as_raw(&self) -> RawFd {
        self.fd
    }

    pub fn extract(&mut self) -> RawFd {
        let result = self.fd;
        self.fd = -1;
        result
    }

    pub fn unwrap(&self) -> RawFd {
        if self.fd < 0 {
            panic!("fd is closed");
        } else {
            self.fd
        }
    }
}

impl Drop for ScopedFd {
    fn drop(&mut self) {
        self.close()
    }
}

impl Display for ScopedFd {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fd)
    }
}
