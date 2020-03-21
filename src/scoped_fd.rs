use nix::fcntl::open;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::close;
use nix::NixPath;
use std::cell::RefCell;
use std::os::unix::io::RawFd;
use std::rc::Rc;

pub type ScopedFdSharedPtr = Rc<RefCell<ScopedFd>>;

// We DON'T want this to be Copy or Clone because of the Drop.
pub struct ScopedFd {
    fd: RawFd,
}

impl ScopedFd {
    pub fn new() -> Self {
        ScopedFd { fd: -1 }
    }

    pub fn from_raw(fd: RawFd) -> Self {
        ScopedFd { fd: fd }
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
            close(self.fd);
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
