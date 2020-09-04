use crate::kernel_metadata::signal_name;
use fmt::Formatter;
use io::ErrorKind;
use nix::sys::signal::Signal;
use std::{convert::TryFrom, fmt, fmt::Display, io};

pub const SIGHUP: Sig = Sig(libc::SIGHUP);
pub const SIGINT: Sig = Sig(libc::SIGINT);
pub const SIGQUIT: Sig = Sig(libc::SIGQUIT);
pub const SIGILL: Sig = Sig(libc::SIGILL);
pub const SIGTRAP: Sig = Sig(libc::SIGTRAP);
pub const SIGABRT: Sig = Sig(libc::SIGABRT); // libc::SIGIOT,
pub const SIGBUS: Sig = Sig(libc::SIGBUS);
pub const SIGFPE: Sig = Sig(libc::SIGFPE);
pub const SIGKILL: Sig = Sig(libc::SIGKILL);
pub const SIGUSR1: Sig = Sig(libc::SIGUSR1);
pub const SIGSEGV: Sig = Sig(libc::SIGSEGV);
pub const SIGUSR2: Sig = Sig(libc::SIGUSR2);
pub const SIGPIPE: Sig = Sig(libc::SIGPIPE);
pub const SIGALRM: Sig = Sig(libc::SIGALRM);
pub const SIGTERM: Sig = Sig(libc::SIGTERM);
pub const SIGSTKFLT: Sig = Sig(libc::SIGSTKFLT); // libc::SIGCLD".into()
pub const SIGCHLD: Sig = Sig(libc::SIGCHLD);
pub const SIGCONT: Sig = Sig(libc::SIGCONT);
pub const SIGSTOP: Sig = Sig(libc::SIGSTOP);
pub const SIGTSTP: Sig = Sig(libc::SIGTSTP);
pub const SIGTTIN: Sig = Sig(libc::SIGTTIN);
pub const SIGTTOU: Sig = Sig(libc::SIGTTOU);
pub const SIGURG: Sig = Sig(libc::SIGURG);
pub const SIGXCPU: Sig = Sig(libc::SIGXCPU);
pub const SIGXFSZ: Sig = Sig(libc::SIGXFSZ);
pub const SIGVTALRM: Sig = Sig(libc::SIGVTALRM);
pub const SIGPROF: Sig = Sig(libc::SIGPROF);
pub const SIGWINCH: Sig = Sig(libc::SIGWINCH); // libc::SIGPOLL
pub const SIGIO: Sig = Sig(libc::SIGIO);
pub const SIGPWR: Sig = Sig(libc::SIGPWR);
pub const SIGSYS: Sig = Sig(libc::SIGSYS);

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Sig(i32);

impl Sig {
    pub fn as_str(&self) -> String {
        signal_name(self.0)
    }

    pub fn as_raw(self) -> i32 {
        self.0
    }

    pub unsafe fn from_raw_unchecked(sig: i32) -> Self {
        Self(sig)
    }

    /// Nix can't deal with realtime signals as of writing this so this
    /// method could fatally fail.
    pub fn as_nix_signal(&self) -> Signal {
        match Signal::try_from(self.0) {
            Ok(s) => s,
            Err(e) => fatal!("Could not convert `{}` to nix signal: {:?}", self.0, e),
        }
    }
}

impl TryFrom<i32> for Sig {
    type Error = io::Error;

    fn try_from(sig: i32) -> Result<Self, Self::Error> {
        if sig > 0 && sig < 0x80 {
            Ok(Sig(sig))
        } else {
            Err(io::Error::new(
                ErrorKind::Other,
                format!("Invalid signal `{}`", sig),
            ))
        }
    }
}

impl Display for Sig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
