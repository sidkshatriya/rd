use std::{
    error::Error,
    process::{ExitCode, Termination},
};

use crate::flags::Flags;

pub enum ExitResult<T: Termination> {
    Ok(T),
    Err(Box<dyn Error>, u8),
}

impl<T: Termination> ExitResult<T> {
    pub fn err_from<E: Error + 'static>(e: E, code: u8) -> ExitResult<T> {
        ExitResult::Err(Box::new(e), code)
    }
}

impl<T: Termination> Termination for ExitResult<T> {
    fn report(self) -> ExitCode {
        match self {
            ExitResult::Ok(t) => t.report(),
            ExitResult::Err(b, c) => {
                if !Flags::get().extra_compat {
                    eprintln!("Error: {:?}", b);
                }
                c.into()
            }
        }
    }
}
