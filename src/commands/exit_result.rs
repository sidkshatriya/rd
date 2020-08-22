use std::{error::Error, process::Termination};

pub enum ExitResult<T: Termination> {
    Ok(T),
    Err(Box<dyn Error>, i32),
}

impl<T: Termination> ExitResult<T> {
    pub fn err_from<E: Error + 'static>(e: E, code: i32) -> ExitResult<T> {
        ExitResult::Err(Box::new(e), code)
    }
}

impl<T: Termination> Termination for ExitResult<T> {
    fn report(self) -> i32 {
        match self {
            ExitResult::Ok(t) => t.report(),
            ExitResult::Err(b, c) => {
                eprintln!("Error: {:?}", b);
                c
            }
        }
    }
}
