pub mod gdb_server {
    use crate::trace::trace_frame::FrameTime;
    use libc::pid_t;

    #[derive(Clone)]
    pub struct Target {
        /// Target process to debug, or `None` to just debug the first process
        pub pid: Option<pid_t>,
        /// If true, wait for the target process to exec() before attaching debugger
        pub require_exec: bool,
        /// Wait until at least 'event' has elapsed before attaching
        pub event: FrameTime,
    }

    impl Target {
        pub fn new() -> Self {
            Self {
                pid: None,
                require_exec: false,
                event: 0,
            }
        }
    }

    impl Default for Target {
        fn default() -> Target {
            Target::new()
        }
    }
}
