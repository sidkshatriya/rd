use crate::{
    bindings::ptrace::PTRACE_DETACH,
    kernel_abi::syscall_number_for_exit,
    log::LogDebug,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::RemotePtr,
    session::{task::task_inner::PtraceData, Session},
    taskish_uid::{AddressSpaceUid, ThreadGroupUid},
    util::is_zombie_process,
};
use libc::{syscall, SYS_tgkill, ESRCH, SIGKILL};
use nix::errno::errno;

/// Forwarded method definition
///
pub(super) fn kill_all_tasks<S: Session>(sess: &S) {
    for (_, t) in sess.task_map.borrow().iter() {
        if !t.is_stopped {
            // During recording we might be aborting the recording, in which case
            // one or more tasks might not be stopped. We haven't got any really
            // good options here so we'll just skip detaching and try killing
            // it with SIGKILL below. rr will usually exit immediately after this
            // so the likelihood that we'll leak a zombie task isn't too bad.
            continue;
        }

        // Prepare to forcibly kill this task by detaching it first. To ensure
        // the task doesn't continue executing, we first set its ip() to an
        // invalid value. We need to do this for all tasks in the Session before
        // kill() is guaranteed to work properly. SIGKILL on ptrace-attached tasks
        // seems to not work very well, and after sending SIGKILL we can't seem to
        // reliably detach.
        log!(LogDebug, "safely detaching from {} ...", t.tid());
        // Detaching from the process lets it continue. We don't want a replaying
        // process to perform syscalls or do anything else observable before we
        // get around to SIGKILLing it. So we move its ip() to an address
        // which will cause it to do an exit() syscall if it runs at all.
        // We used to set this to an invalid address, but that causes a SIGSEGV
        // to be raised which can cause core dumps after we detach from ptrace.
        // Making the process undumpable with PR_SET_DUMPABLE turned out not to
        // be practical because that has a side effect of triggering various
        // security measures blocking inspection of the process (PTRACE_ATTACH,
        // access to /proc/<pid>/fd).
        // Disabling dumps via setrlimit(RLIMIT_CORE, 0) doesn't stop dumps
        // if /proc/sys/kernel/core_pattern is set to pipe the core to a process
        // (e.g. to systemd-coredump).
        // We also tried setting ip() to an address that does an infinite loop,
        // but that leaves a runaway process if something happens to kill rd
        // after detaching but before we get a chance to SIGKILL the tracee.
        let mut r = t.regs_ref().clone();

        // @TODO The privileged_traced_syscall_ip may not have been set yet
        // so the best we can do here is set it to ip 0x0. Need to see what
        // problems if any this may create in practice.
        r.set_ip(
            t.vm()
                .privileged_traced_syscall_ip()
                .unwrap_or(RemoteCodePtr::null()),
        );
        r.set_syscallno(syscall_number_for_exit(r.arch()) as isize);
        r.set_arg1(0);
        t.set_regs(&r);
        t.flush_regs();
        let mut result: isize;
        loop {
            // We have observed this failing with an ESRCH when the thread clearly
            // still exists and is ptraced. Retrying the PTRACE_DETACH seems to
            // work around it.
            result = t.fallible_ptrace(PTRACE_DETACH, RemotePtr::null(), &mut PtraceData::None);
            ed_assert!(&**t, result >= 0 || errno() == ESRCH);
            // But we it might get ESRCH because it really doesn't exist.
            if errno() == ESRCH && is_zombie_process(t.tid()) {
                break;
            }

            if result >= 0 {
                break;
            }
        }
    }

    while !sess.task_map.borrow().is_empty() {
        let (_, t) = sess.task_map.borrow_mut().pop_last().unwrap();
        if !t.unstable.get() {
            // Destroy the OS task backing this by sending it SIGKILL and
            // ensuring it was delivered.  After `kill()`, the only
            // meaningful thing that can be done with this task is to
            // delete it.
            log!(LogDebug, "sending SIGKILL to {} ...", t.tid());
            // If we haven't already done a stable exit via syscall,
            // kill the task and note that the entire thread group is unstable.
            // The task may already have exited due to the preparation above,
            // so we might accidentally shoot down the wrong task :-(, but we
            // have to do this because the task might be in a state where it's not
            // going to run and exit by itself.
            // Linux doesn't seem to give us a reliable way to detach and kill
            // the tracee without races.
            unsafe {
                syscall(SYS_tgkill, t.real_tgid(), t.tid(), SIGKILL);
            }
            t.thread_group_shr_ptr().borrow().destabilize();
        }
        // NOTE: It is NOT necessary to call destroy() on the task here.
    }

    // Manually clean up the vm map and thread group map
    // We have to do this ourselves because the session is probably
    // getting drop()-ed and the thread group and address spaces would
    // not have been able to reach out to session and do this themselves.
    // (search for try_session() method in code base for more info)
    let vm_uids: Vec<AddressSpaceUid> = sess.vm_map().keys().map(|k| *k).collect();
    for vm_uid in vm_uids {
        sess.on_destroy_vm(vm_uid);
    }

    let tg_uids: Vec<ThreadGroupUid> = sess.thread_group_map().keys().map(|k| *k).collect();
    for tg_uid in tg_uids {
        sess.on_destroy_tg(tg_uid);
    }
}
