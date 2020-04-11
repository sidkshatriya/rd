use crate::scoped_fd::ScopedFd;
use crate::util::write_all;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use std::cmp::min;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::io::{Result, Write};
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::{slice, thread};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Sync {
    DontSync,
    Sync,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum WaitFlag {
    Wait,
    NoWait,
}

#[derive(Copy, Clone, Default)]
pub struct BlockHeader {
    pub compressed_length: u32,
    pub uncompressed_length: u32,
}

/// CompressedWriter opens an output file and writes compressed blocks to it.
/// Blocks of a fixed but unspecified size (currently 1MB) are compressed.
/// Each block of compressed data is written to the file preceded by two
/// 32-bit words: the size of the compressed data (excluding block header)
/// and the size of the uncompressed data, in that order. See BlockHeader below.
///
/// We use multiple threads to perform compression. The threads are
/// responsible for the actual data writes. The thread that creates the
/// CompressedWriter is the "producer" thread and must also be the caller of
/// 'write'. The producer thread may block in 'write' if 'buffer_size' bytes are
/// being compressed.
///
/// Each data block is compressed independently using brotli.
pub struct CompressedWriter {
    /// Immutable while threads are running
    fd: ScopedFd,
    block_size: usize,
    mutex: Arc<Mutex<CompressedWriterData>>,
    cond_var: Arc<Condvar>,
    threads: Vec<JoinHandle<()>>,
    producer_reserved_pos: u64,
    producer_reserved_write_pos: u64,
    producer_reserved_upto_pos: u64,
    error: bool,

    /// Carefully shared...
    buffer: Vec<u8>,
}

pub struct CompressedWriterData {
    /// position in output stream that this thread is currently working on,
    ///  `None` if it's idle
    thread_pos: Vec<Option<u64>>,
    /// position in output stream of data to dispatch to next thread
    next_thread_pos: u64,
    /// position in output stream of end of data ready to dispatch
    next_thread_end_pos: u64,
    closing: bool,
    write_error: bool,
    /// DIFF NOTE: This bool is not present in rr
    proceed: bool,
}

struct SharedBuf(*mut u8, usize);

unsafe impl Send for SharedBuf {}

impl CompressedWriter {
    pub fn good(&self) -> bool {
        unimplemented!()
    }
    pub fn new(filename: &OsStr, block_size: usize, num_threads: usize) -> CompressedWriter {
        let fd = ScopedFd::open_path_with_mode(
            filename,
            OFlag::O_CLOEXEC
                | OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_LARGEFILE,
            // @TODO Check this
            Mode::S_IXUSR,
        );
        let mut buffer: Vec<u8> = Vec::with_capacity(block_size * (num_threads + 2));
        buffer.resize(block_size * (num_threads + 2), 0);

        let mut thread_pos: Vec<Option<u64>> = Vec::with_capacity(num_threads);
        for i in 0..num_threads {
            thread_pos[i] = None;
        }

        let next_thread_pos: u64 = 0;
        let next_thread_end_pos: u64 = 0;
        let closing = false;
        let write_error = false;

        let producer_reserved_pos: u64 = 0;
        let producer_reserved_write_pos: u64 = 0;
        let producer_reserved_upto_pos: u64 = 0;
        let mut error = false;
        if !fd.is_open() {
            error = true;
        }

        let mut cw = CompressedWriter {
            fd,
            block_size,
            mutex: Arc::new(Mutex::new(CompressedWriterData {
                thread_pos,
                next_thread_pos,
                next_thread_end_pos,
                closing,
                write_error,
                proceed: false,
            })),
            cond_var: Arc::new(Condvar::new()),
            threads: Vec::new(),
            producer_reserved_pos,
            producer_reserved_write_pos,
            producer_reserved_upto_pos,
            error,
            buffer,
        };

        if error {
            return cw;
        }

        // Hold the lock so threads don't inspect the 'threads' array
        // until we've finished initializing it.
        {
            let mg = cw.mutex.lock().unwrap();
            for i in 0..num_threads {
                let mutex = cw.mutex.clone();
                let cond_var = cw.cond_var.clone();
                let shared_buffer = SharedBuf(cw.buffer.as_mut_ptr(), cw.buffer.len());
                let fd_raw = cw.fd.as_raw();
                cw.threads.push(
                    thread::Builder::new()
                        .name("@TODO".into())
                        .spawn(move || {
                            let mut g = mutex.lock().unwrap();
                            let thread_index = i;
                            // let current = thread::current();
                            let buffer =
                                unsafe { slice::from_raw_parts(shared_buffer.0, shared_buffer.1) };
                            let block_size = block_size;
                            let cond_var = cond_var;
                            // Add slop for incompressible data
                            let mut outputbuf = Vec::<u8>::new();
                            outputbuf.resize(
                                ((block_size as f64 * 1.1) as usize) + size_of::<BlockHeader>(),
                                0u8,
                            );
                            let mut header: BlockHeader = Default::default();

                            loop {
                                if !g.write_error
                                    && g.next_thread_pos < g.next_thread_end_pos
                                    && (g.closing
                                        || g.next_thread_pos + block_size as u64
                                            <= next_thread_end_pos)
                                {
                                    g.thread_pos[thread_index] = Some(g.next_thread_pos);
                                    g.next_thread_pos = min(
                                        next_thread_end_pos,
                                        next_thread_pos + block_size as u64,
                                    );
                                    // header.uncompressed_length must be <= block_size,
                                    // therefore fits in a size_t.
                                    header.uncompressed_length = (g.next_thread_pos
                                        - g.thread_pos[thread_index].unwrap())
                                    .try_into()
                                    .unwrap();

                                    let offset_in_input_buf = g.thread_pos[thread_index].unwrap();
                                    drop(g);
                                    let maybe_compressed_length: Option<u32> = do_compress(
                                        buffer,
                                        offset_in_input_buf,
                                        header.uncompressed_length as usize,
                                        &mut outputbuf[size_of::<BlockHeader>()..],
                                    );
                                    g = mutex.lock().unwrap();

                                    if maybe_compressed_length.is_none() {
                                        g.write_error = true;
                                    } else {
                                        header.compressed_length = maybe_compressed_length.unwrap()
                                    }

                                    unsafe {
                                        copy_nonoverlapping(
                                            &header as *const _ as *const u8,
                                            outputbuf.as_mut_ptr(),
                                            size_of::<BlockHeader>(),
                                        );
                                    }

                                    // wait until we're the next thread that needs to write
                                    while !g.write_error {
                                        let mut other_thread_write_first = false;
                                        for i in 0..g.thread_pos.len() {
                                            if g.thread_pos[i].is_some()
                                                && g.thread_pos[i].unwrap()
                                                    < g.thread_pos[thread_index].unwrap()
                                            {
                                                other_thread_write_first = true;
                                            }
                                        }
                                        if !other_thread_write_first {
                                            break;
                                        }
                                        while !g.proceed {
                                            g = cond_var.wait(g).unwrap();
                                        }
                                        g.proceed = false;
                                    }

                                    if !g.write_error {
                                        drop(g);
                                        write_all(
                                            fd_raw,
                                            &outputbuf[0..size_of::<BlockHeader>()
                                                + header.compressed_length as usize],
                                        );
                                        g = mutex.lock().unwrap();
                                    }

                                    g.thread_pos[thread_index] = None;
                                    // do a broadcast because we might need to unblock
                                    // the producer thread or a compressor thread waiting
                                    // for us to write.
                                    g.proceed = true;
                                    cond_var.notify_one();
                                    continue;
                                }

                                if g.closing
                                    && (g.write_error || g.next_thread_pos == g.next_thread_end_pos)
                                {
                                    break;
                                }

                                while !g.proceed {
                                    g = cond_var.wait(g).unwrap();
                                }
                                g.proceed = false;
                            }
                        })
                        .unwrap(),
                );
            }
        }

        cw
    }
    pub fn close(self, maybe_sync: Option<Sync>) {
        let sync = maybe_sync.unwrap_or(Sync::DontSync);
        for handle in self.threads {
            handle.join().unwrap();
        }
        unimplemented!()
    }
}

impl Write for CompressedWriter {
    fn write(&mut self, _buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<()> {
        unimplemented!()
    }
}

fn do_compress(
    _input_buf: &[u8],
    _offset_in_input_buf: u64,
    _uncompressed_len: usize,
    _output_buf: &mut [u8],
) -> Option<u32> {
    unimplemented!()
}
