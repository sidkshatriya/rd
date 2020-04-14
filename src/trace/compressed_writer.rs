use crate::scoped_fd::ScopedFd;
use crate::util::write_all;
use brotli_sys::{
    BrotliEncoderCompressStream, BrotliEncoderCreateInstance, BrotliEncoderDestroyInstance,
    BrotliEncoderSetParameter, BROTLI_OPERATION_FINISH, BROTLI_OPERATION_PROCESS,
    BROTLI_PARAM_QUALITY,
};
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::fsync;
use std::cmp::min;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::io::{Error, ErrorKind, Result, Write};
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::{ptr, slice, thread};

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

impl Drop for CompressedWriter {
    fn drop(&mut self) {
        self.close(None);
    }
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
}

struct SharedBuf(*mut u8, usize);

unsafe impl Send for SharedBuf {}

impl CompressedWriter {
    pub fn good(&self) -> bool {
        self.error
    }
    pub fn new(filename: &OsStr, block_size: usize, num_threads: usize) -> CompressedWriter {
        let fd = ScopedFd::open_path_with_mode(
            filename,
            OFlag::O_CLOEXEC
                | OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_LARGEFILE,
            Mode::S_IRUSR,
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
            let _mg = cw.mutex.lock().unwrap();
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
                                    let compressed_length: usize = unsafe {
                                        do_compress(
                                            buffer,
                                            offset_in_input_buf,
                                            header.uncompressed_length as usize,
                                            &mut outputbuf[size_of::<BlockHeader>()..],
                                        )
                                    };
                                    g = mutex.lock().unwrap();

                                    if 0 == compressed_length {
                                        g.write_error = true;
                                    } else {
                                        header.compressed_length = compressed_length as u32;
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
                                        g = cond_var.wait(g).unwrap();
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
                                    cond_var.notify_one();
                                    continue;
                                }

                                if g.closing
                                    && (g.write_error || g.next_thread_pos == g.next_thread_end_pos)
                                {
                                    break;
                                }

                                g = cond_var.wait(g).unwrap();
                            }
                        })
                        .unwrap(),
                );
            }
        }

        cw
    }
    pub fn close(&mut self, maybe_sync: Option<Sync>) {
        if !self.fd.is_open() {
            return;
        }

        let sync = maybe_sync.unwrap_or(Sync::DontSync);

        self.update_reservation(WaitFlag::NoWait);

        let mut g = self.mutex.lock().unwrap();
        g.closing = true;
        self.cond_var.notify_all();
        drop(g);

        while let Some(handle) = self.threads.pop() {
            handle.join().unwrap();
        }

        if sync == Sync::Sync {
            if fsync(self.fd.as_raw()).is_err() {
                self.error = true;
            }
        }

        g = self.mutex.lock().unwrap();
        if g.write_error {
            self.error = true;
        }

        self.fd.close();
    }

    pub fn update_reservation(&mut self, wait_flag: WaitFlag) {
        let mut g = self.mutex.lock().unwrap();

        g.next_thread_end_pos = self.producer_reserved_write_pos;
        self.producer_reserved_pos = self.producer_reserved_write_pos;
        // Wake up threads that might be waiting to consume data.
        self.cond_var.notify_all();

        while !self.error {
            if g.write_error {
                self.error = true;
                break;
            }

            let mut completed_pos: u64 = g.next_thread_pos;
            for i in 0..g.thread_pos.len() {
                match g.thread_pos[i] {
                    Some(pos) => completed_pos = min(completed_pos, pos),
                    None => (),
                }
            }

            self.producer_reserved_upto_pos = completed_pos + self.buffer.len() as u64;
            if self.producer_reserved_pos < self.producer_reserved_upto_pos
                || wait_flag == WaitFlag::NoWait
            {
                break;
            }

            g = self.cond_var.wait(g).unwrap();
        }
    }
}

impl Write for CompressedWriter {
    fn write(&mut self, data_to_write: &[u8]) -> Result<usize> {
        let mut data = data_to_write;
        let mut size = data.len();
        while !self.error && size > 0 {
            let reservation_size: usize =
                (self.producer_reserved_upto_pos - self.producer_reserved_write_pos) as usize;
            if reservation_size == 0 {
                self.update_reservation(WaitFlag::Wait);
                continue;
            }
            let buf_offset: usize =
                (self.producer_reserved_write_pos % self.buffer.len() as u64) as usize;
            let amount: usize = min(self.buffer.len() - buf_offset, min(reservation_size, size));
            unsafe {
                copy_nonoverlapping(
                    data.as_ptr(),
                    &mut self.buffer[buf_offset] as *mut u8,
                    amount,
                );
            }
            self.producer_reserved_write_pos += amount as u64;
            data = &data[amount..];
            size -= amount;
        }

        if !self.error
            && self.producer_reserved_write_pos - self.producer_reserved_pos
                >= (self.buffer.len() / 2) as u64
        {
            self.update_reservation(WaitFlag::NoWait);
        }

        // @TODO Is this sufficient
        if self.error {
            return Err(Error::new(ErrorKind::Other, "CompressedWriter error"));
        }
        Ok(data_to_write.len())
    }

    fn flush(&mut self) -> Result<()> {
        // Since we're NOT buffered, this is a no-op.
        Ok(())
    }
}

/// See http://robert.ocallahan.org/2017/07/selecting-compression-algorithm-for-rr.html
const RD_BROTLI_LEVEL: u32 = 5;

unsafe fn do_compress(
    shared_buf: &[u8],
    mut stream_offset: u64,
    mut uncompressed_len: usize,
    output_buf: &mut [u8],
) -> usize {
    let state = BrotliEncoderCreateInstance(None, None, ptr::null_mut());
    if state.is_null() {
        fatal!("BrotliEncoderCreateInstance failed");
    }

    if 0 == BrotliEncoderSetParameter(state, BROTLI_PARAM_QUALITY, RD_BROTLI_LEVEL) {
        fatal!("Brotli initialization failed");
    }

    let mut ret: usize = 0;
    let mut output_buf_len: usize = output_buf.len();
    let mut outp: *mut u8 = &raw mut output_buf[0];
    while uncompressed_len > 0 {
        let shared_buf_offset: usize = (stream_offset % shared_buf.len() as u64) as usize;
        let mut amount: usize = min(uncompressed_len, shared_buf.len() - shared_buf_offset);
        let mut inp = &raw const shared_buf[shared_buf_offset];
        if 0 == BrotliEncoderCompressStream(
            state,
            BROTLI_OPERATION_PROCESS,
            &mut amount,
            &raw mut inp,
            &mut output_buf_len,
            &raw mut outp,
            &raw mut ret,
        ) {
            fatal!("Brotli compression failed");
        }
        let consumed = inp as u64 - &raw const shared_buf[shared_buf_offset] as u64;
        stream_offset += consumed;
        uncompressed_len -= consumed as usize;
    }
    let mut zero: usize = 0;
    if 0 == BrotliEncoderCompressStream(
        state,
        BROTLI_OPERATION_FINISH,
        &raw mut zero,
        ptr::null_mut(),
        &mut output_buf_len,
        &raw mut outp,
        &raw mut ret,
    ) {
        fatal!("Brotli compression failed");
    }

    BrotliEncoderDestroyInstance(state);
    ret
}
