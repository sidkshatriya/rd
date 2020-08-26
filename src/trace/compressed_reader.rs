use crate::{
    scoped_fd::{ScopedFd, ScopedFdSharedPtr},
    trace::compressed_writer::BlockHeader,
    util::read_to_end,
};
use brotli_sys::{BrotliDecoderDecompress, BROTLI_DECODER_RESULT_SUCCESS};
use nix::{
    fcntl::OFlag,
    sys::uio::pread,
    unistd::{lseek, Whence},
};
use std::{
    cell::RefCell,
    cmp::min,
    convert::TryInto,
    ffi::OsStr,
    io,
    io::{BufRead, ErrorKind, Read},
    mem::{size_of, transmute},
    ptr::copy_nonoverlapping,
    rc::Rc,
};

/// CompressedReader opens an input file written by CompressedWriter
/// and reads data from it. Currently data is decompressed by the thread that
/// calls read().
#[derive(Clone)]
pub struct CompressedReader {
    /// Our fd might be the dup of another fd, so we can't rely on its current file position.
    /// Instead track the current position in fd_offset and use pread.
    fd_offset: u64,
    fd: Option<ScopedFdSharedPtr>,
    eof: bool,
    buffer: Vec<u8>,
    buffer_read_pos: usize,
    // Note that the struct members for saving state are not here as we have a separate struct
    // to handle that
}

impl Read for CompressedReader {
    fn read(&mut self, mut data: &mut [u8]) -> io::Result<usize> {
        let amount_requested = data.len();
        let mut left_to_be_provided = amount_requested;
        while left_to_be_provided > 0 {
            // We are in a position to provide _some_ data
            if self.buffer_read_pos < self.buffer.len() {
                let amount_provided: usize = min(
                    left_to_be_provided,
                    self.buffer.len() - self.buffer_read_pos,
                );
                unsafe {
                    copy_nonoverlapping(
                        &self.buffer[self.buffer_read_pos],
                        data.as_mut_ptr(),
                        amount_provided,
                    );
                }
                self.buffer_read_pos += amount_provided;
                left_to_be_provided -= amount_provided;
                data = &mut data[amount_provided..];
                continue;
            }
            // We don't have any more data available in the buffer and we've already reached eof
            else if self.eof {
                return Ok(amount_requested - left_to_be_provided);
            }

            // Otherwise try to refill the buffer and attempt to satisfy the read request again
            self.refill_buffer()?;
        }
        Ok(amount_requested)
    }
}

pub struct CompressedReaderState {
    saved_fd_offset: u64,
    saved_buffer: Vec<u8>,
    saved_buffer_read_pos: usize,
}

impl Default for CompressedReaderState {
    fn default() -> Self {
        CompressedReaderState {
            saved_fd_offset: 0,
            saved_buffer: vec![],
            saved_buffer_read_pos: 0,
        }
    }
}

impl Drop for CompressedReader {
    fn drop(&mut self) {
        self.close()
    }
}

/// CompressedReader opens an input file written by CompressedWriter
/// and reads data from it. Currently data is decompressed by the thread that
/// calls read().
impl CompressedReader {
    pub fn new(filename: &OsStr) -> CompressedReader {
        let fd = ScopedFd::open_path(
            filename,
            OFlag::O_CLOEXEC | OFlag::O_RDONLY | OFlag::O_LARGEFILE,
        );
        let error = !fd.is_open();
        let eof: bool;
        if error {
            eof = false;
        } else {
            let ch: u8 = 0;
            eof = match pread(fd.as_raw(), &mut ch.to_le_bytes(), 0) {
                Ok(0) => true,
                Ok(_) => false,
                // DIFF NOTE: rr does not abort with a fatal error if pread was not successful.
                Err(e) => {
                    fatal!("Could not pread {:?} {:?}", filename, e);
                }
            }
        }
        let buffer_read_pos = 0;
        CompressedReader {
            fd_offset: 0,
            fd: Some(Rc::new(RefCell::new(fd))),
            eof,
            buffer: Vec::new(),
            buffer_read_pos,
        }
    }

    pub fn at_end(&self) -> bool {
        self.eof && self.buffer_read_pos == self.buffer.len()
    }

    /// Advances the read position by the given size.
    pub fn skip(&mut self, mut size: usize) -> io::Result<()> {
        while size > 0 {
            if self.buffer_read_pos < self.buffer.len() {
                let amount: usize = min(size, self.buffer.len() - self.buffer_read_pos);
                size -= amount;
                self.buffer_read_pos += amount;
                continue;
            } else if self.eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF encountered while performing skip() on CompressedReader",
                ));
            }

            self.refill_buffer()?;
        }

        Ok(())
    }

    pub fn rewind(&mut self) {
        self.fd_offset = 0;
        self.buffer_read_pos = 0;
        self.buffer.clear();
        self.eof = false;
    }
    pub fn close(&mut self) {
        self.fd.take();
    }

    /// Get the current state of the CompressedReader.
    /// Slightly different approach from rr which has `save_state()`
    /// Note: Therefore `discard_state()` method in rr is not needed.
    pub fn get_state(&self) -> CompressedReaderState {
        CompressedReaderState {
            saved_fd_offset: self.fd_offset,
            saved_buffer: self.buffer.clone(),
            saved_buffer_read_pos: self.buffer_read_pos,
        }
    }
    /// Restore previously obtained state.
    /// Slightly different approach from rr -- you need to provide state to be restored.
    pub fn restore_state(&mut self, state: CompressedReaderState) {
        if state.saved_fd_offset < self.fd_offset {
            self.eof = false;
        }
        self.fd_offset = state.saved_fd_offset;
        self.buffer = state.saved_buffer;
        self.buffer_read_pos = state.saved_buffer_read_pos;
    }

    /// Gathers stats on the file stream. These are independent of what's
    /// actually been read.
    pub fn uncompressed_bytes(&self) -> io::Result<u64> {
        let mut offset: u64 = 0;
        let mut uncompressed_bytes: u64 = 0;
        let mut header_arr = [0u8; size_of::<BlockHeader>()];
        while read_all(
            &self.fd.as_ref().unwrap().borrow(),
            &mut header_arr,
            &mut offset,
        )? {
            let header: BlockHeader = unsafe { transmute(header_arr.clone()) };
            uncompressed_bytes += header.uncompressed_length as u64;
            offset += header.compressed_length as u64;
        }
        Ok(uncompressed_bytes)
    }

    pub fn compressed_bytes(&self) -> io::Result<u64> {
        let result = lseek(
            self.fd.as_ref().unwrap().borrow().as_raw(),
            0,
            Whence::SeekEnd,
        );
        match result {
            Ok(off) => Ok(off as u64),
            Err(e) => Err(io::Error::new(ErrorKind::Other, e)),
        }
    }

    fn refill_buffer(&mut self) -> io::Result<()> {
        let mut header_vec: Vec<u8> = Vec::with_capacity(size_of::<BlockHeader>());
        header_vec.resize(size_of::<BlockHeader>(), 0u8);
        if false
            == read_all(
                &self.fd.as_ref().unwrap().borrow(),
                &mut header_vec,
                &mut self.fd_offset,
            )?
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF encountered while doing read_all() on header in CompressedReader",
            ));
        }

        let mut header: BlockHeader = Default::default();
        unsafe {
            copy_nonoverlapping(
                header_vec.as_ptr(),
                &raw mut header as *mut u8,
                size_of::<BlockHeader>(),
            );
        }

        let mut compressed_buf: Vec<u8> = Vec::with_capacity(header.compressed_length as usize);
        compressed_buf.resize(header.compressed_length as usize, 0);
        if false
            == read_all(
                &self.fd.as_ref().unwrap().borrow(),
                &mut compressed_buf,
                &mut self.fd_offset,
            )?
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF encountered while doing read_all() on compressed data in CompressedReader",
            ));
        }

        let ch: u8 = 0;
        self.eof = match pread(
            self.fd.as_ref().unwrap().borrow().as_raw(),
            &mut ch.to_le_bytes(),
            // On x86 off_t is an i32 and on x86_64 off_t is an i64
            self.fd_offset.try_into().unwrap(),
        ) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => return Err(io::Error::new(ErrorKind::Other, e)),
        };

        self.buffer.resize(header.uncompressed_length as usize, 0);
        self.buffer_read_pos = 0;
        if !do_decompress(compressed_buf.as_slice(), &mut self.buffer) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Decompression Error. @TODO",
            ));
        }

        Ok(())
    }
}

pub fn read_all(fd: &ScopedFd, data: &mut [u8], offset: &mut u64) -> io::Result<bool> {
    let ret = read_to_end(fd, *offset, data);
    match ret {
        Ok(nread) if nread == data.len() => {
            *offset += nread as u64;
            Ok(true)
        }
        // We encountered an EOF
        Ok(_) => Ok(false),
        Err(e) => Err(io::Error::new(ErrorKind::Other, e)),
    }
}

pub fn do_decompress(compressed: &[u8], uncompressed: &mut [u8]) -> bool {
    let mut out_size = uncompressed.len();
    let decompress_result = unsafe {
        BrotliDecoderDecompress(
            compressed.len(),
            compressed.as_ptr(),
            &raw mut out_size,
            uncompressed.as_mut_ptr(),
        )
    };

    decompress_result == BROTLI_DECODER_RESULT_SUCCESS && out_size == uncompressed.len()
}

impl BufRead for CompressedReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // If available to read bytes are "empty" and we have not yet reached EOF
        if self.buffer_read_pos >= self.buffer.len() && !self.eof {
            self.refill_buffer()?;
        }
        Ok(&self.buffer[self.buffer_read_pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.buffer_read_pos += amt;
    }
}
