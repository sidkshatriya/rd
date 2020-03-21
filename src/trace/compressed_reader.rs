use crate::scoped_fd::ScopedFdSharedPtr;
use std::ffi::OsStr;

/// CompressedReader opens an input file written by CompressedWriter
/// and reads data from it. Currently data is decompressed by the thread that
/// calls read().
pub struct CompressedReader {
    /// Our fd might be the dup of another fd, so we can't rely on its current file position.
    /// Instead track the current position in fd_offset and use pread.
    fd_offset: u64,
    /// @TODO Is a shared pointer what we really want?
    fd: ScopedFdSharedPtr,
    error: bool,
    eof: bool,
    buffer: Vec<u8>,
    buffer_read_pos: usize,

    have_saved_state: bool,
    have_saved_buffer: bool,
    saved_fd_offset: u64,
    saved_buffer: Vec<u8>,
    saved_buffer_read_pos: usize,
}

impl Drop for CompressedReader {
    fn drop(&mut self) {
        self.close()
    }
}

impl Clone for CompressedReader {
    fn clone(&self) -> Self {
        unimplemented!()
    }
}

/// CompressedReader opens an input file written by CompressedWriter
/// and reads data from it. Currently data is decompressed by the thread that
/// calls read().
impl CompressedReader {
    pub fn new(filename: &OsStr) -> CompressedReader {
        unimplemented!()
    }
    pub fn good(&self) -> bool {
        return !self.error;
    }
    pub fn at_end(&self) -> bool {
        self.eof && self.buffer_read_pos == self.buffer.len()
    }
    /// Returns true if successful. Otherwise there's an error and good()
    /// will be false.
    pub fn read(&mut self, data: &mut [u8]) {
        unimplemented!()
    }
    /// Returns pointer/size of some buffered data. Does not change the state.
    /// Returns zero size if at EOF.
    pub fn get_buffer(&self) -> (bool, &[u8]) {
        unimplemented!()
    }
    /// Advances the read position by the given size.
    pub fn skip(&mut self, size: usize) -> bool {
        unimplemented!()
    }

    pub fn rewind(&mut self) {
        unimplemented!()
    }
    pub fn close(&mut self) {
        unimplemented!()
    }

    /// Save the current position. Nested saves are not allowed.
    pub fn save_state(&mut self) {
        unimplemented!()
    }
    /// Restore previously saved position.
    pub fn restore_state(&mut self) {
        unimplemented!()
    }
    /// Discard saved position
    pub fn discard_state(&mut self) {
        unimplemented!()
    }

    /// Gathers stats on the file stream. These are independent of what's
    /// actually been read.
    pub fn uncompressed_bytes(&self) -> u64 {
        unimplemented!()
    }
    pub fn compressed_bytes(&self) -> u64 {
        unimplemented!()
    }

    fn refill_buffer(&mut self) -> bool {
        unimplemented!()
    }
}

// @TODO Some Compressed Reader stream related functionality
