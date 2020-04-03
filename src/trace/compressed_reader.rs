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
    // Note that the struct members for saving state are not here as we have a separate struct
    // to handle that
}

pub struct CompressedReaderState {
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
    pub fn new(_filename: &OsStr) -> CompressedReader {
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
    pub fn read(&mut self, _data: &mut [u8]) {
        unimplemented!()
    }
    /// Returns pointer/size of some buffered data. Does not change the state.
    /// Returns zero size if at EOF.
    pub fn get_buffer(&self) -> (bool, &[u8]) {
        unimplemented!()
    }
    /// Advances the read position by the given size.
    pub fn skip(&mut self, _size: usize) -> bool {
        unimplemented!()
    }

    pub fn rewind(&mut self) {
        unimplemented!()
    }
    pub fn close(&mut self) {
        unimplemented!()
    }

    /// Get the current state of the CompressedReader.
    /// Slightly different approach from rr which has `save_state()`
    /// Note: Therefore `discard_state()` method in rr is not needed.
    pub fn get_state(&mut self) -> CompressedReaderState {
        unimplemented!()
    }
    /// Restore previously obtained state.
    /// Slightly different approach from rr -- you need to provide state to be restored.
    pub fn restore_state(&mut self, state: CompressedReaderState) {
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
