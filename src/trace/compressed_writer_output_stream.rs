use crate::trace::compressed_writer::CompressedWriter;
use std::io::{Result, Write};

pub struct CompressedWriterOutputStream;

impl CompressedWriterOutputStream {
    pub fn new(cw: &mut CompressedWriter) -> CompressedWriterOutputStream {
        unimplemented!()
    }
}

impl Write for CompressedWriterOutputStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<()> {
        unimplemented!()
    }
}
