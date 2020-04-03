use crate::trace::compressed_reader::CompressedReader;
use capnp::message::ReaderSegments;

pub struct CompressedReaderInputStream;

impl CompressedReaderInputStream {
    pub fn new(_reader: &mut CompressedReader) -> CompressedReaderInputStream {
        unimplemented!()
    }
}

/// @TODO Is this what we want??
impl ReaderSegments for CompressedReaderInputStream {
    fn get_segment(&self, _idx: u32) -> Option<&[u8]> {
        unimplemented!()
    }
}
