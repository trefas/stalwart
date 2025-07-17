//! I/O streams for wrapping `BufRead` types as encoders/decoders

use std::io;
use std::io::prelude::*;

#[cfg(feature = "parallel")]
use crate::stream::MtStreamBuilder;
use crate::stream::{Action, Check, Status, Stream};

/// A xz encoder, or compressor.
///
/// This structure implements a `BufRead` interface and will read uncompressed
/// data from an underlying stream and emit a stream of compressed data.
pub struct XzEncoder<R> {
    obj: R,
    data: Stream,
}

/// A xz decoder, or decompressor.
///
/// This structure implements a `BufRead` interface and takes a stream of
/// compressed data as input, providing the decompressed data when read from.
pub struct XzDecoder<R> {
    obj: R,
    data: Stream,
}

impl<R: BufRead> XzEncoder<R> {
    /// Creates a new encoder which will read uncompressed data from the given
    /// stream and emit the compressed stream.
    ///
    /// The `level` argument here is typically 0-9 with 6 being a good default.
    #[inline]
    pub fn new(r: R, level: u32) -> XzEncoder<R> {
        let stream = Stream::new_easy_encoder(level, Check::Crc64).unwrap();
        XzEncoder::new_stream(r, stream)
    }

    /// Creates a new parallel encoder which will read uncompressed data from the given
    /// stream and emit the compressed stream.
    ///
    /// The `level` argument here is typically 0-9 with 6 being a good default.
    #[cfg(feature = "parallel")]
    pub fn new_parallel(r: R, level: u32) -> XzEncoder<R> {
        let stream = MtStreamBuilder::new()
            .preset(level)
            .check(Check::Crc64)
            .threads(num_cpus::get() as u32)
            .encoder()
            .unwrap();
        Self::new_stream(r, stream)
    }

    /// Creates a new encoder with a custom `Stream`.
    ///
    /// The `Stream` can be pre-configured for multithreaded encoding, different
    /// compression options/tuning, etc.
    #[inline]
    pub fn new_stream(r: R, stream: Stream) -> XzEncoder<R> {
        XzEncoder {
            obj: r,
            data: stream,
        }
    }
}

impl<R> XzEncoder<R> {
    /// Acquires a reference to the underlying stream
    #[inline]
    pub fn get_ref(&self) -> &R {
        &self.obj
    }

    /// Acquires a mutable reference to the underlying stream
    ///
    /// Note that mutation of the stream may result in surprising results if
    /// this encoder is continued to be used.
    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.obj
    }

    /// Consumes this encoder, returning the underlying reader.
    #[inline]
    pub fn into_inner(self) -> R {
        self.obj
    }

    /// Returns the number of bytes produced by the compressor
    /// (e.g., the number of bytes read from this stream)
    ///
    /// Note that, due to buffering, this only bears any relation to
    /// total_in() when the compressor chooses to flush its data
    /// (unfortunately, this won't happen in general at the end of the
    /// stream, because the compressor doesn't know if there's more data
    /// to come).  At that point, `total_out() / total_in()` would be
    /// the compression ratio.
    #[inline]
    pub fn total_out(&self) -> u64 {
        self.data.total_out()
    }

    /// Returns the number of bytes consumed by the compressor
    /// (e.g., the number of bytes read from the underlying stream)
    #[inline]
    pub fn total_in(&self) -> u64 {
        self.data.total_in()
    }
}

impl<R: BufRead> Read for XzEncoder<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let (read, consumed, eof, ret);
            {
                let input = self.obj.fill_buf()?;
                eof = input.is_empty();
                let before_out = self.data.total_out();
                let before_in = self.data.total_in();
                let action = if eof { Action::Finish } else { Action::Run };
                ret = self.data.process(input, buf, action);
                read = (self.data.total_out() - before_out) as usize;
                consumed = (self.data.total_in() - before_in) as usize;
            };
            self.obj.consume(consumed);

            ret?;

            // If we haven't ready any data and we haven't hit EOF yet, then we
            // need to keep asking for more data because if we return that 0
            // bytes of data have been read then it will be interpreted as EOF.
            if read == 0 && !eof && !buf.is_empty() {
                continue;
            }
            return Ok(read);
        }
    }
}

impl<W: Write> Write for XzEncoder<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get_mut().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.get_mut().flush()
    }
}

impl<R: BufRead> XzDecoder<R> {
    /// Creates a new decoder which will decompress data read from the given
    /// stream.
    #[inline]
    pub fn new(r: R) -> XzDecoder<R> {
        let stream = Stream::new_stream_decoder(u64::MAX, 0).unwrap();
        XzDecoder::new_stream(r, stream)
    }

    /// Creates a new parallel decoder which will decompress data read from the given
    /// stream.
    #[cfg(feature = "parallel")]
    pub fn new_parallel(r: R) -> Self {
        let stream = MtStreamBuilder::new()
            .memlimit_stop(u64::MAX)
            .threads(num_cpus::get() as u32)
            .decoder()
            .unwrap();
        Self::new_stream(r, stream)
    }

    /// Creates a new decoder which will decompress data read from the given
    /// input. All the concatenated xz streams from input will be consumed.
    #[inline]
    pub fn new_multi_decoder(r: R) -> XzDecoder<R> {
        let stream = Stream::new_auto_decoder(u64::MAX, liblzma_sys::LZMA_CONCATENATED).unwrap();
        XzDecoder::new_stream(r, stream)
    }

    /// Creates a new decoder with a custom `Stream`.
    ///
    /// The `Stream` can be pre-configured for various checks, different
    /// decompression options/tuning, etc.
    #[inline]
    pub fn new_stream(r: R, stream: Stream) -> XzDecoder<R> {
        XzDecoder {
            obj: r,
            data: stream,
        }
    }
}

impl<R> XzDecoder<R> {
    /// Acquires a reference to the underlying stream
    #[inline]
    pub fn get_ref(&self) -> &R {
        &self.obj
    }

    /// Acquires a mutable reference to the underlying stream
    ///
    /// Note that mutation of the stream may result in surprising results if
    /// this encoder is continued to be used.
    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.obj
    }

    /// Consumes this decoder, returning the underlying reader.
    #[inline]
    pub fn into_inner(self) -> R {
        self.obj
    }

    /// Returns the number of bytes that the decompressor has consumed.
    ///
    /// Note that this will likely be smaller than what the decompressor
    /// actually read from the underlying stream due to buffering.
    #[inline]
    pub fn total_in(&self) -> u64 {
        self.data.total_in()
    }

    /// Returns the number of bytes that the decompressor has produced.
    #[inline]
    pub fn total_out(&self) -> u64 {
        self.data.total_out()
    }
}

impl<R: BufRead> Read for XzDecoder<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let (read, consumed, eof, ret);
            {
                let input = self.obj.fill_buf()?;
                eof = input.is_empty();
                let before_out = self.data.total_out();
                let before_in = self.data.total_in();
                ret = self
                    .data
                    .process(input, buf, if eof { Action::Finish } else { Action::Run });
                read = (self.data.total_out() - before_out) as usize;
                consumed = (self.data.total_in() - before_in) as usize;
            }
            self.obj.consume(consumed);

            let status = ret?;
            if read > 0 || eof || buf.is_empty() {
                if read == 0 && status != Status::StreamEnd && !buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "premature eof",
                    ));
                }
                return Ok(read);
            }
            if consumed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "corrupt xz stream",
                ));
            }
        }
    }
}

impl<W: Write> Write for XzDecoder<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get_mut().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.get_mut().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn compressed_and_trailing_data() {
        // Make a vector with compressed data...
        let mut to_compress: Vec<u8> = Vec::new();
        const COMPRESSED_ORIG_SIZE: usize = 1024;
        for num in 0..COMPRESSED_ORIG_SIZE {
            to_compress.push(num as u8)
        }
        let mut encoder = XzEncoder::new(&to_compress[..], 6);

        let mut decoder_input = Vec::new();
        encoder.read_to_end(&mut decoder_input).unwrap();

        assert_eq!(encoder.total_in(), to_compress.len() as u64);
        assert_eq!(encoder.total_out(), decoder_input.len() as u64);

        // ...plus additional unrelated trailing data
        const ADDITIONAL_SIZE: usize = 123;
        let mut additional_data = Vec::new();
        for num in 0..ADDITIONAL_SIZE {
            additional_data.push(((25 + num) % 256) as u8)
        }
        decoder_input.extend(&additional_data);

        // Decoder must be able to read the compressed xz stream, and keep the trailing data.
        let mut decoder_reader = &decoder_input[..];
        {
            let mut decoder = XzDecoder::new(&mut decoder_reader);
            let mut decompressed_data = vec![0u8; to_compress.len()];

            assert_eq!(
                decoder.read(&mut decompressed_data).unwrap(),
                COMPRESSED_ORIG_SIZE
            );
            assert_eq!(decompressed_data, &to_compress[..]);
            assert_eq!(
                decoder.total_in(),
                (decoder_input.len() - ADDITIONAL_SIZE) as u64
            );
            assert_eq!(decoder.total_out(), decompressed_data.len() as u64);
        }

        let mut remaining_data = Vec::new();
        let nb_read = decoder_reader.read_to_end(&mut remaining_data).unwrap();
        assert_eq!(nb_read, ADDITIONAL_SIZE);
        assert_eq!(remaining_data, &additional_data[..]);
    }
}
