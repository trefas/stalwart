//! Reader-based compression/decompression streams

use std::io::prelude::*;
use std::io::{self, BufReader};

use crate::bufread;
use crate::stream::Stream;

/// A compression stream which wraps an uncompressed stream of data. Compressed
/// data will be read from the stream.
pub struct XzEncoder<R: Read> {
    inner: bufread::XzEncoder<BufReader<R>>,
}

/// A decompression stream which wraps a compressed stream of data. Decompressed
/// data will be read from the stream.
pub struct XzDecoder<R: Read> {
    inner: bufread::XzDecoder<BufReader<R>>,
}

impl<R: Read> XzEncoder<R> {
    /// Create a new compression stream which will compress at the given level
    /// to read compress output to the give output stream.
    ///
    /// The `level` argument here is typically 0-9 with 6 being a good default.
    #[inline]
    pub fn new(r: R, level: u32) -> XzEncoder<R> {
        XzEncoder {
            inner: bufread::XzEncoder::new(BufReader::new(r), level),
        }
    }

    /// Create a new parallel compression stream which will compress at the given level
    /// to read compress output to the give output stream.
    ///
    /// The `level` argument here is typically 0-9 with 6 being a good default.
    #[cfg(feature = "parallel")]
    pub fn new_parallel(r: R, level: u32) -> XzEncoder<R> {
        XzEncoder {
            inner: bufread::XzEncoder::new_parallel(BufReader::new(r), level),
        }
    }

    /// Creates a new encoder with a custom `Stream`.
    ///
    /// The `Stream` can be pre-configured for multithreaded encoding, different
    /// compression options/tuning, etc.
    #[inline]
    pub fn new_stream(r: R, stream: Stream) -> XzEncoder<R> {
        XzEncoder {
            inner: bufread::XzEncoder::new_stream(BufReader::new(r), stream),
        }
    }

    /// Acquires a reference to the underlying stream
    #[inline]
    pub fn get_ref(&self) -> &R {
        self.inner.get_ref().get_ref()
    }

    /// Acquires a mutable reference to the underlying stream
    ///
    /// Note that mutation of the stream may result in surprising results if
    /// this encoder is continued to be used.
    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut().get_mut()
    }

    /// Unwrap the underlying writer, finishing the compression stream.
    #[inline]
    pub fn into_inner(self) -> R {
        self.inner.into_inner().into_inner()
    }

    /// Returns the number of bytes produced by the compressor
    /// (e.g. the number of bytes read from this stream)
    ///
    /// Note that, due to buffering, this only bears any relation to
    /// total_in() when the compressor chooses to flush its data
    /// (unfortunately, this won't happen this won't happen in general
    /// at the end of the stream, because the compressor doesn't know
    /// if there's more data to come).  At that point,
    /// `total_out() / total_in()` would be the compression ratio.
    #[inline]
    pub fn total_out(&self) -> u64 {
        self.inner.total_out()
    }

    /// Returns the number of bytes consumed by the compressor
    /// (e.g. the number of bytes read from the underlying stream)
    #[inline]
    pub fn total_in(&self) -> u64 {
        self.inner.total_in()
    }
}

impl<R: Read> Read for XzEncoder<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<W: Write + Read> Write for XzEncoder<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get_mut().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.get_mut().flush()
    }
}

impl<R: Read> XzDecoder<R> {
    /// Create a new decompression stream, which will read compressed
    /// data from the given input stream, and decompress one xz stream.
    /// It may also consume input data that follows the xz stream.
    /// Use [`xz::bufread::XzDecoder`] instead to process a mix of xz and non-xz data.
    #[inline]
    pub fn new(r: R) -> XzDecoder<R> {
        XzDecoder {
            inner: bufread::XzDecoder::new(BufReader::new(r)),
        }
    }

    /// Create a new parallel decompression stream, which will read compressed
    /// data from the given input stream, and decompress one xz stream.
    /// It may also consume input data that follows the xz stream.
    /// Use [`xz::bufread::XzDecoder`] instead to process a mix of xz and non-xz data.
    #[cfg(feature = "parallel")]
    #[inline]
    pub fn new_parallel(r: R) -> XzDecoder<R> {
        XzDecoder {
            inner: bufread::XzDecoder::new_parallel(BufReader::new(r)),
        }
    }

    /// Create a new decompression stream, which will read compressed
    /// data from the given input and decompress all the xz stream it contains.
    #[inline]
    pub fn new_multi_decoder(r: R) -> XzDecoder<R> {
        XzDecoder {
            inner: bufread::XzDecoder::new_multi_decoder(BufReader::new(r)),
        }
    }

    /// Creates a new decoder with a custom `Stream`.
    ///
    /// The `Stream` can be pre-configured for various checks, different
    /// decompression options/tuning, etc.
    #[inline]
    pub fn new_stream(r: R, stream: Stream) -> XzDecoder<R> {
        XzDecoder {
            inner: bufread::XzDecoder::new_stream(BufReader::new(r), stream),
        }
    }

    /// Acquires a reference to the underlying stream
    #[inline]
    pub fn get_ref(&self) -> &R {
        self.inner.get_ref().get_ref()
    }

    /// Acquires a mutable reference to the underlying stream
    ///
    /// Note that mutation of the stream may result in surprising results if
    /// this encoder is continued to be used.
    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut().get_mut()
    }

    /// Unwrap the underlying writer, finishing the compression stream.
    #[inline]
    pub fn into_inner(self) -> R {
        self.inner.into_inner().into_inner()
    }

    /// Returns the number of bytes produced by the decompressor
    /// (e.g. the number of bytes read from this stream)
    ///
    /// Note that, due to buffering, this only bears any relation to
    /// total_in() when the decompressor reaches a sync point
    /// (e.g. where the original compressed stream was flushed).
    /// At that point, `total_in() / total_out()` is the compression ratio.
    #[inline]
    pub fn total_out(&self) -> u64 {
        self.inner.total_out()
    }

    /// Returns the number of bytes consumed by the decompressor
    /// (e.g. the number of bytes read from the underlying stream)
    #[inline]
    pub fn total_in(&self) -> u64 {
        self.inner.total_in()
    }
}

impl<R: Read> Read for XzDecoder<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<W: Write + Read> Write for XzDecoder<W> {
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
    use crate::stream::LzmaOptions;
    use quickcheck::quickcheck;
    use rand::{thread_rng, Rng};
    use std::iter;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn smoke() {
        let m: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let mut c = XzEncoder::new(m, 6);
        let mut data = vec![];
        c.read_to_end(&mut data).unwrap();
        let mut d = XzDecoder::new(&data[..]);
        let mut data2 = Vec::new();
        d.read_to_end(&mut data2).unwrap();
        assert_eq!(data2, m);
    }

    #[test]
    fn smoke2() {
        let m: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let c = XzEncoder::new(m, 6);
        let mut d = XzDecoder::new(c);
        let mut data = vec![];
        d.read_to_end(&mut data).unwrap();
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn smoke3() {
        let m = vec![3u8; 128 * 1024 + 1];
        let c = XzEncoder::new(&m[..], 6);
        let mut d = XzDecoder::new(c);
        let mut data = vec![];
        d.read_to_end(&mut data).unwrap();
        assert_eq!(data, &m[..]);
    }

    #[test]
    fn self_terminating() {
        let m = vec![3u8; 128 * 1024 + 1];
        let mut c = XzEncoder::new(&m[..], 6);

        let mut result = Vec::new();
        c.read_to_end(&mut result).unwrap();

        let mut rng = thread_rng();
        let v = iter::repeat_with(|| rng.gen::<u8>())
            .take(1024)
            .collect::<Vec<_>>();
        for _ in 0..200 {
            result.extend(v.iter().map(|x| *x));
        }

        let mut d = XzDecoder::new(&result[..]);
        let mut data = Vec::with_capacity(m.len());
        unsafe {
            data.set_len(m.len());
        }
        assert_eq!(d.read(&mut data).unwrap(), m.len());
        assert_eq!(data, &m[..]);
    }

    #[test]
    fn zero_length_read_at_eof() {
        let m = Vec::new();
        let mut c = XzEncoder::new(&m[..], 6);

        let mut result = Vec::new();
        c.read_to_end(&mut result).unwrap();

        let mut d = XzDecoder::new(&result[..]);
        let mut data = Vec::new();
        assert_eq!(d.read(&mut data).unwrap(), 0);
    }

    #[test]
    fn zero_length_read_with_data() {
        let m = vec![3u8; 128 * 1024 + 1];
        let mut c = XzEncoder::new(&m[..], 6);

        let mut result = Vec::new();
        c.read_to_end(&mut result).unwrap();

        let mut d = XzDecoder::new(&result[..]);
        let mut data = Vec::new();
        assert_eq!(d.read(&mut data).unwrap(), 0);
    }

    #[test]
    fn qc_lzma1() {
        quickcheck(test as fn(_) -> _);
        fn test(v: Vec<u8>) -> bool {
            let options = LzmaOptions::new_preset(6).unwrap();
            let stream = Stream::new_lzma_encoder(&options).unwrap();
            let r = XzEncoder::new_stream(&v[..], stream);
            let stream = Stream::new_lzma_decoder(u64::MAX).unwrap();
            let mut r = XzDecoder::new_stream(r, stream);
            let mut v2 = Vec::new();
            r.read_to_end(&mut v2).unwrap();
            v == v2
        }
    }

    #[test]
    fn qc() {
        quickcheck(test as fn(_) -> _);

        fn test(v: Vec<u8>) -> bool {
            let r = XzEncoder::new(&v[..], 6);
            let mut r = XzDecoder::new(r);
            let mut v2 = Vec::new();
            r.read_to_end(&mut v2).unwrap();
            v == v2
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn qc_parallel_encode() {
        quickcheck(test as fn(_) -> _);

        fn test(v: Vec<u8>) -> bool {
            let r = XzEncoder::new_parallel(&v[..], 6);
            let mut r = XzDecoder::new(r);
            let mut v2 = Vec::new();
            r.read_to_end(&mut v2).unwrap();
            v == v2
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn qc_parallel_decode() {
        quickcheck(test as fn(_) -> _);

        fn test(v: Vec<u8>) -> bool {
            let r = XzEncoder::new(&v[..], 6);
            let mut r = XzDecoder::new_parallel(r);
            let mut v2 = Vec::new();
            r.read_to_end(&mut v2).unwrap();
            v == v2
        }
    }

    #[test]
    fn two_streams() {
        let mut input_stream1: Vec<u8> = Vec::new();
        let mut input_stream2: Vec<u8> = Vec::new();
        let mut all_input: Vec<u8> = Vec::new();

        // Generate input data.
        const STREAM1_SIZE: usize = 1024;
        for num in 0..STREAM1_SIZE {
            input_stream1.push(num as u8)
        }
        const STREAM2_SIZE: usize = 532;
        for num in 0..STREAM2_SIZE {
            input_stream2.push((num + 32) as u8)
        }
        all_input.extend(&input_stream1);
        all_input.extend(&input_stream2);

        // Make a vector with compressed data
        let mut decoder_input = Vec::new();
        {
            let mut encoder = XzEncoder::new(&input_stream1[..], 6);
            encoder.read_to_end(&mut decoder_input).unwrap();
        }
        {
            let mut encoder = XzEncoder::new(&input_stream2[..], 6);
            encoder.read_to_end(&mut decoder_input).unwrap();
        }

        // Decoder must be able to read the 2 concatenated xz streams and get the same data as input.
        let mut decoder_reader = &decoder_input[..];
        {
            // using `XzDecoder::new` here would fail because only 1 xz stream would be processed.
            let mut decoder = XzDecoder::new_multi_decoder(&mut decoder_reader);
            let mut decompressed_data = vec![0u8; all_input.len()];

            assert_eq!(
                decoder.read(&mut decompressed_data).unwrap(),
                all_input.len()
            );
            assert_eq!(decompressed_data, &all_input[..]);
        }
    }
}
