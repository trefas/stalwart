use core::{
    error::Error,
    fmt,
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    ptr::{copy_nonoverlapping, NonNull},
    slice,
};

use rancor::{fail, Source};

use crate::ser::{Positional, Writer};

#[derive(Debug)]
struct BufferOverflow {
    write_len: usize,
    cap: usize,
    len: usize,
}

impl fmt::Display for BufferOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "overflowed buffer while writing {} bytes into buffer of length \
             {} (capacity is {})",
            self.write_len, self.len, self.cap,
        )
    }
}

impl Error for BufferOverflow {}

/// Wraps a byte buffer and equips it with [`Writer`].
///
/// Common uses include archiving in `#![no_std]` environments and archiving
/// small objects without allocating.
///
/// # Examples
///
/// ```
/// use core::mem::MaybeUninit;
///
/// use rkyv::{
///     access_unchecked,
///     api::high::to_bytes_in,
///     rancor::{Error, Strategy},
///     ser::{writer::Buffer, Writer},
///     util::Align,
///     Archive, Archived, Serialize,
/// };
///
/// #[derive(Archive, Serialize)]
/// enum Event {
///     Spawn,
///     Speak(String),
///     Die,
/// }
///
/// let event = Event::Speak("Help me!".to_string());
/// let mut bytes = Align([MaybeUninit::uninit(); 256]);
/// let buffer = to_bytes_in::<_, Error>(&event, Buffer::from(&mut *bytes))
///     .expect("failed to serialize event");
/// let archived = unsafe { access_unchecked::<Archived<Event>>(&buffer) };
/// if let Archived::<Event>::Speak(message) = archived {
///     assert_eq!(message.as_str(), "Help me!");
/// } else {
///     panic!("archived event was of the wrong type");
/// }
/// ```
#[derive(Debug)]
pub struct Buffer<'a> {
    ptr: NonNull<u8>,
    cap: usize,
    len: usize,
    _phantom: PhantomData<&'a mut [u8]>,
}

impl<'a, const N: usize> From<&'a mut [u8; N]> for Buffer<'a> {
    fn from(bytes: &'a mut [u8; N]) -> Self {
        Self {
            ptr: NonNull::from(bytes).cast(),
            cap: N,
            len: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a> From<&'a mut [u8]> for Buffer<'a> {
    fn from(bytes: &'a mut [u8]) -> Self {
        let size = bytes.len();
        Self {
            ptr: NonNull::from(bytes).cast(),
            cap: size,
            len: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a, const N: usize> From<&'a mut [MaybeUninit<u8>; N]> for Buffer<'a> {
    fn from(bytes: &'a mut [MaybeUninit<u8>; N]) -> Self {
        Self {
            ptr: NonNull::from(bytes).cast(),
            cap: N,
            len: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a> From<&'a mut [MaybeUninit<u8>]> for Buffer<'a> {
    fn from(bytes: &'a mut [MaybeUninit<u8>]) -> Self {
        let size = bytes.len();
        Self {
            ptr: NonNull::from(bytes).cast(),
            cap: size,
            len: 0,
            _phantom: PhantomData,
        }
    }
}

impl Deref for Buffer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for Buffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Positional for Buffer<'_> {
    #[inline]
    fn pos(&self) -> usize {
        self.len
    }
}

impl<E: Source> Writer<E> for Buffer<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), E> {
        if bytes.len() > self.cap - self.len {
            fail!(BufferOverflow {
                write_len: bytes.len(),
                cap: self.cap,
                len: self.len,
            });
        } else {
            unsafe {
                copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.ptr.as_ptr().add(self.len),
                    bytes.len(),
                );
            }
            self.len += bytes.len();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use rancor::Panic;

    use crate::{
        api::serialize_using,
        ser::{writer::Buffer, Serializer},
    };

    #[test]
    fn zeros_padding() {
        use core::mem::size_of;

        use crate::{Archive, Serialize};

        #[derive(Archive, Serialize)]
        #[rkyv(crate)]
        pub struct PaddedExample {
            a: u8,
            b: u64,
        }

        let mut bytes = [MaybeUninit::<u8>::new(0xcc); 256];
        let mut serializer = Serializer::new(Buffer::from(&mut bytes), (), ());
        serialize_using::<_, Panic>(
            &PaddedExample { a: 0u8, b: 0u64 },
            &mut serializer,
        )
        .unwrap();
        let buffer = serializer.into_writer();
        assert!(&buffer[0..size_of::<ArchivedPaddedExample>()]
            .iter()
            .all(|&b| b == 0));
    }
}
