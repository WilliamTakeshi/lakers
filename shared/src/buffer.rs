use core::ops::Index;

// NOTE: This constant is only here for now because it is only ever used in instances of EdhocBuffer.
// TODO: move to lib.rs, once EdhocMessageBuffer is replaced by EdhocBuffer.
pub const MAX_SUITES_LEN: usize = 9;

/// Copies a short slice into the start of a long slice in a way both Rust's const fn and
/// hax are happy with.
///
/// This is a dedicated function because it's tricky to convince hax of it being OK.
// Inlining because this gets optimized into register shuffling and then a call to memcpy, provided
// that the assert gets optimized out (that's usually clear from the context) and short is not
// 0-long (IIUC that's because empty slices may point to NULL in Rust, but memcpy'ing 0 bytes from
// or to NULL is UB in C where the memcpy comes from).
#[inline(always)]
const fn copy_into_longer(long: &mut [u8], short: &[u8]) {
    // So the compiler knows what hax knows
    assert!(short.len() <= long.len());
    let mut cursor = short.len();
    while cursor > 0 {
        cursor = cursor - 1;
        long[cursor] = short[cursor];
    }
}

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum EdhocBufferError {
    BufferAlreadyFull,
    SliceTooLong,
}

/// A fixed-size (but parameterized) buffer for EDHOC messages.
///
/// Trying to have an API as similar as possible to `heapless::Vec`,
/// so that in the future it can be hot-swappable by the application.
// NOTE: how would this const generic thing work across the C and Python bindings?
#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub struct EdhocBuffer<const N: usize> {
    #[deprecated]
    pub content: [u8; N],
    #[deprecated(note = "use .len()")]
    len: usize,
}

#[allow(deprecated)]
impl<const N: usize> Default for EdhocBuffer<N> {
    fn default() -> Self {
        EdhocBuffer {
            content: [0; N],
            len: 0,
        }
    }
}

#[allow(deprecated)]
impl<const N: usize> EdhocBuffer<N> {
    pub const fn new() -> Self {
        EdhocBuffer {
            content: [0u8; N],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub const fn new_from_slice(slice: &[u8]) -> Result<Self, EdhocBufferError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice).is_ok() {
            Ok(buffer)
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    /// Creates a new buffer from an array, with compile-time checking of the size.
    ///
    /// This is identical to [`.new_from_slice`][Self::new_from_slice], but handles overflow as a
    /// built-time error, thus removing the need for a fallible result.
    ///
    /// This is particularly useful in tests and other const contexts:
    ///
    /// ```
    /// # use lakers_shared::*;
    /// const MY_CONST: EdhocMessageBuffer = EdhocMessageBuffer::new_from_array(&[0, 1, 2]);
    /// ```
    ///
    /// While this fails to build:
    ///
    /// ```compile_fail
    /// # use lakers_shared::*;
    /// const MY_CONST: EdhocMessageBuffer = EdhocMessageBuffer::new_from_array(&[0; 10_000]);
    /// ```
    pub const fn new_from_array<const AN: usize>(input: &[u8; AN]) -> Self {
        const {
            if AN > N {
                panic!("Array exceeds buffer size")
            }
        };
        match Self::new_from_slice(input.as_slice()) {
            Ok(s) => s,
            _ => panic!("unreachable: Was checked above in a guaranteed-const fashion"),
        }
    }

    pub fn contains(&self, item: &u8) -> bool {
        self.as_slice().contains(item)
    }

    #[inline]
    pub fn push(&mut self, item: u8) -> Result<(), EdhocBufferError> {
        if self.len < self.content.len() {
            self.content[self.len] = item;
            self.len += 1;
            Ok(())
        } else {
            Err(EdhocBufferError::BufferAlreadyFull)
        }
    }

    pub fn get_slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        if start >= usize::MAX / 2 || len >= usize::MAX / 2 {
            return None;
        }
        let end = start + len;
        if end > self.len {
            None
        } else {
            Some(&self.content[start..end])
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.content[0..self.len]
    }

    pub const fn fill_with_slice(&mut self, slice: &[u8]) -> Result<(), EdhocBufferError> {
        if slice.len() <= self.content.len() {
            copy_into_longer(&mut self.content, slice);
            self.len = slice.len();
            Ok(())
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), EdhocBufferError> {
        // The strict criterion avoids the need to use checked / saturating addition, which is not
        // present in hax for usize.
        if self.len >= usize::MAX / 2 || slice.len() >= usize::MAX / 2 {
            return Err(EdhocBufferError::SliceTooLong);
        }
        let end = self.len() + slice.len();
        if end <= self.content.len() {
            self.content[self.len..end].copy_from_slice(slice);
            self.len += slice.len();
            Ok(())
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    /// Like [`.extend_from_slice()`], but leaves the data in the buffer "uninitialized" --
    /// anticipating that the user will populate `self.content[result]`.
    ///
    /// ("Uninitialized" is in quotes because there are no guarentees on the content; from the
    /// compiler's perspective, that area is initialized because this type doesn't play with
    /// [`MaybeUninit`][core::mem::MaybeUninit], but don't rely on it).
    ///
    /// This is not a fully idiomatic Rust API: Preferably, this would return a `&mut [u8]` of the
    /// requested length. However, as `.as_mut_slice()` or `.get_mut()` can not be checked by hax,
    /// pushing and getting a range is the next best thing.
    pub fn extend_reserve(
        &mut self,
        length: usize,
    ) -> Result<core::ops::Range<usize>, EdhocBufferError> {
        // The strict criterion avoids the need to use checked / saturating addition, which is not
        // present in hax for usize.
        if self.len >= usize::MAX / 2 || length >= usize::MAX / 2 {
            return Err(EdhocBufferError::SliceTooLong);
        }
        let start = self.len;
        let end = start + length;
        if end <= N {
            self.len = end;
            Ok(start..end)
        } else {
            Err(EdhocBufferError::BufferAlreadyFull)
        }
    }
}

#[allow(deprecated)]
impl<const N: usize> Index<usize> for EdhocBuffer<N> {
    type Output = u8;
    #[track_caller]
    fn index(&self, item: usize) -> &Self::Output {
        &self.as_slice()[item]
    }
}

#[allow(deprecated)]
impl<const N: usize> TryFrom<&[u8]> for EdhocBuffer<N> {
    type Error = ();

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let mut buffer = [0u8; N];
        if input.len() <= buffer.len() {
            buffer[..input.len()].copy_from_slice(input);

            Ok(EdhocBuffer {
                content: buffer,
                len: input.len(),
            })
        } else {
            Err(())
        }
    }
}

#[allow(deprecated)]
mod test {

    #[test]
    fn test_edhoc_buffer() {
        let mut buffer = crate::EdhocBuffer::<5>::new();
        assert_eq!(buffer.len, 0);
        assert_eq!(buffer.content, [0; 5]);

        buffer.push(1).unwrap();
        assert_eq!(buffer.len, 1);
        assert_eq!(buffer.content, [1, 0, 0, 0, 0]);
    }

    #[test]
    fn test_new_from_slice() {
        let buffer = crate::EdhocBuffer::<5>::new_from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(buffer.len, 3);
        assert_eq!(buffer.content, [1, 2, 3, 0, 0]);
    }
}
