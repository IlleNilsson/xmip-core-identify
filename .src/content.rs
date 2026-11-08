//! A Stream's content as a technology that reads a claim in it reads it:
//! content that could not be read is an error, never content that names
//! nothing.

use crate::IdentifyError;

/// Content that could not be read, in what a technology reads: never taken
/// for content that names nothing.
impl From<stream::Unread> for IdentifyError {
    fn from(unread: stream::Unread) -> Self {
        Self::new(unread.to_string())
    }
}

/// A Stream's content as text, for a technology that reads a claim in it:
/// `None` where it was read and is not UTF-8, for the technology to judge,
/// and an error where it could not be read, which is never "no claim".
///
/// # Errors
/// The content could not be read.
pub fn text(stream: &stream::Stream) -> Result<Option<&str>, IdentifyError> {
    match stream.text() {
        Ok(text) => Ok(Some(text)),
        Err(stream::TextError::NotUtf8(_)) => Ok(None),
        Err(stream::TextError::Unread(unread)) => Err(unread.into()),
    }
}
