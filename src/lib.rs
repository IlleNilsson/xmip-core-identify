#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use xmip_party::Party;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentificationEvidence {
    pub scheme: String,
    pub value: String,
}

#[derive(Debug)]
pub struct IdentifyError {
    pub message: String,
}

impl fmt::Display for IdentifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.message) }
}
impl Error for IdentifyError {}

pub trait Identifier: Send + Sync {
    fn identify(&self, evidence: &IdentificationEvidence) -> Result<Option<Party>, IdentifyError>;
}
