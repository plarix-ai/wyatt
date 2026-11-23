//! Errors found while loading a policy. Each one names where in the file it is.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub at: String,
    pub msg: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.at.is_empty() { f.write_str(&self.msg) } else { write!(f, "{}: {}", self.at, self.msg) }
    }
}

#[derive(Debug)]
pub struct PolicyErrors(pub Vec<PolicyError>);

impl fmt::Display for PolicyErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyErrors {}
