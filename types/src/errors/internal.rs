use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("clerk: {0}")]
    Clerk(String),
    #[error("mailer: {0}")]
    Mailer(String),
    #[error("other: {0}")]
    Other(String),
}
