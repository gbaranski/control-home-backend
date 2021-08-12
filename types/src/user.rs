use crate::common::Credential;
use serde::{Deserialize, Serialize};

pub type UserID = Credential<16>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Unique ID of the user
    pub id: UserID,

    /// Name of the user
    pub username: String,

    /// Email of the user
    pub email: String,

    /// Hashed user password
    pub password_hash: String,
}
