pub mod sled;

pub use self::sled::Clerk as Sled;

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use houseflow_types::code::VerificationCode;
use houseflow_types::user;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sled error: {0}")]
    Sled(#[from] ::sled::Error),
    #[error("invalid data {0}")]
    InvalidData(String),
    #[error("bincode: {0}")]
    Bincode(#[from] bincode::Error),
}

#[async_trait]
pub trait Clerk: Send + Sync {
    async fn get(&self, code: &VerificationCode) -> Result<Option<user::ID>, Error>;
    async fn add(
        &self,
        code: VerificationCode,
        user_id: user::ID,
        expire_at: DateTime<Utc>,
    ) -> Result<(), Error>;
    async fn remove(&self, code: &VerificationCode) -> Result<bool, Error>;
    async fn clean(&self) -> Result<(), Error>;
    fn count_verification_codes_for_user(&self, user_id: &user::ID) -> Result<usize, Error>;
}

impl From<Error> for houseflow_types::errors::ServerError {
    fn from(val: Error) -> Self {
        houseflow_types::errors::InternalError::Clerk(val.to_string()).into()
    }
}
