use super::Error;
use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use houseflow_types::code::VerificationCode;
use houseflow_types::UserID;
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

const JANITOR_CLEAN_INTERVAL: Duration = Duration::from_secs(60 * 30); // 30 minutes

type JanitorTask = tokio::task::JoinHandle<Result<(), Error>>;

#[derive(Clone)]
pub struct Clerk {
    database: sled::Db,
    janitor_handle: Arc<Mutex<Option<JanitorTask>>>,
}

impl Clerk {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let config = sled::Config::new().path(path);
        Self::with_config(config)
    }

    pub fn new_temporary(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let config = sled::Config::new().path(path).temporary(true);
        Self::with_config(config)
    }

    pub fn with_config(config: sled::Config) -> Result<Self, Error> {
        let clerk = Self {
            database: config.open()?,
            janitor_handle: Arc::new(Mutex::new(None)),
        };
        let janitor_handle = {
            let clerk = clerk.clone();
            tokio::spawn(async move {
                loop {
                    super::Clerk::clean(&clerk).await?;
                    tokio::time::sleep(JANITOR_CLEAN_INTERVAL).await;
                }
            })
        };
        *clerk.janitor_handle.lock().unwrap() = Some(janitor_handle);
        Ok(clerk)
    }
}

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
struct EntryValue {
    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
    user_id: UserID,
}

impl EntryValue {
    pub fn has_expired(&self) -> bool {
        self.expires_at.timestamp() < Utc::now().timestamp()
    }
}

impl TryFrom<&sled::IVec> for EntryValue {
    type Error = Error;

    fn try_from(value: &sled::IVec) -> Result<Self, Self::Error> {
        Ok(bincode::deserialize(value)?)
    }
}

#[async_trait]
impl super::Clerk for Clerk {
    async fn get(&self, code: &VerificationCode) -> Result<Option<UserID>, Error> {
        let result = match self.database.get(code)? {
            Some(vec) => {
                let entry: EntryValue = bincode::deserialize(&vec)?;
                if entry.has_expired() {
                    self.remove(code).await?;
                    None
                } else {
                    Some(entry.user_id)
                }
            }
            None => None,
        };
        Ok(result)
    }

    async fn remove(&self, code: &VerificationCode) -> Result<bool, Error> {
        let did_exist = self.database.remove(code)?.is_some();
        self.database.flush_async().await?;
        Ok(did_exist)
    }

    async fn add(
        &self,
        code: VerificationCode,
        user_id: UserID,
        expire_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let entry_value = EntryValue {
            user_id,
            expires_at: expire_at,
        };
        let serialized = bincode::serialize(&entry_value)?;
        self.database.insert(code, serialized)?;
        Ok(())
    }

    async fn clean(&self) -> Result<(), Error> {
        self.database
            .iter()
            .filter_map(|kv| {
                let (key, value) = kv.unwrap();
                let value: EntryValue = bincode::deserialize(&value).unwrap();
                if value.has_expired() {
                    Some(key)
                } else {
                    None
                }
            })
            .for_each(|key| {
                self.database.remove(&key).unwrap();
            });
        self.database.flush_async().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::super::Clerk as _;
    use super::*;
    use chrono::Duration;

    fn get_clerk() -> Clerk {
        let path = std::env::temp_dir().join(format!("houseflow-clerk-{}", rand::random::<u32>()));
        Clerk::new_temporary(path).unwrap()
    }

    #[tokio::test]
    async fn add_get_remove() {
        let clerk = get_clerk();
        let user_id: UserID = random();
        let verification_code: VerificationCode = random();
        clerk
            .add(
                verification_code.clone(),
                user_id.clone(),
                Utc::now() + Duration::minutes(10),
            )
            .await
            .unwrap();
        assert_eq!(
            clerk.get(&verification_code).await.unwrap().unwrap(),
            user_id
        );
        assert_eq!(clerk.remove(&verification_code).await.unwrap(), true);
        clerk.remove(&verification_code).await.unwrap();
        assert!(clerk.get(&verification_code).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired() {
        let clerk = get_clerk();
        let user_id: UserID = random();
        let verification_code: VerificationCode = random();
        clerk
            .add(
                verification_code.clone(),
                user_id.clone(),
                Utc::now() - Duration::minutes(10),
            )
            .await
            .unwrap();
        assert!(clerk.get(&verification_code).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clean() {
        let clerk = get_clerk();
        let user_id: UserID = random();
        let verification_code_expired: VerificationCode = random();

        clerk
            .add(
                verification_code_expired.clone(),
                user_id.clone(),
                Utc::now() - Duration::minutes(10),
            )
            .await
            .unwrap();

        let verification_code: VerificationCode = random();
        clerk
            .add(
                verification_code.clone(),
                user_id.clone(),
                Utc::now() + Duration::minutes(10),
            )
            .await
            .unwrap();

        clerk.clean().await.unwrap();
        assert!(clerk
            .get(&verification_code_expired)
            .await
            .unwrap()
            .is_none(),);
        assert_eq!(
            clerk.get(&verification_code).await.unwrap().unwrap(),
            user_id
        );
    }
}
