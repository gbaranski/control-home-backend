use bytes::{Buf, BufMut};
use std::{convert::TryInto, str::FromStr};
use thiserror::Error;

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct Credential<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> Credential<N> {
    pub const SIZE: usize = N;

    pub fn into_bytes(self) -> [u8; N] {
        self.inner
    }

    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self::from(bytes)
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.inner);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CredentialError> {
        if buf.remaining() < N {
            return Err(CredentialError::InvalidSize {
                expected: N,
                received: buf.remaining(),
            });
        }

        let mut inner = [0; N];
        buf.copy_to_slice(&mut inner);
        Ok(Self { inner })
    }
}

impl<const N: usize> AsRef<[u8]> for Credential<N> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialError {
    #[error("Invalid size, expected: {expected}, received: {received}")]
    InvalidSize { expected: usize, received: usize },

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),
}

impl<const N: usize> From<[u8; N]> for Credential<N> {
    fn from(v: [u8; N]) -> Self {
        Self { inner: v }
    }
}

impl<const N: usize> From<Credential<N>> for [u8; N] {
    fn from(val: Credential<N>) -> Self {
        val.inner
    }
}

impl<const N: usize> Default for Credential<N> {
    fn default() -> Self {
        Self { inner: [0; N] }
    }
}

impl<const N: usize> From<Credential<N>> for String {
    fn from(val: Credential<N>) -> Self {
        hex::encode(val.inner)
    }
}

impl<const N: usize> FromStr for Credential<N> {
    type Err = CredentialError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        // N * 2 because encoding with hex doubles the size

        if v.len() == N * 2 {
            Ok(Self {
                inner: hex::decode(v)
                    .map_err(|err| CredentialError::InvalidEncoding(err.to_string()))?
                    .try_into()
                    .unwrap(),
            })
        } else {
            Err(CredentialError::InvalidSize {
                expected: N * 2,
                received: v.len(),
            })
        }
    }
}

impl<const N: usize> std::fmt::Display for Credential<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(self.inner))
    }
}

impl<const N: usize> std::fmt::Debug for Credential<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(self.inner))
    }
}

impl<const N: usize> rand::distributions::Distribution<Credential<N>>
    for rand::distributions::Standard
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Credential<N> {
        Credential {
            inner: (0..N)
                .map(|_| rng.gen())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        }
    }
}

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

struct CredentialVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for CredentialVisitor<N> {
    type Value = Credential<N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!("an array of length {}", N))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Credential::from_str(v).map_err(|err| {
            E::invalid_value(
                serde::de::Unexpected::Other(err.to_string().as_str()),
                &"hex encoded credential",
            )
        })
    }
}

impl<'de, const N: usize> Deserialize<'de> for Credential<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CredentialVisitor::<N>)
    }
}

impl<const N: usize> Serialize for Credential<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "rusqlite")]
impl<const N: usize> rusqlite::ToSql for Credential<N> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::Owned(
            rusqlite::types::Value::Text(self.to_string()),
        ))
    }
}

#[cfg(feature = "rusqlite")]
impl<const N: usize> rusqlite::types::FromSql for Credential<N> {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Self::from_str(value.as_str()?)
            .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    const SIZE: usize = 32;

    #[test]
    fn test_buffer_parse() {
        let mut buf = BytesMut::with_capacity(SIZE);
        let credential: Credential<SIZE> = rand::random();
        credential.encode(&mut buf);
        let parsed_credential = Credential::<SIZE>::decode(&mut buf)
            .expect("reading Credential from buffer returned Error");
        assert_eq!(credential, parsed_credential);
    }

    #[test]
    fn test_buffer_parse_underflow() {
        let mut buf = BytesMut::with_capacity(SIZE);
        let credential: Credential<SIZE> = rand::random();
        credential.encode(&mut buf);
        buf = buf[0..SIZE - 1].into(); // Malform some last bytes of Buf
        Credential::<SIZE>::decode(&mut buf)
            .expect_err("reading malformed Credential from buffer did not return Error");
    }
}
