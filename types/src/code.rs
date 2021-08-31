use std::{convert::TryInto, str::FromStr};

#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
    #[error("encoding: {0}")]
    Encoding(String),
    #[error("invalid size. received: {received}. expected: {expected}")]
    InvalidSize { received: usize, expected: usize },
}

const VERIFICATION_CODE_SIZE: usize = 6;

#[derive(Clone)]
pub struct VerificationCode([u8; VERIFICATION_CODE_SIZE]);

impl AsRef<[u8]> for VerificationCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for VerificationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = [0; VERIFICATION_CODE_SIZE * 2];
        hex::encode_to_slice(self.0, &mut bytes).unwrap();
        let string = bytes
            .chunks(2)
            .map(|bytes| std::str::from_utf8(bytes).unwrap())
            .collect::<Vec<_>>()
            .join("-");
        f.write_str(&string)
    }
}

impl std::fmt::Debug for VerificationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl FromStr for VerificationCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.chars().filter(|char| *char != '-').collect::<String>();
        let bytes =
            hex::decode(s).map_err(|err| Error::Encoding(format!("invalid encoding: {}", err)))?;
        let bytes_len = bytes.len();
        Ok(Self(bytes.try_into().map_err(|_| Error::InvalidSize {
            received: bytes_len,
            expected: VERIFICATION_CODE_SIZE,
        })?))
    }
}

impl rand::distributions::Distribution<VerificationCode> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> VerificationCode {
        VerificationCode(
            (0..VERIFICATION_CODE_SIZE)
                .map(|_| rng.gen())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        )
    }
}

use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

struct VerificationCodeVisitor;

impl<'de> Visitor<'de> for VerificationCodeVisitor {
    type Value = VerificationCode;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("verification code in proper format")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        VerificationCode::from_str(v).map_err(|err| {
            E::invalid_value(
                serde::de::Unexpected::Other(err.to_string().as_str()),
                &"verification code",
            )
        })
    }
}

impl<'de> Deserialize<'de> for VerificationCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(VerificationCodeVisitor)
    }
}

impl Serialize for VerificationCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
