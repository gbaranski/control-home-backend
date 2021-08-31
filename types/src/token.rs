use crate::errors::TokenError as Error;
use crate::UserID;
use chrono::DateTime;
use chrono::Utc;
use serde::de;
use serde::ser;
use serde::Deserialize;
use serde::Serialize;

pub type Signature = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    alg: Algorithm,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Token<P: ser::Serialize + de::DeserializeOwned> {
    header: Header,
    payload: P,
    signature: Signature,
}

impl<P: ser::Serialize + de::DeserializeOwned> std::fmt::Display for Token<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl<P: ser::Serialize + de::DeserializeOwned> std::fmt::Debug for Token<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl<P: ser::Serialize + de::DeserializeOwned> std::ops::Deref for Token<P> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

pub type AccessToken = Token<AccessTokenPayload>;
pub type RefreshToken = Token<RefreshTokenPayload>;
pub type AuthorizationCode = Token<AuthorizationCodePayload>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenPayload {
    pub sub: UserID,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodePayload {
    pub sub: UserID,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenPayload {
    pub sub: UserID,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub exp: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasePayload {
    #[serde(with = "chrono::serde::ts_seconds_option")]
    exp: Option<DateTime<Utc>>,
}

fn base64_encode(val: &[u8]) -> String {
    base64::encode_config(&val, base64::URL_SAFE_NO_PAD)
}

fn base64_decode(val: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(val, base64::URL_SAFE_NO_PAD)
}

fn encode_part<T: ser::Serialize>(val: &T) -> String {
    let string = serde_json::to_string(val).unwrap();
    base64_encode(string.as_bytes())
}

fn decode_part<T: de::DeserializeOwned>(val: &str) -> Result<T, Error> {
    let json_bytes = base64_decode(val).map_err(|err| Error::InvalidEncoding(err.to_string()))?;
    let json =
        String::from_utf8(json_bytes).map_err(|err| Error::InvalidEncoding(err.to_string()))?;
    serde_json::from_str(&json).map_err(|err| Error::InvalidJSON(err.to_string()))
}

use ring::hmac;

impl<P: ser::Serialize + de::DeserializeOwned> Token<P> {
    pub fn new(key: &[u8], payload: P) -> Self {
        const ALGORITHM: Algorithm = Algorithm::HS256; // that can be changed in the future
        const HEADER: Header = Header { alg: ALGORITHM };

        let raw_header = encode_part(&HEADER);
        let raw_payload = encode_part(&payload);
        let message = [raw_header, raw_payload].join(".");
        let signature: Signature = match ALGORITHM {
            Algorithm::HS256 => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, key);
                Vec::from(hmac::sign(&key, message.as_bytes()).as_ref())
            }
        };

        Self {
            header: HEADER,
            payload,
            signature,
        }
    }

    pub fn encode(&self) -> String {
        let raw_header = encode_part(&self.header);
        let raw_payload = encode_part(&self.payload);
        let raw_signature = base64_encode(&self.signature);
        [raw_header, raw_payload, raw_signature].join(".")
    }

    pub fn decode_unsafe(token: &str) -> Result<Self, Error> {
        let mut iter = token.split('.');
        let raw_header = iter.next().ok_or(Error::MissingHeader)?;
        let raw_payload = iter.next().ok_or(Error::MissingPayload)?;
        let raw_signature = iter.next().ok_or(Error::MissingSignature)?;

        let header = decode_part::<Header>(raw_header)?;
        let signature =
            base64_decode(raw_signature).map_err(|err| Error::InvalidEncoding(err.to_string()))?;

        let payload_base = decode_part::<BasePayload>(raw_payload)?;
        validate(&payload_base)?;
        let payload = decode_part::<P>(raw_payload)?;
        let token = Token {
            header,
            payload,
            signature,
        };

        Ok(token)
    }

    pub fn decode_unsafe_novalidate(token: &str) -> Result<Self, Error> {
        let mut iter = token.split('.');
        let raw_header = iter.next().ok_or(Error::MissingHeader)?;
        let raw_payload = iter.next().ok_or(Error::MissingPayload)?;
        let raw_signature = iter.next().ok_or(Error::MissingSignature)?;

        let header = decode_part::<Header>(raw_header)?;
        let signature =
            base64_decode(raw_signature).map_err(|err| Error::InvalidEncoding(err.to_string()))?;

        let payload = decode_part::<P>(raw_payload)?;
        let token = Token {
            header,
            payload,
            signature,
        };

        Ok(token)
    }

    pub fn decode(key: &[u8], token: &str) -> Result<Self, Error> {
        let mut iter = token.split('.');
        let raw_header = iter.next().ok_or(Error::MissingHeader)?;
        let raw_payload = iter.next().ok_or(Error::MissingPayload)?;
        let raw_signature = iter.next().ok_or(Error::MissingSignature)?;

        let header = decode_part::<Header>(raw_header)?;
        let signature =
            base64_decode(raw_signature).map_err(|err| Error::InvalidEncoding(err.to_string()))?;

        let is_signature_valid = match header.alg {
            Algorithm::HS256 => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, key);
                hmac::verify(
                    &key,
                    [raw_header, raw_payload].join(".").as_bytes(),
                    &signature,
                )
                .is_ok()
            }
        };
        if !is_signature_valid {
            return Err(Error::InvalidSignature);
        }

        let payload_base = decode_part::<BasePayload>(raw_payload)?;
        validate(&payload_base)?;
        let payload = decode_part::<P>(raw_payload)?;
        let token = Token {
            header,
            payload,
            signature,
        };

        Ok(token)
    }
}

fn validate(base_payload: &BasePayload) -> Result<(), Error> {
    if let Some(exp) = base_payload.exp {
        let difference = Utc::now().timestamp() - exp.timestamp();
        if difference > 0 {
            return Err(Error::Expired {
                seconds: difference as u64,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::SubsecRound;
    use rand::random;

    fn get_key() -> Vec<u8> {
        use rand::RngCore;
        let mut bytes = [0; 32];
        rand::thread_rng().fill_bytes(&mut bytes);

        Vec::from(bytes)
    }

    mod at {
        use super::*;

        #[test]
        fn valid() {
            let key = get_key();
            let payload = AccessTokenPayload {
                sub: random(),
                exp: Utc::now().round_subsecs(0) + chrono::Duration::hours(1),
            };
            let token = AccessToken::new(&key, payload);
            let encoded = token.encode();
            let decoded = AccessToken::decode(&key, &encoded).unwrap();
            assert_eq!(token, decoded);
        }

        #[test]
        fn expired() {
            let key = get_key();
            let expired_by = chrono::Duration::hours(1);
            let payload = AccessTokenPayload {
                sub: random(),
                exp: Utc::now() - expired_by,
            };
            let token = AccessToken::new(&key, payload);
            let encoded = token.encode();
            let err = Token::<AccessTokenPayload>::decode(&key, &encoded).unwrap_err();
            assert_eq!(
                err,
                Error::Expired {
                    seconds: expired_by.num_seconds() as u64
                }
            );
        }

        #[test]
        fn invalid_signature() {
            let valid_key = get_key();
            let invalid_key = get_key();
            let payload = AccessTokenPayload {
                sub: random(),
                exp: Utc::now() - chrono::Duration::hours(1),
            };
            let token = AccessToken::new(&valid_key, payload);
            let encoded = token.encode();
            let err = AccessToken::decode(&invalid_key, &encoded).unwrap_err();
            assert_eq!(err, Error::InvalidSignature);
        }
    }

    mod rt {
        use super::*;

        #[test]
        fn valid_with_exp() {
            let key = get_key();
            let payload = RefreshTokenPayload {
                sub: random(),
                exp: Some(Utc::now().round_subsecs(0) + chrono::Duration::hours(1)),
            };
            let token = RefreshToken::new(&key, payload);
            let encoded = token.encode();
            let decoded = RefreshToken::decode(&key, &encoded).unwrap();
            assert_eq!(token, decoded);
        }

        #[test]
        fn valid_without_exp() {
            let key = get_key();
            let payload = RefreshTokenPayload {
                sub: random(),
                exp: None,
            };
            let token = RefreshToken::new(&key, payload);
            let encoded = token.encode();
            let decoded = RefreshToken::decode(&key, &encoded).unwrap();
            assert_eq!(token, decoded);
        }

        #[test]
        fn expired() {
            let key = get_key();
            let expired_by = chrono::Duration::hours(1);
            let payload = RefreshTokenPayload {
                sub: random(),
                exp: Some(Utc::now() - expired_by),
            };
            let token = Token::new(&key, payload);
            let encoded = token.encode();
            let err = RefreshToken::decode(&key, &encoded).unwrap_err();
            assert_eq!(
                err,
                Error::Expired {
                    seconds: expired_by.num_seconds() as u64
                }
            );
        }

        #[test]
        fn invalid_signature() {
            let valid_key = get_key();
            let invalid_key = get_key();
            let payload = RefreshTokenPayload {
                sub: random(),
                exp: Some(Utc::now().round_subsecs(0) + chrono::Duration::hours(1)),
            };
            let token = RefreshToken::new(&valid_key, payload);
            let encoded = token.encode();
            let err = RefreshToken::decode(&invalid_key, &encoded).unwrap_err();
            assert_eq!(err, Error::InvalidSignature);
        }
    }
}
