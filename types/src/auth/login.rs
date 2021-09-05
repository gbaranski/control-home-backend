use crate::code::VerificationCode;
use serde::Deserialize;
use serde::Serialize;
use validator::Validate;

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
#[serde(rename_all = "kebab-case")]
pub struct Request {
    #[validate(email)]
    pub email: String,
    pub verification_code: Option<VerificationCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    LoggedIn {
        access_token: String,
        refresh_token: String,
    },
    VerificationCodeSent,
}
