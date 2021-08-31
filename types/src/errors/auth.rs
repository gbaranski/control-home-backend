use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, thiserror::Error)]
pub enum Error {
    /// `Authorization` header has invalid syntax
    #[error("invalid authorization header: {0}")]
    InvalidAuthorizationHeader(String),

    /// Client sent invalid token
    #[error("invalid token: {0}")]
    InvalidToken(#[from] super::token::Error),

    /// Client sent invalid verification code
    #[error("invalid verification code: {0}")]
    InvalidVerificationCode(crate::code::Error),

    /// Clerk does not know about the specified verification code
    #[error("clerk doesn't know about the specified verification code")]
    VerificationCodeUnknownByClerk,

    /// Verification code has invalid User ID
    #[error("verification code has invalid user id")]
    VerificationCodeInvalidUserID,

    /// When password hashes doesn't match with the one from database
    #[error("invalid password")]
    InvalidPassword,

    /// When client tries to authenticate, but user with given credentails have not been found
    #[error("user not found")]
    UserNotFound,

    /// When device tries to authenticate, but device with given credentails have not been found
    #[error("device not found")]
    DeviceNotFound,

    /// Occurs when user tries to register, but user with given credentials already exists
    #[error("user already exists")]
    UserAlreadyExists,

    /// Refresh token is blacklisted
    #[error("refresh token is blacklisted")]
    RefreshTokenBlacklisted,

    /// User does not have permission to a device
    #[error("user does not have permission to a specified device")]
    NoDevicePermission,
}
