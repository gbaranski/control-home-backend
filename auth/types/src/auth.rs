use houseflow_token::Token;
use houseflow_types::UserAgent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub user_agent: UserAgent,
}

pub type LoginResponse = Result<LoginResponseBody, LoginError>;

#[derive(Debug, Clone, Deserialize, Serialize, thiserror::Error)]
pub enum LoginError {
    #[error("invalid password")]
    InvalidPassword,

    #[error("user not found")]
    UserNotFound,


    #[error("internal error: `{0}`")]
    // Replace it with better type if needed
    InternalError(String)
}

#[cfg(feature = "houseflow-db")]
impl From<houseflow_db::Error> for LoginError {
    fn from(v: houseflow_db::Error) -> Self {
        LoginError::InternalError(v.to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginResponseBody {
    pub refresh_token: Token,
    pub access_token: Token,
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for LoginError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;

        match self {
            LoginError::InvalidPassword => StatusCode::BAD_REQUEST,
            LoginError::UserNotFound => StatusCode::NOT_FOUND,
            LoginError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        let json = actix_web::web::Json(self);
        actix_web::HttpResponse::build(self.status_code()).json(json)
    }

}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
}

pub type RegisterResponse = Result<RegisterResponseBody, RegisterError>;

#[derive(Debug, Clone, Deserialize, Serialize, thiserror::Error)]
pub enum RegisterError {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterResponseBody {
    pub refresh_token: Token,
    pub access_token: Token,
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for RegisterError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        todo!()
    }
}