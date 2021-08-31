use std::str::FromStr;

use crate::State;
use axum::extract::Extension;
use axum::Json;
use chrono::Duration;
use chrono::Utc;
use houseflow_types::auth::login::Request;
use houseflow_types::auth::login::Response;
use houseflow_types::code::VerificationCode;
use houseflow_types::errors::AuthError;
use houseflow_types::errors::ServerError;
use houseflow_types::token::AccessToken;
use houseflow_types::token::AccessTokenPayload;
use houseflow_types::token::RefreshToken;
use houseflow_types::token::RefreshTokenPayload;
use tracing::Level;

const VERIFICATION_CODE_DURATION: std::time::Duration = std::time::Duration::from_secs(60 * 30);

#[tracing::instrument(
    name = "Login",
    skip(state, request),
    fields(
        email = %request.email,
    ),
    err,
)]
pub async fn handle(
    Extension(state): Extension<State>,
    Json(request): Json<Request>,
) -> Result<Json<Response>, ServerError> {
    validator::Validate::validate(&request)?;
    let user = state
        .config
        .get_user_by_email(&request.email)
        .ok_or(AuthError::UserNotFound)?;

    let response = match request.verification_code {
        Some(verification_code) => {
            let verification_code = VerificationCode::from_str(&verification_code)
                .map_err(AuthError::InvalidVerificationCode)?;
            let user_id = state
                .clerk
                .get(&verification_code)
                .await?
                .ok_or(AuthError::VerificationCodeUnknownByClerk)?;
            if user_id != user.id {
                return Err(AuthError::VerificationCodeInvalidUserID.into());
            }
            let refresh_token = RefreshToken::new(
                state.config.secrets.refresh_key.as_bytes(),
                RefreshTokenPayload {
                    sub: user.id.clone(),
                    exp: Some(Utc::now() + Duration::days(7)),
                },
            );
            let access_token = AccessToken::new(
                state.config.secrets.access_key.as_bytes(),
                AccessTokenPayload {
                    sub: user.id.clone(),
                    exp: Utc::now() + Duration::minutes(10),
                },
            );
            tracing::event!(Level::INFO, user_id = %user.id, "Logged in");
            Response::LoggedIn {
                access_token: access_token.encode(),
                refresh_token: refresh_token.encode(),
            }
        }
        None => {
            let verification_code: VerificationCode = rand::random();
            state
                .clerk
                .add(
                    verification_code.clone(),
                    user.id.clone(),
                    Utc::now() + chrono::Duration::from_std(VERIFICATION_CODE_DURATION).unwrap(),
                )
                .await?;
            state
                .mailer
                .send_verification_code(&user.email, &verification_code)
                .await?;
            Response::VerificationCodeSent
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::Request;
    use super::Response;
    use super::VERIFICATION_CODE_DURATION;
    use crate::test_utils::*;
    use axum::Json;
    use chrono::Utc;
    use houseflow_types::code::VerificationCode;
    use houseflow_types::errors::AuthError;
    use houseflow_types::errors::ServerError;
    use houseflow_types::token::AccessToken;
    use houseflow_types::token::RefreshToken;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn valid() {
        let user = get_user();
        let (mailer_tx, mut mailer_rx) = mpsc::unbounded_channel();
        let state = get_state(
            &mailer_tx,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![user.clone()],
        );
        let Json(response) = super::handle(
            state.clone(),
            Json(Request {
                email: user.email.clone(),
                verification_code: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response, Response::VerificationCodeSent);
        let verification_code = mailer_rx.recv().await.unwrap();
        let Json(response) = super::handle(
            state.clone(),
            Json(Request {
                email: user.email.clone(),
                verification_code: Some(verification_code.to_string()),
            }),
        )
        .await
        .unwrap();
        let (at, rt) = match response {
            Response::LoggedIn {
                access_token,
                refresh_token,
            } => (access_token, refresh_token),
            _ => panic!("expected Response::LoggedIn"),
        };
        let (at, rt) = (
            AccessToken::decode(state.config.secrets.access_key.as_bytes(), &at).unwrap(),
            RefreshToken::decode(state.config.secrets.refresh_key.as_bytes(), &rt).unwrap(),
        );
        assert_eq!(at.sub, rt.sub);
    }

    #[tokio::test]
    async fn verification_code_unknown_by_clerk() {
        let user = get_user();
        let state = get_state(
            &mpsc::unbounded_channel().0,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![user.clone()],
        );
        let verification_code: VerificationCode = rand::random();
        let response = super::handle(
            state.clone(),
            Json(Request {
                email: user.email,
                verification_code: Some(verification_code.to_string()),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            response,
            ServerError::AuthError(AuthError::VerificationCodeUnknownByClerk)
        );
    }

    #[tokio::test]
    async fn verification_code_invalid_user_id() {
        let user = get_user();
        let state = get_state(
            &mpsc::unbounded_channel().0,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![user.clone()],
        );
        let verification_code: VerificationCode = rand::random();
        state
            .clerk
            .add(
                verification_code.clone(),
                rand::random(),
                Utc::now() + chrono::Duration::from_std(VERIFICATION_CODE_DURATION).unwrap(),
            )
            .await
            .unwrap();

        let response = super::handle(
            state.clone(),
            Json(Request {
                email: user.email,
                verification_code: Some(verification_code.to_string()),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            response,
            ServerError::AuthError(AuthError::VerificationCodeInvalidUserID)
        );
    }

    #[tokio::test]
    async fn not_existing_user() {
        let user = get_user();
        let state = get_state(
            &mpsc::unbounded_channel().0,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let response = super::handle(
            state.clone(),
            Json(Request {
                email: user.email,
                verification_code: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(response, ServerError::AuthError(AuthError::UserNotFound));
    }
}
