use crate::extractors::RefreshToken;
use crate::State;
use axum::extract::Extension;
use axum::Json;
use chrono::Duration;
use chrono::Utc;
use houseflow_types::auth::token::Request;
use houseflow_types::auth::token::Response;
use houseflow_types::errors::ServerError;
use houseflow_types::token::AccessToken;
use houseflow_types::token::AccessTokenPayload;
use tracing::Level;

#[tracing::instrument(name = "Refresh token", skip(state, _request), err)]
pub async fn handle(
    Extension(state): Extension<State>,
    RefreshToken(refresh_token): RefreshToken,
    Json(_request): Json<Request>,
) -> Result<Json<Response>, ServerError> {
    let access_token_payload = AccessTokenPayload {
        sub: refresh_token.sub.clone(),
        exp: Utc::now() + Duration::minutes(10),
    };
    let access_token = AccessToken::new(
        state.config.secrets.access_key.as_bytes(),
        access_token_payload,
    );

    tracing::event!(Level::INFO, user_id = %refresh_token.sub, "Refreshed token");

    Ok(Json(Response {
        refresh_token: None,
        access_token: access_token.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;
    use axum::Json;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn valid() {
        let user = get_user();
        let state = get_state(
            &mpsc::unbounded_channel().0,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![user.clone()],
        );
        let refresh_token = houseflow_types::token::RefreshToken::new(
            state.config.secrets.refresh_key.as_bytes(),
            houseflow_types::token::RefreshTokenPayload {
                sub: user.id.clone(),
                exp: None,
            },
        );
        let Json(response) = super::handle(
            state.clone(),
            crate::extractors::RefreshToken(refresh_token.clone()),
            Json(super::Request {}),
        )
        .await
        .unwrap();
        let access_token = houseflow_types::token::AccessToken::decode(
            state.config.secrets.access_key.as_bytes(),
            &response.access_token,
        )
        .unwrap();
        assert_eq!(access_token.sub, refresh_token.sub);
    }
}
