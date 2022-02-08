use crate::extractors::UserID;
use crate::State;
use axum::extract::Extension;
use axum::Json;
use houseflow_types::auth::whoami::Request;
use houseflow_types::auth::whoami::Response;
use houseflow_types::errors::AuthError;
use houseflow_types::errors::ServerError;

#[tracing::instrument(name = "Whoami", skip(state, _request), err)]
pub async fn handle(
    Extension(state): Extension<State>,
    UserID(user_id): UserID,
    Json(_request): Json<Request>,
) -> Result<Json<Response>, ServerError> {
    let user = state
        .config
        .get()
        .get_user(&user_id)
        .ok_or(AuthError::UserNotFound)?
        .to_owned();

    tracing::info!(username = %user.username, email = %user.email);

    Ok(Json(Response {
        username: user.username,
        email: user.email,
    }))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;
    use axum::Json;

    #[tokio::test]
    async fn valid() {
        let user = get_user();
        let state = get_state(GetState {
            users: vec![user.clone()],
            ..Default::default()
        });
        let Json(response) = super::handle(
            state.clone(),
            crate::extractors::UserID(user.id),
            Json(super::Request {}),
        )
        .await
        .unwrap();
        assert_eq!(response.email, user.email);
        assert_eq!(response.username, user.username);
    }
}
