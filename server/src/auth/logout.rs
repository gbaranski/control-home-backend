use crate::{extractors::RefreshToken, Error, State};
use axum::{extract, response};
use houseflow_types::auth::logout::{Request, Response};
use tracing::Level;

#[tracing::instrument(name = "Logout", skip(state, _request, refresh_token))]
pub async fn handle(
    extract::Extension(state): extract::Extension<State>,
    extract::Json(_request): extract::Json<Request>,
    RefreshToken(refresh_token): RefreshToken,
) -> Result<response::Json<Response>, Error> {
    state.token_store.remove(&refresh_token.tid).await.unwrap();
    tracing::event!(Level::INFO, user_id = %refresh_token.sub);
    Ok(response::Json(Response {}))
}
