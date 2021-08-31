use crate::State;
use axum::extract::Extension;
use axum::extract::Form;
use axum::extract::Query;
use chrono::Duration;
use chrono::Utc;
use houseflow_types::auth::login::Request;
use houseflow_types::token::AuthorizationCode;
use houseflow_types::token::AuthorizationCodePayload;

use super::verify_redirect_uri;
use super::AuthorizationRequestQuery;
use super::Error;

#[tracing::instrument(
    name = "Login",
    skip(state, request, query),
    fields(
        email = %request.email,
    ),
    err,
)]
pub async fn handle(
    Extension(state): Extension<State>,
    Form(request): Form<Request>,
    Query(query): Query<AuthorizationRequestQuery>,
) -> Result<http::Response<axum::body::Body>, Error> {
    validator::Validate::validate(&request)
        .map_err(|err| Error::InvalidRequest(Some(err.to_string())))?;
    let user = state
        .config
        .get_user_by_email(&request.email)
        .ok_or_else(|| Error::InvalidGrant(Some(String::from("user not found"))))?;

    let google_config = state.config.google.as_ref().unwrap();
    if *query.client_id != *google_config.client_id {
        return Err(Error::InvalidClient(Some(String::from(
            "invalid client id",
        ))));
    }
    verify_redirect_uri(&query.redirect_uri, &google_config.project_id)
        .map_err(|err| Error::InvalidRequest(Some(err.to_string())))?;
    let authorization_code_payload = AuthorizationCodePayload {
        sub: user.id,
        exp: Utc::now() + Duration::minutes(10),
    };
    let authorization_code = AuthorizationCode::new(
        state.config.secrets.authorization_code_key.as_bytes(),
        authorization_code_payload,
    );
    let mut redirect_uri = query.redirect_uri;
    redirect_uri.set_query(Some(&format!(
        "code={}&state={}",
        authorization_code, query.state
    )));

    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header("Location", redirect_uri.to_string())
        .body(axum::body::Body::empty())
        .unwrap())
}
