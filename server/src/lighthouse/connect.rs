use super::Session;
use crate::Sessions;
use actix_web::{http, web, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use houseflow_db::Database;
use houseflow_types::{lighthouse::ConnectResponseError, DeviceID, DevicePassword};
use itertools::Itertools;
use std::str::FromStr;

fn parse_authorization_header(req: &HttpRequest) -> Result<(DeviceID, DevicePassword), String> {
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| String::from("`Authorization` header is missing"))?
        .to_str()
        .map_err(|err| format!("Invalid string `Authorization` header, error: `{}`", err))?;

    let mut iter = header.split_whitespace();
    let auth_type = iter
        .next()
        .ok_or("Missing auth type in `Authorization` header")?;
    if auth_type != "Basic" {
        return Err(format!("Invalid auth type: {}", auth_type));
    }
    let credentials = iter
        .next()
        .ok_or("Missing credentials in `Authorization` header")?;

    let (device_id, device_password) = credentials
        .split_terminator(':')
        .take(2)
        .next_tuple()
        .ok_or("Missing ID/Password in `Authorization` header")?;

    Ok((
        DeviceID::from_str(device_id).map_err(|err| err.to_string())?,
        DevicePassword::from_str(device_password).map_err(|err| err.to_string())?,
    ))
}

pub async fn on_websocket(
    req: HttpRequest,
    stream: web::Payload,
    sessions: web::Data<Sessions>,
    database: web::Data<dyn Database>,
) -> Result<HttpResponse, ConnectResponseError> {
    let address = req.peer_addr().unwrap();
    let (device_id, device_password) = parse_authorization_header(&req)
        .map_err(ConnectResponseError::InvalidAuthorizationHeader)?;

    let device = database
        .get_device(&device_id)
        .map_err(|err| ConnectResponseError::InternalError(err.to_string()))?
        .ok_or(ConnectResponseError::InvalidCredentials)?;

    if !argon2::verify_encoded(
        &device
            .password_hash
            .expect("missing password hash in device from database"),
        device_password.as_bytes(),
    )
    .unwrap()
    {
        return Err(ConnectResponseError::InvalidCredentials);
    }

    if sessions.lock().unwrap().contains_key(&device_id) {
        return Err(ConnectResponseError::AlreadyConnected);
    }

    let session = Session::new(device_id.clone(), address, sessions.clone().into_inner());
    let (address, response) = ws::start_with_addr(session, &req, stream)
        .map_err(|err| ConnectResponseError::HandshakeError(err.to_string()))?;
    sessions.lock().unwrap().insert(device_id, address);

    Ok(response)
}
