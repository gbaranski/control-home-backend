use actix_web::{
    get, http, post,
    web::{self, Json},
    HttpRequest, HttpResponse, Responder,
};
use actix_web_actors::ws;
pub use config::Config;
use itertools::Itertools;
use lighthouse_proto::{execute, execute_response};
use lighthouse_types::{DeviceError, ExecuteRequest, ExecuteResponse};
use session::Session;
use std::collections::HashMap;
use std::str::FromStr;
use tokio::sync::Mutex;
use types::{DeviceID, DevicePassword};

mod aliases;
pub mod config;
mod session;

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

#[get("/ws")]
async fn on_websocket(
    req: HttpRequest,
    stream: web::Payload,
    app_state: web::Data<AppState>,
) -> impl Responder {
    let address = req.peer_addr().unwrap();
    let (device_id, device_password) = match parse_authorization_header(&req) {
        Ok(v) => v,
        Err(err) => {
            log::debug!("session init error: {}", err);
            return Ok::<HttpResponse, actix_web::Error>(HttpResponse::BadRequest().body(err));
        } // TODO: Consider changing Ok to Err
    };
    log::debug!(
        "DeviceID: {}, DevicePassword: {}",
        device_id,
        device_password
    );
    let session = Session::new(device_id.clone(), address);
    let (address, response) = ws::start_with_addr(session, &req, stream).unwrap();
    app_state.sessions.lock().await.insert(device_id, address);
    log::debug!("Response: {:?}", response);
    Ok(response)
}

#[post("/execute")]
async fn on_execute(
    request: Json<ExecuteRequest>,
    app_state: web::Data<AppState>,
) -> Result<Json<ExecuteResponse>, DeviceError> {
    let response: execute_response::Frame = app_state
        .sessions
        .lock()
        .await
        .get(&request.device_id)
        .ok_or(DeviceError::NotConnected)?
        .send(aliases::ActorExecuteFrame::from(request.frame.clone()))
        .await
        .unwrap()
        .unwrap()
        .into();

    let response = ExecuteResponse::Ok(response);

    log::debug!("Response: {:?}", response);
    Ok(Json(response))
}

#[derive(Default)]
pub struct AppState {
    sessions: Mutex<HashMap<DeviceID, actix::Addr<Session>>>,
}

pub fn configure(cfg: &mut web::ServiceConfig, app_state: web::Data<AppState>) {
    cfg.app_data(app_state).service(on_websocket).service(
        web::scope("/")
            .guard(actix_web::guard::Host("127.0.0.1"))
            .service(on_execute),
    );
}
