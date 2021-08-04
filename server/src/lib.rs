mod extractors;

mod token_store;

mod auth;
mod fulfillment;
mod lighthouse;
// mod oauth;

pub use token_store::{sled::TokenStore as SledTokenStore, TokenStore};

use houseflow_config::server::Config;
use houseflow_db::Database;
use houseflow_types::DeviceID;

use std::{collections::HashMap, sync::Mutex};
pub type Sessions = HashMap<DeviceID, lighthouse::Session>;

pub(crate) fn get_password_salt() -> [u8; 16] {
    rand::random()
}

pub(crate) fn verify_password(hash: &str, password: &str) -> Result<(), Error> {
    match argon2::verify_encoded(hash, password.as_bytes()).unwrap() {
        true => Ok(()),
        false => Err(Error::InvalidPassword.into()),
    }
}

async fn health_check() -> &'static str {
    "I'm alive!"
}

use std::sync::Arc;

pub use houseflow_types::InternalServerError as InternalError;
pub use houseflow_types::ServerError as Error;

#[derive(Clone)]
pub struct State {
    pub token_store: Arc<dyn TokenStore>,
    pub database: Arc<dyn Database>,
    pub config: Arc<Config>,
    pub sessions: Arc<Mutex<Sessions>>,
}

pub async fn run(address: &std::net::SocketAddr, state: State) {
    use axum::{
        prelude::{get, post, route, RoutingDsl},
        routing::nest,
        ws::ws,
    };
    let app = route("/health_check", get(health_check))
        .layer(axum::AddExtensionLayer::new(state))
        .nest(
            "/auth",
            route("/login", post(auth::login::handle))
                .route("/logout", post(auth::logout::handle))
                .route("/register", post(auth::register::handle))
                .route("/token_refresh", post(auth::token_refresh::handle))
                .boxed(),
        )
        .nest(
            "/fulfillment",
            nest(
                "/internal",
                route("/execute", post(fulfillment::internal::execute::handle))
                    .route("/query", post(fulfillment::internal::query::handle))
                    .route("/sync", get(fulfillment::internal::sync::handle)),
            ),
        )
        .nest("/lighthouse", route("/ws", ws(lighthouse::on_websocket)));

    hyper::Server::bind(address)
        .serve(app.into_make_service())
        .await
        .expect("server error");
}

// pub fn configure(
//     cfg: &mut web::ServiceConfig,
//     token_store: web::Data<dyn TokenStore>,
//     database: web::Data<dyn Database>,
//     config: web::Data<Config>,
//     sessions: web::Data<Sessions>,
// ) {
//     cfg.app_data(config)
//         .app_data(token_store)
//         .app_data(sessions)
//         .app_data(database)
//         .route("/health_check", web::get().to(health_check))
//         .service(
//             web::scope("/oauth")
//                 .route("/authorize", web::get().to(oauth::on_authorize))
//                 .route("/login", web::post().to(oauth::on_login))
//                 .service(
//                     web::scope("/")
//                         .app_data(oauth::on_token_grant_form_config())
//                         .route("/token", web::post().to(oauth::on_token_grant)),
//                 ),
//         )
//         .service(
//             web::scope("/auth")
//                 .route("/login", web::post().to(auth::on_login))
//                 .route("/logout", web::post().to(auth::on_logout))
//                 .route("/register", web::post().to(auth::on_register))
//                 .route("/whoami", web::get().to(auth::on_whoami))
//                 .route("/refresh_token", web::post().to(auth::on_refresh_token))
//                 ,
//         )
//         .service(
//             web::scope("/fulfillment")
//                 .service(
//                     web::scope("/internal")
//                         .route(
//                             "/execute",
//                             web::post().to(fulfillment::internal::on_execute),
//                         )
//                         .route("/query", web::get().to(fulfillment::internal::on_query))
//                         .route("/sync", web::get().to(fulfillment::internal::on_sync)),
//                 )
//                 .service(
//                     web::scope("/ghome")
//                         .wrap_fn(|req, srv| {
//                             use actix_service::Service;
//
//                             let config = req
//                                 .app_data::<web::Data<Config>>()
//                                 .expect("config app_data is not configured");
//                             if config.google.is_some() {
//                                 srv.call(req)
//                             } else {
//                                 let fut = async {
//                                     Ok(actix_web::dev::ServiceResponse::new(
//                                         req.into_parts().0,
//                                         actix_web::HttpResponse::NotAcceptable()
//                                             .body("`config.home` is set to None, google home webhook is disabled")))
//                                 };
//                                 Box::pin(fut)
//                             }
//                         })
//                         .route("/webhook", web::post().to(fulfillment::ghome::on_webhook)),
//                 ),
//         )
//         .service(web::scope("/lighthouse").route("/ws", web::get().to(lighthouse::on_websocket)));
// }

// #[cfg(test)]
// mod test_utils {
//     use super::Config;
//     use crate::{token_store, TokenStore};
//     use houseflow_db::{sqlite::Database as SqliteDatabase, Database};
//     use houseflow_types::{Device, DeviceType, Room, Structure, User, UserID};
//
//     use actix_web::web::Data;
//     use std::sync::Arc;
//
//     pub const PASSWORD: &str = "SomePassword";
//     pub const PASSWORD_INVALID: &str = "SomeOtherPassword";
//     pub const PASSWORD_HASH: &str = "$argon2i$v=19$m=4096,t=3,p=1$Zcm15qxfZSBqL9K6S9G5mNIGgz7qmna7TlPPN+t9mqA$ECoZv8pF6Ew6gjh8b9d2oe4QtQA3DO5PIfuWvK2h3OU";
//
//     pub struct State {
//         pub database: Data<dyn Database>,
//         pub token_store: Data<dyn TokenStore>,
//         pub config: Data<Config>,
//     }
//
//     pub fn get_state() -> State {
//         State {
//             database: get_database(),
//             token_store: get_token_store(),
//             config: get_config(),
//         }
//     }
//
//     pub fn get_config() -> Data<Config> {
//         use houseflow_config::defaults;
//
//         Data::from(Arc::new(Config {
//             hostname: defaults::server_hostname(),
//             database_path: std::path::PathBuf::new(),
//             tokens_path: std::path::PathBuf::new(),
//             tls: None,
//             secrets: rand::random(),
//             google: Some(houseflow_config::server::google::Config {
//                 client_id: "some-client-id".to_string(),
//                 client_secret: "some-client-secret".to_string(),
//                 project_id: "some-project-id".to_string(),
//             }),
//         }))
//     }
//
//     pub fn get_database() -> Data<dyn houseflow_db::Database> {
//         Data::from(Arc::new(SqliteDatabase::new_in_memory().unwrap()) as Arc<dyn Database>)
//     }
//
//     pub fn get_token_store() -> Data<dyn TokenStore> {
//         let path =
//             std::env::temp_dir().join(format!("houseflow-server_test-{}", rand::random::<u32>()));
//         Data::from(
//             Arc::new(token_store::sled::TokenStore::new_temporary(path).unwrap())
//                 as Arc<dyn TokenStore>,
//         )
//     }
//
//     pub fn get_user() -> User {
//         let id: UserID = rand::random();
//         User {
//             id: id.clone(),
//             username: format!("john-{}", id.clone()),
//             email: format!("john-{}@example.com", id.clone()),
//             password_hash: PASSWORD_HASH.into(),
//         }
//     }
//
//     pub fn get_structure() -> Structure {
//         Structure {
//             id: rand::random(),
//             name: "test-home".to_string(),
//         }
//     }
//
//     pub fn get_room(structure: &Structure) -> Room {
//         Room {
//             id: rand::random(),
//             structure_id: structure.id.clone(),
//             name: "test-garage".to_string(),
//         }
//     }
//
//     pub fn get_device(room: &Room) -> Device {
//         use semver::Version;
//
//         Device {
//             id: rand::random(),
//             room_id: room.id.clone(),
//             password_hash: Some(PASSWORD_HASH.into()),
//             device_type: DeviceType::Gate,
//             traits: vec![],
//             name: String::from("SuperTestingGate"),
//             will_push_state: true,
//             model: String::from("gate-1200"),
//             hw_version: Version::new(1, 0, 0),
//             sw_version: Version::new(1, 0, 1),
//             attributes: Default::default(),
//         }
//     }
// }
