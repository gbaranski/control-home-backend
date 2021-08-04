use crate::{extractors::AccessToken, Error, State};
use axum::{extract, response};
use houseflow_types::{
    fulfillment::sync::{Request, Response},
    Device,
};
use tracing::Level;

#[tracing::instrument(skip(state, _request, access_token))]
pub async fn handle(
    extract::Extension(state): extract::Extension<State>,
    extract::Json(_request): extract::Json<Request>,
    AccessToken(access_token): AccessToken,
) -> Result<response::Json<Response>, Error> {
    let devices = state.database
        .get_user_devices(&access_token.sub)?
        .into_iter()
        .map(|device| Device {
            password_hash: None,
            ..device
        })
        .collect::<Vec<_>>();

    let device_ids = devices
        .iter()
        .map(|device| device.id.to_string())
        .collect::<Vec<_>>();

    tracing::event!(Level::INFO, user_id = %access_token.sub, synced_devices = ?device_ids);

    let response = Response { devices };

    Ok(response::Json(response))
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::test_utils::*;
//     use actix_web::{http, test};
//     use chrono::{Duration, Utc};
//     use houseflow_types::{
//         token::{AccessToken, AccessTokenPayload},
//         Device, UserStructure,
//     };
// 
//     #[actix_rt::test]
//     async fn sync() {
//         let state = get_state();
// 
//         let user = get_user();
//         let access_token = AccessToken::new(
//             state.config.secrets.access_key.as_bytes(),
//             AccessTokenPayload {
//                 sub: user.id.clone(),
//                 exp: Utc::now() + Duration::minutes(10),
//             },
//         );
//         state.database.add_user(&user).unwrap();
// 
//         let structure_allow = get_structure();
//         let structure_deny = get_structure();
//         let room_allow = get_room(&structure_allow);
//         let room_deny = get_room(&structure_deny);
//         state.database.add_structure(&structure_allow).unwrap();
//         state.database.add_structure(&structure_deny).unwrap();
//         state.database.add_room(&room_allow).unwrap();
//         state.database.add_room(&room_deny).unwrap();
//         let devices_allow = std::iter::repeat_with(|| get_device(&room_allow))
//             .take(5)
//             .collect::<Vec<_>>();
//         let devices_deny = std::iter::repeat_with(|| get_device(&room_deny))
//             .take(5)
//             .collect::<Vec<_>>();
// 
//         devices_allow
//             .iter()
//             .chain(devices_deny.iter())
//             .for_each(|device| state.database.add_device(&device).unwrap());
// 
//         let user_structure = UserStructure {
//             structure_id: structure_allow.id.clone(),
//             user_id: user.id.clone(),
//             is_manager: false,
//         };
//         state.database.add_user_structure(&user_structure).unwrap();
// 
//         let request = test::TestRequest::default()
//             .insert_header((
//                 http::header::AUTHORIZATION,
//                 format!("Bearer {}", access_token.to_string()),
//             ))
//             .to_http_request();
//         let response = on_sync(Json(Request {}), request, state.config, state.database)
//             .await
//             .unwrap()
//             .into_inner();
//         let sort_devices = |devices: Vec<Device>| {
//             devices.clone().sort_by(|a, b| a.id.cmp(&b.id));
//             devices
//         };
//         assert_eq!(
//             sort_devices(response.devices),
//             sort_devices(
//                 devices_allow
//                     .into_iter()
//                     .map(|device| Device {
//                         password_hash: None,
//                         ..device
//                     })
//                     .collect()
//             )
//         );
//     }
// }
