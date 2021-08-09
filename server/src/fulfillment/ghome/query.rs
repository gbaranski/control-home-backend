use crate::State;
use google_smart_home::query::{request, response};
use houseflow_types::{errors::InternalError, DeviceID, UserID};
use std::str::FromStr;

#[tracing::instrument(name = "Query", skip(state), err)]
pub async fn handle(
    state: State,
    user_id: UserID,
    payload: &request::Payload,
) -> Result<response::Payload, InternalError> {
    let database = &state.database;
    let sessions = &state.sessions;
    let user_id = &user_id;

    let responses = payload.devices.iter().map(|device| async move {
        let response = (|| async {
            let device_id = DeviceID::from_str(&device.id).expect("invalid device ID");
            if !database
                .check_user_device_access(user_id, &device_id)
                .unwrap()
            {
                return Ok::<_, InternalError>(response::PayloadDevice {
                    status: response::PayloadDeviceStatus::Error,
                    state: Default::default(),
                    error_code: None,
                });
            }
            let session = match sessions.lock().unwrap().get(&device_id) {
                Some(session) => session.clone(),
                None => {
                    return Ok(response::PayloadDevice {
                        state: Default::default(),
                        status: response::PayloadDeviceStatus::Offline,
                        error_code: Some(String::from("offline")),
                    })
                }
            };

            let request = houseflow_types::lighthouse::proto::query::Frame {};
            let response = match tokio::time::timeout(
                crate::fulfillment::EXECUTE_TIMEOUT,
                session.query(request),
            )
            .await
            {
                Ok(val) => val?,
                Err(_) => {
                    return Ok(response::PayloadDevice {
                        status: response::PayloadDeviceStatus::Offline,
                        state: Default::default(),
                        error_code: Some(String::from("offline")),
                    })
                }
            };

            Ok(response::PayloadDevice {
                status: response::PayloadDeviceStatus::Success,
                error_code: None,
                state: response.state,
            })
        })();
        response
            .await
            .map(|response| (device.id.to_owned(), response))
    });
    Ok(response::Payload {
        error_code: None,
        debug_string: None,
        devices: futures::future::try_join_all(responses)
            .await?
            .into_iter()
            .collect(),
    })
}