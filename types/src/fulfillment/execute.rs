use crate::{lighthouse, DeviceID};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Request {
    pub device_id: DeviceID,

    #[serde(flatten)]
    pub frame: lighthouse::proto::execute::Frame,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Response {
    pub frame: lighthouse::proto::execute_response::Frame,
}