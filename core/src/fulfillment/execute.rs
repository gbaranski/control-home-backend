use crate::{ClientCommand, ClientCommandState};
use fulfillment::types::ExecuteRequest;
use lighthouse::proto::execute;
use types::DeviceID;
use async_trait::async_trait;

use clap::Clap;

#[derive(Clap)]
pub struct ExecuteCommand {
    pub device_id: DeviceID,
}

#[async_trait(?Send)]
impl ClientCommand for ExecuteCommand {
    async fn run(&self, state: ClientCommandState) -> anyhow::Result<()> {
        let access_token = state.access_token().await?;
        let execute_frame = execute::Frame {
            id: rand::random(),
            command: execute::Command::OnOff,
            params: Default::default(),
        };
        let request = ExecuteRequest {
            device_id: self.device_id.clone(),
            frame: execute_frame,
        };
        let response = state.fulfillment.execute(&access_token, &request).await?.into_result()?;
        println!("Device responded with status: {}", response.frame.status);

        Ok(())
    }
}