use super::Handle;
use super::Message as ControllerMessage;
use crate::controllers::Name;
use crate::providers;
use anyhow::Context;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::StreamExt;
use houseflow_config::hub::controllers::Lighthouse as Config;
use houseflow_types::hub;
use houseflow_types::lighthouse;
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
use tokio_tungstenite::WebSocketStream;

#[derive(Debug)]
pub enum LighthouseMessage {
    ServerFrame(lighthouse::ServerFrame),
}

#[derive(Debug, Clone)]
pub struct LighthouseHandle {
    sender: acu::Sender<LighthouseMessage>,
    handle: Handle,
}

impl std::ops::Deref for LighthouseHandle {
    type Target = Handle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl From<LighthouseHandle> for Handle {
    fn from(val: LighthouseHandle) -> Self {
        val.handle
    }
}

impl LighthouseHandle {}

pub struct LighthouseController {
    receiver: acu::Receiver<ControllerMessage>,
    handle: Handle,
    sink: SplitSink<
        WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        WebSocketMessage,
    >,
}

impl LighthouseController {
    pub async fn create(
        provider: providers::Handle,
        hub_id: hub::ID,
        config: Config,
    ) -> Result<Handle, anyhow::Error> {
        let (sender, receiver) = acu::channel(1, Name::Lighthouse.into());
        tracing::debug!(
            "attempting to connect to the lighthouse websocket server on URL: {}",
            config.url
        );

        let authorization_header = format!(
            "Basic {}",
            base64::encode(format!(
                "{}:{}",
                hub_id.to_string().as_str(),
                config.password
            ))
        );

        let request = http::Request::builder()
            .uri(config.url.as_str())
            .header(http::header::AUTHORIZATION, authorization_header)
            .body(())
            .unwrap();

        let (stream, response) = tokio_tungstenite::connect_async(request)
            .await
            .context("lighthouse websocket server connect failed")?;
        tracing::debug!(
            "connected to the lighthouse server via websocket with response: {:?}",
            response
        );
        let (sink, stream) = stream.split();

        let handle = Handle::new(Name::Hap, sender);
        let mut actor = Self {
            receiver,
            handle: handle.clone(),
            sink,
        };
        tokio::spawn(async move { actor.run(stream).await });
        Ok(handle)
    }

    async fn run(
        &mut self,
        mut stream: SplitStream<
            WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        >,
    ) -> Result<(), anyhow::Error> {
        let handle = self.handle.clone();
        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                let message = message?;
                match message {
                    WebSocketMessage::Text(text) => {
                        let frame = serde_json::from_str::<lighthouse::ServerFrame>(&text)?;
                        todo!()
                    }
                    WebSocketMessage::Binary(_) => todo!(),
                    WebSocketMessage::Ping(_) => todo!(),
                    WebSocketMessage::Pong(_) => todo!(),
                    WebSocketMessage::Close(_) => todo!(),
                };
            }

            Ok::<_, anyhow::Error>(())
        });

        while let Some(msg) = self.receiver.recv().await {
            self.handle_controller_message(msg).await?;
        }
        Ok(())
    }

    async fn handle_controller_message(
        &mut self,
        message: ControllerMessage,
    ) -> Result<(), anyhow::Error> {
        match message {
            ControllerMessage::Connected {
                configured_accessory,
            } => {}
            ControllerMessage::Disconnected { accessory_id } => {}
            ControllerMessage::Updated {
                accessory_id,
                service_name,
                characteristic,
            } => {}
        };
        Ok(())
    }

    async fn handle_lighthouse_message(
        &mut self,
        message: LighthouseMessage,
    ) -> Result<(), anyhow::Error> {
        match message {
            LighthouseMessage::ServerFrame(frame) => {}
        };
        Ok(())
    }
}
