use bytes::{Buf, BytesMut};
use futures_util::{Sink, SinkExt, StreamExt};
use lighthouse_proto::{execute_response, Decoder, Encoder, Frame};
use tokio::sync::mpsc;
use tungstenite::Message as WebsocketMessage;
use types::{DeviceID, DevicePassword};
use url::Url;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Event {
    Ping,
    Pong,
    LighthouseFrame(Frame),
    // Execute(frame::execute::Frame),
    // ExecuteResponse(frame::execute_response::Frame),
}

const BUFFER_CAPACITY: usize = 1024;

pub type EventSender = mpsc::Sender<Event>;
pub type EventReceiver = mpsc::Receiver<Event>;

pub struct Options {
    pub url: Url,
    pub id: DeviceID,
    pub password: DevicePassword,
}

pub struct Session {
    opts: Options,
}

impl Session {
    pub fn new(opts: Options) -> Self {
        Self { opts }
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        let http_request = http::Request::builder()
            .uri(self.opts.url.to_string())
            .header(
                http::header::AUTHORIZATION,
                format!("Basic {}:{}", self.opts.id, self.opts.password),
            )
            .body(())
            .unwrap();

        let (stream, _) = tokio_tungstenite::connect_async(http_request).await?;
        let (event_sender, event_receiver) = mpsc::channel::<Event>(8);
        let (stream_sender, stream_receiver) = stream.split();

        tokio::select! {
            v = self.stream_read(stream_receiver, event_sender) => { v }
            v = self.stream_write(stream_sender, event_receiver) => { v }
        }
    }

    async fn stream_read<S>(&self, mut stream: S, events: EventSender) -> Result<(), anyhow::Error>
    where
        S: futures_util::Stream<Item = Result<WebsocketMessage, tungstenite::Error>> + Unpin,
    {
        while let Some(message) = stream.next().await {
            let message = message?;
            match message {
                WebsocketMessage::Text(text) => {
                    log::info!("Received text data: {:?}", text);
                }
                WebsocketMessage::Binary(bytes) => {
                    let mut bytes = BytesMut::from(bytes.as_slice());
                    let frame = Frame::decode(&mut bytes)?;
                    log::info!("Received frame: {:?}", frame);
                    match frame {
                        Frame::Execute(frame) => {
                            let response_frame = execute_response::Frame {
                                id: frame.id,
                                status: execute_response::Status::Success,
                                error: execute_response::Error::None,
                                state: frame.params,
                            };
                            let response_frame = Frame::ExecuteResponse(response_frame);
                            let response_event = Event::LighthouseFrame(response_frame);
                            events
                                .send(response_event)
                                .await
                                .expect("failed sending event");
                        }
                        _ => {
                            panic!("Unexpected frame received")
                        }
                    }
                }
                WebsocketMessage::Ping(payload) => {
                    events
                        .send(Event::Pong)
                        .await
                        .expect("message receiver half is down");
                    log::info!("Received ping, payload: {:?}", payload);
                }
                WebsocketMessage::Pong(payload) => {
                    log::info!("Received ping, payload: {:?}", payload);
                }
                WebsocketMessage::Close(frame) => {
                    log::info!("Received close frame: {:?}", frame);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn stream_write<S>(
        &self,
        mut stream: S,
        mut events: EventReceiver,
    ) -> Result<(), anyhow::Error>
    where
        S: Sink<WebsocketMessage, Error = tungstenite::Error> + Unpin,
    {
        let mut buf = BytesMut::with_capacity(BUFFER_CAPACITY);
        while let Some(event) = events.recv().await {
            match event {
                Event::Ping => {
                    log::info!("Sending Ping");
                    stream.send(WebsocketMessage::Ping(Vec::new())).await?;
                }
                Event::Pong => {
                    log::info!("Sending Pong");
                    stream.send(WebsocketMessage::Pong(Vec::new())).await?;
                }
                Event::LighthouseFrame(frame) => {
                    assert_eq!(buf.remaining(), 0);

                    frame.encode(&mut buf);
                    let vec = buf.to_vec();
                    buf.advance(vec.len());
                    stream.send(WebsocketMessage::Binary(vec)).await?;
                }
            }
        }
        unimplemented!();
    }
}
