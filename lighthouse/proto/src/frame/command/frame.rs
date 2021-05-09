use super::Code;
use crate::{FrameID, Framed, Frame};
use crate::{DecodeError, Decoder, Encoder};
use bytes::{Buf, BufMut};
use lighthouse_macros::decoder;
use serde::{Deserialize, Serialize};
use std::mem::size_of;


#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandFrame {
    pub id: FrameID,
    pub code: Code,
    pub params: serde_json::Value,
}

impl<'de> Framed<'de> for CommandFrame {}

impl Decoder for CommandFrame {
    const MIN_SIZE: usize = size_of::<FrameID>() + size_of::<CommandFrame>();

    #[decoder]
    fn decode(buf: &mut impl Buf) -> Result<Self, DecodeError> {
        let id = FrameID::decode(buf)?;
        let code = Code::decode(buf)?;
        let params = serde_json::Value::decode(buf)?;

        Ok(Self {
            id,
            code,
            params,
        })
    }
}

impl Encoder for CommandFrame {
    fn encode(&self, buf: &mut impl BufMut) {
        self.id.encode(buf);
        self.code.encode(buf);
        self.params.encode(buf);
    }
}

impl Into<Frame> for CommandFrame {
    fn into(self) -> Frame {
        Frame::Command(self)
    }
}
