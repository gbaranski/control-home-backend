use lettre::Message;
use async_trait::async_trait;
use tokio::sync::mpsc;
use super::Error;
use houseflow_types::code::VerificationCode;

pub struct Mailer {
    tx: mpsc::UnboundedSender<VerificationCode>
}

impl Mailer {
    pub fn new(tx: mpsc::UnboundedSender<VerificationCode>) -> Self {
        Self {tx}
    }
}

#[async_trait]
impl super::Mailer for Mailer {
    async fn send(&self, _email: Message) -> Result<(), Error> {
        Ok(())
    }

    fn from_address(&self) -> &str {
        "houseflow@gbaranski.com"
    }

    async fn send_verification_code(
        &self,
        _address: &str,
        code: &VerificationCode,
    ) -> Result<(), Error> {
        self.tx.send(code.clone()).unwrap();
        Ok(())
    }

}
