use super::Error;
use async_trait::async_trait;
use houseflow_config::server::EmailAwsSes as Config;
use lettre::Message;
use rusoto_ses::RawMessage;
use rusoto_ses::SendRawEmailRequest;
use rusoto_ses::Ses;
use rusoto_ses::SesClient;

pub struct Mailer {
    client: SesClient,
    config: Config,
}

impl Mailer {
    pub fn new(config: Config) -> Self {
        let client = SesClient::new(config.region.clone());
        Self { client, config }
    }
}

#[async_trait]
impl super::Mailer for Mailer {
    async fn send(&self, email: Message) -> Result<(), Error> {
        let request = SendRawEmailRequest {
            raw_message: RawMessage {
                data: base64::encode(email.formatted()).into(),
            },
            ..Default::default()
        };
        self.client.send_raw_email(request).await?;
        Ok(())
    }

    fn from_address(&self) -> &str {
        &self.config.from
    }
}
