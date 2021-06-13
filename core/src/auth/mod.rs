use crate::{ClientCommand, ClientCommandState};
use async_trait::async_trait;

use login::LoginCommand;
use logout::LogoutCommand;
use register::RegisterCommand;
use status::StatusCommand;
use refresh::RefreshCommand;

mod login;
mod logout;
mod register;
mod status;
mod refresh;

use clap::Clap;

#[derive(Clap)]
pub struct AuthCommand {
    #[clap(subcommand)]
    pub subcommand: AuthSubcommand,
}

#[derive(Clap)]
pub enum AuthSubcommand {
    /// Log in to existing Houseflow account
    Login(LoginCommand),

    /// Logout from currently logged account
    Logout(LogoutCommand),

    /// Register a new Houseflow account
    Register(RegisterCommand),

    /// Check current authentication status
    Status(StatusCommand),

    /// Refresh access token
    Refresh(RefreshCommand),
}

#[async_trait(?Send)]
impl ClientCommand for AuthCommand {
    async fn run(&self, state: ClientCommandState) -> anyhow::Result<()> {
        match &self.subcommand {
            AuthSubcommand::Login(cmd) => cmd.run(state).await,
            AuthSubcommand::Register(cmd) => cmd.run(state).await,
            AuthSubcommand::Status(cmd) => cmd.run(state).await,
            AuthSubcommand::Logout(cmd) => cmd.run(state).await,
            AuthSubcommand::Refresh(cmd) => cmd.run(state).await,
        }
    }
}
