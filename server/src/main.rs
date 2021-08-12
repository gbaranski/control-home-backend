use houseflow_config::{defaults, server::Config, Config as _, Error as ConfigError};
use houseflow_db::sqlite::Database as SqliteDatabase;
use houseflow_server::{Sessions, SledTokenBlacklist};
use std::sync::{Arc, Mutex};
use tokio_rustls::rustls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const HIDE_TIMESTAMP_ENV: &str = "HOUSEFLOW_SERVER_HIDE_TIMESTAMP";

    houseflow_config::init_logging(std::env::var_os(HIDE_TIMESTAMP_ENV).is_some());
    let config_path = std::env::var("HOUSEFLOW_SERVER_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Config::default_path());

    tracing::debug!("Config path: {}", config_path.to_str().unwrap());

    let config = match Config::read(&config_path) {
        Ok(config) => config,
        Err(ConfigError::IOError(err)) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                tracing::error!(
                    "Config file could not be found at {}",
                    config_path.to_str().unwrap()
                );
                return Ok(());
            }
            _ => panic!("Read config IO Error: {}", err),
        },
        Err(err) => panic!("Config error: {}", err),
    };
    tracing::debug!("Config: {:#?}", config);
    let token_blacklist = SledTokenBlacklist::new(defaults::token_blacklist_path())
        .expect("cannot open token blacklist");
    let database = SqliteDatabase::new(defaults::database_path()).expect("cannot open database");
    let sessions = Sessions::new();

    let state = houseflow_server::State {
        token_blacklist: Arc::new(token_blacklist),
        database: Arc::new(database),
        config: Arc::new(config),
        sessions: Arc::new(Mutex::new(sessions)),
    };

    let address_with_port = |port| std::net::SocketAddr::new(state.config.network.address, port);
    let (address, tls_address) = (
        address_with_port(defaults::server_port()),
        address_with_port(defaults::server_port_tls()),
    );

    if let Some(tls) = &state.config.tls {
        let mut rustls_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        let certificate = &mut std::io::BufReader::new(
            std::fs::File::open(&tls.certificate).expect("read certificate fail"),
        );
        let private_key = &mut std::io::BufReader::new(
            std::fs::File::open(&tls.private_key).expect("read private key fail"),
        );
        let certificate_chain = rustls::internal::pemfile::certs(certificate).unwrap();
        let keys = rustls::internal::pemfile::pkcs8_private_keys(private_key).unwrap();
        rustls_config
            .set_single_cert(certificate_chain, keys.into_iter().next().unwrap())
            .unwrap();

        tracing::info!("Starting server at {}", address);
        let run_fut = houseflow_server::run(&address, state.clone());
        tracing::info!("Starting TLS server at {}", tls_address);
        let run_tls_fut = houseflow_server::run_tls(&tls_address, state, Arc::new(rustls_config));

        tokio::select! {
            val = run_fut => val?,
            val = run_tls_fut => val?
        };
    } else {
        tracing::info!("Starting server at {}", address);
        houseflow_server::run(&address, state).await?;
    }

    Ok(())
}
