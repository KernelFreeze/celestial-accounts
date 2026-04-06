use std::env::var;
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;
use tokio::net::TcpListener;

use crate::auth::password::PasswordVerifier;
use crate::auth::token::PasetoKeys;
use crate::auth::totp::TotpVerifier;
use crate::database::Database;
use crate::state::AppState;

mod auth;
mod database;
mod extractors;
mod state;
mod views;

const ADDR_ENVVAR: &'static str = "ADDR";
const PORT_ENVVAR: &'static str = "PORT";

const DEFAULT_BIND_ADDR: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
const DEFAULT_PORT: u16 = 8080;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to bind to address: {0}")]
    Bind(#[from] std::io::Error),

    #[error("Failed to serve: {0}")]
    Serve(#[from] axum::Error),

    #[error(transparent)]
    BindAddress(#[from] BindAddressError),

    #[error("Failed to connect to database: {0}")]
    Database(#[from] database::DatabaseConnectionError),

    #[error("DATABASE_URL environment variable must be set")]
    DatabaseUrlNotSet,

    #[error("PEPPER environment variable must be set")]
    PepperNotSet,

    #[error("PEPPER must be valid hex: {0}")]
    PepperInvalidHex(#[from] hex::FromHexError),

    #[error("PASETO_PRIVATE_KEY environment variable must be set (base64-encoded Ed25519 key)")]
    PasetoPrivateKeyNotSet,

    #[error("PASETO_PRIVATE_KEY must be valid base64: {0}")]
    PasetoPrivateKeyInvalidBase64(base64::DecodeError),

    #[error("PASETO_LOCAL_KEY environment variable must be set (hex-encoded 256-bit key)")]
    PasetoLocalKeyNotSet,

    #[error("PASETO_KEY_ID environment variable must be set")]
    PasetoKeyIdNotSet,

    #[error("TOTP_ENCRYPTION_KEY environment variable must be set (hex-encoded 256-bit key)")]
    TotpEncryptionKeyNotSet,

    #[error("TOTP_ENCRYPTION_KEY must be exactly 32 bytes")]
    TotpEncryptionKeyInvalidLength,
}

#[derive(Debug, Error)]
pub enum BindAddressError {
    #[error("Failed to parse address: {0}")]
    ParseAddress(#[from] std::net::AddrParseError),

    #[error("Failed to parse port: {0}")]
    ParsePort(#[from] std::num::ParseIntError),
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let database_url = var("DATABASE_URL").map_err(|_| Error::DatabaseUrlNotSet)?;
    let pepper_hex = var("PEPPER").map_err(|_| Error::PepperNotSet)?;
    let pepper = hex::decode(&pepper_hex)?;

    // PASETO keys
    let paseto_private_key = {
        use base64::Engine;
        let b64 = var("PASETO_PRIVATE_KEY").map_err(|_| Error::PasetoPrivateKeyNotSet)?;
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(Error::PasetoPrivateKeyInvalidBase64)?
    };
    let paseto_local_key = {
        let hex_str = var("PASETO_LOCAL_KEY").map_err(|_| Error::PasetoLocalKeyNotSet)?;
        hex::decode(&hex_str)?
    };
    let paseto_key_id = var("PASETO_KEY_ID").map_err(|_| Error::PasetoKeyIdNotSet)?;
    let paseto_keys = PasetoKeys::new(paseto_private_key, paseto_local_key, paseto_key_id);

    // TOTP encryption key
    let totp_encryption_key = {
        let hex_str = var("TOTP_ENCRYPTION_KEY").map_err(|_| Error::TotpEncryptionKeyNotSet)?;
        let bytes = hex::decode(&hex_str)?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::TotpEncryptionKeyInvalidLength)?
    };
    let totp_verifier = TotpVerifier::new(totp_encryption_key);

    let database = Database::new_with_url(database_url).await?;
    let password_verifier = PasswordVerifier::new(pepper);
    let app = views::router()
        .with_state(AppState::new(database, password_verifier, paseto_keys, totp_verifier))
        .into_make_service_with_connect_info::<SocketAddr>();

    let socket_addr = socket_address()?;
    let listener = TcpListener::bind(socket_addr).await?;

    axum::serve(listener, app).await?;
    Ok(())
}

fn bind_address() -> Result<IpAddr, BindAddressError> {
    var(ADDR_ENVVAR)
        .map(|addr| addr.parse().map_err(BindAddressError::ParseAddress))
        .unwrap_or(Ok(DEFAULT_BIND_ADDR))
}

fn bind_port() -> Result<u16, BindAddressError> {
    var(PORT_ENVVAR)
        .map(|port| port.parse().map_err(BindAddressError::ParsePort))
        .unwrap_or(Ok(DEFAULT_PORT))
}

fn socket_address() -> Result<SocketAddr, BindAddressError> {
    let addr = bind_address()?;
    let port = bind_port()?;
    Ok(SocketAddr::new(addr, port))
}
