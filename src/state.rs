use std::sync::Arc;

use derive_more::{Deref, DerefMut};

use crate::auth::password::PasswordVerifier;
use crate::auth::token::PasetoKeys;
use crate::auth::totp::TotpVerifier;
use crate::database::Database;

#[derive(Clone, Deref, DerefMut)]
pub struct AppState(Arc<StateInner>);

pub struct StateInner {
    database: Database,
    paseto_keys: PasetoKeys,
    password_verifier: PasswordVerifier,
    totp_verifier: TotpVerifier,
}

impl StateInner {
    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn password_verifier(&self) -> &PasswordVerifier {
        &self.password_verifier
    }

    pub fn paseto_keys(&self) -> &PasetoKeys {
        &self.paseto_keys
    }

    pub fn totp_verifier(&self) -> &TotpVerifier {
        &self.totp_verifier
    }
}

impl AppState {
    pub fn new(
        database: Database, password_verifier: PasswordVerifier, paseto_keys: PasetoKeys, totp_verifier: TotpVerifier,
    ) -> Self {
        let inner = StateInner {
            database,
            password_verifier,
            paseto_keys,
            totp_verifier,
        };
        AppState(Arc::new(inner))
    }
}
