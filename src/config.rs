use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub key_size: usize,
    #[serde(default = "Config::default_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub users: Vec<User>,
    pub issuer: String,
}

impl Config {
    fn default_algorithm() -> String {
        "RSA".to_string()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub sub: String,
    #[serde(default)]
    pub claims: HashMap<String, Value>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub key_pair: crate::keys::SigningKeyPair,
    pub access_token_lifetime: chrono::TimeDelta,
    pub refresh_token_lifetime: chrono::TimeDelta,
    pub authorization_code_lifetime: chrono::TimeDelta,
}

impl AppState {
    pub fn new(config: Config, key_pair: crate::keys::SigningKeyPair) -> AppState {
        AppState {
            config,
            key_pair,
            access_token_lifetime: chrono::TimeDelta::minutes(5),
            refresh_token_lifetime: chrono::TimeDelta::hours(1),
            authorization_code_lifetime: chrono::TimeDelta::minutes(1),
        }
    }

    pub fn get_user_by_name(&self, name: &str) -> Option<User> {
        self.config.users.iter().find(|u| u.sub == name).cloned()
    }
}

#[derive(Serialize, Deserialize)]
pub struct MidToken {
    pub aud: String,
    pub sub: String,
    pub scp: Option<String>,
    pub nonce: Option<String>,
    pub code_hash: Option<String>,
    pub iat: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DynamicAdditionalClaims(pub HashMap<String, Value>);
impl openidconnect::AdditionalClaims for DynamicAdditionalClaims {}
