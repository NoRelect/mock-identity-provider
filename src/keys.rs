use std::sync::Arc;

use openidconnect::core::{
    CoreEdDsaPrivateSigningKey, CoreJsonWebKey, CoreRsaPrivateSigningKey,
};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;

#[derive(Clone)]
pub enum SigningKeyPair {
    Rsa {
        private_key: Arc<CoreRsaPrivateSigningKey>,
        public_key: CoreJsonWebKey,
    },
    Ed25519 {
        private_key: Arc<CoreEdDsaPrivateSigningKey>,
        public_key: CoreJsonWebKey,
    },
}

pub fn generate_keys(config: &crate::config::Config) -> SigningKeyPair {
    if config.algorithm == "EdDSA" {
        generate_ed25519_key()
    } else {
        generate_rsa_key(config.key_size)
    }
}

fn generate_ed25519_key() -> SigningKeyPair {
    let seed: [u8; 32] = {
        let mut rng = rsa::rand_core::OsRng;
        let mut s: [u8; 32] = [0; 32];
        use rsa::rand_core::RngCore;
        rng.fill_bytes(&mut s);
        s
    };

    use pkcs8::{EncodePrivateKey, LineEnding};
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pem = sign_key.to_pkcs8_pem(LineEnding::CRLF).expect("PKCS#8 PEM");

    let private_key = Arc::new(
        CoreEdDsaPrivateSigningKey::from_ed25519_pem(
            &pem,
            Some(JsonWebKeyId::new("ed25519-key".to_string())),
        )
        .expect("Failed to create Ed25519 signing key"),
    );
    let public_key = private_key.as_verification_key();

    SigningKeyPair::Ed25519 { private_key, public_key }
}

fn generate_rsa_key(key_size: usize) -> SigningKeyPair {
    let effective_key_size = if key_size > 0 { key_size } else { 4096 };

    let mut rng = rsa::rand_core::OsRng;
    let rsa_priv_key =
        RsaPrivateKey::new(&mut rng, effective_key_size).expect("Failed to generate a key");
    let rsa_pem = rsa_priv_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::CRLF)
        .expect("Failed to convert private key to PEM");

    let rsa_private_key = CoreRsaPrivateSigningKey::from_pem(
        &rsa_pem,
        Some(JsonWebKeyId::new("rsa-key".to_string())),
    )
    .unwrap();
    let rsa_public_key = rsa_private_key.as_verification_key().clone();

    SigningKeyPair::Rsa {
        private_key: Arc::new(rsa_private_key),
        public_key: rsa_public_key,
    }
}
