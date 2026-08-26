use axum::Json;
use axum::extract::State;

use openidconnect::core::{
    CoreClaimName, CoreGrantType, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, Scope,
    TokenUrl, UserInfoUrl,
};

pub fn get_core_provider_metadata(state: &crate::config::AppState) -> CoreProviderMetadata {
    let issuer = state.config.issuer.clone();

    let signing_algos: Vec<CoreJwsSigningAlgorithm> = if state.config.algorithm == "EdDSA" {
        vec![CoreJwsSigningAlgorithm::EdDsa]
    } else {
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]
    };

    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new(issuer.clone()).unwrap(),
        AuthUrl::new(format!("{}authorize.html", issuer)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}.well-known/jwks.json", issuer)).unwrap(),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::IdToken, CoreResponseType::Token]),
            ResponseTypes::new(vec![CoreResponseType::Token]),
        ],
        vec![CoreSubjectIdentifierType::Public],
        signing_algos,
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{}token", issuer)).unwrap()))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{}userinfo", issuer)).unwrap(),
    ))
    .set_scopes_supported(Some(vec![Scope::new("openid".to_string())]))
    .set_grant_types_supported(Some(vec![
        CoreGrantType::Password,
        CoreGrantType::RefreshToken,
        CoreGrantType::AuthorizationCode,
        CoreGrantType::ClientCredentials,
        CoreGrantType::Implicit,
    ]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
    ]));
    provider_metadata
}

pub async fn get_provider_metadata_route(
    State(state): State<crate::config::AppState>,
) -> Json<CoreProviderMetadata> {
    Json(get_core_provider_metadata(&state))
}

pub async fn get_jwks_route(
    State(state): State<crate::config::AppState>,
) -> Json<CoreJsonWebKeySet> {
    let public_key = match &state.key_pair {
        crate::keys::SigningKeyPair::Rsa { public_key, .. } => public_key.clone(),
        crate::keys::SigningKeyPair::Ed25519 { public_key, .. } => public_key.clone(),
    };
    let jwks = CoreJsonWebKeySet::new(vec![public_key]);
    Json(jwks)
}
