use std::str::FromStr;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use openidconnect::core::{
    CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
};
use openidconnect::{ClientId, IdToken, IdTokenVerifier, IssuerUrl, JsonWebKeySet, Nonce};
use serde_json::{Map, Value};

type AccessJwt = IdToken<
    crate::config::DynamicAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

fn verify_no_nonce(_nonce: Option<&Nonce>) -> Result<(), String> {
    Ok(())
}

pub async fn handle_userinfo_route(
    State(state): State<crate::config::AppState>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split_once(' ').and_then(|(scheme, token)| {
                if scheme.eq_ignore_ascii_case("bearer") {
                    Some(token)
                } else {
                    None
                }
            })
        })
    else {
        return userinfo_error("invalid_request", "a bearer token is required");
    };

    let token: AccessJwt = match AccessJwt::from_str(token) {
        Ok(token) => token,
        Err(_) => return userinfo_error("invalid_token", "the access token is not a valid JWT"),
    };

    let public_key = match &state.key_pair {
        crate::keys::SigningKeyPair::Rsa { public_key, .. } => public_key.clone(),
        crate::keys::SigningKeyPair::Ed25519 { public_key, .. } => public_key.clone(),
    };

    let verifier = IdTokenVerifier::new_public_client(
        ClientId::new("user-info-endpoint".to_string()),
        IssuerUrl::new(state.config.issuer.clone()).unwrap(),
        JsonWebKeySet::new(vec![public_key]),
    )
    .require_audience_match(false)
    .require_issuer_match(true)
    .allow_any_alg()
    .allow_all_jose_types();

    let claims = match token.into_claims(&verifier, verify_no_nonce) {
        Ok(claims) => claims,
        Err(_) => {
            return userinfo_error(
                "invalid_token",
                "the access token failed verification, it may be expired or tampered with",
            );
        }
    };

    let user = match state.get_user_by_name(claims.subject()) {
        Some(user) => user,
        None => {
            return userinfo_error(
                "invalid_token",
                "the user for this access token is unknown to this provider",
            );
        }
    };

    let mut user_claims: Map<String, Value> = Map::new();
    user_claims.insert("sub".to_string(), Value::String(user.sub.clone()));
    for (name, claim) in &user.claims {
        if name != "sub" {
            user_claims.insert(name.clone(), claim.clone());
        }
    }

    tracing::info!("Returned user info for user '{}'", user.sub);

    (StatusCode::OK, Json(Value::Object(user_claims))).into_response()
}

fn userinfo_error(error: &str, description: &str) -> Response {
    let body = Json(serde_json::json!({
        "error": error,
        "error_description": description,
    }));
    (
        StatusCode::UNAUTHORIZED,
        [("content-type", "application/json")],
        body,
    )
        .into_response()
}
