use std::ops::Add;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::Utc;
use openidconnect::core::{
    CoreErrorResponseType, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreTokenType, CoreGrantType};
use openidconnect::{
    AccessToken, Audience, AuthorizationCodeHash,
    EmptyExtraTokenFields, IdToken, IdTokenClaims, IdTokenFields,
    Nonce, RefreshToken, StandardClaims, StandardErrorResponse,
    StandardTokenResponse, SubjectIdentifier};
use serde::Deserialize;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: CoreGrantType,
    code: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
    username: Option<String>,
    scope: Option<String>,
    nonce: Option<String>,
}

// ── Token request handling ────────────────────────────────────────────────

pub async fn handle_token_route(
    State(state): State<crate::config::AppState>,
    Form(request): Form<TokenRequest>,
) -> Response {
    if request.grant_type == CoreGrantType::Password {
        handle_password_grant(&state, request).await
    } else if request.grant_type == CoreGrantType::ClientCredentials {
        handle_client_credentials_grant(&state, request).await
    } else if request.grant_type == CoreGrantType::RefreshToken {
        handle_refresh_token_grant(&state, request).await
    } else if request.grant_type == CoreGrantType::AuthorizationCode {
        handle_authorization_code_grant(&state, request).await
    } else {
        Json(error_response("invalid_grant")).into_response()
    }
}

async fn handle_password_grant(
    state: &crate::config::AppState,
    request: TokenRequest,
) -> Response {
    let client_id = match request.client_id {
        Some(id) => id,
        None => return Json(error_response("client_id is missing")).into_response(),
    };

    let username = match request.username {
        Some(name) => name,
        None => return Json(error_response("username is missing")).into_response(),
    };

    let Some(user) = state.get_user_by_name(&username) else {
        return Json(error_response("user not found")).into_response();
    };

    create_token_response(state, client_id, &user, request.scope, request.nonce, None)
}

async fn handle_client_credentials_grant(
    state: &crate::config::AppState,
    request: TokenRequest,
) -> Response {
    let client_id = match request.client_id {
        Some(id) => id,
        None => return Json(error_response("client_id is missing")).into_response(),
    };

    let Some(user) = state.get_user_by_name(&client_id) else {
        return Json(error_response("user not found")).into_response();
    };

    create_token_response(state, client_id, &user, request.scope, request.nonce, None)
}

async fn handle_refresh_token_grant(
    state: &crate::config::AppState,
    request: TokenRequest,
) -> Response {
    let refresh_token_str = match request.refresh_token {
        Some(rt) => rt,
        None => return Json(error_response("refresh_token is missing")).into_response(),
    };

    let refresh_token_decoded = match URL_SAFE.decode(&refresh_token_str) {
        Ok(data) => data,
        Err(_) => return Json(error_response("refresh_token is not valid base64 url data")).into_response(),
    };

    let token: crate::config::MidToken = match serde_json::from_slice(&refresh_token_decoded) {
        Ok(t) => t,
        Err(_) => return Json(error_response("refresh_token is invalid")).into_response(),
    };

    // Only check audience match if client_id was provided
    if let Some(cid) = request.client_id {
        if token.aud != cid {
            return Json(error_response("refresh_token is not valid for this client_id")).into_response();
        }
    }

    if token.iat.add(state.refresh_token_lifetime) <= Utc::now() {
        return Json(error_response("refresh_token has expired")).into_response();
    }

    let Some(user) = state.get_user_by_name(&token.sub) else {
        return Json(error_response("user not found")).into_response();
    };

    create_token_response(
        state,
        token.aud,
        &user,
        token.scp,
        token.nonce,
        token.code_hash,
    )
}

async fn handle_authorization_code_grant(
    state: &crate::config::AppState,
    request: TokenRequest,
) -> Response {
    let code = match request.code {
        Some(c) => c,
        None => return Json(error_response("code is missing")).into_response(),
    };

    let authorization_code = match URL_SAFE.decode(&code) {
        Ok(data) => data,
        Err(_) => return Json(error_response("code is not valid base64 url data")).into_response(),
    };

    let token: crate::config::MidToken = match serde_json::from_slice(&authorization_code) {
        Ok(t) => t,
        Err(_) => return Json(error_response("code is invalid")).into_response(),
    };

    // Only check audience match if client_id was provided
    if let Some(cid) = request.client_id {
        if token.aud != cid {
            return Json(error_response("code is not valid for this client_id")).into_response();
        }
    }

    if token.iat.add(state.authorization_code_lifetime) <= Utc::now() {
        return Json(error_response("code has expired")).into_response();
    }

    let Some(user) = state.get_user_by_name(&token.sub) else {
        return Json(error_response("user not found")).into_response();
    };

    create_token_response(state, token.aud, &user, token.scp, token.nonce, Some(code))
}

fn error_response(message: &str) -> StandardErrorResponse<CoreErrorResponseType> {
    error!("Returned error response: {}", message);
    StandardErrorResponse::new(
        CoreErrorResponseType::InvalidRequest,
        Some(message.to_string()),
        None,
    )
}

// ── Config JS ─────────────────────────────────────────────────────────────

pub async fn handle_configjs_route(
    State(state): State<crate::config::AppState>,
) -> Response {
    let app_config = serde_json::to_string(&state.config).unwrap();
    let openid_config = serde_json::to_string(&crate::openid::get_core_provider_metadata(&state)).unwrap();
    let js_body = format!(
        "const APP_CONFIG = {};\nconst OPENID_CONFIG = {};",
        app_config, openid_config
    );
    (
        [
            ("content-type", "text/javascript"),
            ("cache-control", "no-store"),
        ],
        js_body,
    )
        .into_response()
}

// ── Token creation ────────────────────────────────────────────────────────

fn create_token_response(
    state: &crate::config::AppState,
    client_id: String,
    user: &crate::config::User,
    scope: Option<String>,
    nonce: Option<String>,
    code: Option<String>,
) -> Response {
    let issue_time = Utc::now();
    let expiration_time = issue_time.add(state.access_token_lifetime);

    let standard_claims: StandardClaims<CoreGenderClaim> =
        StandardClaims::new(SubjectIdentifier::new(user.sub.clone()));
    let access_token_claims = IdTokenClaims::new(
        openidconnect::IssuerUrl::new(state.config.issuer.clone()).unwrap(),
        vec![Audience::new(client_id.clone())],
        expiration_time,
        issue_time,
        standard_claims,
        crate::config::DynamicAdditionalClaims(user.claims.clone()),
    );

    let mut id_token_claims = access_token_claims.clone();

    let (access_token_bearer, id_token, authorization_code_hash) = match &state.key_pair {
        crate::keys::SigningKeyPair::Rsa {
            private_key,
            public_key,
        } => {
            let alg = CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
            let access_token_inner: IdToken<
                crate::config::DynamicAdditionalClaims,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            > = IdToken::new(
                access_token_claims.clone(),
                private_key.as_ref(),
                alg.clone(),
                None,
                None,
            )
            .unwrap();
            let access_token_bearer_temp = AccessToken::new(access_token_inner.to_string());

            if let Some(nonce) = nonce.clone() {
                id_token_claims = id_token_claims.set_nonce(Some(Nonce::new(nonce)));
            }

            let auth_code_hash = match &code {
                Some(code) => {
                    AuthorizationCodeHash::from_code(
                        &openidconnect::AuthorizationCode::new(code.as_str().to_string()),
                        &alg,
                        public_key,
                    )
                    .ok()
                }
                None => None,
            };

            id_token_claims = id_token_claims.set_code_hash(auth_code_hash.clone());

            let id_token_inner: IdToken<
                crate::config::DynamicAdditionalClaims,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            > = IdToken::new(
                id_token_claims,
                private_key.as_ref(),
                alg,
                Some(&access_token_bearer_temp),
                None,
            )
            .unwrap();

            (access_token_bearer_temp, id_token_inner, auth_code_hash)
        }
        crate::keys::SigningKeyPair::Ed25519 {
            private_key,
            public_key,
        } => {
            let alg = CoreJwsSigningAlgorithm::EdDsa;
            let access_token_inner: IdToken<
                crate::config::DynamicAdditionalClaims,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            > = IdToken::new(
                access_token_claims.clone(),
                private_key.as_ref(),
                alg.clone(),
                None,
                None,
            )
            .unwrap();
            let access_token_bearer_temp = AccessToken::new(access_token_inner.to_string());

            if let Some(nonce) = nonce.clone() {
                id_token_claims = id_token_claims.set_nonce(Some(Nonce::new(nonce)));
            }

            let auth_code_hash = match &code {
                Some(code) => {
                    AuthorizationCodeHash::from_code(
                        &openidconnect::AuthorizationCode::new(code.as_str().to_string()),
                        &alg,
                        public_key,
                    )
                    .ok()
                }
                None => None,
            };

            id_token_claims = id_token_claims.set_code_hash(auth_code_hash.clone());

            let id_token_inner: IdToken<
                crate::config::DynamicAdditionalClaims,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            > = IdToken::new(
                id_token_claims,
                private_key.as_ref(),
                alg,
                Some(&access_token_bearer_temp),
                None,
            )
            .unwrap();

            (access_token_bearer_temp, id_token_inner, auth_code_hash)
        }
    };

    let mut token_response = StandardTokenResponse::new(
        access_token_bearer,
        CoreTokenType::Bearer,
        IdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    let refresh_token = crate::config::MidToken {
        aud: client_id,
        sub: user.sub.clone(),
        scp: scope,
        nonce: nonce,
        code_hash: match authorization_code_hash {
            Some(c) => Some(c.to_string()),
            None => None,
        },
        iat: issue_time,
    };
    token_response.set_refresh_token(Some(RefreshToken::new(
        URL_SAFE.encode(serde_json::to_vec(&refresh_token).unwrap()),
    )));

    info!("Issued tokens for user '{}'", user.sub);

    Json(token_response).into_response()
}
