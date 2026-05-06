use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, Method, request::Parts as RequestParts};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json, Router, routing::get, routing::post};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{DateTime, TimeDelta, Utc};
use openidconnect::core::{
    CoreClaimName, CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
    CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
    CoreTokenType,
};
use openidconnect::{
    AccessToken, AdditionalClaims, Audience, AuthUrl, AuthorizationCodeHash,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, IdToken, IdTokenClaims, IdTokenFields,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, Nonce, PrivateSigningKey, RefreshToken,
    ResponseTypes, Scope, StandardClaims, StandardErrorResponse, StandardTokenResponse,
    SubjectIdentifier, TokenUrl,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::signal;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info};

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    key_size: usize,
    users: Vec<User>,
    issuer: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct User {
    sub: String,
    claims: HashMap<String, Value>,
}

#[derive(Clone)]
struct AppState {
    pub config: Config,
    pub rsa_private_key: Arc<CoreRsaPrivateSigningKey>,
    pub rsa_public_key: CoreJsonWebKey,
    pub access_token_lifetime: TimeDelta,
    pub refresh_token_lifetime: TimeDelta,
    pub authorization_code_lifetime: TimeDelta,
}

impl AppState {
    pub fn new(
        config: Config,
        rsa_private_key: CoreRsaPrivateSigningKey,
        rsa_public_key: CoreJsonWebKey,
    ) -> AppState {
        return AppState {
            config,
            rsa_private_key: Arc::new(rsa_private_key),
            rsa_public_key,
            access_token_lifetime: TimeDelta::minutes(5),
            refresh_token_lifetime: TimeDelta::hours(1),
            authorization_code_lifetime: TimeDelta::minutes(1),
        };
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let config_json =
        std::fs::read_to_string("config.json").expect("Unable to read config.json contents");
    let mut config: Config =
        serde_json::from_str(&config_json).expect("Invalid configuration json");

    if !config.issuer.ends_with('/') {
        config.issuer.push('/');
    }

    info!("Loaded configuration");
    info!("Generating RSA key, this may take some time...");

    let mut rng = rsa::rand_core::OsRng;
    let rsa_priv_key =
        RsaPrivateKey::new(&mut rng, config.key_size).expect("Failed to generate a key");
    let rsa_pem = rsa_priv_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::CRLF)
        .expect("Failed to convert private key to PEM");

    info!("Generated RSA key");

    let rsa_private_key = CoreRsaPrivateSigningKey::from_pem(
        &rsa_pem,
        Some(JsonWebKeyId::new("rsa-key".to_string())),
    )
    .unwrap();
    let rsa_public_key = rsa_private_key.as_verification_key();

    let state = AppState::new(config, rsa_private_key, rsa_public_key);

    let serve_dir = ServeDir::new("www").not_found_service(ServeFile::new("www/index.html"));

    let cors = CorsLayer::new()
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(AllowOrigin::predicate(
            | _: &HeaderValue, _: &RequestParts | true
        ));

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(get_provider_metadata),
        )
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/js/config.js", get(handle_configjs_request))
        .route("/token", post(handle_token_request))
        .with_state(state)
        .layer(cors)
        .fallback_service(serve_dir);

    let listener = tokio::net::TcpListener::bind("[::]:8000").await.unwrap();

    info!("Created listener");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn get_core_provider_metadata(state: AppState) -> CoreProviderMetadata {
    let issuer = state.config.issuer;

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
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{}token", issuer)).unwrap()))
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
    return provider_metadata;
}

async fn get_provider_metadata(State(state): State<AppState>) -> Json<CoreProviderMetadata> {
    return Json(get_core_provider_metadata(state));
}

async fn get_jwks(State(state): State<AppState>) -> Json<CoreJsonWebKeySet> {
    let jwks = CoreJsonWebKeySet::new(vec![state.rsa_public_key]);
    return Json(jwks);
}

async fn handle_configjs_request(State(state): State<AppState>) -> Response {
    let app_config = serde_json::to_string(&state.config).unwrap();
    let openid_config = serde_json::to_string(&get_core_provider_metadata(state)).unwrap();
    let js_body = format!(
        "const APP_CONFIG = {};\nconst OPENID_CONFIG = {};",
        app_config, openid_config
    );
    return (
        [
            ("content-type", "text/javascript"),
            ("cache-control", "no-store"),
        ],
        js_body,
    )
        .into_response();
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: CoreGrantType,
    code: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
    username: Option<String>,
    scope: Option<String>,
    nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct MidToken {
    aud: String,
    sub: String,
    scp: Option<String>,
    nonce: Option<String>,
    code_hash: Option<String>,
    iat: DateTime<Utc>,
}

fn get_user_by_name(state: &AppState, name: String) -> Option<User> {
    let Some(user) = state.config.users.iter().find(|u| u.sub == name) else {
        return None;
    };
    return Some(user.clone());
}

async fn handle_token_request(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Response {
    let Some(client_id) = request.client_id else {
        return Json(error_response("client_id is missing")).into_response();
    };

    if request.grant_type == CoreGrantType::Password {
        let Some(username) = request.username else {
            return Json(error_response("username is missing")).into_response();
        };

        let Some(user) = get_user_by_name(&state, username) else {
            return Json(error_response("user not found")).into_response();
        };

        return create_token_response(state, client_id, &user, request.scope, request.nonce, None);
    }

    if request.grant_type == CoreGrantType::ClientCredentials {
        let Some(user) = get_user_by_name(&state, client_id.clone()) else {
            return Json(error_response("user not found")).into_response();
        };

        return create_token_response(state, client_id, &user, request.scope, request.nonce, None);
    }

    if request.grant_type == CoreGrantType::RefreshToken {
        let Some(refresh_token) = request.refresh_token else {
            return Json(error_response("refresh_token is missing")).into_response();
        };

        let Ok(refresh_token) = URL_SAFE.decode(refresh_token) else {
            return Json(error_response("refresh_token is not valid base64 url data"))
                .into_response();
        };

        let Ok(token) = serde_json::from_slice::<MidToken>(&refresh_token) else {
            return Json(error_response("refresh_token is invalid")).into_response();
        };

        if token.aud != client_id {
            return Json(error_response(
                "refresh_token is not valid for this client_id",
            ))
            .into_response();
        }

        if token.iat.add(state.refresh_token_lifetime) <= Utc::now() {
            return Json(error_response("refresh_token has expired")).into_response();
        }

        let Some(user) = get_user_by_name(&state, token.sub) else {
            return Json(error_response("user not found")).into_response();
        };

        return create_token_response(
            state,
            token.aud,
            &user,
            token.scp,
            token.nonce,
            token.code_hash,
        );
    }

    if request.grant_type == CoreGrantType::AuthorizationCode {
        let Some(code) = request.code else {
            return Json(error_response("code is missing")).into_response();
        };

        let Ok(authorization_code) = URL_SAFE.decode(code.clone()) else {
            return Json(error_response("code is not valid base64 url data")).into_response();
        };

        let Ok(token) = serde_json::from_slice::<MidToken>(&authorization_code) else {
            return Json(error_response("code is invalid")).into_response();
        };

        if token.aud != client_id {
            return Json(error_response("code is not valid for this client_id")).into_response();
        }

        if token.iat.add(state.authorization_code_lifetime) <= Utc::now() {
            return Json(error_response("code has expired")).into_response();
        }

        let Some(user) = get_user_by_name(&state, token.sub) else {
            return Json(error_response("user not found")).into_response();
        };

        return create_token_response(state, token.aud, &user, token.scp, token.nonce, Some(code));
    }

    return Json(StandardErrorResponse::new(
        CoreErrorResponseType::InvalidGrant,
        None,
        None,
    ))
    .into_response();
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct DynamicAdditionalClaims(HashMap<String, Value>);
impl AdditionalClaims for DynamicAdditionalClaims {}

fn create_token_response(
    state: AppState,
    client_id: String,
    user: &User,
    scope: Option<String>,
    nonce: Option<String>,
    code: Option<String>,
) -> Response {
    let issue_time = Utc::now();
    let expiration_time = issue_time.add(state.access_token_lifetime);
    let standard_claims: StandardClaims<CoreGenderClaim> =
        StandardClaims::new(SubjectIdentifier::new(user.sub.clone()));
    let access_token_claims = IdTokenClaims::new(
        IssuerUrl::new(state.config.issuer.clone()).unwrap(),
        vec![Audience::new(client_id.clone())],
        expiration_time,
        issue_time,
        standard_claims,
        DynamicAdditionalClaims(user.claims.clone()),
    );
    let mut id_token_claims = access_token_claims.clone();

    let access_token: openidconnect::IdToken<_, _, CoreJweContentEncryptionAlgorithm, _> =
        IdToken::new(
            access_token_claims,
            state.rsa_private_key.as_ref(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .unwrap();
    let access_token = AccessToken::new(access_token.to_string());

    if let Some(nonce) = nonce.clone() {
        id_token_claims = id_token_claims.set_nonce(Some(Nonce::new(nonce)));
    }

    let authorization_code_hash = match code {
        Some(code) => Some(
            AuthorizationCodeHash::from_code(
                &openidconnect::AuthorizationCode::new(code),
                &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                &state.rsa_public_key,
            )
            .unwrap(),
        ),
        None => None,
    };

    id_token_claims = id_token_claims.set_code_hash(authorization_code_hash.clone());

    let id_token: IdToken<
        DynamicAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    > = IdToken::new(
        id_token_claims,
        state.rsa_private_key.as_ref(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(&access_token),
        None,
    )
    .unwrap();

    let mut token_response = StandardTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        IdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    let refresh_token = MidToken {
        aud: client_id,
        sub: user.sub.clone(),
        scp: scope,
        nonce: nonce,
        code_hash: match authorization_code_hash {
            Some(code_hash) => Some(code_hash.to_string()),
            None => None,
        },
        iat: issue_time,
    };
    token_response.set_refresh_token(Some(RefreshToken::new(
        URL_SAFE.encode(serde_json::to_vec(&refresh_token).unwrap()),
    )));

    info!("Issued tokens for user '{}'", user.sub);

    return Json(token_response).into_response();
}

fn error_response(message: &str) -> StandardErrorResponse<CoreErrorResponseType> {
    error!("Returned error response: {}", message);
    return StandardErrorResponse::new(
        CoreErrorResponseType::InvalidRequest,
        Some(message.to_string()),
        None,
    );
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
