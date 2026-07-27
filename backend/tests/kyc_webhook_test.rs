use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

fn sign_payload(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn sign_payload_raw_hex(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn valid_payload() -> &'static str {
    r#"{"wallet_address":"GDTEST123","status":"approved","event_type":"kyc.status_update","provider_reference":"ref-001"}"#
}

fn test_state(secret: Option<&str>) -> std::sync::Arc<inheritx_backend::AppState> {
    use inheritx_backend::stellar_anchor::AnchorRegistry;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/test".to_string());
    let (kyc_tx, _) = tokio::sync::broadcast::channel(100);
    let pool = sqlx::PgPool::connect_lazy(&database_url).unwrap();

    std::sync::Arc::new(inheritx_backend::AppState {
        anchor: std::sync::Arc::new(AnchorRegistry::new()),
        db_pool: pool,
        kyc_webhook_secret: secret.map(str::to_string),
        apy_config: inheritx_backend::yield_calculator::ApyConfig::default(),
        plan_cache: inheritx_backend::PlanCache::disabled(),
        kyc_tx,
        stellar_submit: inheritx_backend::stellar_submit::StellarSubmitClient::new(
            "https://horizon-testnet.stellar.org".to_string(),
        ),
    })
}

async fn cleanup_test_wallet() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/test".to_string());
    if let Ok(pool) = sqlx::PgPool::connect_lazy(&database_url) {
        let _ = sqlx::query("DELETE FROM kyc_records WHERE wallet_address='GDTEST123'")
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE wallet_address='GDTEST123'")
            .execute(&pool)
            .await;
    }
}

// ─── WEBHOOK SIGNATURE & AUTHENTICATION TESTS ──────────────────

#[tokio::test]
async fn test_webhook_rejects_invalid_signature() {
    let app = inheritx_backend::create_router(test_state(Some("test-secret")));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .header("x-kyc-signature", "sha256=invalidsignature")
                .body(Body::from(valid_payload()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_webhook_rejects_missing_signature_header() {
    let app = inheritx_backend::create_router(test_state(Some("test-secret")));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .body(Body::from(valid_payload()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_webhook_rejects_signature_for_a_different_body() {
    let secret = "test-secret";
    let sig = sign_payload(
        secret,
        br#"{"wallet_address":"GDOTHER","status":"rejected"}"#,
    );

    let app = inheritx_backend::create_router(test_state(Some(secret)));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .header("x-kyc-signature", sig)
                .body(Body::from(valid_payload()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_webhook_accepts_raw_hex_signature_without_prefix() {
    let secret = "test-secret";
    let body = valid_payload();
    let sig = sign_payload_raw_hex(secret, body.as_bytes());

    let app = inheritx_backend::create_router(test_state(Some(secret)));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .header("x-kyc-signature", sig)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_webhook_rejects_invalid_json() {
    let secret = "test-secret";
    let body = "not valid json";
    let sig = sign_payload(secret, body.as_bytes());

    let app = inheritx_backend::create_router(test_state(Some(secret)));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .header("x-kyc-signature", sig)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_valid_signature_accepted() {
    let secret = "test-secret-2";
    let body = valid_payload();
    let sig = sign_payload(secret, body.as_bytes());

    let app = inheritx_backend::create_router(test_state(Some(secret)));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .header("x-kyc-signature", sig)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_webhook_fails_closed_when_secret_not_configured() {
    let body = valid_payload();
    let app = inheritx_backend::create_router(test_state(None));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/webhook")
                .header("content-type", "application/json")
                .header(
                    "x-kyc-signature",
                    sign_payload("any-secret", body.as_bytes()),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ─── KYC ENDPOINT REQUEST TESTS ─────────────────────────────

#[tokio::test]
async fn test_get_kyc_status_endpoint() {
    cleanup_test_wallet().await;
    let app = inheritx_backend::create_router(test_state(None));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/kyc/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["wallet_address"], "GDTEST123");
    assert_eq!(json["kyc_status"], "pending");
}

#[tokio::test]
async fn test_submit_kyc_endpoint() {
    let app = inheritx_backend::create_router(test_state(None));
    let payload = serde_json::json!({
        "full_name": "John Doe",
        "email": "john@example.com",
        "date_of_birth": "1990-01-01",
        "nationality": "US",
        "id_type": "international_passport",
        "id_number": "A12345678",
        "expiry_date": "2030-01-01",
        "street_address": "123 Main St",
        "city": "New York",
        "country": "US",
        "postal_code": "10001",
        "document_id": "doc-123",
        "provider_reference": "ref-001"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/submit")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["kyc_status"], "submitted");
    assert_eq!(json["provider_reference"], "ref-001");
}

#[tokio::test]
async fn test_upload_kyc_document_endpoint() {
    let app = inheritx_backend::create_router(test_state(None));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kyc/upload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(json.get("document_id").is_some());
    assert!(json.get("url").is_some());
}

#[tokio::test]
async fn test_is_kyc_required_endpoint() {
    let app = inheritx_backend::create_router(test_state(None));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/kyc/required")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["required"], true);
}

#[tokio::test]
async fn test_get_kyc_requirements_endpoint() {
    let app = inheritx_backend::create_router(test_state(None));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/kyc/requirements")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["requires_id"], true);
    assert_eq!(json["requires_address_proof"], true);
    assert!(json["supported_id_types"].is_array());
    assert!(json["supported_countries"].is_array());
}
