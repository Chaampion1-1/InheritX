use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use inheritx_backend::middleware::{rate_limit_middleware, RateLimitConfig, RateLimitStore};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn build_rate_limited_app(max_requests: u64, window_secs: u64) -> Router {
    let store = RateLimitStore::new();
    let config = Arc::new(RateLimitConfig {
        max_requests,
        window: Duration::from_secs(window_secs),
    });

    Router::new()
        .route("/test", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(move |req, next| {
            rate_limit_middleware(req, next, store.clone(), config.clone())
        }))
}

#[tokio::test]
async fn test_requests_within_limit_succeed() {
    let app = build_rate_limited_app(5, 60);

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_request_exceeding_limit_returns_429() {
    let app = build_rate_limited_app(3, 60);

    for _ in 0..3 {
        app.clone()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
    }

    // 4th request should be rate limited
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_rate_limit_window_resets() {
    let store = RateLimitStore::new();
    let config = RateLimitConfig {
        max_requests: 2,
        window: Duration::from_millis(100),
    };

    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // Use up the limit
    assert!(store.check_and_increment(ip, &config));
    assert!(store.check_and_increment(ip, &config));
    // 3rd should fail
    assert!(!store.check_and_increment(ip, &config));

    // Wait for window to expire
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Should be allowed again after window reset
    assert!(store.check_and_increment(ip, &config));
}

#[tokio::test]
async fn test_heavy_mock_traffic_triggers_rate_limit() {
    let app = build_rate_limited_app(10, 60);
    let mut limited_count = 0;

    for _ in 0..30 {
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            limited_count += 1;
        }
    }

    // At least 20 requests should have been rate limited
    assert!(
        limited_count >= 20,
        "Expected at least 20 limited, got {limited_count}"
    );
}

#[tokio::test]
async fn test_different_ips_have_independent_limits() {
    let store = RateLimitStore::new();
    let config = RateLimitConfig {
        max_requests: 1,
        window: Duration::from_secs(60),
    };

    let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();

    // IP1 uses its limit
    assert!(store.check_and_increment(ip1, &config));
    assert!(!store.check_and_increment(ip1, &config));

    // IP2 should still be allowed independently
    assert!(store.check_and_increment(ip2, &config));
}

// ─── JWT MIDDLEWARE REQUEST TESTS ───────────────────────────

use inheritx_backend::auth::{jwt_auth_middleware, Claims};
use jsonwebtoken::{encode, EncodingKey, Header};

fn generate_test_jwt(secret: &str, role: &str, expires_in_secs: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let exp = (now + expires_in_secs) as usize;
    let claims = Claims {
        sub: "admin-uuid-1234".to_string(),
        role: role.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn build_jwt_protected_app() -> Router {
    Router::new()
        .route("/api/admin/protected", get(|| async { "admin ok" }))
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
}

#[tokio::test]
async fn test_jwt_auth_missing_header_returns_401() {
    std::env::set_var("JWT_SECRET", "test-secret-key-12345");
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"], "Missing authorization header");
}

#[tokio::test]
async fn test_jwt_auth_invalid_header_format_returns_401() {
    std::env::set_var("JWT_SECRET", "test-secret-key-12345");
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .header("Authorization", "Basic invalidtokenformat")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"], "Invalid authorization header format");
}

#[tokio::test]
async fn test_jwt_auth_empty_token_returns_401() {
    std::env::set_var("JWT_SECRET", "test-secret-key-12345");
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .header("Authorization", "Bearer ")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"], "Missing token");
}

#[tokio::test]
async fn test_jwt_auth_invalid_signature_returns_401() {
    std::env::set_var("JWT_SECRET", "correct-secret-key");
    let token = generate_test_jwt("wrong-secret-key", "admin", 3600);
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"], "Invalid token");
}

#[tokio::test]
async fn test_jwt_auth_expired_token_returns_401() {
    let secret = "test-secret-key-12345";
    std::env::set_var("JWT_SECRET", secret);
    let expired_token = generate_test_jwt(secret, "admin", -3600);
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .header("Authorization", format!("Bearer {expired_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"], "Invalid token");
}

#[tokio::test]
async fn test_jwt_auth_non_admin_role_returns_401() {
    let secret = "test-secret-key-12345";
    std::env::set_var("JWT_SECRET", secret);
    let user_token = generate_test_jwt(secret, "user", 3600);
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .header("Authorization", format!("Bearer {user_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"], "Unauthorized");
}

#[tokio::test]
async fn test_jwt_auth_valid_admin_token_succeeds() {
    let secret = "test-secret-key-12345";
    std::env::set_var("JWT_SECRET", secret);
    let admin_token = generate_test_jwt(secret, "admin", 3600);
    let app = build_jwt_protected_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/protected")
                .header("Authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_admin_login_empty_payload_returns_400() {
    use inheritx_backend::stellar_anchor::AnchorRegistry;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect_lazy(&database_url).unwrap();

    let state = std::sync::Arc::new(inheritx_backend::AppState {
        anchor: std::sync::Arc::new(AnchorRegistry::new()),
        db_pool: pool,
        kyc_webhook_secret: None,
        apy_config: inheritx_backend::yield_calculator::ApyConfig::default(),
        plan_cache: inheritx_backend::PlanCache::disabled(),
        kyc_tx: tokio::sync::broadcast::channel(16).0,
        stellar_submit: inheritx_backend::stellar_submit::StellarSubmitClient::new(
            "https://horizon-testnet.stellar.org".to_string(),
        ),
    });

    let app = inheritx_backend::create_router(state);

    let payload = serde_json::json!({
        "email": "",
        "password": ""
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/login")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
