//! Health check endpoint for load balancers and monitoring.
//!
//! Returns 200 OK if the service is healthy (database and Redis reachable),
//! 503 Service Unavailable otherwise.

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(health_check))
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    database: bool,
    redis: bool,
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.database)
        .await
        .is_ok();

    let redis_ok = match state.redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .is_ok(),
        Err(_) => false,
    };

    let healthy = db_ok && redis_ok;

    let response = HealthResponse {
        status: if healthy { "ok" } else { "unhealthy" },
        database: db_ok,
        redis: redis_ok,
    };

    let status = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}
