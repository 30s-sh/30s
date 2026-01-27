use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub enum AppError {
    /// Internal errors - logged but return generic 500 to user
    Internal(anyhow::Error),
    /// User-facing errors - message is safe to show
    External(StatusCode, &'static str),
    /// Validation errors - safe to show
    Validation(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Internal(err) => {
                tracing::error!("internal error: {:?}", err);
                sentry::capture_error(
                    err.as_ref() as &(dyn std::error::Error + Send + Sync + 'static)
                );

                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
            AppError::External(status, msg) => (status, msg).into_response(),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
        }
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn response_body(response: Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn internal_error_returns_500_generic_message() {
        let err = AppError::Internal(anyhow::anyhow!("database connection failed"));
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response_body(response).await, "Internal server error");
    }

    #[tokio::test]
    async fn internal_error_hides_sensitive_details() {
        let err = AppError::Internal(anyhow::anyhow!("password=secret123 leaked"));
        let response = err.into_response();

        let body = response_body(response).await;

        assert!(!body.contains("secret123"));
        assert!(!body.contains("password"));
    }

    #[tokio::test]
    async fn external_error_returns_specified_status_and_message() {
        let err = AppError::External(StatusCode::NOT_FOUND, "Drop not found");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_body(response).await, "Drop not found");
    }

    #[tokio::test]
    async fn validation_error_returns_400_with_details() {
        let err = AppError::Validation("email: invalid format".into());
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_body(response).await, "email: invalid format");
    }

    #[tokio::test]
    async fn sqlx_error_converts_to_internal() {
        // Simulating what happens when a DB query fails
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "db down");
        let err: AppError = io_err.into();

        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
