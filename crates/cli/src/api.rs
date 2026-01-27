//! HTTP client for the 30s API.

use anyhow::Result;
use reqwest::{Client, Response};
use shared::api::{
    CreateDropPayload, CreateDropResponse, DeviceInfo, DevicePublicKey, Drop, GetPublicKeysPayload,
    InboxItem, MeResponse, RegisterDevicePayload, RequestCodePayload, RotateVerifyPayload,
    RotateVerifyResponse, VerifyCodePayload, VerifyCodeResponse,
};

pub struct Api {
    pub http: Client,
    pub base_url: String,
}

impl Api {
    pub fn new(base_url: String) -> Self {
        Self {
            http: Client::new(),
            base_url,
        }
    }

    /// Requests a verification code be sent to the given email.
    pub async fn request_code(&self, payload: RequestCodePayload) -> Result<()> {
        let _ = Self::check_response(
            self.http
                .post(format!("{}/auth/code", self.base_url))
                .json(&payload)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Verifies an email with the code and returns an API key.
    pub async fn verify_code(&self, payload: VerifyCodePayload) -> Result<VerifyCodeResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/auth/verify", self.base_url))
                .json(&payload)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Registers a device's public key for receiving encrypted secrets.
    pub async fn register_device(&self, key: String, payload: RegisterDevicePayload) -> Result<()> {
        let _ = Self::check_response(
            self.http
                .post(format!("{}/devices/register", self.base_url))
                .bearer_auth(key)
                .json(&payload)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Fetches public keys for a list of recipient emails (for encrypting secrets to them).
    pub async fn get_public_keys(
        &self,
        key: String,
        emails: Vec<String>,
    ) -> Result<Vec<DevicePublicKey>> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/devices/public-keys", self.base_url))
                .bearer_auth(key)
                .json(&GetPublicKeysPayload { emails })
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Creates an encrypted drop for one or more recipients.
    pub async fn create_drop(
        &self,
        key: String,
        payload: CreateDropPayload,
    ) -> Result<CreateDropResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/drops/create", self.base_url))
                .bearer_auth(key)
                .json(&payload)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Lists drops in the authenticated user's inbox.
    pub async fn get_inbox(&self, key: String) -> Result<Vec<InboxItem>> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/drops/inbox", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Fetches a specific drop by ID.
    pub async fn get_drop(&self, key: String, id: &str) -> Result<Drop> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/drops/{}", self.base_url, id))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Deletes a drop (sender only).
    pub async fn delete_drop(&self, key: String, id: &str) -> Result<()> {
        Self::check_response(
            self.http
                .delete(format!("{}/drops/{}", self.base_url, id))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Gets the authenticated user's email.
    pub async fn get_me(&self, key: String) -> Result<MeResponse> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/auth/me", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Lists the authenticated user's devices.
    pub async fn list_devices(&self, key: String) -> Result<Vec<DeviceInfo>> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/devices", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Deletes a device by ID.
    pub async fn delete_device(&self, key: String, id: &str) -> Result<()> {
        Self::check_response(
            self.http
                .delete(format!("{}/devices/{}", self.base_url, id))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Updates a device's public key.
    pub async fn update_device(
        &self,
        key: String,
        id: &str,
        payload: RegisterDevicePayload,
    ) -> Result<()> {
        Self::check_response(
            self.http
                .put(format!("{}/devices/{}", self.base_url, id))
                .bearer_auth(key)
                .json(&payload)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Deletes the user's account and all associated data.
    pub async fn delete_account(&self, key: String) -> Result<()> {
        Self::check_response(
            self.http
                .delete(format!("{}/auth/me", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Requests a verification code for API key rotation.
    pub async fn request_rotate(&self, key: String) -> Result<()> {
        Self::check_response(
            self.http
                .post(format!("{}/auth/rotate", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Verifies the rotation code and returns a new API key.
    pub async fn verify_rotate(&self, key: String, code: String) -> Result<RotateVerifyResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/auth/rotate/verify", self.base_url))
                .bearer_auth(key)
                .json(&RotateVerifyPayload { code })
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    async fn check_response(response: Response) -> Result<Response> {
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Try to extract error message from JSON response
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|json| {
                    json.get("error")
                        .or_else(|| json.get("message"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| {
                    if body.is_empty() {
                        status
                            .canonical_reason()
                            .unwrap_or("Request failed")
                            .to_string()
                    } else {
                        body
                    }
                });

            anyhow::bail!("{}", message);
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test error message extraction from API responses
    mod check_response {
        use super::*;

        // Helper to create a mock response
        async fn mock_response(status: u16, body: &str) -> Response {
            // Use a local server or construct response manually
            // Since we can't easily mock reqwest::Response, we'll use wiremock
            use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

            let server = MockServer::start().await;

            Mock::given(any())
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;

            reqwest::get(server.uri()).await.unwrap()
        }

        #[tokio::test]
        async fn extracts_error_field_from_json() {
            let response = mock_response(400, r#"{"error": "Invalid code"}"#).await;
            let err = Api::check_response(response).await.unwrap_err();

            assert_eq!(err.to_string(), "Invalid code");
        }

        #[tokio::test]
        async fn extracts_message_field_from_json() {
            let response = mock_response(400, r#"{"message": "Rate limited"}"#).await;
            let err = Api::check_response(response).await.unwrap_err();

            assert_eq!(err.to_string(), "Rate limited");
        }

        #[tokio::test]
        async fn prefers_error_over_message() {
            let response =
                mock_response(400, r#"{"error": "Specific", "message": "Generic"}"#).await;
            let err = Api::check_response(response).await.unwrap_err();

            assert_eq!(err.to_string(), "Specific");
        }

        #[tokio::test]
        async fn falls_back_to_raw_body_for_non_json() {
            let response = mock_response(500, "Internal server error").await;
            let err = Api::check_response(response).await.unwrap_err();

            assert_eq!(err.to_string(), "Internal server error");
        }

        #[tokio::test]
        async fn uses_status_reason_for_empty_body() {
            let response = mock_response(404, "").await;
            let err = Api::check_response(response).await.unwrap_err();

            assert_eq!(err.to_string(), "Not Found");
        }

        #[tokio::test]
        async fn passes_through_success_response() {
            let response = mock_response(200, r#"{"data": "ok"}"#).await;
            let result = Api::check_response(response).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_json_without_error_or_message() {
            let response = mock_response(400, r#"{"code": 123}"#).await;
            let err = Api::check_response(response).await.unwrap_err();

            // Falls back to raw body since no error/message field
            assert_eq!(err.to_string(), r#"{"code": 123}"#);
        }
    }
}
