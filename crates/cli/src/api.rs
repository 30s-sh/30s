//! HTTP client for the 30s API.

use anyhow::Result;
use reqwest::{Client, Response};
use shared::api::{
    ActivityLogQuery, ActivityLogResponse, AddDomainPayload, AddDomainResponse, BillingStatus,
    CreateCheckoutSessionResponse, CreateDropPayload, CreateDropResponse,
    CreatePortalSessionResponse, CreateWorkspacePayload, DeviceInfo, DevicePublicKey, DomainInfo,
    Drop, GetPublicKeysPayload, InboxItem, MeResponse, RegisterDevicePayload, RequestCodePayload,
    RotateVerifyPayload, RotateVerifyResponse, SetWebhookPayload, UpdatePoliciesPayload,
    VerifyCodePayload, VerifyCodeResponse, VerifyDomainResponse, WebhookConfig,
    WebhookTestResponse, WorkspaceInfo, WorkspacePolicies,
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

    /// Gets the user's workspace information.
    pub async fn get_workspace(&self, key: String) -> Result<WorkspaceInfo> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/workspace", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Adds a domain for verification.
    pub async fn add_domain(&self, key: String, domain: &str) -> Result<AddDomainResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/workspace/domains", self.base_url))
                .bearer_auth(key)
                .json(&AddDomainPayload {
                    domain: domain.to_string(),
                })
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Verifies a domain via DNS TXT record.
    pub async fn verify_domain(&self, key: String, domain: &str) -> Result<VerifyDomainResponse> {
        let response = Self::check_response(
            self.http
                .post(format!(
                    "{}/workspace/domains/{}/verify",
                    self.base_url, domain
                ))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Lists domains for the user's workspace.
    pub async fn list_domains(&self, key: String) -> Result<Vec<DomainInfo>> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/workspace/domains", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Creates a new workspace.
    pub async fn create_workspace(&self, key: String, name: &str) -> Result<WorkspaceInfo> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/workspace", self.base_url))
                .bearer_auth(key)
                .json(&CreateWorkspacePayload {
                    name: name.to_string(),
                })
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Creates a Stripe Checkout session for subscription.
    pub async fn create_checkout(&self, key: String) -> Result<CreateCheckoutSessionResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/billing/checkout", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Creates a Stripe Customer Portal session.
    pub async fn create_portal(&self, key: String) -> Result<CreatePortalSessionResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/billing/portal", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Gets billing status for the user's workspace.
    pub async fn billing_status(&self, key: String) -> Result<BillingStatus> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/billing/status", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Gets workspace policies.
    pub async fn get_policies(&self, key: String) -> Result<WorkspacePolicies> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/workspace/policies", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Updates workspace policies (admin only).
    pub async fn update_policies(&self, key: String, payload: UpdatePoliciesPayload) -> Result<()> {
        Self::check_response(
            self.http
                .put(format!("{}/workspace/policies", self.base_url))
                .bearer_auth(key)
                .json(&payload)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Gets workspace activity log.
    pub async fn get_activity(
        &self,
        key: String,
        query: ActivityLogQuery,
    ) -> Result<ActivityLogResponse> {
        let mut url = format!("{}/workspace/activity", self.base_url);

        // Build query string
        let mut params = vec![];
        if let Some(since) = query.since {
            params.push(format!("since={}", since));
        }
        if let Some(event_type) = &query.event_type {
            params.push(format!("event_type={}", event_type));
        }
        if let Some(limit) = query.limit {
            params.push(format!("limit={}", limit));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let response =
            Self::check_response(self.http.get(&url).bearer_auth(key).send().await?).await?;

        Ok(response.json().await?)
    }

    /// Sets a webhook URL for the authenticated user.
    pub async fn set_webhook(&self, key: String, url: &str) -> Result<WebhookConfig> {
        let response = Self::check_response(
            self.http
                .put(format!("{}/webhooks", self.base_url))
                .bearer_auth(key)
                .json(&SetWebhookPayload {
                    url: url.to_string(),
                })
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Gets the current webhook configuration.
    pub async fn get_webhook(&self, key: String) -> Result<WebhookConfig> {
        let response = Self::check_response(
            self.http
                .get(format!("{}/webhooks", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(response.json().await?)
    }

    /// Clears the webhook configuration.
    pub async fn clear_webhook(&self, key: String) -> Result<()> {
        Self::check_response(
            self.http
                .delete(format!("{}/webhooks", self.base_url))
                .bearer_auth(key)
                .send()
                .await?,
        )
        .await?;

        Ok(())
    }

    /// Sends a test webhook event.
    pub async fn test_webhook(&self, key: String) -> Result<WebhookTestResponse> {
        let response = Self::check_response(
            self.http
                .post(format!("{}/webhooks/test", self.base_url))
                .bearer_auth(key)
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
