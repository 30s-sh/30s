//! Unkey API client for key management and verification.
//!
//! Uses the v2 API: https://www.unkey.com/docs/api-reference

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    root_key: String,
    api_id: String,
}

impl Client {
    pub fn new(root_key: impl Into<String>, api_id: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            root_key: root_key.into(),
            api_id: api_id.into(),
        }
    }

    /// Verify an API key. Returns the verification result.
    pub async fn verify_key(&self, key: &str) -> Result<VerifyKeyResponse, Error> {
        let response = self
            .http
            .post("https://api.unkey.com/v2/keys.verifyKey")
            .header("Authorization", format!("Bearer {}", self.root_key))
            .json(&VerifyKeyRequest { key })
            .send()
            .await
            .map_err(|e| Error::Request(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                message: body,
            });
        }

        let wrapper: ApiResponse<VerifyKeyResponse> = response
            .json()
            .await
            .map_err(|e| Error::Parse(e.to_string()))?;

        Ok(wrapper.data)
    }

    /// Create a new API key for a user.
    pub async fn create_key(
        &self,
        external_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<CreateKeyResponse, Error> {
        let response = self
            .http
            .post("https://api.unkey.com/v2/keys.createKey")
            .header("Authorization", format!("Bearer {}", self.root_key))
            .json(&CreateKeyRequest {
                api_id: self.api_id.clone(),
                external_id: external_id.into(),
                name: name.into(),
            })
            .send()
            .await
            .map_err(|e| Error::Request(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                message: body,
            });
        }

        let wrapper: ApiResponse<CreateKeyResponse> = response
            .json()
            .await
            .map_err(|e| Error::Parse(e.to_string()))?;

        Ok(wrapper.data)
    }

    /// Delete/revoke an API key by its key_id.
    pub async fn delete_key(&self, key_id: &str) -> Result<(), Error> {
        let response = self
            .http
            .post("https://api.unkey.com/v2/keys.deleteKey")
            .header("Authorization", format!("Bearer {}", self.root_key))
            .json(&DeleteKeyRequest { key_id })
            .send()
            .await
            .map_err(|e| Error::Request(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                message: body,
            });
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    Request(String),
    Api { status: u16, message: String },
    Parse(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Request(e) => write!(f, "request failed: {}", e),
            Error::Api { status, message } => write!(f, "API error {}: {}", status, message),
            Error::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Serialize)]
struct VerifyKeyRequest<'a> {
    key: &'a str,
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    data: T,
}

#[derive(Deserialize)]
pub struct VerifyKeyResponse {
    pub valid: bool,
    pub identity: Option<Identity>,
}

#[derive(Deserialize)]
pub struct Identity {
    #[serde(rename = "externalId")]
    pub external_id: String,
}

#[derive(Serialize)]
struct CreateKeyRequest {
    #[serde(rename = "apiId")]
    api_id: String,
    #[serde(rename = "externalId")]
    external_id: String,
    name: String,
}

#[derive(Deserialize)]
pub struct CreateKeyResponse {
    pub key: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
}

#[derive(Serialize)]
struct DeleteKeyRequest<'a> {
    #[serde(rename = "keyId")]
    key_id: &'a str,
}
