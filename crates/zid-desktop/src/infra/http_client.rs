use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};

use crate::error::AppError;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    base_url: String,
    access_token: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct ServerErrorBody {
    error: Option<String>,
    message: Option<String>,
}

impl HttpClient {
    pub fn new(base_url: &str) -> Result<Self, AppError> {
        let client = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| AppError::ServerUnreachable)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: None,
        })
    }

    pub fn set_access_token(&mut self, token: Option<String>) {
        self.access_token = token;
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> Result<T, AppError> {
        let status = response.status();

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30);
            return Err(AppError::RateLimited {
                retry_after: Duration::from_secs(retry_after),
            });
        }

        if status.is_success() {
            return response
                .json::<T>()
                .await
                .map_err(|e| AppError::ServerError(status.as_u16(), e.to_string()));
        }

        let code = status.as_u16();
        let body = response.json::<ServerErrorBody>().await.ok();
        let msg = body
            .and_then(|b| b.error.or(b.message))
            .unwrap_or_else(|| format!("HTTP {code}"));

        match code {
            401 => Err(AppError::SessionExpired),
            403 => {
                if msg.to_lowercase().contains("frozen") {
                    Err(AppError::IdentityFrozen)
                } else if msg.to_lowercase().contains("mfa") {
                    Err(AppError::MfaRequired)
                } else {
                    Err(AppError::InvalidCredentials)
                }
            }
            404 => Err(AppError::NotFound(msg)),
            409 => Err(AppError::Conflict(msg)),
            _ => Err(AppError::ServerError(code, msg)),
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, AppError> {
        let mut req = self.client.get(self.url(path));
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, AppError> {
        let mut req = self.client.post(self.url(path)).json(body);
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    pub async fn put<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, AppError> {
        let mut req = self.client.put(self.url(path)).json(body);
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, AppError> {
        let mut req = self.client.delete(self.url(path));
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    pub async fn delete_no_body(&self, path: &str) -> Result<(), AppError> {
        let mut req = self.client.delete(self.url(path));
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30);
            return Err(AppError::RateLimited {
                retry_after: Duration::from_secs(retry_after),
            });
        }
        if status.is_success() {
            Ok(())
        } else {
            let code = status.as_u16();
            let body = resp.json::<ServerErrorBody>().await.ok();
            let msg = body
                .and_then(|b| b.error.or(b.message))
                .unwrap_or_else(|| format!("HTTP {code}"));
            Err(AppError::ServerError(code, msg))
        }
    }
}
