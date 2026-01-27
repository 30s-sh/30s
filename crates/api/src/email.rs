//! Email sending abstraction.
//!
//! Uses Resend in production, SMTP (lettre) in development.
//! This allows local development without a Resend account.

use anyhow::Result;
use lettre::{
    Message, SmtpTransport, Transport,
    message::{Mailbox, header::ContentType},
};
use resend_rs::types::CreateEmailBaseOptions;

/// Email sender abstraction.
pub enum EmailSender {
    /// SMTP-based sender using lettre (for development)
    Smtp(SmtpSender),
    /// Resend API sender (for production)
    Resend(ResendSender),
}

impl EmailSender {
    /// Create a new email sender based on config.
    /// Uses Resend if api key is provided, otherwise falls back to SMTP.
    pub fn new(resend_api_key: Option<String>, smtp_url: Option<String>) -> Result<Self> {
        if let Some(api_key) = resend_api_key.filter(|k| !k.is_empty()) {
            Ok(Self::Resend(ResendSender::new(api_key)))
        } else if let Some(url) = smtp_url.filter(|u| !u.is_empty()) {
            Ok(Self::Smtp(SmtpSender::new(url)?))
        } else {
            anyhow::bail!("Either RESEND_API_KEY or SMTP_URL must be configured")
        }
    }

    /// Send a verification code email.
    pub async fn send_verification_code(&self, to: &str, code: &str) -> Result<()> {
        match self {
            Self::Resend(sender) => sender.send_verification_code(to, code).await,
            Self::Smtp(sender) => sender.send_verification_code(to, code),
        }
    }
}

/// SMTP sender using lettre.
pub struct SmtpSender {
    transport: SmtpTransport,
}

impl SmtpSender {
    pub fn new(smtp_url: String) -> Result<Self> {
        let transport = SmtpTransport::from_url(&smtp_url)?.build();

        Ok(Self { transport })
    }

    pub fn send_verification_code(&self, to: &str, code: &str) -> Result<()> {
        let email = Message::builder()
            .from(Mailbox::new(
                Some("30s".to_owned()),
                "noreply@mail.30s.sh".parse()?,
            ))
            .to(Mailbox::new(None, to.parse()?))
            .subject("Your 30s verification code")
            .header(ContentType::TEXT_PLAIN)
            .body(format!(
                "Your verification code is: {}\n\nThis code expires in 15 minutes.",
                code
            ))?;

        self.transport.send(&email)?;

        Ok(())
    }
}

/// Resend API sender.
pub struct ResendSender {
    client: resend_rs::Resend,
}

impl ResendSender {
    pub fn new(api_key: String) -> Self {
        Self {
            client: resend_rs::Resend::new(&api_key),
        }
    }

    pub async fn send_verification_code(&self, to: &str, code: &str) -> Result<()> {
        let email = CreateEmailBaseOptions::new(
            "30s <noreply@mail.30s.sh>",
            [to],
            "Your 30s verification code",
        )
        .with_text(&format!(
            "Your verification code is: {}\n\nThis code expires in 15 minutes.",
            code
        ));

        self.client.emails.send(email).await?;

        Ok(())
    }
}
