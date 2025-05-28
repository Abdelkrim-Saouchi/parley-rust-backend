use std::env;

use anyhow::{anyhow, Context};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};

pub async fn send_verification_email(
    to_email: &str,
    verification_link: &str,
) -> Result<(), anyhow::Error> {
    let smtp_server = env::var("SMTP_SERVER").context("Missing SMTP_SERVER env var")?;
    let smtp_port: u16 = env::var("SMTP_PORT")
        .context("Missing SMTP_PORT env var")?
        .parse()
        .context("SMTP_PORT must be a valid u16 integer")?;
    let smtp_username = env::var("SMTP_USERNAME").context("Missing SMTP_USERNAME env var")?;
    let smtp_password = env::var("SMTP_PASSWORD").context("Missing SMTP_PASSWORD env var")?;
    let smtp_from = env::var("SMTP_FROM").context("Missing SMTP_FROM env var")?;

    let from_mailbox = smtp_from
        .parse::<Mailbox>()
        .context("Invalid SMTP_FROM email address")?;
    let to_mailbox = to_email
        .trim()
        .parse::<Mailbox>()
        .context("Invalid recipient email address")?;

    let email = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject("Parley: Verify your email address")
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(format!(
            "Welcome to Parley! \n\nPlease verify your email by clicking the link below:\n\n{}\n\nIf you did not sign up, please ignore this email.",
                    verification_link
                ))
        .context("Failed to build email message")?;

    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
        .context("Failed to create SMTP relay")?
        .port(smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await.map_err(|e| {
        eprintln!("Email sending error: {}", e);
        anyhow!("Failed to send email: {}", e)
    })?;
    Ok(())
}

pub async fn send_password_reset_email(
    to_email: &str,
    reset_link: &str,
) -> Result<(), anyhow::Error> {
    let smtp_server = env::var("SMTP_SERVER").context("Missing SMTP_SERVER env var")?;
    let smtp_port: u16 = env::var("SMTP_PORT")
        .context("Missing SMTP_PORT env var")?
        .parse()
        .context("SMTP_PORT must be a valid u16 integer")?;
    let smtp_username = env::var("SMTP_USERNAME").context("Missing SMTP_USERNAME env var")?;
    let smtp_password = env::var("SMTP_PASSWORD").context("Missing SMTP_PASSWORD env var")?;
    let smtp_from = env::var("SMTP_FROM").context("Missing SMTP_FROM env var")?;

    let from_mailbox = smtp_from
        .parse::<Mailbox>()
        .context("Invalid SMTP_FROM email address")?;
    let to_mailbox = to_email
        .trim()
        .parse::<Mailbox>()
        .context("Invalid recipient email address")?;

    let email = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject("Parley: Reset your password") // Specific subject
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(format!(
            "We received a request to reset your password for your Parley account.\n\nPlease click the link below to set a new password:\n\n{}\n\nIf you did not request a password reset, please ignore this email.",
            reset_link
        ))
        .context("Failed to build email message for password reset")?;

    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
        .context("Failed to create SMTP relay for password reset")?
        .port(smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await.map_err(|e| {
        eprintln!("Password reset email sending error: {}", e);
        anyhow!("Failed to send password reset email: {}", e)
    })?;
    Ok(())
}
