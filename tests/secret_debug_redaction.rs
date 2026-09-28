//! Types that carry a password, a code, a token or a provider credential must
//! not print it through `Debug` (GA audit 2026-09-28, L20; CLAUDE.md: sensitive
//! data "MUST NOT implement Debug/Display/Serialize revealing contents").
//!
//! Each of these derived `Debug`, so any `{:?}` of the value — a tracing
//! field, a panic message, an `expect` on a `Result` that holds it — wrote the
//! secret out in clear.

use hearth::config::{
    MailgunConfig, MailtrapConfig, PostmarkConfig, SendgridConfig, SmtpConfig, SnsSmsConfig,
    TwilioConfig,
};
use hearth::identity::{PasswordGrantRequest, StepUpMfaGrantRequest};
use hearth::protocol::web::account::ChangePasswordForm;
use hearth::protocol::web::handlers::{LoginForm, RegisterForm, ResetPasswordFormData};

const SECRET: &str = "Sup3r-Secret-Value-9f1c";

fn assert_redacted(what: &str, debug: &str) {
    assert!(
        !debug.contains(SECRET),
        "{what} must not print the secret through Debug: {debug}"
    );
}

#[test]
fn web_forms_do_not_print_passwords() {
    assert_redacted(
        "LoginForm",
        &format!(
            "{:?}",
            LoginForm {
                email: "user@example.com".to_string(),
                password: SECRET.to_string(),
                return_to: None,
                locale: None,
                csrf: SECRET.to_string(),
            }
        ),
    );
    assert_redacted(
        "ChangePasswordForm",
        &format!(
            "{:?}",
            ChangePasswordForm {
                current_password: SECRET.to_string(),
                new_password: SECRET.to_string(),
                confirm_password: SECRET.to_string(),
                csrf: SECRET.to_string(),
            }
        ),
    );
    assert_redacted(
        "ResetPasswordFormData",
        &format!(
            "{:?}",
            ResetPasswordFormData {
                token: SECRET.to_string(),
                password: SECRET.to_string(),
                password_confirm: SECRET.to_string(),
            }
        ),
    );
    assert_redacted(
        "RegisterForm",
        &format!(
            "{:?}",
            RegisterForm {
                email: "user@example.com".to_string(),
                display_name: String::new(),
                first_name: String::new(),
                last_name: String::new(),
                password: SECRET.to_string(),
                password_confirm: SECRET.to_string(),
                invitation_token: Some(SECRET.to_string()),
                captcha_token: SECRET.to_string(),
                csrf: SECRET.to_string(),
            }
        ),
    );
}

#[test]
fn grant_requests_do_not_print_credentials() {
    assert_redacted(
        "PasswordGrantRequest",
        &format!(
            "{:?}",
            PasswordGrantRequest {
                email: "user@example.com".to_string(),
                password: SECRET.to_string(),
                ..Default::default()
            }
        ),
    );
    assert_redacted(
        "StepUpMfaGrantRequest",
        &format!(
            "{:?}",
            StepUpMfaGrantRequest {
                email: "user@example.com".to_string(),
                password: SECRET.to_string(),
                mfa_code: SECRET.to_string(),
                scope: None,
                client_ip: None,
                user_agent: None,
            }
        ),
    );
}

#[test]
fn email_provider_configs_do_not_print_credentials() {
    let smtp: SmtpConfig = serde_norway::from_str(&format!(
        "host: smtp.example.com\nport: 587\nusername: mailer\npassword: {SECRET}\n"
    ))
    .expect("smtp config");
    assert_redacted("SmtpConfig", &format!("{smtp:?}"));
    let sendgrid: SendgridConfig =
        serde_norway::from_str(&format!("api_key: {SECRET}\n")).expect("sendgrid config");
    assert_redacted("SendgridConfig", &format!("{sendgrid:?}"));
    let postmark: PostmarkConfig =
        serde_norway::from_str(&format!("server_token: {SECRET}\n")).expect("postmark config");
    assert_redacted("PostmarkConfig", &format!("{postmark:?}"));
    let mailgun: MailgunConfig =
        serde_norway::from_str(&format!("api_key: {SECRET}\ndomain: mg.example.com\n"))
            .expect("mailgun config");
    assert_redacted("MailgunConfig", &format!("{mailgun:?}"));
    let mailtrap: MailtrapConfig =
        serde_norway::from_str(&format!("api_key: {SECRET}\n")).expect("mailtrap config");
    assert_redacted("MailtrapConfig", &format!("{mailtrap:?}"));
}

#[test]
fn sms_provider_configs_do_not_print_credentials() {
    let twilio: TwilioConfig = serde_norway::from_str(&format!(
        "account_sid: AC123\nauth_token: {SECRET}\nfrom: \"+15550000000\"\n"
    ))
    .expect("twilio config");
    assert_redacted("TwilioConfig", &format!("{twilio:?}"));
    let sns: SnsSmsConfig = serde_norway::from_str(&format!(
        "region: us-east-1\naccess_key_id: AKIAEXAMPLE\nsecret_access_key: {SECRET}\n"
    ))
    .expect("sns config");
    assert_redacted("SnsSmsConfig", &format!("{sns:?}"));
}

#[test]
fn webhook_types_do_not_print_the_signing_secret() {
    use hearth::webhook::{CreateWebhookRequest, UpdateWebhookRequest};
    let create = CreateWebhookRequest {
        realm_id: hearth::core::RealmId::new(uuid::Uuid::new_v4()),
        url: "https://hooks.example.com/h".to_string(),
        secret: SECRET.to_string(),
        enabled: true,
        event_filters: Vec::new(),
    };
    assert_redacted("CreateWebhookRequest", &format!("{create:?}"));
    let update = UpdateWebhookRequest {
        secret: Some(SECRET.to_string()),
        ..Default::default()
    };
    assert_redacted("UpdateWebhookRequest", &format!("{update:?}"));
}
