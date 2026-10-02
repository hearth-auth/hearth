//! Types that carry a password, a code, a token or a provider credential must
//! not print it through `Debug` (GA audit 2026-09-28, L20; CLAUDE.md: sensitive
//! data "MUST NOT implement Debug/Display/Serialize revealing contents").
//!
//! Each of these derived `Debug`, so any `{:?}` of the value — a tracing
//! field, a panic message, an `expect` on a `Result` that holds it — wrote the
//! secret out in clear.

use hearth::config::{MailgunConfig, MailtrapConfig, PostmarkConfig, SendgridConfig, SmtpConfig};
use hearth::core::FormSecret;
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
                password: FormSecret::new(SECRET.to_string()),
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
                current_password: FormSecret::new(SECRET.to_string()),
                new_password: FormSecret::new(SECRET.to_string()),
                confirm_password: FormSecret::new(SECRET.to_string()),
                csrf: SECRET.to_string(),
            }
        ),
    );
    assert_redacted(
        "ResetPasswordFormData",
        &format!(
            "{:?}",
            ResetPasswordFormData {
                link_binding: String::new(),
                password: FormSecret::new(SECRET.to_string()),
                password_confirm: FormSecret::new(SECRET.to_string()),
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
                password: FormSecret::new(SECRET.to_string()),
                password_confirm: FormSecret::new(SECRET.to_string()),
                invitation_token: Some(FormSecret::new(SECRET.to_string())),
                captcha_token: SECRET.to_string(),
                csrf: SECRET.to_string(),
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
